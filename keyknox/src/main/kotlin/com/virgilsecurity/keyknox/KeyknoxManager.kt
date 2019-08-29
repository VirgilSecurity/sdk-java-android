/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.keyknox


import com.virgilsecurity.keyknox.client.KeyknoxClientProtocol
import com.virgilsecurity.keyknox.crypto.KeyknoxCryptoProtocol
import com.virgilsecurity.keyknox.exception.EmptyPublicKeysException
import com.virgilsecurity.keyknox.exception.KeyknoxServiceException
import com.virgilsecurity.keyknox.exception.TamperedServerResponseException
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.PrivateKey
import com.virgilsecurity.sdk.crypto.PublicKey
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import java.util.*

/**
 * Class responsible for interactions with Keyknox cloud + encrypting/decrypting those values.
 */
class KeyknoxManager(private val accessTokenProvider: AccessTokenProvider,
                     private val keyknoxClient: KeyknoxClientProtocol,
                     var publicKeys: List<VirgilPublicKey>,
                     var privateKey: VirgilPrivateKey,
                     private val crypto: KeyknoxCryptoProtocol,
                     val retryOnUnauthorized: Boolean = false) {

    init {
        if (publicKeys.isEmpty()) {
            throw EmptyPublicKeysException()
        }
    }

    /**
     * Signs then encrypts and pushed value to Keyknox service.
     *
     * @param value Value to push.
     * @param previousHash Previous hash value.
     */
    fun pushValue(value: ByteArray, previousHash: ByteArray?): DecryptedKeyknoxValue {
        val operation = { b: Boolean ->
            val tokenContext = TokenContext("put", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            val encryptedValue = this.crypto.encrypt(value, this.privateKey, this.publicKeys)
            val response = this.keyknoxClient.pushValue(encryptedValue.first, encryptedValue.second, previousHash, token.stringRepresentation())
            verifyServerResponse(encryptedValue, response)
            this.crypto.decrypt(response, this.privateKey, this.publicKeys)
        }

        return run(operation)
    }

    /**
     * Pull value, decrypt then verify signature.
     */
    fun pullValue(): DecryptedKeyknoxValue {
        val operation = { b: Boolean ->
            val tokenContext = TokenContext("get", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            val response = this.keyknoxClient.pullValue(token.stringRepresentation())
            this.crypto.decrypt(response, this.privateKey, this.publicKeys)
        }
        return run(operation)
    }

    /**
     * Resets Keyknox value (makes it empty). Also increments version.
     */
    fun resetValue(): DecryptedKeyknoxValue {
        val operation = { b: Boolean ->
            val tokenContext = TokenContext("delete", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            val response = this.keyknoxClient.resetValue(token.stringRepresentation())

            if ((response.meta == null || response.meta.isEmpty())
                    && (response.value == null || response.value.isEmpty())) {
                response
            } else {
                throw TamperedServerResponseException()
            }
        }
        return run(operation)
    }

    /**
     * Updates public keys for ecnryption and signature verification and private key for decryption and signature generation.
     *
     * @param newPublicKeys New public keys that will be used for encryption and signature verification.
     * @param newPrivateKey New private key that will be used for decryption and signature generation.
     *
     * @return DecryptedKeyknoxValue.
     */
    @JvmOverloads
    fun updateRecipients(newPublicKeys: List<VirgilPublicKey>? = null,
                         newPrivateKey: VirgilPrivateKey? = null): DecryptedKeyknoxValue {

        val tmpPublicKeys = newPublicKeys ?: this.publicKeys
        if (tmpPublicKeys.isEmpty()) {
            throw EmptyPublicKeysException()
        }
        val tmpPrivateKey = newPrivateKey ?: this.privateKey

        val pullOperation = { b: Boolean ->
            val tokenContext = TokenContext("get", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            this.keyknoxClient.pullValue(token.stringRepresentation())
        }
        val pulledValue = run(pullOperation)
        val decryptedValue = this.crypto.decrypt(pulledValue, this.privateKey, this.publicKeys)

        if (decryptedValue.meta == null
                || decryptedValue.meta.isEmpty()
                || decryptedValue.value == null
                || decryptedValue.value.isEmpty()) {

            // Empty data, no need to re-encrypt anything
            return decryptedValue
        }

        this.privateKey = tmpPrivateKey
        this.publicKeys = tmpPublicKeys
        val encryptedValue = this.crypto.encrypt(decryptedValue.value, tmpPrivateKey, tmpPublicKeys)

        val pushOperation = { b: Boolean ->
            val tokenContext = TokenContext("put", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            val response = this.keyknoxClient.pushValue(encryptedValue.first,
                                                        encryptedValue.second,
                                                        pulledValue.keyknoxHash,
                                                        token.stringRepresentation())
            verifyServerResponse(encryptedValue, response)
            this.crypto.decrypt(response, this.privateKey, this.publicKeys)
        }
        return run(pushOperation)
    }

    /**
     * Updates public keys for ecnryption and signature verification and private key for decryption
     * and signature generation.
     *
     * @param value Current Keyknox value.
     * @param previousHash Previous Keyknox value hash.
     * @param newPublicKeys New public keys that will be used for encryption and signature verification.
     * @param newPrivateKey New private key that will be used for decryption and signature generation.
     *
     * @return DecryptedKeyknoxValue.
     */
    @JvmOverloads
    fun updateRecipients(value: ByteArray?,
                         previousHash: ByteArray?,
                         newPublicKeys: List<VirgilPublicKey>? = null,
                         newPrivateKey: VirgilPrivateKey? = null): DecryptedKeyknoxValue {

        val tmpPublicKeys = newPublicKeys ?: this.publicKeys
        if (tmpPublicKeys.isEmpty()) {
            throw EmptyPublicKeysException()
        }
        val tmpPrivateKey = newPrivateKey ?: this.privateKey
        val encryptedValue: Pair<ByteArray, ByteArray> = if (value == null) {
            this.crypto.encrypt(byteArrayOf(), tmpPrivateKey, tmpPublicKeys)
        } else {
            this.crypto.encrypt(value, tmpPrivateKey, tmpPublicKeys)
        }

        this.privateKey = tmpPrivateKey
        this.publicKeys = tmpPublicKeys

        val operation = { b: Boolean ->
            val tokenContext = TokenContext("put", b, "keyknox")
            val token = this.accessTokenProvider.getToken(tokenContext)
            val response = this.keyknoxClient.pushValue(encryptedValue.first,
                                                        encryptedValue.second,
                                                        previousHash,
                                                        token.stringRepresentation())

            verifyServerResponse(encryptedValue, response)
            this.crypto.decrypt(response, this.privateKey, this.publicKeys)
        }
        return run(operation)
    }

    private fun verifyServerResponse(encryptedValue: Pair<ByteArray, ByteArray>, response: EncryptedKeyknoxValue) {
        if (!Arrays.equals(encryptedValue.first, response.meta)) {
            throw TamperedServerResponseException("Response meta is tampered")
        }
        if (!Arrays.equals(encryptedValue.second, response.value)) {
            throw TamperedServerResponseException("Response value is tampered")
        }
    }

    private fun <R> run(f: (Boolean) -> R): R {
        return try {
            f(false)
        } catch (e: KeyknoxServiceException) {
            if (this.retryOnUnauthorized && e.responseCode == 401) {
                f(true)
            } else {
                throw e
            }
        }
    }
}
