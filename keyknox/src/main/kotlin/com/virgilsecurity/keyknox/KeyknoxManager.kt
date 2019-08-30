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


import com.virgilsecurity.keyknox.client.*
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.crypto.KeyknoxCryptoProtocol
import com.virgilsecurity.keyknox.exception.KeyknoxServiceException
import com.virgilsecurity.keyknox.exception.TamperedServerResponseException
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import java.util.*

/**
 * Class responsible for interactions with Keyknox cloud + encrypting/decrypting those values.
 */
class KeyknoxManager(
    private val keyknoxClient: KeyknoxClientProtocol,
    private val crypto: KeyknoxCryptoProtocol,
    val retryOnUnauthorized: Boolean = false
) {

    constructor(
        accessTokenProvider: AccessTokenProvider,
        crypto: VirgilCrypto
    ) : this(KeyknoxClient(accessTokenProvider), KeyknoxCrypto(crypto))

    /**
     * Signs then encrypts and pushed value to Keyknox service.
     *
     * @param value Value to push.
     * @param previousHash Previous hash value.
     */
    fun pushValue(
        params: KeyknoxPushParams? = null,
        data: ByteArray,
        previousHash: ByteArray?,
        publicKeys: List<VirgilPublicKey>,
        privateKey: VirgilPrivateKey
    ): DecryptedKeyknoxValue {

        val operation = { _: Boolean ->
            val encryptedValue = this.crypto.encrypt(data, privateKey, publicKeys)
            val response = this.keyknoxClient.pushValue(
                params,
                encryptedValue.first,
                encryptedValue.second,
                previousHash
            )

            verifyServerResponse(encryptedValue, response)
            this.crypto.decrypt(response, privateKey, publicKeys)
        }

        return run(operation)
    }

    /**
     * Pull value, decrypt then verify signature.
     */
    fun pullValue(
        params: KeyknoxPullParams? = null,
        publicKeys: List<VirgilPublicKey>,
        privateKey: VirgilPrivateKey
    ): DecryptedKeyknoxValue {

        val operation = { _: Boolean ->
            val response = this.keyknoxClient.pullValue(params)
            this.crypto.decrypt(response, privateKey, publicKeys)
        }
        return run(operation)
    }

    /**
     * Returns set of keys.
     *
     * @param params Get keys params.
     *
     * @return List of keys.
     */
    fun getKeys(params: KeyknoxGetKeysParams): Set<String> {
        val operation = { _: Boolean ->
            this.keyknoxClient.getKeys(params)
        }
        return run(operation)
    }

    /**
     * Resets Keyknox value (makes it empty). Also increments version.
     *
     * @param params Reset params.
     *
     * @return Decrypted Keyknox Value.
     */
    fun resetValue(params: KeyknoxResetParams? = null): DecryptedKeyknoxValue {
        val operation = { _: Boolean ->
            this.keyknoxClient.resetValue(params)

//            if ((response.meta == null || response.meta.isEmpty())
//                    && (response.value == null || response.value.isEmpty())) {
//                response
//            } else {
//                throw TamperedServerResponseException()
//            }

            // TODO do we need this check above?
        }
        return run(operation)
    }

    /**
     * Deletes recipient from list of shared.
     *
     * @param params Delete recipient params.
     *
     * @return Decrypted Keyknox Value.
     */
    fun deleteRecipient(params: KeyknoxDeleteRecipientParams): DecryptedKeyknoxValue {
        val operation = { _: Boolean ->
            this.keyknoxClient.deleteRecipient(params)
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

    private fun <R> run(executable: (Boolean) -> R): R {
        return try {
            executable(false)
        } catch (e: KeyknoxServiceException) {
            if (this.retryOnUnauthorized && e.responseCode == 401) {
                executable(true)
            } else {
                throw e
            }
        }
    }
}
