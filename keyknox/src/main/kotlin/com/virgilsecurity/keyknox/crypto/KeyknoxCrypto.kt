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

package com.virgilsecurity.keyknox.crypto

import com.virgilsecurity.crypto.foundation.Aes256Gcm
import com.virgilsecurity.crypto.foundation.RecipientCipher
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.SignatureVerificationException
import com.virgilsecurity.keyknox.exception.SignerNotFoundException
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.keyknox.utils.requires
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import java.util.*

class KeyknoxCrypto : KeyknoxCryptoProtocol {

    private val crypto: VirgilCrypto = VirgilCrypto(false)

    @Throws(CryptoException::class, IllegalArgumentException::class)
    override fun encrypt(data: ByteArray,
                         privateKey: VirgilPrivateKey,
                         publicKeys: List<VirgilPublicKey>): Pair<ByteArray, ByteArray> {

        requires(data.isNotEmpty(), "data")
        requires(publicKeys.isNotEmpty(), "privateKey")

        val signature = crypto.generateSignature(data, privateKey)

        Aes256Gcm().use { aesGcm ->
            RecipientCipher().use { cipher ->
                cipher.setEncryptionCipher(aesGcm)
                cipher.setRandom(crypto.rng)

                publicKeys.forEach {
                    cipher.addKeyRecipient(it.identifier, it.publicKey)
                }

                cipher.customParams().addData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID, privateKey.identifier)
                cipher.customParams().addData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature)

                cipher.startEncryption()
                val meta = cipher.packMessageInfo()
                var encryptedData = cipher.processEncryption(data)
                encryptedData += cipher.finishEncryption()

                return Pair(meta, encryptedData)
            }
        }
    }

    @Throws(CryptoException::class, IllegalArgumentException::class)
    override fun decrypt(encryptedKeyknoxValue: EncryptedKeyknoxValue,
                         privateKey: VirgilPrivateKey,
                         publicKeys: List<VirgilPublicKey>): DecryptedKeyknoxValue {

        requires(publicKeys.isNotEmpty(), "privateKey")


        if ((encryptedKeyknoxValue.meta == null || encryptedKeyknoxValue.meta.isEmpty()) &&
                (encryptedKeyknoxValue.value == null || encryptedKeyknoxValue.value.isEmpty())) {

            return DecryptedKeyknoxValue(meta = ByteArray(0),
                                         value = ByteArray(0),
                                         version = encryptedKeyknoxValue.version,
                                         keyknoxHash = encryptedKeyknoxValue.keyknoxHash)
        }

        val meta = encryptedKeyknoxValue.meta
        val value = encryptedKeyknoxValue.value

        requireNotNull(meta) { "'meta' should not be null" }
        requireNotNull(value) { "'value' should not be null" }

        val decryptedData = RecipientCipher().use { cipher ->
            cipher.startDecryptionWithKey(privateKey.identifier,
                                          privateKey.privateKey,
                                          ByteArray(0))

            val data = meta + value

            val decryptedData = try {
                val process = cipher.processDecryption(data)
                val finish = cipher.finishDecryption()
                process + finish
            } catch (throwable: Throwable) {
                throw DecryptionFailedException()
            }

            val signersPublicKey: VirgilPublicKey?

            val signerId = try {
                cipher.customParams().findData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID)
            } catch (throwable: Throwable) {
                throw SignerNotFoundException("Signer's Public key not found")
            }

            signersPublicKey = publicKeys.firstOrNull { Arrays.equals(it.identifier, signerId) }

            if (signersPublicKey == null) throw SignerNotFoundException("Signer's Public key not found")

            val signature = try {
                cipher.customParams().findData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE)
            } catch (throwable: Throwable) {
                throw SignatureVerificationException()
            }

            val isValid = crypto.verifySignature(signature, decryptedData, signersPublicKey)

            if (!isValid) throw SignatureVerificationException()

            decryptedData
        }

        return DecryptedKeyknoxValue(meta,
                                     decryptedData,
                                     encryptedKeyknoxValue.version,
                                     encryptedKeyknoxValue.keyknoxHash)
    }
}