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

import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException

interface KeyknoxCryptoProtocol {

    /**
     * Encrypts data for Keyknox.
     *
     * @param data Data to encrypt.
     * @param privateKey Private key to sign data. Should be of type [VirgilPrivateKey].
     * @param publicKeys Public keys to encrypt data. Should be of type VirgilPublicKey.
     *
     * @return Meta information and encrypted blob.
     *
     * @throws CryptoException Re-thrown from Cipher, Signer.
     * @throws IllegalArgumentException If some of provided arguments is empty.
     */
    @Throws(CryptoException::class, IllegalArgumentException::class)
    fun encrypt(data: ByteArray,
                privateKey: VirgilPrivateKey,
                publicKeys: List<VirgilPublicKey>): Pair<ByteArray, ByteArray>

    /**
     * Decrypts EncryptedKeyknoxValue.
     *
     * @param encryptedKeyknoxValue Encrypted value from Keyknox service.
     * @param privateKey Private key to decrypt data. Should be of type [VirgilPrivateKey].
     * @param publicKeys Allowed public keys to verify signature. Should be of type [VirgilPublicKey].
     *
     * @return The DecryptedKeyknoxValue.
     *
     * @throws CryptoException Re-thrown from Cipher, Signer.
     * @throws IllegalArgumentException If some of provided arguments is empty.
     */
    @Throws(CryptoException::class, IllegalArgumentException::class)
    fun decrypt(encryptedKeyknoxValue: EncryptedKeyknoxValue,
                privateKey: VirgilPrivateKey,
                publicKeys: List<VirgilPublicKey>): DecryptedKeyknoxValue
}