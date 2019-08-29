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

import com.virgilsecurity.keyknox.exception.SignerNotFoundException
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * @author Andrii Iakovenko
 */
class KeyknoxCryptoTest {

    private lateinit var crypto: KeyknoxCryptoProtocol
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var publicKey: VirgilPublicKey
    private lateinit var publicKeys: MutableList<VirgilPublicKey>

    @BeforeEach
    @Throws(CryptoException::class)
    fun setup() {
        this.crypto = KeyknoxCrypto()

        val virgilCrypto = VirgilCrypto(false)
        var keyPair = virgilCrypto.generateKeyPair()
        this.privateKey = keyPair.privateKey
        this.publicKey = keyPair.publicKey

        val keysCount = 10
        this.publicKeys = ArrayList(keysCount)
        for (i in 0 until keysCount) {
            keyPair = virgilCrypto.generateKeyPair()
            this.publicKeys.add(keyPair.publicKey)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun encrypt_emptyPublicKeys() {
        assertThrows<IllegalArgumentException> {
            this.crypto.encrypt(TEST_DATA, privateKey, ArrayList())
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun encrypt() {
        val result = this.crypto.encrypt(TEST_DATA, privateKey, publicKeys)
        assertNotNull(result)
        assertNotNull(result.first)
        assertNotNull(result.second)
    }

    @Test
    @Throws(CryptoException::class)
    fun decrypt_emptyEncryptedKeyknoxValue() {
        val encryptedKeyknoxValue = EncryptedKeyknoxValue(meta = null, value = null,
                version = UUID.randomUUID().toString(),
                keyknoxHash = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8))

        val decryptedKeyknoxValue = this.crypto.decrypt(encryptedKeyknoxValue,
                privateKey, publicKeys)
        assertNotNull(decryptedKeyknoxValue)
        assertNotNull(decryptedKeyknoxValue.meta)
        assertTrue(decryptedKeyknoxValue.meta!!.isEmpty())
        assertNotNull(decryptedKeyknoxValue.value)
        assertTrue(decryptedKeyknoxValue.value!!.isEmpty())
        assertEquals(encryptedKeyknoxValue.version, decryptedKeyknoxValue.version)
        assertArrayEquals(encryptedKeyknoxValue.keyknoxHash,
                decryptedKeyknoxValue.keyknoxHash)
    }

    @Test
    @Throws(CryptoException::class)
    fun decrypt_emptyPublicKeys() {
        assertThrows<IllegalArgumentException> {
            this.crypto.decrypt(encryptTestData(), privateKey, ArrayList())
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun decrypt_noSigner() {
        val encryptedKeyknoxValue = encryptTestData()
        assertThrows<SignerNotFoundException> {
            this.crypto.decrypt(encryptedKeyknoxValue, privateKey, publicKeys)
        }
    }

    @Test
    @Throws(CryptoException::class)
    fun decrypt() {
        val encryptedKeyknoxValue = encryptTestData()
        val keys = ArrayList(publicKeys)
        keys.add(publicKey)

        val decryptedKeyknoxValue = this.crypto.decrypt(encryptedKeyknoxValue,
                privateKey, keys)
        assertNotNull(decryptedKeyknoxValue)
        assertNotNull(decryptedKeyknoxValue.value)
        assertArrayEquals(TEST_DATA, decryptedKeyknoxValue.value)
        assertEquals(encryptedKeyknoxValue.version, decryptedKeyknoxValue.version)
    }

    @Throws(CryptoException::class)
    private fun encryptTestData(): EncryptedKeyknoxValue {
        val keys = ArrayList(this.publicKeys)
        keys.add(this.publicKey)
        val result = this.crypto.encrypt(TEST_DATA, privateKey, keys)
        return EncryptedKeyknoxValue(meta = result.first, value = result.second, version = "1.0")
    }

    companion object {

        private val TEST_DATA = "Test data".toByteArray(StandardCharsets.UTF_8)
    }

}
