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

import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.crypto.KeyknoxCryptoProtocol
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.KeyknoxCryptoException
import com.virgilsecurity.keyknox.exception.SignerNotFoundException
import com.virgilsecurity.keyknox.utils.base64Encode
import com.virgilsecurity.keyknox.utils.random
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * @author Andrii Iakovenko
 */
class KeyknoxManagerTest {

    private val numberOfKeys = 20
    private val identity = UUID.randomUUID().toString()
    private lateinit var publicKeys: List<VirgilPublicKey>
    private lateinit var publicKey: VirgilPublicKey
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var virgilCrypto: VirgilCrypto
    private lateinit var keyknoxCrypto: KeyknoxCryptoProtocol
    private lateinit var keyknoxClient: KeyknoxClient
    private lateinit var keyknoxManager: KeyknoxManager
    private lateinit var provider: CachingJwtProvider

    @BeforeEach
    fun setup() {
        this.virgilCrypto = VirgilCrypto(false)
        this.keyknoxCrypto = KeyknoxCrypto()
        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        this.privateKey = keyPair.privateKey
        this.publicKey = keyPair.publicKey
        this.publicKeys = arrayListOf(this.publicKey)


        val jwtGenerator = JwtGenerator(TestConfig.appId, TestConfig.apiKey, TestConfig.apiPublicKeyId, TimeSpan.fromTime(600, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(this.virgilCrypto))
        this.provider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { jwtGenerator.generateToken(identity) })

        this.keyknoxClient = KeyknoxClient()
        this.keyknoxManager = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = this.privateKey, publicKeys = this.publicKeys, retryOnUnauthorized = false)
    }

    @Test
    fun pushValue() {
        // KTC-6
        val data = base64Encode(UUID.randomUUID().toString())
        val decryptedValue = this.keyknoxManager.pushValue(data, null)
        assertArrayEquals(data, decryptedValue.value)
    }

    @Test
    fun pullValue() {
        // KTC-7
        val data = base64Encode(UUID.randomUUID().toString())
        this.keyknoxManager.pushValue(data, null)
        val decryptedValue = this.keyknoxManager.pullValue()
        assertArrayEquals(data, decryptedValue.value)
    }

    @Test
    fun pullValue_empty() {
        // KTC-8
        val decryptedValue = this.keyknoxManager.pullValue()

        assertNotNull(decryptedValue.value)
        assertTrue(decryptedValue.value!!.isEmpty())
        assertNotNull(decryptedValue.meta)
        assertTrue(decryptedValue.meta!!.isEmpty())
        assertEquals("1.0", decryptedValue.version)
    }

    @Test
    fun pullValue_multiplePubKeys() {
        // KTC-9
        val data = base64Encode(UUID.randomUUID().toString())
        val pubKeys1 = mutableListOf<VirgilPublicKey>()
        val pubKeys2 = mutableListOf<VirgilPublicKey>()
        var privKey: VirgilPrivateKey = this.privateKey
        for (i in 0..this.numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            if (i == 0) {
                privKey = keyPair.privateKey
            }
            if (i < this.numberOfKeys / 2) {
                pubKeys1.add(keyPair.publicKey)
            } else {
                pubKeys2.add(keyPair.publicKey)
            }
        }

        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = privKey,
                                             publicKeys = pubKeys1,
                                             retryOnUnauthorized = false)

        keyknoxManager1.pushValue(data, null)
        val decryptedValue = keyknoxManager1.pullValue()
        assertArrayEquals(data, decryptedValue.value)

        val keyknoxManager2 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = privKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        try {
            keyknoxManager2.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: SignerNotFoundException) {
        }
    }

    @Test
    fun pullValue_privateKeysDiffer() {
        // KTC-10
        val data = base64Encode(UUID.randomUUID().toString())
        val keyPairs = mutableListOf<VirgilKeyPair>()
        val pubKeys = mutableListOf<VirgilPublicKey>()
        val pubKeys1 = mutableListOf<VirgilPublicKey>()
        val half = this.numberOfKeys / 2
        val last = this.numberOfKeys - 1
        for (i in 0..last) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            keyPairs.add(keyPair)
            pubKeys.add(keyPair.publicKey)
            if (i <= half) {
                pubKeys1.add(keyPair.publicKey)
            }
        }

        val privKey1 = keyPairs[(0..half).random()].privateKey
        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = privKey1, publicKeys = pubKeys1, retryOnUnauthorized = false)
        val decryptedValue1 = keyknoxManager1.pushValue(data, null)
        assertArrayEquals(data, decryptedValue1.value)

        val privKey2 = keyPairs[(0..half).random()].privateKey
        val keyknoxManager2 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = privKey2, publicKeys = pubKeys1, retryOnUnauthorized = false)
        val decryptedValue2 = keyknoxManager2.pullValue()
        assertArrayEquals(data, decryptedValue2.value)

        val privKey3 = keyPairs[(half + 1..last).random()].privateKey
        val keyknoxManager3 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = privKey3, publicKeys = pubKeys1, retryOnUnauthorized = false)
        try {
            keyknoxManager3.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: KeyknoxCryptoException) {
        }
    }

    @Test
    fun updateRecipients() {
        // KTC-11
        val data = base64Encode(UUID.randomUUID().toString())
        val keyPairs = mutableListOf<VirgilKeyPair>()
        val pubKeys1 = mutableListOf<VirgilPublicKey>()
        val pubKeys2 = mutableListOf<VirgilPublicKey>()
        val half = this.numberOfKeys / 2
        val last = this.numberOfKeys - 1
        for (i in 0..last) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            keyPairs.add(keyPair)
            if (i <= half) {
                pubKeys1.add(keyPair.publicKey)
            } else {
                pubKeys2.add(keyPair.publicKey)
            }
        }

        val rand = (0..half).random()
        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand].privateKey,
                                             publicKeys = pubKeys1,
                                             retryOnUnauthorized = false)
        val decryptedValue1 = keyknoxManager1.pushValue(data, null)
        assertArrayEquals(data, decryptedValue1.value)

        val rand1 = (0..half).random()
        val rand2 = (half + 1..last).random()
        val keyknoxManager2 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand1].privateKey,
                                             publicKeys = pubKeys1,
                                             retryOnUnauthorized = false)
        val decryptedValue2 = keyknoxManager2.updateRecipients(pubKeys2, keyPairs[rand2].privateKey)
        assertArrayEquals(data, decryptedValue2.value)
        //TODO verify publicKeys and privateKey are changed

        val rand3 = (half + 1..last).random()
        val keyknoxManager3 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand3].privateKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        val decryptedValue3 = keyknoxManager3.pullValue()
        assertArrayEquals(data, decryptedValue3.value)

        val rand4 = (0..half).random()
        val keyknoxManager4 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand4].privateKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        try {
            keyknoxManager4.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: KeyknoxCryptoException) {
            val str = ""
        }

        val rand5 = (half + 1..last).random()
        val keyknoxManager5 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand5].privateKey,
                                             publicKeys = pubKeys1,
                                             retryOnUnauthorized = false)
        try {
            keyknoxManager5.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: KeyknoxCryptoException) {
        }
    }

    @Test
    fun updateRecipientsWithValue() {
        // KTC-12
        val data = base64Encode(UUID.randomUUID().toString())
        val keyPairs = mutableListOf<VirgilKeyPair>()
        val pubKeys1 = mutableListOf<VirgilPublicKey>()
        val pubKeys2 = mutableListOf<VirgilPublicKey>()

        val half = this.numberOfKeys / 2
        for (i in 0 until this.numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)

            keyPairs.add(keyPair)
            if (i < half) {
                pubKeys1.add(keyPair.publicKey)
            } else {
                pubKeys2.add(keyPair.publicKey)
            }
        }

        val rand = (0 until half).random()
        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand].privateKey,
                                             publicKeys = pubKeys1,
                                             retryOnUnauthorized = false)
        val decryptedValue = keyknoxManager1.pushValue(data, null)
        assertArrayEquals(data, decryptedValue.value)

        val rand1 = (half until this.numberOfKeys).random()
        val decryptedValue1 = keyknoxManager1.updateRecipients(value = decryptedValue.value,
                                                               previousHash = decryptedValue.keyknoxHash,
                                                               newPublicKeys = pubKeys2,
                                                               newPrivateKey = keyPairs[rand1].privateKey)
        assertArrayEquals(data, decryptedValue1.value)

        val rand2 = (half until this.numberOfKeys).random()
        val keyknoxManager2 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand2].privateKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        val decryptedValue2 = keyknoxManager2.pullValue()
        assertArrayEquals(data, decryptedValue2.value)

        val rand3 = (0 until half).random()
        val keyknoxManager3 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand3].privateKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        try {
            keyknoxManager3.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: DecryptionFailedException) {
        }

        val keyknoxManager4 = KeyknoxManager(accessTokenProvider = provider,
                                             keyknoxClient = this.keyknoxClient,
                                             crypto = this.keyknoxCrypto,
                                             privateKey = keyPairs[rand3].privateKey,
                                             publicKeys = pubKeys2,
                                             retryOnUnauthorized = false)
        try {
            keyknoxManager4.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: DecryptionFailedException) {
        }

        val rand5 = (half until this.numberOfKeys).random()
        val keyknoxManager5 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = keyPairs[rand5].privateKey, publicKeys = pubKeys1, retryOnUnauthorized = false)
        try {
            keyknoxManager5.pullValue()
            fail<Boolean>("Keys hacked with wrong keys")
        } catch (e: SignerNotFoundException) {
        }
    }

    @Test
    fun updateRecipients_emptyValue() {
        // KTC-13
        val keyPairs = mutableListOf<VirgilKeyPair>()
        val pubKeys1 = mutableListOf<VirgilPublicKey>()
        val pubKeys2 = mutableListOf<VirgilPublicKey>()
        val half = this.numberOfKeys / 2
        for (i in 1..this.numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            keyPairs.add(keyPair)
            if (i < half) {
                pubKeys1.add(keyPair.publicKey)
            } else {
                pubKeys2.add(keyPair.publicKey)
            }
        }

        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = keyPairs[0].privateKey, publicKeys = pubKeys1, retryOnUnauthorized = false)
        val decryptedValue = keyknoxManager1.updateRecipients(newPublicKeys = pubKeys2, newPrivateKey = keyPairs[half].privateKey)
        assertNotNull(decryptedValue.value)
        assertTrue(decryptedValue.value!!.isEmpty())
        assertNotNull(decryptedValue.meta)
        assertTrue(decryptedValue.meta!!.isEmpty())
        assertEquals("1.0", decryptedValue.version)
    }

    @Test
    fun resetValue() {
        // KTC-14
        val data = base64Encode(UUID.randomUUID().toString())

        val decryptedValue = this.keyknoxManager.pushValue(data, null)
        assertArrayEquals(data, decryptedValue.value)

        val decryptedValue1 = this.keyknoxManager.resetValue()
        assertNotNull(decryptedValue.value)
        assertTrue(decryptedValue1.value!!.isEmpty())
        assertNotNull(decryptedValue.meta)
        assertTrue(decryptedValue1.meta!!.isEmpty())
        assertEquals("2.0", decryptedValue1.version)
    }

    @Test
    fun resetValue_invalidValue() {
        // KTC-15
        val data = base64Encode(UUID.randomUUID().toString())
        val keyPair1 = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val keyPair2 = this.virgilCrypto.generateKeyPair(KeyType.ED25519)

        val keyknoxManager1 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = keyPair1.privateKey, publicKeys = arrayListOf(keyPair1.publicKey), retryOnUnauthorized = false)
        val decryptedValue1 = keyknoxManager1.pushValue(data, null)
        assertArrayEquals(data, decryptedValue1.value)

        val keyknoxManager2 = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = this.keyknoxClient, crypto = this.keyknoxCrypto,
                privateKey = keyPair2.privateKey, publicKeys = arrayListOf(keyPair2.publicKey), retryOnUnauthorized = false)
        val decryptedValue2 = keyknoxManager2.resetValue()
        assertNotNull(decryptedValue2.value)
        assertTrue(decryptedValue2.value!!.isEmpty())
        assertNotNull(decryptedValue2.meta)
        assertTrue(decryptedValue2.meta!!.isEmpty())
        assertEquals("2.0", decryptedValue2.version)
    }

    @Test
    fun getWithKeyknoxClient() {
        // KTC-16
        val data = base64Encode(UUID.randomUUID().toString())

        val decryptedValue1 = this.keyknoxManager.pushValue(data, null)
        assertArrayEquals(data, decryptedValue1.value)

        val tokenContext = TokenContext(null, "", false, "")
        val token = this.provider.getToken(tokenContext)
        val encryptedValue = this.keyknoxClient.pullValue(token.stringRepresentation())

        val meta = encryptedValue.meta
        val value = encryptedValue.value

        assertNotNull(meta) { "'meta' should not be null" }
        assertNotNull(value) { "'value' should not be null" }

        val decryptedData = virgilCrypto.decrypt(meta!! + value!!, this.privateKey)
        assertArrayEquals(data, decryptedData)
    }

}
