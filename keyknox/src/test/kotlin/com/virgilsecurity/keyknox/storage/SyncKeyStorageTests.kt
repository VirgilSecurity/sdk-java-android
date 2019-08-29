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

package com.virgilsecurity.keyknox.storage

import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.TestConfig
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.cloud.CloudKeyStorageProtocol
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.exception.CloudEntryNotFoundWhileUpdatingException
import com.virgilsecurity.keyknox.exception.CloudStorageOutOfSyncException
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.SignerNotFoundException
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.TimeUnit

class SyncKeyStorageTests {

    private val identity = UUID.randomUUID().toString()
    private lateinit var publicKey: VirgilPublicKey
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var virgilCrypto: VirgilCrypto
    private lateinit var keyknoxManager: KeyknoxManager
    private lateinit var cloudKeyStorage: CloudKeyStorageProtocol
    private lateinit var keyStorage: KeyStorage
    private lateinit var keychainStorageWrapper: KeyStorageWrapper
    private lateinit var syncKeyStorage: SyncKeyStorage

    @BeforeEach
    fun setup() {
        this.virgilCrypto = VirgilCrypto(false)

        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        this.privateKey = keyPair.privateKey
        this.publicKey = keyPair.publicKey

        val jwtGenerator = JwtGenerator(TestConfig.appId, TestConfig.apiKey, TestConfig.apiPublicKeyId, TimeSpan.fromTime(100, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(this.virgilCrypto))
        val provider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { jwtGenerator.generateToken(identity) })
        val keyknoxClient = KeyknoxClient()
        this.keyknoxManager = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = keyknoxClient, crypto = KeyknoxCrypto(),
                privateKey = this.privateKey, publicKeys = arrayListOf(this.publicKey), retryOnUnauthorized = false)

        this.cloudKeyStorage = CloudKeyStorage(this.keyknoxManager)
        this.cloudKeyStorage.retrieveCloudEntries()

        val cloudKeyStorage = CloudKeyStorage(this.keyknoxManager)
        this.keyStorage = DefaultKeyStorage(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString())
        this.keychainStorageWrapper = KeyStorageWrapper(this.identity, this.keyStorage)
        this.syncKeyStorage = SyncKeyStorage(identity = this.identity, keyStorage = this.keyStorage, cloudKeyStorage = cloudKeyStorage)
    }

    @Test
    fun init() {
        val jwtGenerator = JwtGenerator(TestConfig.appId, TestConfig.apiKey, TestConfig.apiPublicKeyId, TimeSpan.fromTime(100, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(this.virgilCrypto))

        // Setup Access Token provider to provide access token for Virgil services
        // Check https://github.com/VirgilSecurity/virgil-sdk-java-android
        val accessTokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { jwtGenerator.generateToken(identity) })

        // Download public keys of users that should have access to data from Virgil Cards service
        // Check https://github.com/VirgilSecurity/virgil-sdk-java-android
        val publicKeys = arrayListOf(this.publicKey)

        // Load private key from Keychain
        val privateKey = this.privateKey

        val syncKeyStorage = SyncKeyStorage(identity = "Alice", accessTokenProvider = accessTokenProvider,
                publicKeys = publicKeys, privateKey = privateKey)

        syncKeyStorage.sync()
        assertTrue(syncKeyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun sync() {
        // KTC-29
        this.syncKeyStorage.sync()
        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())

        val keyEntries = mutableListOf<KeyEntry>()
        for (i in 0..1) {
            val name = UUID.randomUUID().toString()
            val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())

            val keyEntry = this.keychainStorageWrapper.createEntry(name, data)
            keyEntries.add(keyEntry)
        }

        this.cloudKeyStorage.store(arrayListOf(keyEntries[0]))
        this.syncKeyStorage.sync()

        val keychainEntries = this.keychainStorageWrapper.retrieveAll()
        assertEquals(1, keychainEntries.size)
        assertEquals(keyEntries[0].name, keychainEntries[0].name)
        assertArrayEquals(keyEntries[0].value, keychainEntries[0].value)

        val keychainEntries2 = this.keychainStorageWrapper.retrieveAll()
        assertEquals(1, keychainEntries2.size)
        assertEquals(keyEntries[0].name, keychainEntries2[0].name)
        assertArrayEquals(keyEntries[0].value, keychainEntries2[0].value)

        this.cloudKeyStorage.store(arrayListOf(keyEntries[1]))
        this.syncKeyStorage.sync()

        val keychainEntries3 = this.keychainStorageWrapper.retrieveAll()
        assertEquals(2, keychainEntries3.size)
        val loadedEntry1 = keychainEntries3.first { it.name.equals(keyEntries[1].name) }
        assertNotNull(loadedEntry1)
        assertArrayEquals(keyEntries[1].value, loadedEntry1.value)

        // Delete all entries
        this.keyStorage.names().forEach { name ->
            this.keyStorage.delete(name)
        }

        this.syncKeyStorage.sync()

        val keychainEntries4 = this.keychainStorageWrapper.retrieveAll()
        assertEquals(2, keychainEntries4.size)

        val loadedEntry2 = keychainEntries4.first { it.name.equals(keyEntries[0].name) }
        assertNotNull(loadedEntry2)
        assertArrayEquals(keyEntries[0].value, loadedEntry2.value)

        val loadedEntry3 = keychainEntries4.first { it.name.equals(keyEntries[1].name) }
        assertNotNull(loadedEntry3)
        assertArrayEquals(keyEntries[1].value, loadedEntry3.value)

        this.cloudKeyStorage.delete(keyEntries[0].name)
        this.syncKeyStorage.sync()

        val keychainEntries5 = this.keychainStorageWrapper.retrieveAll()
        assertEquals(1, keychainEntries5.size)
        assertEquals(keyEntries[1].name, keychainEntries5[0].name)
        assertArrayEquals(keyEntries[1].value, keychainEntries5[0].value)

        val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        this.cloudKeyStorage.update(keyEntries[1].name, data)
        this.syncKeyStorage.sync()

        val keychainEntries6 = this.keychainStorageWrapper.retrieveAll()
        assertEquals(1, keychainEntries6.size)
        assertEquals(keyEntries[1].name, keychainEntries6[0].name)
        assertArrayEquals(data, keychainEntries6[0].value)

        this.cloudKeyStorage.deleteAll()
        this.syncKeyStorage.sync()
        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())
    }

    @Test
    fun storeEntry() {
        // KTC-30
        val name = UUID.randomUUID().toString()
        val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.cloudKeyStorage.retrieveCloudEntries()
        this.syncKeyStorage.sync()

        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())
        this.syncKeyStorage.store(name, data)

        this.cloudKeyStorage.retrieveCloudEntries()

        val entry = this.cloudKeyStorage.retrieve(name)
        assertEquals(1, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(name, entry.name)
        assertArrayEquals(data, entry.data)

        val keychainEntry = this.keychainStorageWrapper.retrieve(name)
        assertNotNull(keychainEntry)
        assertEquals(name, keychainEntry.name)
        assertArrayEquals(data, keychainEntry.value)

        val keychainEntry2 = this.syncKeyStorage.retrieve(name)
        assertNotNull(keychainEntry2)
        assertEquals(name, keychainEntry2.name)
        assertArrayEquals(data, keychainEntry2.value)
    }

    @Test
    fun deleteEntry() {
        // KTC-31
        val name1 = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name2 = UUID.randomUUID().toString()
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.cloudKeyStorage.retrieveCloudEntries()
        this.syncKeyStorage.sync()
        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())

        this.syncKeyStorage.store(name1, data1)
        this.syncKeyStorage.store(name2, data2)

        this.cloudKeyStorage.retrieveCloudEntries()
        assertEquals(2, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(2, this.keychainStorageWrapper.retrieveAll().size)

        this.syncKeyStorage.delete(name1)

        this.cloudKeyStorage.retrieveCloudEntries()
        assertEquals(1, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(1, this.keychainStorageWrapper.retrieveAll().size)

        assertNotNull(this.keychainStorageWrapper.retrieve(name2))
        assertNotNull(this.cloudKeyStorage.retrieve(name2))
    }

    @Test
    fun updateEntry() {
        // KTC-32
        val name = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.cloudKeyStorage.retrieveCloudEntries()
        this.syncKeyStorage.sync()
        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())

        this.syncKeyStorage.store(name, data1)
        this.syncKeyStorage.update(name, data2)

        this.cloudKeyStorage.retrieveCloudEntries()
        assertEquals(1, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(1, this.keychainStorageWrapper.retrieveAll().size)

        val keychainEntry = this.keychainStorageWrapper.retrieve(name)
        assertNotNull(keychainEntry)
        assertEquals(name, keychainEntry.name)
        assertArrayEquals(data2, keychainEntry.value)

        val keychainEntry2 = this.syncKeyStorage.retrieve(name)
        assertNotNull(keychainEntry2)
        assertEquals(name, keychainEntry2.name)
        assertArrayEquals(data2, keychainEntry2.value)
    }

    @Test
    fun updateRecipients() {
        // KTC-33
        val name = UUID.randomUUID().toString()
        val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val newPublicKeys = arrayListOf(keyPair.publicKey, this.virgilCrypto.generateKeyPair(KeyType.ED25519).publicKey)
        val newPrivateKey = keyPair.privateKey

        this.syncKeyStorage.sync()
        this.syncKeyStorage.store(name, data)

        this.syncKeyStorage.updateRecipients(newPublicKeys, newPrivateKey)

        val pubIds = keyknoxManager.publicKeys.map {
            (it as VirgilPublicKey).identifier
        }
        assertEquals(newPublicKeys.map { it.identifier }, pubIds)
        assertEquals(newPrivateKey.identifier, (keyknoxManager.privateKey as VirgilPrivateKey).identifier)

        val keychainEntry2 = this.syncKeyStorage.retrieve(name)
        assertEquals(name, keychainEntry2.name)
        assertArrayEquals(data, keychainEntry2.value)

        this.syncKeyStorage.sync()

        val keychainEntry3 = this.syncKeyStorage.retrieve(name)
        assertEquals(name, keychainEntry3.name)
        assertArrayEquals(data, keychainEntry3.value)
    }

    @Test
    fun storeEntries() {
        // KTC-34
        val name1 = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name2 = UUID.randomUUID().toString()
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.cloudKeyStorage.retrieveCloudEntries()
        this.syncKeyStorage.sync()

        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())
        this.syncKeyStorage.store(arrayListOf(this.keyStorage.createEntry(name1, data1),
                this.keyStorage.createEntry(name2, data2)))

        this.cloudKeyStorage.retrieveCloudEntries()

        val entry1 = this.cloudKeyStorage.retrieve(name1)
        val entry2 = this.cloudKeyStorage.retrieve(name2)
        assertEquals(2, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(name1, entry1.name)
        assertArrayEquals(data1, entry1.data)
        assertEquals(name2, entry2.name)
        assertArrayEquals(data2, entry2.data)

        val keychainEntry1 = this.keychainStorageWrapper.retrieve(name1)
        assertEquals(name1, keychainEntry1.name)
        assertArrayEquals(data1, keychainEntry1.value)

        val keychainEntry2 = this.keychainStorageWrapper.retrieve(name2)
        assertNotNull(keychainEntry2)
        assertEquals(name2, keychainEntry2.name)
        assertArrayEquals(data2, keychainEntry2.value)
    }

    @Test
    fun deleteEntries() {
        // KTC-35
        val name1 = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name2 = UUID.randomUUID().toString()
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name3 = UUID.randomUUID().toString()
        val data3 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.cloudKeyStorage.retrieveCloudEntries()
        this.syncKeyStorage.sync()
        assertTrue(this.keychainStorageWrapper.retrieveAll().isEmpty())

        this.syncKeyStorage.store(arrayListOf(this.keyStorage.createEntry(name1, data1),
                this.keyStorage.createEntry(name2, data2), this.keyStorage.createEntry(name3, data3)))
        this.syncKeyStorage.delete(arrayListOf(name1, name2))

        this.cloudKeyStorage.retrieveCloudEntries()
        assertEquals(1, this.cloudKeyStorage.retrieveAll().size)
        assertEquals(1, this.keychainStorageWrapper.retrieveAll().size)
        assertEquals(1, this.syncKeyStorage.retrieveAll().size)

        val entry = this.cloudKeyStorage.retrieve(name3)
        assertEquals(name3, entry.name)
        assertArrayEquals(data3, entry.data)

        val keychainEntry = this.keychainStorageWrapper.retrieve(name3)
        assertEquals(name3, keychainEntry.name)
        assertArrayEquals(data3, keychainEntry.value)

        val syncKeychainEntry = this.syncKeyStorage.retrieve(name3)
        assertEquals(name3, syncKeychainEntry.name)
        assertArrayEquals(data3, syncKeychainEntry.value)
    }

    @Test
    fun retrieveAll() {
        // KTC-36
        val name1 = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name2 = UUID.randomUUID().toString()
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val fakeData = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val fakeData1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val fakeData2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.syncKeyStorage.sync()
        this.syncKeyStorage.store(arrayListOf(this.keyStorage.createEntry(name1, data1),
                this.keyStorage.createEntry(name2, data2)))

        val fakeCloudEntry = CloudEntry("name1", fakeData, Date(), Date())

        // Add some random keys
        this.keyStorage.store(this.keyStorage.createEntry("name1", fakeData1))
        val fakeEntry = this.keyStorage.createEntry("name2", fakeData2)
        fakeEntry.meta = KeychainUtils().createMetaForKeychain(fakeCloudEntry)
        this.keyStorage.store(fakeEntry)

        val allEntries = this.syncKeyStorage.retrieveAll()
        assertEquals(2, allEntries.size)

        val syncKeychainEntry1 = this.syncKeyStorage.retrieve(name1)
        assertEquals(name1, syncKeychainEntry1.name)
        assertArrayEquals(data1, syncKeychainEntry1.value)

        val syncKeychainEntry2 = this.syncKeyStorage.retrieve(name2)
        assertEquals(name2, syncKeychainEntry2.name)
        assertArrayEquals(data2, syncKeychainEntry2.value)
    }

    @Test
    fun deleteAll() {
        // KTC-37
        val name1 = UUID.randomUUID().toString()
        val data1 = ConvertionUtils.toBytes(UUID.randomUUID().toString())
        val name2 = UUID.randomUUID().toString()
        val data2 = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.syncKeyStorage.sync()
        this.syncKeyStorage.store(arrayListOf(this.keyStorage.createEntry(name1, data1),
                this.keyStorage.createEntry(name2, data2)))

        this.syncKeyStorage.deleteAll()
        assertTrue(this.cloudKeyStorage.retrieveAll().isEmpty())
        assertTrue(this.keyStorage.names().isEmpty())
        assertTrue(this.syncKeyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun deleteAll_empty() {
        // KTC-38
        this.syncKeyStorage.sync()
        this.syncKeyStorage.deleteAll()
        assertTrue(this.cloudKeyStorage.retrieveAll().isEmpty())
        assertTrue(this.keyStorage.names().isEmpty())
        assertTrue(this.syncKeyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun exists() {
        // KTC-39
        val name1 = UUID.randomUUID().toString()
        val name2 = UUID.randomUUID().toString()
        val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.syncKeyStorage.sync()
        this.syncKeyStorage.store(name1, data)

        assertTrue(this.syncKeyStorage.exists(name1))
        assertFalse(this.syncKeyStorage.exists(name2))
    }

    @Test
    fun outOfSync() {
        // KTC-40
        val name = UUID.randomUUID().toString()
        val data = ConvertionUtils.toBytes(UUID.randomUUID().toString())

        this.keychainStorageWrapper.store(name, data)

        try {
            this.syncKeyStorage.delete(name)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudStorageOutOfSyncException) {
        }

        try {
            this.syncKeyStorage.delete(arrayListOf(name))
            fail<String>("Storage should be out of sync")
        } catch (e: CloudStorageOutOfSyncException) {
        }

        try {
            this.syncKeyStorage.store("test", data)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudStorageOutOfSyncException) {
        }

        try {
            this.syncKeyStorage.store(arrayListOf(this.keyStorage.createEntry("test", data)))
            fail<String>("Storage should be out of sync")
        } catch (e: CloudStorageOutOfSyncException) {
        }

        assertTrue(this.syncKeyStorage.exists(name))
        this.syncKeyStorage.retrieveAll()
        this.syncKeyStorage.retrieve(name)

        try {
            this.syncKeyStorage.update(name, data)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudEntryNotFoundWhileUpdatingException) {
        }

        try {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            this.syncKeyStorage.updateRecipients(arrayListOf(keyPair.publicKey), keyPair.privateKey)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudStorageOutOfSyncException) {
        }
    }

    @Test
    fun conversation() {
        val keyPair2 = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val privateKey2 = keyPair2.privateKey
        val publicKey2 = keyPair2.publicKey

        val jwtGenerator = JwtGenerator(TestConfig.appId, TestConfig.apiKey, TestConfig.apiPublicKeyId, TimeSpan.fromTime(100, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(this.virgilCrypto))
        val provider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { jwtGenerator.generateToken(identity) })
        var keyknoxManager = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = KeyknoxClient(), crypto = KeyknoxCrypto(),
                privateKey = privateKey2, publicKeys = arrayListOf(publicKey2), retryOnUnauthorized = false)

        val keyStorage = DefaultKeyStorage(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString())
        var syncKeyStorage2 = SyncKeyStorage(identity = this.identity, keyStorage = keyStorage, cloudKeyStorage = CloudKeyStorage(keyknoxManager))

        val name = UUID.randomUUID().toString()
        val data = virgilCrypto.exportPublicKey(publicKey2)

        syncKeyStorage.sync()
        syncKeyStorage.store(name, data)

        try {
            syncKeyStorage2.sync()
            fail<String>("Data in cloud is not encrypted with my key")
        } catch (e: DecryptionFailedException) {
        }

        syncKeyStorage.updateRecipients(arrayListOf(this.publicKey, publicKey2))

        try {
            syncKeyStorage2.sync()
            fail<String>("I don't have signers public key yet")
        } catch (e: SignerNotFoundException) {
        }

        // Reinit syncKeyStorage2
        keyknoxManager = KeyknoxManager(accessTokenProvider = provider, keyknoxClient = KeyknoxClient(), crypto = KeyknoxCrypto(),
                privateKey = privateKey2, publicKeys = arrayListOf(this.publicKey, publicKey2), retryOnUnauthorized = false)
        syncKeyStorage2 = SyncKeyStorage(identity = this.identity, keyStorage = keyStorage, cloudKeyStorage = CloudKeyStorage(keyknoxManager))

        syncKeyStorage2.sync()
        assertEquals(1, syncKeyStorage2.retrieveAll().size)
    }

}