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

package com.virgilsecurity.keyknox.cloud

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.TestConfig
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.crypto.KeyknoxCryptoProtocol
import com.virgilsecurity.keyknox.exception.CloudKeyStorageException
import com.virgilsecurity.keyknox.exception.CloudStorageOutOfSyncException
import com.virgilsecurity.keyknox.exception.EntryNotFoundException
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.keyknox.utils.base64Decode
import com.virgilsecurity.keyknox.utils.base64Encode
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyEntry
import com.virgilsecurity.sdk.utils.ConvertionUtils
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.TimeUnit

class CloudKeyStorageTest {

    private val identity = UUID.randomUUID().toString()
    private lateinit var publicKeys: List<VirgilPublicKey>
    private lateinit var publicKey: VirgilPublicKey
    private lateinit var privateKey: VirgilPrivateKey
    private lateinit var virgilCrypto: VirgilCrypto
    private lateinit var keyknoxCrypto: KeyknoxCryptoProtocol
    private lateinit var keyknoxClient: KeyknoxClient
    private lateinit var keyknoxManager: KeyknoxManager
    private lateinit var provider: CachingJwtProvider
    private lateinit var keyStorage: CloudKeyStorageProtocol

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

        this.keyStorage = CloudKeyStorage(this.keyknoxManager)
    }

    @Test
    fun retrieveCloudEntries_empty() {
        // KTC-19
        this.keyStorage.retrieveCloudEntries()
        val entries = this.keyStorage.retrieveAll()
        assertTrue(entries.isEmpty())
    }

    @Test
    fun store() {
        // KTC-20
        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val privateKeyData = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
        val name = "test"
        val meta = mapOf("test_key" to "test_value")
        val now = Date()

        this.keyStorage.retrieveCloudEntries()
        this.keyStorage.store(name = name, data = privateKeyData, meta = meta)

        val entries = this.keyStorage.retrieveAll()
        assertEquals(1, entries.size)

        val entry = this.keyStorage.retrieve(name)
        assertNotNull(entry)
        assertEquals(name, entry.name)
        assertArrayEquals(privateKeyData, entry.data)
        assertTrue(now.before(entry.creationDate))
        assertEquals(entry.creationDate, entry.modificationDate)
        assertTrue(meta == entry.meta)
    }

    @Test
    fun store_twoTimes() {
        // KTC-20
        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val privateKeyData = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
        val name = "test"
        val name2 = "test2"
        val meta = mapOf("test_key" to "test_value")
        val now = Date()

        this.keyStorage.retrieveCloudEntries()
        this.keyStorage.store(name = name, data = privateKeyData, meta = meta)
        this.keyStorage.store(name = name2, data = privateKeyData, meta = meta)

        val entries = this.keyStorage.retrieveAll()
        assertEquals(2, entries.size)

        var entry = this.keyStorage.retrieve(name)
        assertNotNull(entry)
        assertEquals(name, entry.name)
        assertArrayEquals(privateKeyData, entry.data)
        assertTrue(now.before(entry.creationDate))
        assertEquals(entry.creationDate, entry.modificationDate)
        assertTrue(meta == entry.meta)

        entry = this.keyStorage.retrieve(name2)
        assertNotNull(entry)
        assertEquals(name2, entry.name)
        assertArrayEquals(privateKeyData, entry.data)
        assertTrue(now.before(entry.creationDate))
        assertEquals(entry.creationDate, entry.modificationDate)
        assertTrue(meta == entry.meta)
    }

    @Test
    fun exists() {
        // KTC-21
        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val privateKeyData = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
        val name = "test"

        this.keyStorage.retrieveCloudEntries()
        this.keyStorage.store(name = name, data = privateKeyData)

        val entries = this.keyStorage.retrieveAll()
        assertEquals(1, entries.size)

        assertTrue(this.keyStorage.exists("test"))
        assertFalse(this.keyStorage.exists("test2"))

        this.keyStorage.retrieveCloudEntries()
        val entries2 = this.keyStorage.retrieveAll()
        assertEquals(1, entries2.size)

        assertTrue(this.keyStorage.exists("test"))
        assertFalse(this.keyStorage.exists("test2"))
    }

    @Test
    fun storeEntries() {
        // KTC-22
        val numberOfKeys = 100
        val privateKeys = mutableListOf<VirgilPrivateKey>()
        val keyEntries = mutableListOf<KeyEntry>()
        val second = 1
        val preLast = numberOfKeys - 2

        // Generate 100 key entries
        for (i in 0 until numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            privateKeys.add(keyPair.privateKey)

            if (i in second..preLast) {
                val name = "$i"
                val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
                val keyEntry = JsonKeyEntry(name, data)
                keyEntries.add(keyEntry)
            }
        }
        assertEquals(numberOfKeys - 2, keyEntries.size)

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // Store first key entry
        val firstPrivateKeyData = this.virgilCrypto.exportPrivateKey(privateKeys[0])
        this.keyStorage.store(name = "first", data = firstPrivateKeyData)

        // Store next 98 key entries
        this.keyStorage.store(keyEntries)

        // 99 keys exist and equals to what was stored
        assertEquals(numberOfKeys - 1, this.keyStorage.retrieveAll().size)

        var firstEntry = this.keyStorage.retrieve("first")
        assertNotNull(firstEntry)
        assertEquals("first", firstEntry.name)
        assertArrayEquals(firstPrivateKeyData, firstEntry.data)

        for (i in second..preLast) {
            val name = "$i"
            val entry = this.keyStorage.retrieve(name)
            assertNotNull(entry)
            val privateKey = this.virgilCrypto.importPrivateKey(entry.data)
            assertArrayEquals(privateKeys[i].identifier,
                              privateKey.privateKey.identifier,
                              "Entry $name has invalid identifier")
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // 99 keys exist and equals to what was stored
        assertEquals(numberOfKeys - 1, this.keyStorage.retrieveAll().size)
        firstEntry = this.keyStorage.retrieve("first")
        assertNotNull(firstEntry)
        assertEquals("first", firstEntry.name)
        assertArrayEquals(firstPrivateKeyData, firstEntry.data)

        for (i in 1..(numberOfKeys - 2)) {
            val name = "$i"
            val entry = this.keyStorage.retrieve(name)
            assertNotNull(entry)
            val privateKey = this.virgilCrypto.importPrivateKey(entry.data)
            assertArrayEquals(privateKeys[i].identifier, privateKey.privateKey.identifier)
        }

        // Store last key entry
        val lastPrivateKeyData = this.virgilCrypto.exportPrivateKey(privateKeys[numberOfKeys - 1])
        this.keyStorage.store(name = "last", data = lastPrivateKeyData)

        // 100 keys exist and equals to what was stored
        assertEquals(numberOfKeys, this.keyStorage.retrieveAll().size)
        firstEntry = this.keyStorage.retrieve("first")
        assertNotNull(firstEntry)
        assertEquals("first", firstEntry.name)
        assertArrayEquals(firstPrivateKeyData, firstEntry.data)

        for (i in 1..(numberOfKeys - 2)) {
            val name = "$i"
            val entry = this.keyStorage.retrieve(name)
            assertNotNull(entry)
            val privateKey = this.virgilCrypto.importPrivateKey(entry.data)
            assertArrayEquals(privateKeys[i].identifier, privateKey.privateKey.identifier)
        }

        var lastEntry = this.keyStorage.retrieve("last")
        assertNotNull(lastEntry)
        assertEquals("last", lastEntry.name)
        assertArrayEquals(lastPrivateKeyData, lastEntry.data)

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // 100 keys exist and equals to what was stored
        assertEquals(numberOfKeys, this.keyStorage.retrieveAll().size)
        firstEntry = this.keyStorage.retrieve("first")
        assertNotNull(firstEntry)
        assertEquals("first", firstEntry.name)
        assertArrayEquals(firstPrivateKeyData, firstEntry.data)

        for (i in 1..(numberOfKeys - 2)) {
            val name = "$i"
            val entry = this.keyStorage.retrieve(name)
            assertNotNull(entry)
            val privateKey = this.virgilCrypto.importPrivateKey(entry.data)
            assertArrayEquals(privateKeys[i].identifier, privateKey.privateKey.identifier)
        }

        lastEntry = this.keyStorage.retrieve("last")
        assertNotNull(lastEntry)
        assertEquals("last", lastEntry.name)
        assertArrayEquals(lastPrivateKeyData, lastEntry.data)
    }

    @Test
    fun deleteAll() {
        // KTC-23
        val numberOfKeys = 100
        val keyEntries = mutableListOf<KeyEntry>()

        // Generate 100 key entries
        for (i in 1..numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            val name = "$i"
            val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
            val keyEntry = JsonKeyEntry(name, data)
            keyEntries.add(keyEntry)
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // Store key entries
        this.keyStorage.store(keyEntries)

        // 100 keys exist and equals to what was stored
        assertEquals(numberOfKeys, this.keyStorage.retrieveAll().size)

        // Delete all entries
        this.keyStorage.deleteAll()

        // No entries exist
        assertTrue(this.keyStorage.retrieveAll().isEmpty())

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // No entries exist
        assertTrue(this.keyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun deleteAll_empty() {
        // KTC-24

        // Delete all entries
        this.keyStorage.deleteAll()

        // No entries exist
        assertTrue(this.keyStorage.retrieveAll().isEmpty())

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // No entries exist
        assertTrue(this.keyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun delete() {
        // KTC-25
        val numberOfKeys = 10
        val keyEntries = mutableListOf<KeyEntry>()

        // Generate 100 key entries
        for (i in 1..numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            val name = "$i"
            val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
            val keyEntry = JsonKeyEntry(name, data)
            keyEntries.add(keyEntry)
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // Store entries
        this.keyStorage.store(keyEntries)

        // Delete entry
        this.keyStorage.delete(keyEntries[0].name)
        assertEquals(numberOfKeys - 1, this.keyStorage.retrieveAll().size)
        try {
            this.keyStorage.retrieve(keyEntries[0].name)
            fail<String>("Entry ${keyEntries[0].name} deleted")
        } catch (e: EntryNotFoundException) {
        }

        // Delete 2 entries
        this.keyStorage.delete(arrayListOf(keyEntries[1].name, keyEntries[2].name))
        assertEquals(numberOfKeys - 3, this.keyStorage.retrieveAll().size)
        try {
            this.keyStorage.retrieve(keyEntries[1].name)
            fail<String>("Entry ${keyEntries[1].name} deleted")
        } catch (e: EntryNotFoundException) {
        }
        try {
            this.keyStorage.retrieve(keyEntries[2].name)
            fail<String>("Entry ${keyEntries[2].name} deleted")
        } catch (e: EntryNotFoundException) {
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()
        assertEquals(numberOfKeys - 3, this.keyStorage.retrieveAll().size)
        try {
            this.keyStorage.retrieve(keyEntries[0].name)
            fail<String>("Entry ${keyEntries[0].name} deleted")
        } catch (e: EntryNotFoundException) {
        }
        try {
            this.keyStorage.retrieve(keyEntries[1].name)
            fail<String>("Entry ${keyEntries[1].name} deleted")
        } catch (e: EntryNotFoundException) {
        }
        try {
            this.keyStorage.retrieve(keyEntries[2].name)
            fail<String>("Entry ${keyEntries[2].name} deleted")
        } catch (e: EntryNotFoundException) {
        }
    }

    @Test
    fun update() {
        // KTC-26
        val numberOfKeys = 10
        val keyEntries = mutableListOf<KeyEntry>()

        // Generate 100 key entries
        for (i in 1..numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            val name = "$i"
            val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
            val keyEntry = JsonKeyEntry(name, data)
            keyEntries.add(keyEntry)
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // Store entries
        this.keyStorage.store(keyEntries)

        val meta = mapOf("key" to "value")

        val cloudEntry = this.keyStorage.update(keyEntries[0].name, keyEntries[1].value, meta)
        assertNotNull(cloudEntry)
        assertEquals(cloudEntry.name, keyEntries[0].name)
        assertArrayEquals(cloudEntry.data, keyEntries[1].value)
        assertEquals(cloudEntry.meta, meta)

        val cloudEntry2 = this.keyStorage.retrieve(keyEntries[0].name)
        assertNotNull(cloudEntry2)
        assertEquals(cloudEntry2.name, keyEntries[0].name)
        assertArrayEquals(cloudEntry2.data, keyEntries[1].value)
        assertEquals(cloudEntry2.meta, meta)

        this.keyStorage.retrieveCloudEntries()

        val cloudEntry3 = this.keyStorage.retrieve(keyEntries[0].name)
        assertNotNull(cloudEntry3)
        assertEquals(cloudEntry3.name, keyEntries[0].name)
        assertArrayEquals(cloudEntry3.data, keyEntries[1].value)
        assertEquals(cloudEntry3.meta, meta)
    }

    @Test
    fun updateRecipient() {
        // KTC-27
        val numberOfKeys = 10
        val keyEntries = mutableListOf<KeyEntry>()

        // Generate 100 key entries
        for (i in 1..numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            val name = "$i"
            val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
            val keyEntry = JsonKeyEntry(name, data)
            keyEntries.add(keyEntry)
        }

        // Retrieve cloud entries
        this.keyStorage.retrieveCloudEntries()

        // Store entries
        this.keyStorage.store(keyEntries)

        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)

        this.keyStorage.updateRecipients(arrayListOf(keyPair.publicKey), keyPair.privateKey)
        assertEquals(numberOfKeys, this.keyStorage.retrieveAll().size)

        this.keyStorage.retrieveCloudEntries()
        assertEquals(numberOfKeys, this.keyStorage.retrieveAll().size)
    }

    @Test
    fun outOfSync() {
        // KTC-28
        try {
            this.keyStorage.retrieveAll()
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.retrieve("test")
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.exists("test")
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        val numberOfKeys = 10
        val keyEntries = mutableListOf<KeyEntry>()

        // Generate 100 key entries
        for (i in 1..numberOfKeys) {
            val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
            val name = "$i"
            val data = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
            val keyEntry = JsonKeyEntry(name, data)
            keyEntries.add(keyEntry)
        }

        try {
            this.keyStorage.store(keyEntries[0].name, keyEntries[0].value)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.store(keyEntries)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.update(keyEntries[0].name, keyEntries[0].value)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.delete(keyEntries[0].name)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.delete(arrayListOf(keyEntries[0].name, keyEntries[1].name))
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }

        try {
            this.keyStorage.updateRecipients(arrayListOf(this.publicKey), this.privateKey)
            fail<String>("Storage should be out of sync")
        } catch (e: CloudKeyStorageException) {
            assertTrue(e is CloudStorageOutOfSyncException)
        }
    }

    @Test
    fun deleteAll_randomString() {
        // KTC-41
        val keyPair = this.virgilCrypto.generateKeyPair(KeyType.ED25519)
        val privateKeyData = this.virgilCrypto.exportPrivateKey(keyPair.privateKey)
        val name = "test"

        this.keyStorage.retrieveCloudEntries()
        this.keyStorage.store(name = name, data = privateKeyData)
        this.keyStorage.deleteAll()
        assertTrue(this.keyStorage.retrieveAll().isEmpty())
    }

    @Test
    fun serializeEntries() {
        // KTC-17
        val cloudJson = JsonParser().parse(CloudKeyStorageTest::class.java.getResource("/cloud.json").readText()) as JsonObject
        val cloudKeyStorage = this.keyStorage as CloudKeyStorage

        // Create dictionary dict1 of CloudEntry instances using data in Cloud.json file
        val entriesArray = mutableListOf<CloudEntry>()
        val map = mutableMapOf<String, String>()
        cloudJson.get("kMeta1")?.asJsonObject?.entrySet()?.forEach { entry ->
            map[entry.key] = entry.value.asString
        }
        entriesArray.add(CloudEntry(cloudJson.get("kName1").asString!!,
                                    base64Decode(cloudJson.get("kData1").asString!!),
                                    Date(cloudJson.get("kCreationDate1").asLong),
                                    Date(cloudJson.get("kModificationDate1").asLong),
                                    map))
        entriesArray.add(CloudEntry(cloudJson.get("kName2").asString!!,
                                    base64Decode(cloudJson.get("kData2").asString!!),
                                    Date(cloudJson.get("kCreationDate2").asLong),
                                    Date(cloudJson.get("kModificationDate2").asLong)))

        val serializedEntries = cloudKeyStorage.serializeEntries(entriesArray)
        assertNotNull(serializedEntries)

        val expectedJson = JsonParser().parse(ConvertionUtils.base64ToString(cloudJson.get("kExpectedResult").asString)) as JsonObject
        val actualJson = JsonParser().parse(ConvertionUtils.toString(serializedEntries)) as JsonObject

        assertEquals(expectedJson.size(), actualJson.size())
        assertEquals(expectedJson.get("key1").asJsonObject, actualJson.get("key1").asJsonObject)
//        assertTrue(TestUtils.compareJson(expectedJson.get("key1").asJsonObject, actualJson.get("key1").asJsonObject))
        assertEquals(expectedJson.get("key2").asJsonObject?.get("name")?.asString,
                actualJson.get("key2").asJsonObject?.get("name")?.asString)
        assertEquals(expectedJson.get("key2").asJsonObject?.get("data")?.asString,
                actualJson.get("key2").asJsonObject?.get("data")?.asString)
        assertEquals(expectedJson.get("key2").asJsonObject?.get("creation_date")?.asLong,
                actualJson.get("key2").asJsonObject?.get("creation_date")?.asLong)
        assertEquals(expectedJson.get("key2").asJsonObject?.get("modification_date")?.asLong,
                actualJson.get("key2").asJsonObject?.get("modification_date")?.asLong)
        assertEquals(0, actualJson.get("key2").asJsonObject?.get("meta")?.asJsonObject?.size())
    }

    @Test
    fun deserializeEntries() {
        // KTC-17
        val cloudJson = JsonParser().parse(CloudKeyStorageTest::class.java.getResource("/cloud.json").readText()) as JsonObject
        val cloudKeyStorage = this.keyStorage as CloudKeyStorage

        val data = ConvertionUtils.base64ToBytes(cloudJson.get("kExpectedResult").asString)
        val entries = cloudKeyStorage.deserializeEntries(data)
        assertNotNull(entries)
        assertEquals(2, entries.size)
        assertEquals(cloudJson.get("kData1").asString, base64Encode(entries[0].data))
        assertEquals(cloudJson.get("kName1").asString, entries[0].name)
        assertEquals(Date(cloudJson.get("kCreationDate1").asLong), entries[0].creationDate)
        assertEquals(Date(cloudJson.get("kModificationDate1").asLong), entries[0].modificationDate)
        assertNotNull(entries[0].meta)
        cloudJson.get("kMeta1").asJsonObject?.entrySet()?.forEach { entry ->
            assertEquals(entry.value.asString, entries[0].meta[entry.key])
        }
        assertEquals(cloudJson.get("kData2").asString, base64Encode(entries[1].data))
        assertEquals(cloudJson.get("kName2").asString, entries[1].name)
        assertEquals(Date(cloudJson.get("kCreationDate2").asLong), entries[1].creationDate)
        assertEquals(Date(cloudJson.get("kModificationDate2").asLong), entries[1].modificationDate)
        assertNotNull(entries[1].meta)
    }

    @Test
    fun deserializeEntries_empty() {
        // KTC-18
        val cloudKeyStorage = this.keyStorage as CloudKeyStorage
        val entries = cloudKeyStorage.deserializeEntries(byteArrayOf())
        assertNotNull(entries)
        assertTrue(entries.isEmpty())
    }

}
