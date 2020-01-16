/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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


import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.exception.CloudStorageOutOfSyncException
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.keyknox.exception.EntryNotFoundException
import com.virgilsecurity.keyknox.exception.EntrySavingException
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyEntry
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Class responsible for storing keys in Keyknox cloud in a key/value storage manner.
 */
open class CloudKeyStorage : CloudKeyStorageProtocol {

    val keyknoxManager: KeyknoxManager

    // Public keys used for encryption and signature verification
    var publicKeys: List<VirgilPublicKey>

    // Private key used for decryption and signing
    var privateKey: VirgilPrivateKey

    private var cache: MutableMap<String, CloudEntry> = ConcurrentHashMap()
    private var decryptedKeyknoxData: DecryptedKeyknoxValue? = null
    private val cloudEntrySerializer = CloudEntrySerializer()

    // Shows whether this storage was synced
    var storageWasSynced: Boolean = false
        get() = this.decryptedKeyknoxData != null
        private set

    /**
     * Instantiates [CloudKeyStorage] with provided [keyknoxManager], [publicKeys] which are used for encryption and
     * signature verification and [privateKey] that is used for decryption and signature verification.
     */
    constructor(
        keyknoxManager: KeyknoxManager,
        publicKeys: List<VirgilPublicKey>,
        privateKey: VirgilPrivateKey
    ) {
        this.keyknoxManager = keyknoxManager
        this.publicKeys = publicKeys
        this.privateKey = privateKey
    }

    /**
     * Instantiates [CloudKeyStorage] with provided [accessTokenProvider] which is [AccessTokenProvider] implementation,
     * [VirgilCrypto], [publicKeys] which are used for encryption and signature verification and [privateKey] that is
     * used for decryption and signature verification.
     */
    constructor(accessTokenProvider: AccessTokenProvider,
                crypto: VirgilCrypto,
                publicKeys: List<VirgilPublicKey>,
                privateKey: VirgilPrivateKey
    ) {
        this.keyknoxManager = KeyknoxManager(accessTokenProvider = accessTokenProvider, crypto = crypto)
        this.publicKeys = publicKeys
        this.privateKey = privateKey
    }

    override fun store(keyEntries: List<KeyEntry>): List<CloudEntry> {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }
        synchronized(this.cache) {
            keyEntries.forEach { entry ->
                if (this.cache.containsKey(entry.name)) {
                    throw EntryAlreadyExistsException()
                }
            }

            val cloudEntries = arrayListOf<CloudEntry>()
            keyEntries.forEach { entry ->
                val now = Date()
                val cloudEntry = CloudEntry(entry.name, entry.value, now, now, entry.meta)
                cloudEntries.add(cloudEntry)
                this.cache[cloudEntry.name] = cloudEntry
            }
            val entryData = cloudEntrySerializer.serializeEntries(this.cache.values)

            val hash = this.decryptedKeyknoxData?.keyknoxHash

            val response = keyknoxManager.pushValue(
                data = entryData,
                previousHash = hash,
                publicKeys = this.publicKeys,
                privateKey = this.privateKey
            )

            val newEntries = cloudEntrySerializer.deserializeEntries(response.value)
            cacheEntries(newEntries)
            this.decryptedKeyknoxData = response

            return cloudEntries
        }
    }

    override fun store(name: String, data: ByteArray, meta: Map<String, String>?): CloudEntry {
        val keyEntry = JsonKeyEntry(name, data)
        keyEntry.meta = meta ?: keyEntry.meta
        val cloudEntries = store(listOf(keyEntry))

        if (cloudEntries.size != 1) {
            throw EntrySavingException()
        }

        return cloudEntries.first()
    }

    override fun update(name: String, data: ByteArray, meta: Map<String, String>?): CloudEntry {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }
        val now = Date()
        synchronized(this.cache) {
            val creationDate = this.cache[name]?.creationDate ?: now

            val cloudEntry = CloudEntry(
                name = name,
                data = data,
                creationDate =
                creationDate,
                modificationDate = now,
                meta = meta ?: mapOf()
            )

            this.cache[name] = cloudEntry

            val entryData = cloudEntrySerializer.serializeEntries(this.cache.values)

            val response = this.keyknoxManager.pushValue(
                data = entryData,
                previousHash = this.decryptedKeyknoxData?.keyknoxHash,
                publicKeys = this.publicKeys,
                privateKey = this.privateKey
            )

            cacheEntries(cloudEntrySerializer.deserializeEntries(response.value))
            this.decryptedKeyknoxData = response

            return cloudEntry
        }
    }

    override fun retrieveAll(): List<CloudEntry> {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }

        synchronized(this.cache) {
            val cacheEntries = mutableListOf<CloudEntry>()
            cacheEntries.addAll(this.cache.values)

            return cacheEntries
        }
    }

    override fun retrieve(name: String): CloudEntry {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }

        return this.cache[name] ?: throw EntryNotFoundException(name)
    }

    override fun exists(name: String): Boolean {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }

        return this.cache.containsKey(name)
    }

    override fun delete(name: String) {
        delete(listOf(name))
    }

    override fun delete(names: List<String>) {
        if (!storageWasSynced) {
            throw CloudStorageOutOfSyncException()
        }
        synchronized(this.cache) {
            names.forEach { name ->
                if (!this.cache.containsKey(name)) {
                    throw EntryNotFoundException(name)
                }
            }
            names.forEach { name ->
                this.cache.remove(name)
            }
            val entryData = cloudEntrySerializer.serializeEntries(this.cache.values)
            val response = this.keyknoxManager.pushValue(
                data = entryData,
                previousHash = this.decryptedKeyknoxData?.keyknoxHash,
                publicKeys = this.publicKeys,
                privateKey = this.privateKey
            )
            cacheEntries(cloudEntrySerializer.deserializeEntries(response.value))
            this.decryptedKeyknoxData = response
        }
    }

    override fun deleteAll() {
        synchronized(this.cache) {
            val response = this.keyknoxManager.resetValue()
            cacheEntries(cloudEntrySerializer.deserializeEntries(response.value), true)
            this.decryptedKeyknoxData = response
        }
    }

    override fun retrieveCloudEntries() {
        synchronized(this.cache) {
            val response = this.keyknoxManager.pullValue(publicKeys = this.publicKeys, privateKey = this.privateKey)
            cacheEntries(cloudEntrySerializer.deserializeEntries(response.value), true)
            this.decryptedKeyknoxData = response
        }
    }

    override fun updateRecipients(newPublicKeys: List<VirgilPublicKey>?, newPrivateKey: VirgilPrivateKey?) {
        synchronized(this.cache) {
            val decryptedKeyknoxData = this.decryptedKeyknoxData ?: throw CloudStorageOutOfSyncException()


            // Cloud is empty, no need to update anything
            if (decryptedKeyknoxData.value.isEmpty() && decryptedKeyknoxData.meta.isEmpty()) {
                return
            }

            val tmpPublicKeys = newPublicKeys ?: this.publicKeys
            val tmpPrivateKeys = newPrivateKey ?: this.privateKey

            val response = this.keyknoxManager.pushValue(
                data = decryptedKeyknoxData.value,
                previousHash = decryptedKeyknoxData.keyknoxHash,
                publicKeys = tmpPublicKeys,
                privateKey = tmpPrivateKeys
            )
            cacheEntries(cloudEntrySerializer.deserializeEntries(response.value))
            this.decryptedKeyknoxData = response
            this.publicKeys = tmpPublicKeys
            this.privateKey = tmpPrivateKeys
        }
    }

    private fun cacheEntries(cloudEntries: MutableList<CloudEntry>, clear: Boolean = false) {
        if (clear) {
            this.cache.clear()
        }
        cloudEntries.forEach { cloudEntry ->
            this.cache[cloudEntry.name] = cloudEntry
        }
    }

    companion object {
        public const val ROOT = "DEFAULT"
        public const val PATH = "DEFAULT"
        public const val KEY = "DEFAULT"
    }
}
