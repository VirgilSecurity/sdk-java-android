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

import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.cloud.CloudKeyStorageProtocol
import com.virgilsecurity.keyknox.exception.*
import com.virgilsecurity.sdk.crypto.PrivateKey
import com.virgilsecurity.sdk.crypto.PublicKey
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage

/**
 * Class responsible for synchronization between Keychain and Keyknox Cloud.
 */
class SyncKeyStorage {

    val identity: String
    val cloudKeyStorage: CloudKeyStorageProtocol
    private var keyStorage: KeyStorageWrapper
    private val keychainUtils = KeychainUtils()

    /**
     * @param identity User's identity to separate keys in Keychain.
     * @param keyStorage KeychainStorageProtocol implementation.
     * @param cloudKeyStorage CloudKeyStorageProtocol implementation.
     */
    constructor(identity: String, keyStorage: KeyStorage,
                cloudKeyStorage: CloudKeyStorageProtocol) {
        this.identity = identity
        this.keyStorage = KeyStorageWrapper(identity, keyStorage)
        this.cloudKeyStorage = cloudKeyStorage
    }

    /**
     * @param identity User's identity to separate keys in Keychain.
     * @param cloudKeyStorage CloudKeyStorageProtocol implementation.
     */
    constructor(identity: String, cloudKeyStorage: CloudKeyStorageProtocol) {
        this.identity = identity
        this.cloudKeyStorage = cloudKeyStorage
        this.keyStorage = KeyStorageWrapper(identity, DefaultKeyStorage())
    }

    /**
     * @param identity User's identity to separate keys in Keychain.
     * @param accessTokenProvider AccessTokenProvider implementation.
     * @param publicKeys Public keys used for encryption and signature verification.
     * @param privateKey Private key used for decryption and signature generation.
     */
    constructor(identity: String,
                accessTokenProvider: AccessTokenProvider,
                publicKeys: List<VirgilPublicKey>,
                privateKey: VirgilPrivateKey) {
        this.identity = identity
        this.cloudKeyStorage = CloudKeyStorage(accessTokenProvider = accessTokenProvider,
                                               publicKeys = publicKeys,
                                               privateKey = privateKey)
        this.keyStorage = KeyStorageWrapper(identity, DefaultKeyStorage())
    }

    /**
     * Updates entry in Keyknox Cloud and Keychain.
     *
     * @param name Entry name.
     * @param data New data.
     * @param meta New meta.
     */
    fun update(name: String, data: ByteArray, meta: Map<String, String>? = null) {
        if (!this.keyStorage.exists(name)) {
            throw KeychainEntryNotFoundWhileUpdatingException()
        }
        try {
            this.cloudKeyStorage.exists(name)
        } catch (e: Exception) {
            throw CloudEntryNotFoundWhileUpdatingException()
        }
        val cloudEntry = this.cloudKeyStorage.update(name, data, meta)
        val newMeta = this.keychainUtils.createMetaForKeychain(cloudEntry)
        this.keyStorage.update(name, data, newMeta)
    }

    /**
     * Retrieves entry from Keychain.
     *
     * @param name Name.
     *
     * @return Key entry.
     */
    fun retrieve(name: String): KeyEntry {
        return this.keyStorage.retrieve(name)
    }

    /**
     * Deletes entries from both Keychain and Keyknox Cloud.
     *
     * @param names Names to delete.
     */
    fun delete(names: List<String>) {
        names.forEach { name ->
            if (!this.keyStorage.exists(name)) {
                throw CloudEntryNotFoundWhileDeletingException()
            }
        }

        this.cloudKeyStorage.delete(names)

        names.forEach { name ->
            this.keyStorage.delete(name)
        }
    }

    /**
     * Deletes entry from both Keychain and Keyknox Cloud.
     *
     * @param name Name.
     */
    fun delete(name: String) {
        this.delete(kotlin.collections.listOf(name))
    }

    /**
     * Stores entry in both Keychain and Keyknox Cloud.
     *
     * @param name Name.
     * @param data Data.
     * @param meta Meta.
     *
     * @return Key entry.
     */
    fun store(name: String, data: ByteArray, meta: Map<String, String>? = null): KeyEntry {
        val keyEntry = this.keyStorage.createEntry(name, data)
        keyEntry.meta = meta ?: mapOf()

        val keyEntries = this.store(kotlin.collections.listOf(keyEntry))
        if (keyEntries.size != 1) {
            throw EntrySavingException()
        }
        return keyEntries.first()
    }

    /**
     * Stores entries in both Keychain and Keyknox Cloud.
     *
     * @param keyEntries Key entries to store.
     *
     * @return List of stored entries.
     */
    fun store(keyEntries: List<KeyEntry>): List<KeyEntry> {
        keyEntries.forEach { keyEntry ->
            if (this.keyStorage.exists(keyEntry.name)) {
                throw KeychainEntryAlreadyExistsWhileStoringException(keyEntry.name)
            }
            if (this.cloudKeyStorage.exists(keyEntry.name)) {
                throw CloudEntryAlreadyExistsWhileStoringException(keyEntry.name)
            }
        }

        val cloudEntries = this.cloudKeyStorage.store(keyEntries)
        val keychainEntries = mutableListOf<KeyEntry>()

        val keyEntryIt = keyEntries.iterator()
        val cloudEntryIt = cloudEntries.listIterator()
        while (keyEntryIt.hasNext() && cloudEntryIt.hasNext()) {
            val keyEntry = keyEntryIt.next()
            val cloudEntry = cloudEntryIt.next()

            if (!keyEntry.name.equals(cloudEntry.name)) {
                throw InconsistentStateException()
            }

            val meta = this.keychainUtils.createMetaForKeychain(cloudEntry)
            val keychainEntry = this.keyStorage.store(keyEntry.name, keyEntry.value, meta)

            keychainEntries.add(keychainEntry)
        }

        if (keyEntries.size != cloudEntries.size) {
            throw InconsistentStateException()
        }

        return keychainEntries
    }

    /**
     * Performs synchronization between Keychain and Keyknox Cloud.
     */
    fun sync() {
        this.cloudKeyStorage.retrieveCloudEntries()
        val keychainEntries = this.keyStorage.retrieveAll().filter {
            this.keychainUtils.filterKeyknoxKeychainEntry(it)
        }
        val cloudEntries = this.cloudKeyStorage.retrieveAll()

        val keychainSet = keychainEntries.map { it.name }
        val cloudSet = cloudEntries.map { it.name }

        val entriesToDelete = keychainSet.subtract(cloudSet).toList()
        val entriesToStore = cloudSet.subtract(keychainSet).toList()
        val entriesToCompare = keychainSet.intersect(cloudSet).toList()

        this.syncDeleteEntries(entriesToDelete)
        this.syncStoreEntries(entriesToStore)
        this.syncCompareEntries(entriesToCompare, keychainEntries)
    }

    /**
     * Updates recipients. See KeyknoxManager.updateRecipients.
     *
     * @param newPublicKeys New public keys.
     * @param newPrivateKey New private key.
     */
    fun updateRecipients(newPublicKeys: List<VirgilPublicKey>? = null, newPrivateKey: VirgilPrivateKey? = null) {
        this.cloudKeyStorage.updateRecipients(newPublicKeys, newPrivateKey)
    }

    /**
     * Retrieves all entries from Keychain.
     *
     * @return Keychain entries.
     */
    fun retrieveAll(): List<KeyEntry> {
        return this.keyStorage.retrieveAll()
    }

    /**
     * Checks if entry exists in Keychain.
     *
     * @param name Entry name.
     *
     * @return True if entry exists, false - otherwise.
     */
    fun exists(name: String): Boolean {
        return this.keyStorage.exists(name)
    }

    /**
     * Deletes all entries in both Keychain and Keyknox Cloud.
     */
    fun deleteAll() {
        this.cloudKeyStorage.deleteAll()

        val entriesToDelete = this.keyStorage.retrieveAll()
                .filter { this.keychainUtils.filterKeyknoxKeychainEntry(it) }
                .map { it.name }

        this.syncDeleteEntries(entriesToDelete)
    }

    private fun syncDeleteEntries(entriesToDelete: List<String>) {
        entriesToDelete.forEach {
            this.keyStorage.delete(it)
        }
    }

    private fun syncStoreEntries(entriesToStore: List<String>) {
        entriesToStore.forEach { name ->
            val cloudEntry = this.cloudKeyStorage.retrieve(name)

            val meta = this.keychainUtils.createMetaForKeychain(cloudEntry)
            this.keyStorage.store(cloudEntry.name, cloudEntry.data, meta)
        }
    }

    private fun syncCompareEntries(entriesToCompare: List<String>, keychainEntries: List<KeyEntry>) {
        // Determine newest version and either update keychain entry or upload newer version to cloud
        entriesToCompare.forEach { name ->
            val keychainEntry = keychainEntries.firstOrNull { name == it.name }
                    ?: throw KeychainEntryNotFoundWhileComparingException()
            val cloudEntry = this.cloudKeyStorage.retrieve(name)
            val keychainDate = this.keychainUtils.extractModificationDate(keychainEntry)

            if (keychainDate.second < cloudEntry.modificationDate) {
                val meta = this.keychainUtils.createMetaForKeychain(cloudEntry)
                this.keyStorage.update(cloudEntry.name, cloudEntry.data, meta)
            }
        }
    }
}
