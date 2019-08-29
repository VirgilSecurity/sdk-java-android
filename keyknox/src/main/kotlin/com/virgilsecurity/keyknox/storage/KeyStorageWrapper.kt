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

import com.virgilsecurity.keyknox.exception.ConvertKeychainEntryException
import com.virgilsecurity.sdk.storage.KeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage

class KeyStorageWrapper(val identity: String, val keychainStorage: KeyStorage) {

    fun store(name: String, data: ByteArray, meta: Map<String, String>? = null): KeyEntry {
        val keychainName = this.keychainName(name)
        val keyEntry = this.keychainStorage.createEntry(keychainName, data)
        keyEntry.meta = meta ?: mapOf()
        this.keychainStorage.store(keyEntry)

        return keyEntry
    }

    fun update(name: String, data: ByteArray, meta: Map<String, String>? = null) {
        val keychainName = this.keychainName(name)
        val keyEntry = this.keychainStorage.createEntry(keychainName, data)
        keyEntry.meta = meta ?: mapOf()

        this.keychainStorage.update(keyEntry)
    }

    fun retrieve(name: String): KeyEntry {
        val keychainName = this.keychainName(name)

        val keychainEntry = this.keychainStorage.load(keychainName)
        return mapKeychainEntry(keychainEntry) ?: throw ConvertKeychainEntryException()
    }

    fun retrieveAll(): List<KeyEntry> {
        return this.keychainStorage.names().mapNotNull { name ->
            val entry = this.keychainStorage.load(name)
            mapKeychainEntry(entry)
        }
    }

    fun delete(name: String) {
        val keychainName = this.keychainName(name)

        this.keychainStorage.delete(keychainName)
    }

    fun exists(name: String): Boolean {
        val keychainName = this.keychainName(name)

        return this.keychainStorage.exists(keychainName)
    }

    fun createEntry(name: String, data: ByteArray): KeyEntry {
        return this.keychainStorage.createEntry(name, data)
    }

    private fun keychainPrefix(): String {
        return "VIRGIL.IDENTITY=${this.identity}."
    }

    private fun keychainName(entryName: String): String {
        val prefix = this.keychainPrefix()
        return "$prefix$entryName"
    }

    private fun entryName(keychainName: String): String? {
        if (!keychainName.startsWith(this.keychainPrefix())) {
            return null
        }

        return keychainName.replaceFirst(this.keychainPrefix(), "")
    }

    private fun mapKeychainEntry(keychainEntry: KeyEntry): KeyEntry? {
        val entryName = this.entryName(keychainEntry.name) ?: return null

        val entry = this.keychainStorage.createEntry(entryName, keychainEntry.value)
        entry.meta = keychainEntry.meta

        return entry
    }

}