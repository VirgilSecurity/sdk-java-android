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

import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.*

class KeyStorageWrapperTest {

    private lateinit var keyStorageWrapper: KeyStorageWrapper
    private lateinit var keyStorage: KeyStorage

    @BeforeEach
    fun setup() {
        this.keyStorage = DefaultKeyStorage(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString())
        this.keyStorageWrapper = KeyStorageWrapper("identity", this.keyStorage)
    }

    @Test
    fun delete() {
        assertTrue(this.keyStorageWrapper.retrieveAll().isEmpty())
        assertTrue(this.keyStorage.names().isEmpty())

        val name = UUID.randomUUID().toString()
        val wrappedName = "VIRGIL.IDENTITY=identity.$name"
        val data1 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)
        val data2 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)

        this.keyStorageWrapper.store(name, data1)

        assertEquals(1, this.keyStorageWrapper.retrieveAll().size)
        assertEquals(1, this.keyStorage.names().size)

        var entry1 = this.keyStorageWrapper.retrieve(name)
        assertNotNull(entry1)
        assertEquals(name, entry1.name)
        assertArrayEquals(data1, entry1.value)

        this.keyStorage.store(this.keyStorage.createEntry(name, data2))

        val wrappedEntries = this.keyStorageWrapper.retrieveAll()
        assertEquals(1, wrappedEntries.size)
        assertEquals(name, wrappedEntries[0].name)
        assertArrayEquals(data1, wrappedEntries[0].value)

        val names = this.keyStorage.names()
        assertEquals(2, names.size)
        assertTrue(names.contains(name))
        assertTrue(names.contains(wrappedName))

        entry1 = this.keyStorage.load(wrappedName)
        assertNotNull(entry1)
        assertEquals(wrappedName, entry1.name)
        assertArrayEquals(data1, entry1.value)

        var entry2 = this.keyStorage.load(name)
        assertNotNull(entry1)
        assertEquals(name, entry2.name)
        assertArrayEquals(data2, entry2.value)

        entry1 = this.keyStorageWrapper.retrieve(name)
        assertNotNull(entry1)
        assertEquals(name, entry1.name)
        assertArrayEquals(data1, entry1.value)

        this.keyStorageWrapper.delete(name)
        assertTrue(this.keyStorageWrapper.retrieveAll().isEmpty())
        assertEquals(1, this.keyStorage.names().size)

        assertFalse(this.keyStorageWrapper.exists(name))
        try {
            this.keyStorageWrapper.retrieve(name)
            fail<String>("Entry had been removed")
        } catch (e: KeyStorageException) {
            // nothing to do
        }
        try {
            this.keyStorageWrapper.retrieve(wrappedName)
            fail<String>("Entry had been removed")
        } catch (e: KeyStorageException) {
            // nothing to do
        }

        entry2 = this.keyStorage.load(name)
        assertNotNull(entry1)
        assertEquals(name, entry2.name)
        assertArrayEquals(data2, entry2.value)
    }

    @Test
    fun exists() {
        val name1 = UUID.randomUUID().toString()
        val name2 = UUID.randomUUID().toString()
        val data1 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)
        val data2 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)

        this.keyStorageWrapper.store(name1, data1)
        this.keyStorage.store(this.keyStorage.createEntry(name2, data2))

        assertTrue(this.keyStorageWrapper.exists(name1))
        assertFalse(this.keyStorageWrapper.exists(name2))

        assertFalse(this.keyStorage.exists(name1))
        assertTrue(this.keyStorage.exists(name2))
    }

    @Test
    fun update() {
        val name1 = UUID.randomUUID().toString()
        val name2 = UUID.randomUUID().toString()
        val data1 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)
        val data2 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)
        val data3 = UUID.randomUUID().toString().toByteArray(StandardCharsets.UTF_8)

        this.keyStorageWrapper.store(name1, data1)
        this.keyStorage.store(this.keyStorage.createEntry(name2, data2))

        this.keyStorageWrapper.update(name1, data3)
        try {
            this.keyStorageWrapper.update(name2, data3)
            fail<String>("Entry not exists")
        } catch (e: KeyStorageException) {
            // nothing to do
        }
        val entry = this.keyStorageWrapper.retrieve(name1)
        assertNotNull(entry)
        assertEquals(name1, entry.name)
        assertArrayEquals(data3, entry.value)
    }
}