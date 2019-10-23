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

package com.virgilsecurity.keyknox.utils

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.sdk.utils.ConvertionUtils
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.*

class SerializerTest {

    private val date = Date()
    private val name = UUID.randomUUID().toString()
    private val data = ConvertionUtils.toBytes(name)

    @Test
    fun date_serialize() {
        val entry = CloudEntry(name, data, date, date)
        val entryStr = Serializer.gson.toJson(entry)
        val json = JsonParser().parse(entryStr) as JsonObject

        assertEquals(name, json["name"].asString)
        assertEquals(base64Encode(data), json["data"].asString)
        assertEquals(date.time, json["creation_date"].asLong)
        assertEquals(date.time, json["modification_date"].asLong)
    }

    @Test
    fun date_deserialize() {
        val json = JsonObject()
        json.addProperty("name", this.name)
        json.addProperty("data", base64Encode(this.data))
        json.addProperty("creation_date", this.date.time)
        json.addProperty("modification_date", this.date.time)

        val meta = JsonObject()
        meta.addProperty("k1", "Hello")
        meta.addProperty("k2", "Virgil")
        json.add("meta", meta)

        val entry = Serializer.gson.fromJson(json.toString(), CloudEntry::class.java)
        assertNotNull(entry)
        assertEquals(name, entry!!.name)
        assertArrayEquals(this.data, entry.data)
        assertEquals(date, entry.creationDate)
        assertEquals(date, entry.modificationDate)
        assertFalse(entry.meta.isEmpty())
        assertEquals("Hello", entry.meta["k1"])
        assertEquals("Virgil", entry.meta["k2"])
    }

}
