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

package com.virgilsecurity.common.model

import com.virgilsecurity.common.util.toHexString
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import kotlin.experimental.and

class DataTest {

    private val TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
    private val DATA = TEXT.toByteArray(StandardCharsets.UTF_8)
    private val BASE64_DATA = java.util.Base64.getEncoder().encode(DATA)
    private val BASE64_TEXT = java.util.Base64.getEncoder().encodeToString(DATA)
    private lateinit var data: Data

    @BeforeEach
    fun setup() {
        this.data = Data(DATA)
    }

    @Test
    fun fromBase64String() {
        assertArrayEquals(DATA, Data.fromBase64String(BASE64_TEXT).value)
    }

    @Test
    fun toBase64String() {
        assertEquals(BASE64_TEXT, data.toBase64String())
    }

    @Test
    fun toHexString() {
        assertEquals(bytesToHex(DATA), data.toHexString())
    }

    private val hexArray = "0123456789ABCDEF".toLowerCase().toCharArray()
    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = (bytes[j] and 0xFF.toByte()).toInt()
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }
}
