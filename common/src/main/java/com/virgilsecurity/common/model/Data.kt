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

import com.virgilsecurity.crypto.foundation.Base64
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Data class that represents binary data with convenient transformations to/from Base64 string.
 */
class Data(val data: ByteArray) { // TODO Consider another name for parameter, so it won't be like data.data

    init {
        requireNotNull(data) { "\'data\' cannot be null" } // TODO if we remove requireNotNull - can we pass null from java?
    }

    /**
     * This function serializes current object to Base64 String format. String is UTF_8 encoded.
     */
    fun toBase64String(): String {
        return String(Base64.encode(data), StandardCharsets.UTF_8)
    }

    /**
     * This function serializes current object to Base64 String format. Provided [charset] is used for string encoding.
     */
    fun toBase64String(charset: Charset?): String {
        requireNotNull(charset) { "\'charset\' cannot be null" }

        return String(Base64.encode(data), charset)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val data1 = other as Data?
        return Arrays.equals(data, data1!!.data)
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(data)
    }

    companion object {

        /**
         * This function de-serializes provided [base64] String to [Data] object. String must be UTF_8 encoded.
         */
        @JvmStatic fun fromBase64String(base64: String?): Data {
            requireNotNull(base64) { "\'base64\' cannot be null" }

            return Data(Base64.decode(base64.toByteArray(StandardCharsets.UTF_8)))
        }

        /**
         * This function de-serializes provided [base64] String to [Data] object. Provided [charset] defines which
         * encoding in provided [base64] String is used.
         */
        @JvmStatic fun fromBase64String(base64: String?, charset: Charset?): Data {
            requireNotNull(base64) { "\'base64\' cannot be null" }
            requireNotNull(charset) { "\'charset\' cannot be null" }

            return Data(Base64.decode(base64.toByteArray(charset)))
        }
    }
}