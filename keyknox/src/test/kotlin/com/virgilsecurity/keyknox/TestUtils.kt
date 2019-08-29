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

import com.google.gson.JsonElement
import com.google.gson.JsonObject



class TestUtils {

    companion object {
        fun pause() {
            Thread.sleep(2000)
        }

        fun compareJson(json1: JsonElement?, json2: JsonElement?): Boolean {
            var isEqual = true
            // Check whether both jsonElement are not null
            if (json1 != null && json2 != null) {

                // Check whether both jsonElement are objects
                if (json1.isJsonObject && json2.isJsonObject) {
                    val ens1 = (json1 as JsonObject).entrySet()
                    val ens2 = (json2 as JsonObject).entrySet()
                    val json2obj = json2 as JsonObject?
                    if (ens1 != null && ens2 != null && ens2.size == ens1.size) {
                        // Iterate JSON Elements with Key values
                        for ((key, value) in ens1) {
                            isEqual = isEqual && compareJson(value, json2obj!!.get(key))
                        }
                    } else {
                        return false
                    }
                } else if (json1.isJsonArray && json2.isJsonArray) {
                    val jarr1 = json1.asJsonArray
                    val jarr2 = json2.asJsonArray
                    if (jarr1.size() != jarr2.size()) {
                        return false
                    } else {
                        var i = 0
                        // Iterate JSON Array to JSON Elements
                        for (je in jarr1) {
                            isEqual = isEqual && compareJson(je, jarr2.get(i))
                            i++
                        }
                    }
                } else return if (json1.isJsonNull && json2.isJsonNull) {
                    true
                } else if (json1.isJsonPrimitive && json2.isJsonPrimitive) {
                    json1 == json2
                } else {
                    false
                }
            } else return json1 == null && json2 == null
            return isEqual
        }
    }
}