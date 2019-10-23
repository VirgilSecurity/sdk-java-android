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

import com.virgilsecurity.keyknox.exception.InvalidCreationDateInKeychainEntryException
import com.virgilsecurity.keyknox.exception.InvalidModificationDateInKeychainEntryException
import com.virgilsecurity.keyknox.exception.NoMetaInKeychainEntryException
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.sdk.storage.KeyEntry
import java.util.*

class KeychainUtils {

    fun createMetaForKeychain(cloudEntry: CloudEntry): Map<String, String> {
        val meta = mutableMapOf<String, String>()

        meta[KEYKNOX_META_CREATION_DATE_KEY] = cloudEntry.creationDate.time.toString()
        meta[KEYKNOX_META_MODIFICATION_DATE_KEY] = cloudEntry.modificationDate.time.toString()
        meta.putAll(cloudEntry.meta)

        return meta
    }

    fun filterKeyknoxKeychainEntry(keyEntry: KeyEntry): Boolean {
        try {
            extractModificationDate(keyEntry)
            return true
        } catch (e: Exception) {
            return false
        }
    }

    fun extractModificationDate(keyEntry: KeyEntry): Pair<Date, Date> {
        val meta = keyEntry.meta ?: throw NoMetaInKeychainEntryException()

        val modificationTimestampStr = meta[KeychainUtils.KEYKNOX_META_MODIFICATION_DATE_KEY]
                ?: throw InvalidModificationDateInKeychainEntryException()
        val modificationTimestamp = try {
            modificationTimestampStr.toLong()
        } catch (e: NumberFormatException) {
            throw InvalidModificationDateInKeychainEntryException()
        }

        val creationTimestampStr = meta[KeychainUtils.KEYKNOX_META_CREATION_DATE_KEY]
                ?: throw InvalidCreationDateInKeychainEntryException()
        val creationTimestamp = try {
            creationTimestampStr.toLong()
        } catch (e: NumberFormatException) {
            throw InvalidCreationDateInKeychainEntryException()
        }

        return Pair(Date(creationTimestamp), Date(modificationTimestamp))
    }


    companion object {
        val KEYKNOX_META_CREATION_DATE_KEY = "k_cda"
        val KEYKNOX_META_MODIFICATION_DATE_KEY = "k_mda"
    }
}