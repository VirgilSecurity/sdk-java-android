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

import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.storage.KeyEntry

interface CloudKeyStorageProtocol {

    /**
     * Store entries to cloud.
     *
     * @param keyEntries entries to store
     *
     * @return List<CloudEntry>
     */
    fun store(keyEntries: List<KeyEntry>): List<CloudEntry>


    /**
     * Store entry to cloud.
     *
     * @param name name
     * @param data data
     * @param meta metadata
     *
     * @return CloudEntry
     */
    fun store(name: String, data: ByteArray, meta: Map<String, String>? = null): CloudEntry

    /**
     * Update entry in Cloud.
     *
     * @param name name
     * @param data data
     * @param meta metadata
     *
     * @return CloudEntry
     */
    fun update(name: String, data: ByteArray, meta: Map<String, String>? = null): CloudEntry

    /**
     * Returns all entries loaded from Cloud.
     *
     * @return all entries
     */
    fun retrieveAll(): List<CloudEntry>

    /**
     * Retrieve entry loaded from Cloud.
     *
     * @param name name
     *
     * @return CloudEntry
     */
    fun retrieve(name: String): CloudEntry

    /**
     * Check if entry exists in list of loaded from Cloud entries.
     *
     * @param name name
     *
     * @return true if entry exists, false - otherwise
     */
    fun exists(name: String): Boolean

    /**
     * Deletes entry from Cloud.
     *
     * @param name name
     */
    fun delete(name: String)

    /**
     * Deletes entries from Cloud.
     *
     * @param names names of entries to delete
     */
    fun delete(names: List<String>)

    /**
     * Deletes all entries from Cloud.
     */
    fun deleteAll()

    /**
     * Retrieves entries from Cloud.
     */
    fun retrieveCloudEntries()

    /**
     * Updated recipients. See KeyknoxManager.updateRecipients.
     *
     * @param newPublicKeys new public keys
     * @param newPrivateKey new private key
     */
    fun updateRecipients(newPublicKeys: List<VirgilPublicKey>? = null,
                         newPrivateKey: VirgilPrivateKey? = null)

}