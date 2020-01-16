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

package com.virgilsecurity.keyknox.client

import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue

/**
 * Interface for interactions with Keyknox service.
 */
interface KeyknoxClientProtocol {

    /**
     * Get keys for given root.
     *
     * @param params params
     *
     * @return set of keys
     */
    fun getKeys(params: KeyknoxGetKeysParams): Set<String>

    /**
     * Delete recipient.
     *
     * @param params params
     *
     * @return DecryptedKeyknoxValue
     */
    fun deleteRecipient(params: KeyknoxDeleteRecipientParams): DecryptedKeyknoxValue

    /**
     * Push value to Keyknox service.
     *
     * @param params params
     * @param meta metadata
     * @param value encrypted blob
     * @param previousHash hash of previous blob
     * @param token auth token
     *
     * @return EncryptedKeyknoxValue
     */
    fun pushValue(params: KeyknoxPushParams? = null, meta: ByteArray, value: ByteArray, previousHash: ByteArray?): EncryptedKeyknoxValue

    /**
     * Pulls values from Keyknox service.
     *
     * @param params params
     * @param token auth token
     *
     * @return EncryptedKeyknoxValue
     */
    fun pullValue(params: KeyknoxPullParams? = null): EncryptedKeyknoxValue

    /**
     * Resets Keyknox value (makes it empty). Also increments version.
     *
     * @param params params
     * @param token auth token
     *
     * @return DecryptedKeyknoxValue
     */
    fun resetValue(params: KeyknoxResetParams? = null): DecryptedKeyknoxValue

}
