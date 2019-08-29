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

package com.virgilsecurity.keyknox.model

import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.client.model.KeyknoxData
import com.virgilsecurity.keyknox.client.model.KeyknoxDataV2
import java.util.*

/**
 * Class represents value stored in Keyknox cloud.
 */
open class KeyknoxValue {

    val root: String
    val path: String
    val key: String
    val owner: String
    val identities: Collection<String>
    val meta: ByteArray?
    val value: ByteArray?
    val keyknoxHash: ByteArray?

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray) : this(keyknoxData.root,
        keyknoxData.path, keyknoxData.key, keyknoxData.owner, keyknoxData.identities,
        keyknoxData.meta, keyknoxData.value, keyknoxHash) {
    }

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String): this(
        KeyknoxClient.DEFAULT_ROOT, KeyknoxClient.DEFAULT_PATH, KeyknoxClient.DEFAULT_KEY,
    identity, setOf(identity), keyknoxData.meta, keyknoxData.value,keyknoxHash)

    constructor(root: String, path: String, key: String, owner: String,
                identities: Collection<String>, meta: ByteArray, value: ByteArray,
                keyknoxHash: ByteArray) {
        this.root = root
        this.path = path
        this.key = key
        this.owner = owner
        this.identities = identities
        this.meta = meta
        this.value = value
        this.keyknoxHash = keyknoxHash
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedKeyknoxValue

        if (!Arrays.equals(meta, other.meta)) return false
        if (!Arrays.equals(value, other.value)) return false
        if (!Arrays.equals(keyknoxHash, other.keyknoxHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = meta?.let { Arrays.hashCode(it) } ?: 0
        result = 31 * result + (value?.let { Arrays.hashCode(it) } ?: 0)
        result = 31 * result + (keyknoxHash?.let { Arrays.hashCode(it) } ?: 0)
        return result
    }
}

/**
 * Decrypted value stored in Keyknox cloud.
 *
 */
class DecryptedKeyknoxValue (root: String, path: String, key: String, owner: String,
                            identities: Collection<String>, meta: ByteArray, value: ByteArray,
                            keyknoxHash: ByteArray) :
        KeyknoxValue(root, path, key, owner, identities, meta, value, keyknoxHash) {

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray):
            super (keyknoxData = keyknoxData, keyknoxHash = keyknoxHash)

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String):
            super (keyknoxData = keyknoxData, keyknoxHash = keyknoxHash, identity = identity)
}

/**
 * Encrypted value stored in Keyknox cloud.
 *
 */
class EncryptedKeyknoxValue (root: String, path: String, key: String, owner: String,
                            identities: Collection<String>, meta: ByteArray, value: ByteArray,
                            keyknoxHash: ByteArray) :
    KeyknoxValue(root, path, key, owner, identities, meta, value, keyknoxHash) {

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray):
            super (keyknoxData = keyknoxData, keyknoxHash = keyknoxHash)

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String):
            super (keyknoxData = keyknoxData, keyknoxHash = keyknoxHash, identity = identity)
}