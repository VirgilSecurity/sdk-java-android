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

package com.virgilsecurity.keyknox.model

import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.client.model.KeyknoxData
import com.virgilsecurity.keyknox.client.model.KeyknoxDataV2

/**
 * Class represents value stored in Keyknox cloud.
 */
open class KeyknoxValue {

    val root: String
    val path: String
    val key: String
    val owner: String
    val identities: Collection<String>
    val meta: ByteArray
    val value: ByteArray
    @Deprecated("Version is deprecated") val version: String?
    val keyknoxHash: ByteArray

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray) : this(
        keyknoxData.root,
        keyknoxData.path,
        keyknoxData.key,
        keyknoxData.owner,
        keyknoxData.identities,
        keyknoxData.meta,
        keyknoxData.value,
        keyknoxData.version,
        keyknoxHash
    )

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String): this(
        KeyknoxClient.DEFAULT_ROOT,
        KeyknoxClient.DEFAULT_PATH,
        KeyknoxClient.DEFAULT_KEY,
        identity,
        setOf(identity),
        keyknoxData.meta,
        keyknoxData.value,
        keyknoxData.version,
        keyknoxHash
    )

    constructor(
        root: String,
        path: String,
        key: String,
        owner: String,
        identities: Collection<String>,
        meta: ByteArray,
        value: ByteArray,
        version: String?,
        keyknoxHash: ByteArray
    ) {
        this.root = root
        this.path = path
        this.key = key
        this.owner = owner
        this.identities = identities
        this.meta = meta
        this.value = value
        this.version = version
        this.keyknoxHash = keyknoxHash
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyknoxValue

        if (root != other.root) return false
        if (path != other.path) return false
        if (key != other.key) return false
        if (owner != other.owner) return false
        if (identities != other.identities) return false
        if (!meta.contentEquals(other.meta)) return false
        if (!value.contentEquals(other.value)) return false
        if (!keyknoxHash.contentEquals(other.keyknoxHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = root.hashCode()
        result = 31 * result + path.hashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + owner.hashCode()
        result = 31 * result + identities.hashCode()
        result = 31 * result + meta.contentHashCode()
        result = 31 * result + value.contentHashCode()
        result = 31 * result + keyknoxHash.contentHashCode()
        return result
    }
}

/**
 * Decrypted value stored in Keyknox cloud.
 */
class DecryptedKeyknoxValue : KeyknoxValue {

    constructor(
        root: String,
        path: String,
        key: String,
        owner: String,
        identities: Collection<String>,
        meta: ByteArray,
        value: ByteArray,
        version: String?,
        keyknoxHash: ByteArray
    ) : super(root, path, key, owner, identities, meta, value, version, keyknoxHash)

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray) : super(
        keyknoxData = keyknoxData,
        keyknoxHash = keyknoxHash
    )

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String) : super(
        keyknoxData = keyknoxData,
        keyknoxHash = keyknoxHash,
        identity = identity
    )
}

/**
 * Encrypted value stored in Keyknox cloud.
 *
 */
class EncryptedKeyknoxValue : KeyknoxValue {

    constructor(
        root: String,
        path: String,
        key: String,
        owner: String,
        identities: Collection<String>,
        meta: ByteArray,
        value: ByteArray,
        version: String?,
        keyknoxHash: ByteArray
    ) : super(root, path, key, owner, identities, meta, value, version, keyknoxHash)

    constructor(keyknoxData: KeyknoxDataV2, keyknoxHash: ByteArray) : super(
        keyknoxData = keyknoxData,
        keyknoxHash = keyknoxHash
    )

    constructor(keyknoxData: KeyknoxData, keyknoxHash: ByteArray, identity: String) : super(
        keyknoxData = keyknoxData,
        keyknoxHash = keyknoxHash,
        identity = identity
    )
}