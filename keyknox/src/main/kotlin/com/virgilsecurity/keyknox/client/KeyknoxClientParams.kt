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

package com.virgilsecurity.keyknox.client

/**
 * Keyknox get parameters.
 *
 * @param identity Keyknox owner identity.
 * @param root root.
 * @param path path.
 */
class KeyknoxGetKeysParams constructor(
    val identity: String?,
    val root: String?,
    val path: String?
)

/**
 * Keyknox delete participant parameters.
 *
 * @param identity recipient identity.
 * @param root root.
 * @param path path.
 * @param key key.
 */
class KeyknoxDeleteRecipientParams constructor(
    val identity: String,
    val root: String,
    val path: String,
    val key: String?
)

/**
 * Keyknox reset parameters
 *
 * @param root root.
 * @param path path.
 * @param key key.
 */
class KeyknoxResetParams constructor(
    val root: String?,
    val path: String?,
    val key: String?
)

/**
 * Keyknox pull parameters.
 *
 * @param identity owner identity.
 * @param root root.
 * @param path path.
 * @param key key.
 */
class KeyknoxPullParams constructor(
    val identity: String,
    val root: String,
    val path: String,
    val key: String?
)

/**
 * Keyknox push parameters.
 *
 * @param identities identities with an access.
 * @param root root.
 * @param path path.
 * @param key key.
 */
class KeyknoxPushParams constructor(
    val identities: Collection<String>,
    val root: String,
    val path: String,
    val key: String
)
