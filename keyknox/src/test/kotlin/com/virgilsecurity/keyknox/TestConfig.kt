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

import com.virgilsecurity.keyknox.utils.base64Decode
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey

class TestConfig {
    companion object {
        val virgilCrypto = VirgilCrypto(false)
        val appId: String by lazy {
            if (System.getProperty("APP_ID") != null)
                System.getProperty("APP_ID")
            else
                System.getenv("APP_ID")
        }
        val apiKey: VirgilPrivateKey by lazy {
            (if (System.getProperty("API_PRIVATE_KEY") != null)
                System.getProperty("API_PRIVATE_KEY")
            else
                System.getenv("API_PRIVATE_KEY")).let {
                this.virgilCrypto.importPrivateKey(base64Decode(it)).privateKey
            }
        }
        val apiPublicKey: VirgilPublicKey by lazy {
            (if (System.getProperty("API_PUBLIC_KEY") != null)
                System.getProperty("API_PUBLIC_KEY")
            else
                System.getenv("API_PUBLIC_KEY")).let {
                this.virgilCrypto.importPublicKey(base64Decode(it))
            }
        }
        val apiPublicKeyId: String by lazy {
            if (System.getProperty("API_PUBLIC_KEY_ID") != null)
                System.getProperty("API_PUBLIC_KEY_ID")
            else
                System.getenv("API_PUBLIC_KEY_ID")
        }
    }
}