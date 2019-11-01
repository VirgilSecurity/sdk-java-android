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
import com.virgilsecurity.testcommon.property.EnvPropertyReader
import com.virgilsecurity.testcommon.utils.PropertyUtils

class TestConfig {
    companion object {
        private const val APP_ID = "APP_ID"
        private const val APP_PRIVATE_KEY = "APP_PRIVATE_KEY"
        private const val APP_PUBLIC_KEY_ID = "APP_PUBLIC_KEY_ID"
        private const val KEYKNOX_SERVICE_ADDRESS = "KEYKNOX_SERVICE_ADDRESS"

        private const val ENVIRONMENT_PARAMETER = "environment"

        private val propertyReader: EnvPropertyReader by lazy {
            val environment = PropertyUtils.getSystemProperty(ENVIRONMENT_PARAMETER)

            if (environment != null)
                EnvPropertyReader.Builder()
                    .environment(EnvPropertyReader.Environment.fromType(environment))
                    .isDefaultSubmodule(true)
                    .build()
            else
                EnvPropertyReader.Builder()
                    .isDefaultSubmodule(true)
                    .build()
        }

        val virgilCrypto = VirgilCrypto(false)
        val appId: String by lazy { propertyReader.getProperty(APP_ID) }
        val appPrivateKey: VirgilPrivateKey by lazy {
            with(propertyReader.getProperty(APP_PRIVATE_KEY)) {
                virgilCrypto.importPrivateKey(base64Decode(this)).privateKey
            }
        }
        val appPublicKeyId: String by lazy { propertyReader.getProperty(APP_PUBLIC_KEY_ID) }
        val keyknoxServiceAddress: String by lazy { propertyReader.getProperty(KEYKNOX_SERVICE_ADDRESS) }
    }
}
