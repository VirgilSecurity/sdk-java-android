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

import com.google.gson.reflect.TypeToken
import com.virgilsecurity.keyknox.client.model.*
import com.virgilsecurity.keyknox.exception.EmptyIdentitiesException
import com.virgilsecurity.keyknox.exception.InvalidHashHeaderException
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.keyknox.utils.base64Decode
import com.virgilsecurity.keyknox.utils.base64Encode
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.net.URL

/**
 * KeyknoxClientProtocol implementation.
 */
class KeyknoxClient @JvmOverloads constructor(
    val serviceUrl: URL = URL("https://api.virgilsecurity.com"),
    val httpClient: HttpClientProtocol = HttpClient()
) : KeyknoxClientProtocol {

    override fun getKeys(params: KeyknoxGetKeysParams, token: String): Collection<String> {
        val requestData = GetKeysData(params.root, params.path, params.identity)
        val body = ConvertionUtils.getGson().toJson(requestData)
        val url = URL(this.serviceUrl, "keyknox/v2/keys")
        val response = this.httpClient.send(url, Method.POST, token, body)

        val listType = object : TypeToken<List<String>>() {}.type
        val keys = ConvertionUtils.getGson().fromJson<List<String>>(response.body, listType)

        return keys
    }

    override fun deleteRecipient(
        params: KeyknoxDeleteRecipientParams,
        token: String
    ): DecryptedKeyknoxValue {
        val requestData = DeleteRecipientData(params.root, params.path, params.key, params.identity)
        val body = ConvertionUtils.getGson().toJson(requestData)
        val url = URL(this.serviceUrl, "keyknox/v2/reset")
        val response = this.httpClient.send(url, Method.POST, token, body)
        val hashCode = extractKeyknoxHash(response)
        val keyknoxData =
            ConvertionUtils.getGson().fromJson(response.body, KeyknoxDataV2::class.java)
        val keyknoxValue = DecryptedKeyknoxValue(keyknoxData, hashCode)

        return keyknoxValue
    }

    override fun pushValue(
        params: KeyknoxPushParams?,
        meta: ByteArray,
        value: ByteArray,
        previousHash: ByteArray?,
        token: String
    ): EncryptedKeyknoxValue {
        val requestData = PushValueData(meta, value)
        val headers = hashMapOf<String, String>()
        previousHash?.let {
            headers[VIRGIL_KEYKNOX_PREVIOUS_HASH_KEY] = base64Encode(previousHash)
        }

        val keyknoxValue: EncryptedKeyknoxValue

        if (params == null) {
            val url = URL(this.serviceUrl, "keyknox/v1")
            val body = ConvertionUtils.getGson().toJson(requestData)

            val response = this.httpClient.send(url, Method.PUT, token, body, headers)
            keyknoxValue = extractEncryptedKeyknoxValueV1(response)
        } else {
            if (params.identities.isEmpty()) {
                throw EmptyIdentitiesException()
            }

            requestData.root = params.root
            requestData.path = params.path
            requestData.key = params.key
            requestData.identities = params.identities

            val url = URL(this.serviceUrl, "keyknox/v2/push")
            val body = ConvertionUtils.getGson().toJson(requestData)

            val response = this.httpClient.send(url, Method.PUT, token, body, headers)
            keyknoxValue = extractEncryptedKeyknoxValueV2(response)
        }

        return keyknoxValue
    }

    override fun pullValue(params: KeyknoxPullParams?, token: String): EncryptedKeyknoxValue {
        val keyknoxValue: EncryptedKeyknoxValue
        if (params == null) {
            val url = URL(this.serviceUrl, "keyknox/v1")
            val response = this.httpClient.send(url, Method.GET, token)
            keyknoxValue = extractEncryptedKeyknoxValueV1(response)
        } else {
            val requestData = PullValueData(params.root, params.path, params.key, params.identity)
            val body = ConvertionUtils.getGson().toJson(requestData)
            val url = URL(this.serviceUrl, "keyknox/v2/pull")
            val response = this.httpClient.send(url, Method.POST, token, body)
            keyknoxValue = extractEncryptedKeyknoxValueV2(response)
        }
        return keyknoxValue
    }

    override fun resetValue(params: KeyknoxResetParams?, token: String): DecryptedKeyknoxValue {
        var keyknoxValue: DecryptedKeyknoxValue
        if (params == null) {
            val url = URL(this.serviceUrl, "keyknox/v1/reset")
            val response = this.httpClient.send(url, Method.POST, token)
            val hashCode = extractKeyknoxHash(response)
            val keyknoxData =
                ConvertionUtils.getGson().fromJson(response.body, KeyknoxData::class.java)
            //FIXME
            val identity = ""
            keyknoxValue = DecryptedKeyknoxValue(keyknoxData, hashCode, identity)
        } else {
            val requestData = ResetValueData(params.root, params.path, params.key)
            val body = ConvertionUtils.getGson().toJson(requestData)
            val url = URL(this.serviceUrl, "keyknox/v2/reset")
            val response = this.httpClient.send(url, Method.POST, token, body)
            val hashCode = extractKeyknoxHash(response)
            val keyknoxData =
                ConvertionUtils.getGson().fromJson(response.body, KeyknoxDataV2::class.java)
            keyknoxValue = DecryptedKeyknoxValue(keyknoxData, hashCode)
        }

        return keyknoxValue
    }

    private fun extractKeyknoxHash(response: Response): ByteArray {
        val hashStr = response.headers[VIRGIL_KEYKNOX_HASH_KEY]
        if (hashStr == null || hashStr.isBlank()) {
            throw InvalidHashHeaderException()
        }
        val hash = base64Decode(hashStr)
        return hash
    }

    private fun extractEncryptedKeyknoxValueV1(response: Response): EncryptedKeyknoxValue {
        val hashCode = extractKeyknoxHash(response)
        val keyknoxData = ConvertionUtils.getGson().fromJson(response.body, KeyknoxData::class.java)
        //FIXME
        val identity = ""
        return EncryptedKeyknoxValue(keyknoxData, hashCode, identity)
    }

    private fun extractEncryptedKeyknoxValueV2(response: Response): EncryptedKeyknoxValue {
        val hashCode = extractKeyknoxHash(response)
        val keyknoxData =
            ConvertionUtils.getGson().fromJson(response.body, KeyknoxDataV2::class.java)
        return EncryptedKeyknoxValue(keyknoxData, hashCode)
    }

    companion object {
        const val VIRGIL_KEYKNOX_HASH_KEY = "virgil-keyknox-hash"
        const val VIRGIL_KEYKNOX_PREVIOUS_HASH_KEY = "virgil-keyknox-previous-hash"

        const val DEFAULT_ROOT = "DEFAULT_ROOT"
        const val DEFAULT_PATH = "DEFAULT_PATH"
        const val DEFAULT_KEY = "DEFAULT_KEY"
    }

}