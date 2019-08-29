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

import com.google.gson.JsonObject
import com.virgilsecurity.keyknox.build.VersionVirgilAgent
import com.virgilsecurity.keyknox.exception.KeyknoxServiceException
import com.virgilsecurity.keyknox.utils.Loggable
import com.virgilsecurity.keyknox.utils.Serializer
import com.virgilsecurity.sdk.common.ErrorResponse
import com.virgilsecurity.sdk.utils.ConvertionUtils
import com.virgilsecurity.sdk.utils.OsUtils
import com.virgilsecurity.sdk.utils.StringUtils
import java.io.BufferedInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.logging.Level

class HttpClient : HttpClientProtocol, Loggable {

    private val virgilAgentHeader: String

    constructor() {
        virgilAgentHeader =
                "$VIRGIL_AGENT_PRODUCT;$VIRGIL_AGENT_FAMILY;${OsUtils.getOsAgentName()};${VersionVirgilAgent.VERSION}"
    }

    constructor(product: String, version: String) {
        virgilAgentHeader = "$product;$VIRGIL_AGENT_FAMILY;${OsUtils.getOsAgentName()};$version"
    }

    override fun send(url: URL, method: Method, accessToken: String, body: Any?, headers: Map<String, String>?): Response {
        try {
            logger().fine("${method.name} to $url")
            val urlConnection = createConnection(url, method, accessToken)
            headers?.forEach { (key, value) ->
                urlConnection.setRequestProperty(key, value)
            }

            body?.let {
                val bodyStr = if (body is JsonObject) {
                    body.toString()
                } else {
                    Serializer.gson.toJson(body)
                }
                urlConnection.outputStream.write(ConvertionUtils.toBytes(bodyStr))
                urlConnection.outputStream.flush()
            }
            try {
                if (urlConnection.responseCode >= HttpURLConnection.HTTP_BAD_REQUEST) {
                    logger().fine("Error ${urlConnection.responseCode} \t ${method.name} to $url")
                    // Get error code from request
                    BufferedInputStream(urlConnection.errorStream).use { `in` ->
                        val responseBody = ConvertionUtils.toString(`in`)
                        if (!StringUtils.isBlank(responseBody)) {
                            val error = ConvertionUtils.getGson().fromJson(responseBody, ErrorResponse::class.java)
                            throw KeyknoxServiceException(urlConnection.responseCode, error.code, error.message)
                        } else {
                            throw KeyknoxServiceException(urlConnection.responseCode)
                        }
                    }
                } else {
                    BufferedInputStream(urlConnection.inputStream).use { instream ->
                        val responseBody = ConvertionUtils.toString(instream)
                        val headerFields = mutableMapOf<String, String>()
                        urlConnection.headerFields?.keys?.filterNotNull()?.forEach { key ->
                            val value = urlConnection.headerFields[key]
                            value?.let {
                                headerFields[key.toLowerCase()] = value.first()
                            }
                        }
                        return Response(responseBody, headerFields)
                    }
                }
            } finally {
                logger().finest("Disconnecting...")
                urlConnection.disconnect()
            }
        } catch (e: IOException) {
            logger().log(Level.SEVERE, "Connection error", e)
            throw KeyknoxServiceException(-1)
        }

    }

    private fun createConnection(url: URL, method: Method, accessToken: String): HttpURLConnection {
        val urlConnection = url.openConnection() as HttpURLConnection
        urlConnection.requestMethod = method.name
        urlConnection.useCaches = false

        when (method) {
            Method.DELETE, Method.POST, Method.PUT -> urlConnection.doOutput = true
            else -> {
                urlConnection.doOutput = false
            }
        }

        if (!StringUtils.isBlank(accessToken)) {
            urlConnection.setRequestProperty("Authorization", "Virgil $accessToken")
        }
        urlConnection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER_KEY, virgilAgentHeader)

        return urlConnection
    }

    companion object {
        private const val VIRGIL_AGENT_HEADER_KEY = "virgil-agent"
        private const val VIRGIL_AGENT_PRODUCT = "keyknox"
        private const val VIRGIL_AGENT_FAMILY = "jvm"
    }
}