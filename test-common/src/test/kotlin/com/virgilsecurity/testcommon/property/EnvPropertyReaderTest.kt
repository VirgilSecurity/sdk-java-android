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

package com.virgilsecurity.testcommon.property

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.io.File

/**
 * EnvPropertyReaderTest class.
 */
@Suppress("RECEIVER_NULLABILITY_MISMATCH_BASED_ON_JAVA_ANNOTATIONS")
class EnvPropertyReaderTest {

    @Test
    fun read_environment_properties() {
        val envFileUrl = this.javaClass
            .classLoader
            .getResource("com/virgilsecurity/testcommon/property/$TEST_ENV_FILE_NAME")
        assertNotNull(envFileUrl)

        val envFilePath = envFileUrl.path.removeSuffix(TEST_ENV_FILE_NAME)
        assertNotNull(envFilePath)

        val fileLines = File(envFileUrl.toURI()).readLines()

        for (environment in EnvPropertyReader.Environment.values()) {
            for (line in fileLines) {
                if (line.contains(environment.type.toRegex())) {
                    val propertyLine1 = fileLines[fileLines.indexOf(line) + 1] // First line of property
                    val propertyLine2 = fileLines[fileLines.indexOf(line) + 2] // Second line of property

                    val propertyEntry1 = propertyLine1.replace("\"", "")
                        .removeSuffix(",")
                        .trim()
                        .split(":")
                        .let { Pair(it[0], it[1]) }
                    val propertyEntry2 = propertyLine2.replace("\"", "")
                        .removeSuffix(",")
                        .trim()
                        .split(":")
                        .let { Pair(it[0], it[1]) }

                    val envReader = EnvPropertyReader.Builder()
                        .environment(environment)
                        .filePath(envFilePath)
                        .fileName(TEST_ENV_FILE_NAME)
                        .isDefaultSubmodule(false)
                        .build()

                    when(environment) {
                        EnvPropertyReader.Environment.DEV -> {
                            assertEquals(DEV_PROPERTY1, propertyEntry1.first)
                            assertEquals(envReader.getProperty(DEV_PROPERTY1), propertyEntry1.second)

                            assertEquals(DEV_PROPERTY2, propertyEntry2.first)
                            assertEquals(envReader.getProperty(DEV_PROPERTY2), propertyEntry2.second)
                        }
                        EnvPropertyReader.Environment.STG -> {
                            assertEquals(STG_PROPERTY1, propertyEntry1.first)
                            assertEquals(envReader.getProperty(STG_PROPERTY1), propertyEntry1.second)

                            assertEquals(STG_PROPERTY2, propertyEntry2.first)
                            assertEquals(envReader.getProperty(STG_PROPERTY2), propertyEntry2.second)
                        }
                        EnvPropertyReader.Environment.PRO -> {
                            assertEquals(PRO_PROPERTY1, propertyEntry1.first)
                            assertEquals(envReader.getProperty(PRO_PROPERTY1), propertyEntry1.second)

                            assertEquals(PRO_PROPERTY2, propertyEntry2.first)
                            assertEquals(envReader.getProperty(PRO_PROPERTY2), propertyEntry2.second)
                        }
                    }
                }
            }
        }
    }

    companion object {
        private const val TEST_ENV_FILE_NAME = "test_env.json"

        private const val DEV_PROPERTY1 = "DEV_PROPERTY1"
        private const val DEV_PROPERTY2 = "DEV_PROPERTY2"

        private const val STG_PROPERTY1 = "STG_PROPERTY1"
        private const val STG_PROPERTY2 = "STG_PROPERTY2"

        private const val PRO_PROPERTY1 = "PRO_PROPERTY1"
        private const val PRO_PROPERTY2 = "PRO_PROPERTY2"
    }
}
