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

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.testcommon.utils.Constants
import com.virgilsecurity.testcommon.utils.PropertyUtils
import java.io.File

/**
 * EnvPropertyReader reads properties from JSON file that has format:
 * {
 *   "dev": {
 *     "key1":"value1",
 *     "key2":"value2",
 *   },
 *
 *   "stg": {
 *     // ...
 *   },
 *
 *   "pro": {
 *     // ...
 *   }
 * }
 */
class EnvPropertyReader private constructor(environment: Environment, filePath: String?, fileName: String) {

    private val properties: Map<String, String>

    init {
        val fileContent = File(filePath, fileName).readText()

        val envJson = JsonParser().parse(fileContent)
        val selectedEnvironment = (envJson as JsonObject).get(environment.type)
        val propertyEntriesSet = (selectedEnvironment as JsonObject).entrySet()

        val propertiesMap = mutableMapOf<String, String>()
        for (entry in propertyEntriesSet) {
            propertiesMap[entry.key] = entry.value.asString
        }

        this.properties = propertiesMap
    }

    class Builder {

        private var environment: Environment = Environment.PRO
        private var filePath: String? = null
        private var fileName: String = ENV_FILE_NAME
        private var isSubmodule: Boolean = false

        /**
         * Set custom [environment] which will be read from file with credentials. Default [environment] is
         * [Environment.PRO].
         */
        fun environment(environment: Environment) = apply { this.environment = environment }

        /**
         * Set custom [filePath] of file with credentials. Default [filePath] is taken from
         * PropertyUtils.getSystemProperty("user.dir") result.
         */
        fun filePath(filePath: String) = apply { this.filePath = filePath }

        /**
         * Set custom [fileName] of file with credentials. Default file name is [ENV_FILE_NAME].
         */
        fun fileName(fileName: String) = apply { this.fileName = fileName }

        /**
         * If set to *true* - *user.dir*'s parent folder will be used as filePath. Overrides filePath if provided.
         *
         * This flag's intention is to get file with credentials for current sub-module from the root folder of project
         * that, has default structure as:
         *
         * parent
         * |
         * |-- submodule1
         * |
         * |-- submodule2
         *
         */
        fun isDefaultSubmodule(isSubmodule: Boolean) = apply { this.isSubmodule = isSubmodule }

        /**
         * Build [EnvPropertyReader] instance with specified properties.
         */
        fun build(): EnvPropertyReader {
            val path = filePath ?: if (isSubmodule) {
                File(System.getProperty(Constants.USER_DIR)).parent
            } else {
                PropertyUtils.getSystemProperty(Constants.USER_DIR) ?: error("user.dir is a mandatory property")
            }

            return EnvPropertyReader(environment, path, fileName)
        }
    }

    /**
     * Gets property from specified in a constructor environment. If no property has been found [IllegalStateException]
     * will be thrown.
     */
    fun getProperty(name: String) = properties[name] ?: error("No property with name: \'$name\' provided.")

    companion object {
        private const val ENV_FILE_NAME = "env.json"
    }

    /**
     * Available environments. Please, see JSON file structure in the [EnvPropertyReader] description.
     */
    enum class Environment(val type: String) {
        DEV("dev"),
        STG("stg"),
        PRO("pro");

        override fun toString(): String {
            return DEV.type + ", " + STG.type + ", " + PRO.type
        }

        companion object {

            /**
             * Converts provided [type] to an instance of [Environment]. Please, check [Environment.values] to get
             * available values. If wrong value has been provided [IllegalArgumentException] will be thrown.
             */
            @JvmStatic
            fun fromType(type: String): Environment {
                return when (type) {
                    DEV.type -> DEV
                    STG.type -> STG
                    PRO.type -> PRO
                    else -> throw IllegalArgumentException("Environment can only be: ${toString()}")
                }
            }
        }
    }
}
