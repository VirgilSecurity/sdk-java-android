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

package com.virgilsecurity.sdk.storage;

import com.virgilsecurity.common.model.Data;

import java.util.Set;

public interface FileSystem {

    /**
     * Delete all in root directory.
     */
    boolean delete();

    /**
     * Delete data file in root directory.
     *
     * @param filename File name.
     */
    boolean delete(String filename);

    /**
     * Delete data file.
     *
     * @param filename   File name.
     * @param path Path to a directory with a file.
     */
    boolean delete(String filename, String path);

    /**
     * Delete a directory by the path.
     *
     * @param path Path to a directory.
     */
    boolean deleteDirectory(String path);

    /**
     * Checks whether file exists in root directory.
     *
     * @param filename Name of file.
     * @return {@code true} if file exists, otherwise {@code false}.
     */
    boolean exists(String filename) throws Exception;

    /**
     * Checks whether subdirectory exists.
     *
     * @param path path to the directory.
     * @return {@code true} if subdirectory exists, otherwise {@code false}.
     */
    boolean directoryExists(String path) throws Exception;

    /**
     * Checks whether file exists.
     *
     * @param filename   Name of file.
     * @param path path to a directory.
     * @return {@code true} if file exists, otherwise {@code false}.
     */
    boolean exists(String filename, String path) throws Exception;

    /**
     * Returns file names in root directory.
     *
     * @return File names.
     */
    Set<String> listFiles();

    /**
     * Returns file names in directory.
     *
     * @param path path to a directory.
     * @return Names of files in a directory.
     */
    Set<String> listFiles(String path) throws Exception;

    /**
     * Read data from file stored in root directory.
     *
     * @param filename File name.
     * @return Data.
     */
    Data read(String filename) throws Exception;

    /**
     * Read data from a file which is stored in subdirectory.
     * @param filename   File name.
     * @param path Path to subdirectory.
     * @return Data.
     */
    Data read(String filename, String path) throws Exception;

    /**
     * Write data to file in root directory.
     * If file exists, it data will be replaced. To avoid this please, use {@link #exists(String)} method first.
     *
     * @param data Data to write.
     * @param filename File name.
     */
    void write(Data data, String filename) throws Exception;

    /**
     * Write data to a file system.
     *
     * @param data   Data to write.
     * @param filename   File name.
     * @param path Path to a directory with a file.
     */
    void write(Data data, String filename, String path) throws Exception;
}
