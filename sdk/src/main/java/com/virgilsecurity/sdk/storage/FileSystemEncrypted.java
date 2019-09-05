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

package com.virgilsecurity.sdk.storage;

import com.virgilsecurity.common.model.Data;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.io.*;
import java.nio.file.InvalidPathException;
import java.util.HashSet;
import java.util.Set;

/**
 * FileSystemEncrypted class. Intended for storing data as plain files. Optionally can encrypt stored files.
 */
public class FileSystemEncrypted {

    private static final int CHUNK_SIZE = 4096;

    private String rootPath;
    private FileSystemEncryptedCredentials credentials;

    /**
     * Instantiates FileSystemEncrypted class.
     *
     * @param rootPath    Root path for storing files.
     * @param credentials If {@code credentials} is not {@code null} - {@code FileSystemEncrypted} will encrypt files
     *                    with provided credentials. Otherwise if {@code credentials} is {@code null} files are stored
     *                    without encryption.
     */
    public FileSystemEncrypted(String rootPath, FileSystemEncryptedCredentials credentials) {
        if (rootPath == null) {
            throw new NullArgumentException("rootPath");
        }

        this.rootPath = rootPath;
        this.credentials = credentials;

        initFileSystem();
    }

    /**
     * Instantiates FileSystemEncrypted class.
     *
     * @param rootPath Root path for storing files.
     */
    public FileSystemEncrypted(String rootPath) {
        this.rootPath = rootPath;

        initFileSystem();
    }

    private void initFileSystem() {
        File dir = new File(this.rootPath);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new InvalidPathException(this.rootPath, "Is not a directory");
            }
        } else {
            boolean created = dir.mkdirs();

            if (!created) {
                throw new IllegalStateException("Cannot create directory: \'" + rootPath + "\'");
            }
        }
    }

    /**
     * Write data.
     *
     * @param data   Data to write.
     * @param name   File name.
     * @param subdir Subdirectory.
     */
    public void write(Data data, String name, String subdir) throws IOException, CryptoException {
        File file;
        if (subdir != null) {
            File subdirectory = new File(this.rootPath + File.separator + subdir);
            if (subdirectory.exists() && subdirectory.isDirectory()) {
                file = new File(this.rootPath + File.separator + subdir, name);
            } else {
                boolean created = subdirectory.mkdirs();
                if (!created) {
                    throw new IllegalStateException("Cannot create directory: \'" + subdir + "\'");
                }

                file = new File(this.rootPath + File.separator + subdir, name);
            }
        } else {
            file = new File(this.rootPath, name);
        }

        byte[] dataToWrite;

        if (credentials != null) {
            dataToWrite = credentials.getCrypto().signThenEncrypt(data.getData(),
                    credentials.getKeyPair().getPrivateKey(), credentials.getKeyPair().getPublicKey());
        } else {
            dataToWrite = data.getData();
        }

        try (FileOutputStream os = new FileOutputStream(file)) {
            os.write(dataToWrite);
        }
    }

    /**
     * Write data. Will overwrite existing data, to avoid this please, use {@link #exists(String)} method first.
     *
     * @param data Data to write.
     * @param name File name.
     */
    public void write(Data data, String name) throws IOException, CryptoException {
        write(data, name, null);
    }

    /**
     * @param name   File name.
     * @param subdir Subdirectory.
     * @return Data.
     */
    public Data read(String name, String subdir) throws IOException, CryptoException {
        if (name == null) {
            throw new NullArgumentException("name");
        }

        File file;
        if (subdir != null) {
            file = new File(this.rootPath + File.separator + subdir, name);
        } else {
            file = new File(this.rootPath, name);
        }

        try (FileInputStream is = new FileInputStream(file);
             ByteArrayOutputStream os = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[CHUNK_SIZE];
            int n;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            byte[] data = os.toByteArray();
            byte[] dataResult;

            if (credentials != null) {
                dataResult = credentials.getCrypto().decryptThenVerify(data,
                        credentials.getKeyPair().getPrivateKey(), credentials.getKeyPair().getPublicKey());
            } else {
                dataResult = data;
            }

            return new Data(dataResult);
        }
    }

    /**
     * Read data.
     *
     * @param name File name.
     * @return Data. // TODO add throws to descriptions
     */
    public Data read(String name) throws IOException, CryptoException {
        return read(name, null);
    }

    /**
     * Returns file names in subdirectory.
     *
     * @param subdir Subdirectory.
     * @return File names in subdirectory.
     */
    public Set<String> listFileNames(String subdir) {
        File directory;
        if (subdir != null) {
            directory = new File(this.rootPath + File.separator + subdir);
        } else {
            directory = new File(this.rootPath);
        }

        Set<String> fileNames;
        if (!directory.exists()) {
            throw new InvalidPathException(directory.getPath(), "Directory: \'" + subdir + "\' doesn\'t exist.");
        }
        if (!directory.isDirectory()) {
            throw new InvalidPathException(directory.getPath(), "Isn\'t a directory: \'" + subdir + "\'");
        }

        fileNames = new HashSet<>();
        //noinspection ConstantConditions
        for (File file : directory.listFiles()) {
            fileNames.add(file.getName());
        }


        return fileNames;
    }

    /**
     * Returns file names in root directory.
     *
     * @return File names.
     */
    public Set<String> listFileNames() {
        return listFileNames(null);
    }

    /**
     * Delete data file.
     *
     * @param name   File name.
     * @param subdir Subdirectory.
     */
    public boolean delete(String name, String subdir) {
        if (name == null) {
            throw new NullArgumentException("name");
        }

        File file;
        if (subdir != null) {
            file = new File(this.rootPath + File.separator + subdir, name);
        } else {
            file = new File(this.rootPath, name);
        }

        return file.delete();
    }

    /**
     * Delete data file.
     *
     * @param name File name.
     */
    public boolean delete(String name) {
        return delete(name, null);
    }

    /**
     * Delete subdirectory.
     *
     * @param subdir Subdirectory.
     */
    public boolean deleteSubdir(String subdir) {
        File directory;
        if (subdir != null) {
            directory = new File(this.rootPath + File.separator + subdir);
        } else {
            directory = new File(this.rootPath);
        }

        return deleteDirectoryRecursively(directory);
    }

    /**
     * Delete all in root directory.
     */
    public boolean delete() {
        return deleteSubdir(null);
    } // TODO add tests

    /**
     * Checks whether file exists.
     *
     * @param name   Name of file.
     * @param subdir Subdirectory.
     * @return {@code true} if file exists, otherwise {@code false}.
     */
    public boolean exists(String name, String subdir) throws IOException {
        if (name == null) {
            throw new NullArgumentException("name");
        }

        File file;
        if (subdir != null) {
            file = new File(this.rootPath + File.separator + subdir, name);
        } else {
            file = new File(this.rootPath, name);
        }

        if (file.isDirectory()) {
            throw new IOException("Specified file is a directory. Please, use \'existsSubdir\' method instead.");
        }
        return file.exists();
    }

    /**
     * Checks whether file exists.
     *
     * @param name Name of file.
     * @return {@code true} if file exists, otherwise {@code false}.
     */
    public boolean exists(String name) throws IOException {
        return exists(name, null);
    }

    /**
     * Checks whether subdirectory exists.
     *
     * @param subdir Name of subdirectory.
     * @return {@code true} if subdirectory exists, otherwise {@code false}.
     */
    public boolean existsSubdir(String subdir) throws IOException {
        if (subdir == null) {
            throw new NullArgumentException("subdir");
        }

        File file = new File(this.rootPath, subdir);
        if (!file.isDirectory()) {
            throw new IOException("Specified directory is a file. Please, use \'exists\' method instead.");
        }
        return file.exists();
    }

    private boolean deleteDirectoryRecursively(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectoryRecursively(file);
            }
        }
        return directoryToBeDeleted.delete();
    }
}
