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

import com.virgilsecurity.common.exception.NullArgumentException;
import com.virgilsecurity.common.model.Data;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.storage.exceptions.*;

import java.io.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * FileSystemEncrypted class. Intended for storing data as plain files. Optionally can encrypt stored files.
 */
public class FileSystemEncrypted implements FileSystem {

    private static final Logger LOGGER = Logger.getLogger(FileSystemEncrypted.class.getName());
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
     *
     * @throws FileSystemException
     */
    public FileSystemEncrypted(String rootPath, FileSystemEncryptedCredentials credentials) throws FileSystemException {
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
     *
     * @throws FileSystemException
     */
    public FileSystemEncrypted(String rootPath) throws FileSystemException {
        this(rootPath, null);
    }

    private void initFileSystem() throws FileSystemException {
        File dir = new File(this.rootPath);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new NotADirectoryException(this.rootPath + " is not a directory");
            }
        } else {
            boolean created = dir.mkdirs();

            if (!created) {
                throw new CreateDirectoryException("Cannot create directory: \'" + rootPath + "\'");
            }
        }
    }

    /**
     * Write data.
     *
     * @param data   Data to write.
     * @param filename   File name.
     * @param path Subdirectory.
     *
     * @throws IOException
     * @throws CryptoException
     */
    public void write(Data data, String filename, String path) throws IOException, CryptoException {
        File file;
        if (path != null) {
            File subdirectory = new File(this.rootPath + File.separator + path);
            if (subdirectory.exists() && subdirectory.isDirectory()) {
                file = new File(this.rootPath + File.separator + path, filename);
            } else {
                boolean created = subdirectory.mkdirs();
                if (!created) {
                    throw new CreateDirectoryException("Cannot create directory: \'" + path + "\'");
                }

                file = new File(this.rootPath + File.separator + path, filename);
            }
        } else {
            file = new File(this.rootPath, filename);
        }

        byte[] dataToWrite;

        if (credentials != null) {
            dataToWrite = credentials.getCrypto().authEncrypt(data.getValue(),
                    credentials.getKeyPair().getPrivateKey(), credentials.getKeyPair().getPublicKey());
        } else {
            dataToWrite = data.getValue();
        }

        try (FileOutputStream os = new FileOutputStream(file)) {
            os.write(dataToWrite);
        }
    }

    /**
     * Write data. Will overwrite existing data, to avoid this please, use {@link #exists(String)} method first.
     *
     * @param data Data to write.
     * @param filename File name.
     *
     * @throws IOException
     * @throws CryptoException
     */
    public void write(Data data, String filename) throws IOException, CryptoException {
        write(data, filename, null);
    }

    /**
     * @param filename   File name.
     * @param path Subdirectory.
     *
     * @return Data.
     *
     * @throws IOException
     * @throws CryptoException
     */
    public Data read(String filename, String path) throws IOException, CryptoException {
        if (filename == null) {
            throw new NullArgumentException("filename");
        }

        File file;
        if (path != null) {
            file = new File(this.rootPath + File.separator + path, filename);
        } else {
            file = new File(this.rootPath, filename);
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
                dataResult = credentials.getCrypto().authDecrypt(data, credentials.getKeyPair().getPrivateKey(),
                        credentials.getKeyPair().getPublicKey(), true);
            } else {
                dataResult = data;
            }

            return new Data(dataResult);
        }
    }

    /**
     * Read data.
     *
     * @param filename File name.
     *
     * @return Data.
     *
     * @throws IOException
     * @throws CryptoException
     */
    public Data read(String filename) throws IOException, CryptoException {
        return read(filename, null);
    }

    /**
     * Returns file names in subdirectory.
     *
     * @param path Subdirectory.
     *
     * @return File names in subdirectory.
     *
     * @throws DirectoryNotExistsException
     * @throws NotADirectoryException
     */
    public Set<String> listFiles(String path) throws DirectoryNotExistsException, NotADirectoryException {
        File directory;
        if (path != null) {
            directory = new File(this.rootPath + File.separator + path);
        } else {
            directory = new File(this.rootPath);
        }

        Set<String> fileNames;
        if (!directory.exists()) {
            throw new DirectoryNotExistsException("Directory: \'" + path + "\' doesn\'t exist.");
        }
        if (!directory.isDirectory()) {
            throw new NotADirectoryException(path + " is not a directory:");
        }

        fileNames = new HashSet<>();
        //noinspection ConstantConditions
        for (File file : directory.listFiles()) {
            if (file.isFile()) {
                fileNames.add(file.getName());
            }
        }


        return fileNames;
    }

    /**
     * Returns file names in root directory.
     *
     * @return File names.
     */
    public Set<String> listFiles() {
        try {
            return listFiles(null);
        }
        catch (FileSystemException e) {
            // This should never happen.
            LOGGER.log(Level.SEVERE, "Can't list file in the root directory", e);
        }
        return Collections.emptySet();
    }

    /**
     * Delete data file.
     *
     * @param filename   File name.
     * @param path Path to a directory with a file.
     */
    public boolean delete(String filename, String path) {
        if (filename == null) {
            throw new NullArgumentException("filename");
        }

        File file;
        if (path != null) {
            file = new File(this.rootPath + File.separator + path, filename);
        } else {
            file = new File(this.rootPath, filename);
        }

        return file.delete();
    }

    /**
     * Delete data file.
     *
     * @param filename File name.
     */
    public boolean delete(String filename) {
        return delete(filename, null);
    }

    /**
     * Delete subdirectory.
     *
     * @param path Subdirectory.
     */
    public boolean deleteDirectory(String path) {
        File directory;
        if (path != null) {
            directory = new File(this.rootPath + File.separator + path);
        } else {
            directory = new File(this.rootPath);
        }

        return deleteDirectoryRecursively(directory);
    }

    /**
     * Delete all in root directory.
     */
    public boolean delete() {
        return deleteDirectory(null);
    } // TODO add tests

    /**
     * Checks whether file exists.
     *
     * @param filename   Name of file.
     * @param path Subdirectory.
     *
     * @return {@code true} if file exists, otherwise {@code false}.
     *
     * @throws NotAFileException
     */
    public boolean exists(String filename, String path) throws NotAFileException {
        if (filename == null) {
            throw new NullArgumentException("filename");
        }

        File file;
        if (path != null) {
            file = new File(this.rootPath + File.separator + path, filename);
        } else {
            file = new File(this.rootPath, filename);
        }

        if (!file.exists()) {
            return false;
        }

        if (file.isDirectory()) {
            throw new NotAFileException("Specified file is a directory. Please, use \'directoryExists\' method instead.");
        }
        return true;
    }

    /**
     * Checks whether file exists.
     *
     * @param filename Name of file.
     *
     * @return {@code true} if file exists, otherwise {@code false}.
     *
     * @throws NotAFileException
     */
    public boolean exists(String filename) throws NotAFileException {
        return exists(filename, null);
    }

    /**
     * Checks whether subdirectory exists.
     *
     * @param path Name of subdirectory.
     *
     * @return {@code true} if subdirectory exists, otherwise {@code false}.
     *
     * @throws NotADirectoryException
     */
    public boolean directoryExists(String path) throws NotADirectoryException {
        if (path == null) {
            throw new NullArgumentException("path");
        }

        File file = new File(this.rootPath, path);
        if (!file.exists()) {
            return false;
        }

        if (!file.isDirectory()) {
            throw new NotADirectoryException("Specified directory is a file. Please, use \'exists\' method instead.");
        }
        return true;
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
