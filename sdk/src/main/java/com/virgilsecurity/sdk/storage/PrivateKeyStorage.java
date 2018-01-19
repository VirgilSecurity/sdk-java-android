/*
 * Copyright (c) 2016, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.nio.file.InvalidPathException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;

/**
 * VIRGIL implementation of a storage facility for cryptographic keys.
 *
 * @author Andrii Iakovenko
 *
 */
public class PrivateKeyStorage implements KeyStorage {

    private String directoryName;
    private String fileName;

    /**
     * Create a new instance of {@code VirgilKeyStorage}
     *
     */
    public PrivateKeyStorage() {
        StringBuilder path = new StringBuilder(System.getProperty("user.home"));
        path.append(File.separator).append("VirgilSecurity");
        path.append(File.separator).append("KeyStore");

        this.directoryName = path.toString();
        this.fileName = "virgil.keystore";

        init();
    }

    /**
     * Create a new instance of {@code VirgilKeyStorage}
     *
     */
    public PrivateKeyStorage(String directoryName, String fileName) {
        this.directoryName = directoryName;
        this.fileName = fileName;

        init();
    }

    private void init() {
        File dir = new File(this.directoryName);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new InvalidPathException(this.directoryName, "Is not a directory");
            }
        } else {
            dir.mkdirs();
        }
        File file = new File(dir, this.fileName);
        if (!file.exists()) {
            save(new Entries());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#store(com.virgilsecurity.sdk. crypto.KeyEntry)
     */
    @Override
    public void store(KeyEntry keyEntry) {
        String name = keyEntry.getName();

        synchronized (this) {
            Entries entries = load();
            if (entries.containsKey(name)) {
                throw new KeyEntryAlreadyExistsException();
            }
            entries.put(name, (VirgilKeyEntry) keyEntry);
            save(entries);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#load(java.lang.String)
     */
    @Override
    public KeyEntry load(String keyName) {
        synchronized (this) {
            Entries entries = load();
            if (!entries.containsKey(keyName)) {
                throw new KeyEntryNotFoundException();
            }
            VirgilKeyEntry entry = entries.get(keyName);
            entry.setName(keyName);
            return entry;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#exists(java.lang.String)
     */
    @Override
    public boolean exists(String keyName) {
        if (keyName == null) {
            return false;
        }
        synchronized (this) {
            Entries entries = load();
            return entries.containsKey(keyName);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.KeyStore#delete(java.lang.String)
     */
    @Override
    public void delete(String keyName) {
        synchronized (this) {
            Entries entries = load();
            if (!entries.containsKey(keyName)) {
                throw new KeyEntryNotFoundException();
            }
            entries.remove(keyName);
            save(entries);
        }
    }

    private Entries load() {
        File file = new File(this.directoryName, this.fileName);
        try (FileInputStream is = new FileInputStream(file)) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            byte[] bytes = os.toByteArray();

            Entries entries = getGson().fromJson(new String(bytes, Charset.forName("UTF-8")), Entries.class);

            return entries;
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    /**
     * @param entries
     */
    private void save(Entries entries) {
        File file = new File(this.directoryName, this.fileName);
        try (FileOutputStream os = new FileOutputStream(file)) {
            String json = getGson().toJson(entries);
            os.write(json.getBytes(Charset.forName("UTF-8")));
        } catch (Exception e) {
            throw new KeyStorageException(e);
        }
    }

    private Gson getGson() {
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();

        return gson;
    }

    private static class Entries extends HashMap<String, VirgilKeyEntry> {
        private static final long serialVersionUID = 261773342073013945L;

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.storage.KeyStorage#names()
     */
    @Override
    public List<String> names() {
        Entries entries = load();
        if (entries.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> names = new ArrayList<>(entries.keySet());
        return names;
    }

}
