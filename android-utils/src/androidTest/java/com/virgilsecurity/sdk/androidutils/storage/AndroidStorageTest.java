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

package com.virgilsecurity.sdk.androidutils.storage;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public class AndroidStorageTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private KeyStorage storage;
    private KeyEntry entry;
    private File tmpDir;
    private String keyAlias;
    private String keyStoreAlias;

    @Before
    public void setUp() throws CryptoException {
        VirgilCrypto crypto = new VirgilCrypto();

        tmpDir = new File(InstrumentationRegistry.getContext().getFilesDir().getAbsolutePath()
                + File.separator + UUID.randomUUID().toString());
        keyStoreAlias = UUID.randomUUID().toString();
        storage = new AndroidKeyStorage.Builder(keyStoreAlias).isAuthenticationRequired(false)
                .onPath(tmpDir.getAbsolutePath()).build();

        VirgilKeyPair keyPair = crypto.generateKeyPair();

        keyAlias = UUID.randomUUID().toString();

        entry = new AndroidKeyEntry();
        entry.setName(keyAlias);
        entry.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));
        entry.getMeta().put(UUID.randomUUID().toString(), UUID.randomUUID().toString());
    }

    @Test
    public void delete() {
        storage.store(entry);
        storage.delete(keyAlias);

        assertFalse(storage.exists(keyAlias));
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nonExisting() {
        storage.delete(keyAlias);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void delete_nullName() {
        storage.delete(null);
    }

    @Test
    public void exists() throws IOException {
        File storageFile = new File(tmpDir.getAbsolutePath(),
                File.separator + "VirgilSecurity" + File.separator + "Keys" + File.separator + keyStoreAlias);

        if (!storageFile.exists()) {
            boolean isCreated = storageFile.mkdirs();

            if (!isCreated) {
                fail("Cannot create directory");
            }
        }

        File tmpFile = File.createTempFile(keyAlias, "", storageFile);
        String name = tmpFile.getName();

        assertTrue(storage.exists(name));
    }

    @Test
    public void exists_nullAlias() {
        assertFalse(storage.exists(null));
    }

    @Test
    public void exists_randomName() {
        assertFalse(storage.exists(UUID.randomUUID().toString()));
    }

    @Test
    public void load() {
        storage.store(entry);

        KeyEntry loadedEntry = storage.load(keyAlias);

        assertTrue(loadedEntry instanceof AndroidKeyEntry);
        assertEquals(entry.getName(), loadedEntry.getName());
        assertArrayEquals(entry.getValue(), loadedEntry.getValue());
        assertEquals(entry.getMeta(), loadedEntry.getMeta());
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nonExisting() {
        storage.load(keyAlias);
    }

    @Test(expected = KeyEntryNotFoundException.class)
    public void load_nullName() {
        storage.load(keyAlias);
    }

    @Test
    public void names() {
        storage.store(entry);
        Set<String> names = storage.names();
        assertNotNull(names);
        assertEquals(1, names.size());
        assertEquals(entry.getName(), names.iterator().next());
    }

    @Test
    public void names_empty() {
        Set<String> names = storage.names();
        assertNotNull(names);
        assertTrue(names.isEmpty());
    }

    @Test
    public void store() {
        storage.store(entry);

        assertTrue(storage.exists(keyAlias));
    }

    @Test(expected = KeyEntryAlreadyExistsException.class)
    public void store_duplicated() {
        storage.store(entry);

        // Should fail
        storage.store(entry);
    }

    @Ignore("Hard to reproduce on emulator, run manually")
    @Test()
    public void validity_duration_expired() throws CryptoException, InterruptedException {
        String keyStorageAlias = UUID.randomUUID().toString();
        String path = new File(InstrumentationRegistry.getContext().getFilesDir().getAbsolutePath()
                + File.separator + UUID.randomUUID().toString()).getAbsolutePath();
        AndroidKeyStorage androidKeyStorage =
                new AndroidKeyStorage.Builder(keyStorageAlias).withKeyValidityDuration(20).onPath(path).build();

        // Generate entry
        VirgilCrypto crypto = new VirgilCrypto();
        VirgilKeyPair keyPair = crypto.generateKeyPair();
        String keyAliasOne = UUID.randomUUID().toString();

        AndroidKeyEntry keyEntry = new AndroidKeyEntry();
        keyEntry.setName(keyAliasOne);
        keyEntry.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));

        androidKeyStorage.store(keyEntry);
        KeyEntry keyEntryLoaded = androidKeyStorage.load(keyAliasOne);
        assertNotNull(keyEntryLoaded);

        Thread.sleep(20 * 1000); // 10 sec

        expectedException.expect(UserNotAuthenticatedException.class);
        androidKeyStorage.load(keyAliasOne);
    }

    @Test
    public void update_key() throws CryptoException {
        storage.store(entry);

        KeyEntry loadedEntry = storage.load(keyAlias);
        assertNotNull(loadedEntry);

        // Generate entry
        VirgilCrypto crypto = new VirgilCrypto();
        VirgilKeyPair keyPair = crypto.generateKeyPair();

        AndroidKeyEntry entryNew = new AndroidKeyEntry();
        entryNew.setName(entry.getName());
        entryNew.setValue(crypto.exportPrivateKey(keyPair.getPrivateKey()));

        storage.update(entryNew);
        KeyEntry loadedEntryNew = storage.load(entry.getName());
        assertNotNull(loadedEntryNew);
        assertTrue(loadedEntryNew instanceof AndroidKeyEntry);
        assertEquals(entryNew.getName(), loadedEntryNew.getName());
        assertArrayEquals(entryNew.getValue(), loadedEntryNew.getValue());
        assertEquals(entryNew.getMeta(), loadedEntryNew.getMeta());
    }
}
