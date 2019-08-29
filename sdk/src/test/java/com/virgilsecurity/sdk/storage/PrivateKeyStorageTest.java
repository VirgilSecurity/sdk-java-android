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

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKeyExporter;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.utils.Tuple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.internal.util.collections.Sets;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@code VirgilKeyStorage}.
 *
 * @author Andrii Iakovenko
 * @see PrivateKeyStorage
 */
@ExtendWith(MockitoExtension.class)
public class PrivateKeyStorageTest {
  private VirgilCrypto crypto;
  private String keyName;
  private VirgilPrivateKey privateKey;

  @Mock
  private VirgilPrivateKeyExporter keyExporter;

  @Mock
  private KeyStorage keyStorage;
  private PrivateKeyStorage storage;

  @BeforeEach
  public void setUp() throws CryptoException {
    this.crypto = new VirgilCrypto();
    this.privateKey = this.crypto.generateKeyPair().getPrivateKey();
    this.keyName = UUID.randomUUID().toString();

    this.storage = new PrivateKeyStorage(keyExporter, keyStorage);
  }

  @Test
  public void delete() {
    storage.delete(this.keyName);

    ArgumentCaptor<String> keyNameCaptor = ArgumentCaptor.forClass(String.class);
    verify(this.keyStorage, times(1)).delete(keyNameCaptor.capture());

    assertEquals(this.keyName, keyNameCaptor.getValue());
  }

  @Test
  public void delete_nonExisting() {
    doThrow(KeyEntryNotFoundException.class).when(this.keyStorage).delete(this.keyName);

    assertThrows(KeyEntryNotFoundException.class, () -> {
      storage.delete(this.keyName);
    });
  }

  @Test
  public void delete_nullName() {
    doThrow(KeyEntryNotFoundException.class).when(this.keyStorage).delete(null);

    assertThrows(KeyEntryNotFoundException.class, () -> {
      storage.delete(null);
    });
  }

  @Test
  public void exists() throws IOException, CryptoException {
    when(this.keyStorage.exists(this.keyName)).thenReturn(true);

    assertTrue(storage.exists(this.keyName));
  }

  @Test
  public void exists_nullAlias() {
    when(this.keyStorage.exists(null)).thenReturn(false);

    assertFalse(storage.exists(null));
  }

  @Test
  public void exists_randomName() {
    when(this.keyStorage.exists(Mockito.anyString())).thenReturn(false);

    assertFalse(storage.exists(UUID.randomUUID().toString()));
  }

  @Test
  public void load() throws CryptoException {
    // Configure mocks
    byte[] privateKeyData = this.crypto.exportPrivateKey(privateKey);
    when(this.keyExporter.exportPrivateKey(privateKey)).thenReturn(privateKeyData);
    when(this.keyExporter.importPrivateKey(privateKeyData))
        .thenReturn(this.crypto.importPrivateKey(privateKeyData).getPrivateKey());

    Map<String, String> meta = new HashMap<>();
    meta.put("key1", "value1");
    meta.put("key2", "value2");
    KeyEntry entry = new JsonKeyEntry(this.keyName,
        this.keyExporter.exportPrivateKey(this.privateKey));
    entry.setMeta(meta);
    when(this.keyStorage.load(this.keyName)).thenReturn(entry);

    Tuple<VirgilPrivateKey, Map<String, String>> keyData = storage.load(this.keyName);
    assertNotNull(keyData);

    VirgilPrivateKey key = keyData.getLeft();
    assertNotNull(key);
    assertEquals(this.privateKey, key);

    assertEquals(meta, keyData.getRight());
  }

  @Test
  public void load_noMeta() throws CryptoException {
    // Configure mocks
    byte[] privateKeyData = this.crypto.exportPrivateKey(privateKey);
    when(this.keyExporter.exportPrivateKey(privateKey)).thenReturn(privateKeyData);
    when(this.keyExporter.importPrivateKey(privateKeyData))
        .thenReturn(this.crypto.importPrivateKey(privateKeyData).getPrivateKey());

    KeyEntry entry = new JsonKeyEntry(this.keyName,
        this.keyExporter.exportPrivateKey(this.privateKey));
    when(this.keyStorage.load(this.keyName)).thenReturn(entry);

    Tuple<VirgilPrivateKey, Map<String, String>> keyData = storage.load(this.keyName);
    assertNotNull(keyData);

    VirgilPrivateKey key = keyData.getLeft();
    assertNotNull(key);
    assertEquals(this.privateKey, key);

    assertTrue(keyData.getRight().isEmpty());
  }

  @Test
  public void load_nonExisting() {
    when(this.keyStorage.load(this.keyName)).thenThrow(KeyEntryNotFoundException.class);
    assertThrows(KeyEntryNotFoundException.class, () -> {
      storage.load(this.keyName);
    });
  }

  @Test
  public void load_nullName() {
    when(this.keyStorage.load(null)).thenThrow(KeyEntryNotFoundException.class);
    assertThrows(KeyEntryNotFoundException.class, () -> {
      storage.load(null);
    });
  }

  @Test
  public void names() {
    when(this.keyStorage.names()).thenReturn(Sets.newSet("key1"));

    Set<String> names = storage.names();
    assertNotNull(names);
    assertEquals(1, names.size());
    assertEquals("key1", names.iterator().next());
  }

  @SuppressWarnings("unchecked")
  @Test
  public void names_empty() {
    when(this.keyStorage.names()).thenReturn(Collections.EMPTY_SET);

    Set<String> names = storage.names();
    assertNotNull(names);
    assertTrue(names.isEmpty());
  }

  @Test
  public void store() throws CryptoException {
    // Configure mocks
    byte[] privateKeyData = this.crypto.exportPrivateKey((VirgilPrivateKey) privateKey);
    when(this.keyExporter.exportPrivateKey(privateKey)).thenReturn(privateKeyData);

    Map<String, String> meta = new HashMap<>();
    meta.put("key1", "value1");
    meta.put("key2", "value2");
    storage.store(this.privateKey, this.keyName, meta);

    verify(this.keyExporter, times(1)).exportPrivateKey(privateKey);

    ArgumentCaptor<KeyEntry> keyEntryCaptor = ArgumentCaptor.forClass(KeyEntry.class);
    verify(this.keyStorage, times(1)).store(keyEntryCaptor.capture());

    KeyEntry keyEntry = keyEntryCaptor.getValue();
    assertNotNull(keyEntry);
    assertEquals(this.keyName, keyEntry.getName());
    assertArrayEquals(crypto.exportPrivateKey((VirgilPrivateKey) this.privateKey),
        keyEntry.getValue());
    assertNotNull(keyEntry.getMeta());
    assertEquals(meta, keyEntry.getMeta());
  }

  @SuppressWarnings("unchecked")
  @Test
  public void store_noMeta() throws CryptoException {
    // Configure mocks
    byte[] privateKeyData = this.crypto.exportPrivateKey((VirgilPrivateKey) privateKey);
    when(this.keyExporter.exportPrivateKey(privateKey)).thenReturn(privateKeyData);

    storage.store(this.privateKey, this.keyName, Collections.EMPTY_MAP);

    verify(this.keyExporter, times(1)).exportPrivateKey(privateKey);

    ArgumentCaptor<KeyEntry> keyEntryCaptor = ArgumentCaptor.forClass(KeyEntry.class);
    verify(this.keyStorage, times(1)).store(keyEntryCaptor.capture());

    KeyEntry keyEntry = keyEntryCaptor.getValue();
    assertNotNull(keyEntry);
    assertEquals(this.keyName, keyEntry.getName());
    assertArrayEquals(crypto.exportPrivateKey((VirgilPrivateKey) this.privateKey),
        keyEntry.getValue());
    assertNotNull(keyEntry.getMeta());
    assertTrue(keyEntry.getMeta().isEmpty());
  }

}
