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
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link KeyStorage} which verify cross-platform compatibility.
 *
 * @author Andrii Iakovenko
 */
public class KeyStorageCompatibilityTest {

  private VirgilCrypto crypto;
  private String keyName;
  private KeyStorage keyStorage;

  @BeforeEach
  public void setUp() throws CryptoException {
    this.crypto = new VirgilCrypto();
    this.keyName = UUID.randomUUID().toString();

    this.keyStorage = new JsonFileKeyStorage(
        System.getProperty("java.io.tmpdir") + File.separator + this.keyName);
  }

  @Test
  public void stc_5() throws CryptoException {
    // STC_5
    // Generate some data and instantiate KeyEntry1
    VirgilPrivateKey privateKey1 = this.crypto.generateKeyPair().getPrivateKey();
    byte[] privateKeyData1 = this.crypto.exportPrivateKey(privateKey1);
    Map<String, String> meta1 = generateMeta();
    KeyEntry keyEntry1 = new JsonKeyEntry(this.keyName, privateKeyData1);
    keyEntry1.setMeta(meta1);

    // Store KeyEntry1
    this.keyStorage.store(keyEntry1);

    // Load KeyEntry1
    KeyEntry loadedKeyEntry1 = this.keyStorage.load(this.keyName);
    assertNotNull(loadedKeyEntry1);

    // Loaded KeyEntry1 is exactly the same as instantiated
    assertEquals(keyEntry1.getName(), loadedKeyEntry1.getName());
    assertArrayEquals(keyEntry1.getValue(), loadedKeyEntry1.getValue());
    assertEquals(keyEntry1.getMeta(), loadedKeyEntry1.getMeta());

    // Create KeyEntry2
    String keyName2 = UUID.randomUUID().toString();
    VirgilPrivateKey privateKey2 = this.crypto.generateKeyPair().getPrivateKey();
    byte[] privateKeyData2 = this.crypto.exportPrivateKey(privateKey2);
    Map<String, String> meta2 = generateMeta();
    KeyEntry keyEntry2 = new JsonKeyEntry(keyName2, privateKeyData2);
    keyEntry1.setMeta(meta2);

    // Store KeyEntry2
    this.keyStorage.store(keyEntry2);

    // Load KeyEntry2
    KeyEntry loadedKeyEntry2 = this.keyStorage.load(keyName2);
    assertNotNull(loadedKeyEntry2);

    // Loaded KeyEntry2 is exactly the same as instantiated
    assertEquals(keyEntry2.getName(), loadedKeyEntry2.getName());
    assertArrayEquals(keyEntry2.getValue(), loadedKeyEntry2.getValue());
    assertEquals(keyEntry2.getMeta(), loadedKeyEntry2.getMeta());

    // Delete KeyEntry1
    this.keyStorage.delete(this.keyName);

    // Load KeyEntry1
    try {
      this.keyStorage.load(this.keyName);
      fail("KeyEntry1 is deleted");
    } catch (KeyEntryNotFoundException e) {
      // KeyEntry1 is absent
    }

    // Load KeyEntry2
    loadedKeyEntry2 = this.keyStorage.load(keyName2);
    assertNotNull(loadedKeyEntry2);

    // Delete KeyEntry2
    this.keyStorage.delete(keyName2);

    // Load KeyEntry2
    try {
      this.keyStorage.load(keyName2);
      fail("KeyEntry2 is deleted");
    } catch (KeyEntryNotFoundException e) {
      // KeyEntry2 is absent
    }
  }

  @Test
  public void stc_6() throws CryptoException {
    // STC_6
    // Generate some data and instantiate KeyEntry1
    VirgilPrivateKey privateKey1 = this.crypto.generateKeyPair().getPrivateKey();
    byte[] privateKeyData1 = this.crypto.exportPrivateKey(privateKey1);
    Map<String, String> meta1 = generateMeta();
    KeyEntry keyEntry1 = new JsonKeyEntry(this.keyName, privateKeyData1);
    keyEntry1.setMeta(meta1);

    // Store KeyEntry1
    this.keyStorage.store(keyEntry1);

    // Create KeyEntry2 with the same name
    VirgilPrivateKey privateKey2 = this.crypto.generateKeyPair().getPrivateKey();
    byte[] privateKeyData2 = this.crypto.exportPrivateKey(privateKey2);
    Map<String, String> meta2 = generateMeta();
    KeyEntry keyEntry2 = new JsonKeyEntry(this.keyName, privateKeyData2);
    keyEntry1.setMeta(meta2);

    // Store KeyEntry2
    try {
      this.keyStorage.store(keyEntry2);
      fail("Duplicated key name");
    } catch (KeyEntryAlreadyExistsException e) {
      // It's OK if Error has occured
    }
  }

  private Map<String, String> generateMeta() {
    Map<String, String> meta = new HashMap<>();
    meta.put("key1", "value1");
    meta.put("key2", "value2");

    return meta;
  }

}
