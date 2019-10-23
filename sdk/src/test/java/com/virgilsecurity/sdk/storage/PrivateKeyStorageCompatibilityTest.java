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

import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.utils.TestUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link PrivateKeyStorage} which verify cross-platform compatibility.
 *
 * @author Andrii Iakovenko
 */
public class PrivateKeyStorageCompatibilityTest {

  private VirgilCrypto crypto;
  private String keyName;
  private PrivateKeyStorage privateKeyStorage;

  @BeforeEach
  public void setUp() {
    this.crypto = new VirgilCrypto();
    this.keyName = UUID.randomUUID().toString();

    VirgilPrivateKeyExporter keyExporter = new VirgilPrivateKeyExporter(this.crypto);
    KeyStorage keyStorage = new JsonFileKeyStorage(
        System.getProperty("java.io.tmpdir") + File.separator + this.keyName);
    privateKeyStorage = new PrivateKeyStorage(keyExporter, keyStorage);
  }

  @Test
  public void stc_7() throws CryptoException {
    // STC_7
    // Generate PrivateKey
    VirgilPrivateKey privateKey = this.crypto.generateKeyPair().getPrivateKey();

    // Store PrivateKey
    this.privateKeyStorage.store(privateKey, this.keyName, null);

    // Load PrivateKey
    Tuple<VirgilPrivateKey, Map<String, String>> privateKeyInfo = this.privateKeyStorage
        .load(this.keyName);
    assertNotNull(privateKeyInfo);

    // Loaded PrivateKey is exactly the same as instantiated
    VirgilPrivateKey loadedVirgilPrivateKey = privateKeyInfo.getLeft();
    assertArrayEquals(privateKey.getIdentifier(), loadedVirgilPrivateKey.getIdentifier());
    assertArrayEquals(TestUtils.exportPrivateKey(privateKey.getPrivateKey()),
        TestUtils.exportPrivateKey(loadedVirgilPrivateKey.getPrivateKey()));
    assertTrue(privateKeyInfo.getRight().isEmpty());

    // Delete PrivateKey
    this.privateKeyStorage.delete(this.keyName);

    // Load PrivateKey
    try {
      this.privateKeyStorage.load(this.keyName);
      fail("Private key is removed");
    } catch (KeyEntryNotFoundException e) {
      // PrivateKey is absent
    }
  }

}
