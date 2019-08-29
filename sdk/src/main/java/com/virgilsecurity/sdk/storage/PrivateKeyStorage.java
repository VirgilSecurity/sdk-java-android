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

import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKeyExporter;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.Tuple;

import java.security.PrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Virgil implementation of a storage facility for cryptographic keys.
 *
 * @author Andrii Iakovenko
 */
public class PrivateKeyStorage {

  private class PrivateKeyEntry implements KeyEntry {

    private String name;
    private byte[] value;
    private Map<String, String> meta;
    private Date createdAt;
    private Date modifiedAt;

    /**
     * Create new instance of {@link PrivateKeyEntry}.
     *
     * @param name  The entry name.
     * @param value The entry value.
     */
    public PrivateKeyEntry(String name, byte[] value) {
      super();
      this.name = name;
      this.value = value;

      this.meta = new HashMap<>();
    }

    /**
     * Get the entry metadata.
     *
     * @return The metadata.
     */
    public Map<String, String> getMeta() {
      return meta;
    }

    /**
     * Get the entry name.
     *
     * @return The name.
     */
    public String getName() {
      return name;
    }

    /**
     * Get the entry value.
     *
     * @return The value.
     */
    public byte[] getValue() {
      return value;
    }

    /**
     * Set the entry metadata.
     *
     * @param meta The meta to set.
     */
    public void setMeta(Map<String, String> meta) {
      this.meta = meta;
    }

    /**
     * Set the entry name.
     *
     * @param name The name to set.
     */
    public void setName(String name) {
      this.name = name;
    }

    /**
     * Set the entry value.
     *
     * @param value The value to set.
     */
    public void setValue(byte[] value) {
      this.value = value;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#getCreatedAt()
     */
    public Date getCreatedAt() {
      return createdAt;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#setCreatedAt(java.util.Date)
     */
    public void setCreatedAt(Date createdAt) {
      this.createdAt = createdAt;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#getModifiedAt()
     */
    public Date getModifiedAt() {
      return modifiedAt;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#setModifiedAt(java.util.Date)
     */
    public void setModifiedAt(Date modifiedAt) {
      this.modifiedAt = modifiedAt;
    }

  }

  private VirgilPrivateKeyExporter keyExporter;

  private KeyStorage keyStorage;

  /**
   * Create new instance of {@link PrivateKeyStorage}.
   *
   * @param keyExporter The {@link VirgilPrivateKeyExporter}.
   * @param keyStorage  The {@link KeyStorage}.
   */
  public PrivateKeyStorage(VirgilPrivateKeyExporter keyExporter, KeyStorage keyStorage) {
    super();
    if (keyExporter == null) {
      throw new NullArgumentException("keyExporter");
    }
    if (keyStorage == null) {
      throw new NullArgumentException("keyStorage");
    }
    this.keyExporter = keyExporter;
    this.keyStorage = keyStorage;
  }

  /**
   * Remove key from key storage.
   *
   * @param keyName The alias which identifies stored key.
   */
  public void delete(String keyName) {
    this.keyStorage.delete(keyName);
  }

  /**
   * Check if key stored in key store.
   *
   * @param keyName The alias which identifies stored key.
   *
   * @return {@code true} if key exists, {@code false} otherwise.
   */
  public boolean exists(String keyName) {
    return this.keyStorage.exists(keyName);
  }

  /**
   * Load private key from key storage.
   *
   * @param keyName The alias which identifies stored key.
   *
   * @return The pair of private key and key meta data.
   *
   * @throws CryptoException If private key couldn't be imported.
   */
  public Tuple<VirgilPrivateKey, Map<String, String>> load(String keyName) throws CryptoException {
    KeyEntry keyEntry = this.keyStorage.load(keyName);
    if (keyEntry != null) {
      VirgilPrivateKey privateKey = this.keyExporter.importPrivateKey(keyEntry.getValue());
      Tuple<VirgilPrivateKey, Map<String, String>> pair = new Tuple<>(
              privateKey, keyEntry.getMeta());
      return pair;
    }
    return null;
  }

  /**
   * List name of all keys stored in key storage.
   *
   * @return The keys names as a list.
   */
  public Set<String> names() {
    return this.keyStorage.names();
  }

  /**
   * Store private key in key storage.
   *
   * @param privateKey The private key to store.
   * @param name       The alias which identifies stored key.
   * @param meta       The key meta data.
   *
   * @throws CryptoException If private couldn't be exported.
   */
  public void store(VirgilPrivateKey privateKey, String name, Map<String, String> meta)
      throws CryptoException {
    byte[] exportedKeyData = this.keyExporter.exportPrivateKey(privateKey);

    KeyEntry keyEntry = new PrivateKeyEntry(name, exportedKeyData);
    if (meta != null && !meta.isEmpty()) {
      keyEntry.getMeta().putAll(meta);
    }
    this.keyStorage.store(keyEntry);
  }

}
