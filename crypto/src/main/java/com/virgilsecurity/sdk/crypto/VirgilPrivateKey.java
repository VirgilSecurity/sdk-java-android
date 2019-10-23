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

package com.virgilsecurity.sdk.crypto;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * A private key.
 */
public class VirgilPrivateKey implements Serializable {

  private static final long serialVersionUID = 3949844179494530851L;

  /**
   * The Private key identifier.
   */
  private byte[] identifier;

  /**
   * The Private key raw date.
   */
  private com.virgilsecurity.crypto.foundation.PrivateKey privateKey;

  /**
   * The Private Key type.
   */
  private KeyType keyType;

  /**
   * Create a new instance of {@code VirgilPrivateKey}.
   */
  public VirgilPrivateKey() {
  }

  /**
   * Create a new instance of {@code VirgilPrivateKey}.
   *
   * @param identifier The key identifier.
   * @param privateKey Underlying private key.
   * @param keyType    The key type.
   */
  public VirgilPrivateKey(byte[] identifier,
                          com.virgilsecurity.crypto.foundation.PrivateKey privateKey,
                          KeyType keyType) {
    this.identifier = identifier;
    this.privateKey = privateKey;
    this.keyType = keyType;
  }

  /**
   * Get identifier byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] getIdentifier() {
    return identifier;
  }

  /**
   * Sets identifier.
   *
   * @param identifier the identifier.
   */
  public void setIdentifier(byte[] identifier) {
    this.identifier = identifier;
  }

  /**
   * Gets private key.
   *
   * @return the private key.
   */
  public com.virgilsecurity.crypto.foundation.PrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * Sets private key.
   *
   * @param privateKey the private key.
   */
  public void setPrivateKey(com.virgilsecurity.crypto.foundation.PrivateKey privateKey) {
    this.privateKey = privateKey;
  }

  /**
   * Gets key type.
   *
   * @return the key type.
   */
  public KeyType getKeyType() {
    return keyType;
  }

  /**
   * Sets key type.
   *
   * @param keyType the key type.
   */
  public void setKeyType(KeyType keyType) {
    this.keyType = keyType;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    VirgilPrivateKey that = (VirgilPrivateKey) o;
    return Arrays.equals(identifier, that.identifier)
        && keyType == that.keyType;
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(privateKey, keyType);
    result = 31 * result + Arrays.hashCode(identifier);
    return result;
  }
}
