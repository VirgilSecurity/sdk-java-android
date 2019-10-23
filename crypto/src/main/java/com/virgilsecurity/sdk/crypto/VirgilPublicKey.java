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
 * A public key.
 */
public class VirgilPublicKey implements Serializable {

  private static final long serialVersionUID = -9006213204395528391L;

  /**
   * The Public key identifier.
   */
  private byte[] identifier;

  /**
   * The Public key rawKey.
   */
  private com.virgilsecurity.crypto.foundation.PublicKey publicKey;

  /**
   * The Public key type.
   */
  private KeyType keyType;

  /**
   * For serialization only!
   * <p>
   * Do NOT create object with this constructor.
   */
  public VirgilPublicKey() {
  }

  /**
   * Create a new instance of {@code VirgilPublicKey}.
   *
   * @param identifier the public key identifier.
   * @param publicKey  the public key.
   * @param keyType    the public key type.
   */
  public VirgilPublicKey(byte[] identifier,
                         com.virgilsecurity.crypto.foundation.PublicKey publicKey,
                         KeyType keyType) {
    this.identifier = identifier;
    this.publicKey = publicKey;
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
   * Set the Public key hash.
   *
   * @param identifier the Id to set.
   */
  public void setIdentifier(byte[] identifier) {
    this.identifier = identifier;
  }

  /**
   * Gets public key.
   *
   * @return the public key.
   */
  public com.virgilsecurity.crypto.foundation.PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Sets public key.
   *
   * @param publicKey the public key.
   */
  public void setPublicKey(com.virgilsecurity.crypto.foundation.PublicKey publicKey) {
    this.publicKey = publicKey;
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
    VirgilPublicKey that = (VirgilPublicKey) o;
    return Arrays.equals(identifier, that.identifier)
        && keyType == that.keyType;
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(publicKey, keyType);
    result = 31 * result + Arrays.hashCode(identifier);
    return result;
  }
}
