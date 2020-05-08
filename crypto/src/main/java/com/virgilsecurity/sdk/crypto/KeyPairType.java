/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

import com.virgilsecurity.common.model.Pair;
import com.virgilsecurity.crypto.foundation.AlgId;
import com.virgilsecurity.crypto.foundation.Key;
import com.virgilsecurity.crypto.foundation.KeyInfo;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.UnknownCompoundKeyException;

/**
 * KeyType class with key types supported by Crypto.
 */
public enum KeyPairType {

  /**
   * Diffie–Hellman X25519.
   */
  CURVE25519(),

  /**
   * EdDSA Ed25519.
   */
  ED25519(),

  /**
   * SECP256R1 (NIST P-256).
   */
  SECP256R1(),

  /**
   * RSA 2048 bit.
   */
  RSA_2048(),

  /**
   * RSA 4096 bit.
   */
  RSA_4096(),

  /**
   * RSA 8192 bit.
   */
  RSA_8192(),

  /**
   * Compound key CURVE25519 ROUND5 ED25519 FALCON
   */
  CURVE25519_ROUND5_ED25519_FALCON(),

  /**
   * Compound key CURVE25519 ED25519
   */
  CURVE25519_ED25519();

  private static final int RSA_2048_LENGTH = 2048;
  private static final int RSA_4096_LENGTH = 4096;
  private static final int RSA_8192_LENGTH = 8192;

  public static KeyPairType fromKey(Key key) throws CryptoException {
    KeyInfo keyInfo = new KeyInfo(key.algInfo());

    if (keyInfo.isCompound()) {
      if (keyInfo.compoundHybridCipherFirstKeyAlgId() == AlgId.CURVE25519
              && keyInfo.compoundHybridCipherSecondKeyAlgId() == AlgId.ROUND5_ND_1CCA_5D
              && keyInfo.compoundHybridSignerFirstKeyAlgId() == AlgId.ED25519
              && keyInfo.compoundHybridSignerSecondKeyAlgId() == AlgId.FALCON) {

        return KeyPairType.CURVE25519_ROUND5_ED25519_FALCON;
      } else if (keyInfo.compoundCipherAlgId() == AlgId.CURVE25519
              && keyInfo.compoundSignerAlgId() == AlgId.ED25519) {

        return KeyPairType.CURVE25519_ED25519;
      } else {
        throw new UnknownCompoundKeyException();
      }
    }

    AlgId algId = keyInfo.algId();

    if (algId == AlgId.RSA) {
      return KeyPairType.fromRsaBitLen(key.bitlen());
    }

    switch (algId) {
      case ED25519:
        return KeyPairType.ED25519;
      case CURVE25519:
        return KeyPairType.CURVE25519;
      case SECP256R1:
        return KeyPairType.SECP256R1;
      default:
        throw new CryptoException("Unknown algorithm id: " + key.algId().name());
    }
  }

  public static KeyPairType fromRsaBitLen(int length) throws CryptoException {
    switch (length) {
      case RSA_2048_LENGTH:
        return KeyPairType.RSA_2048;
      case RSA_4096_LENGTH:
        return KeyPairType.RSA_4096;
      case RSA_8192_LENGTH:
        return KeyPairType.RSA_8192;
      default:
        throw new CryptoException("Unsupported RSA length: " + length);
    }
  }

  public static KeyPairType fromAlgId(AlgId algId) throws CryptoException {
    switch (algId) {
      case ED25519:
        return KeyPairType.ED25519;
      case CURVE25519:
        return KeyPairType.CURVE25519;
      case SECP256R1:
        return KeyPairType.SECP256R1;
      case RSA:
        throw new CryptoException("RSA should be constructed directly.");
      default:
        throw new CryptoException("Unknown algorithm id: " + algId.name());
    }
  }

  public AlgId getAlgId() throws CryptoException {
    switch (this) {
      case ED25519:
        return AlgId.ED25519;
      case CURVE25519:
        return AlgId.CURVE25519;
      case SECP256R1:
        return AlgId.SECP256R1;
      case RSA_2048:
      case RSA_4096:
      case RSA_8192:
        return AlgId.RSA;
      case CURVE25519_ROUND5_ED25519_FALCON:
      case CURVE25519_ED25519:
        throw new CryptoException("Compound key should be generated directly.");
      default:
        throw new IllegalStateException("Impossible to get here. Just removing compiler error.");
    }
  }

  /**
   * Get key len.
   *
   * @return Key length in bits if key of RSA, -1 otherwise.
   */
  int getRsaBitLen() {
    switch (this) {
      case RSA_2048:
        return RSA_2048_LENGTH;
      case RSA_4096:
        return RSA_4096_LENGTH;
      case RSA_8192:
        return RSA_8192_LENGTH;
      default:
        return -1;
    }
  }

  /**
   * Checks whether key is compound.
   *
   * @return *true* if the key is compound, *false* otherwise.
   */
  boolean isCompound() {
    switch (this) {
      case CURVE25519_ED25519:
      case CURVE25519_ROUND5_ED25519_FALCON:
        return true;
      case CURVE25519:
      case ED25519:
      case RSA_2048:
      case RSA_4096:
      case RSA_8192:
      case SECP256R1:
        return false;
      default:
        throw new IllegalStateException("Impossible to get here. Just removing compiler error.");
    }
  }

  /**
   * Gets signer keys algorithm Ids.
   *
   * @return {@link Pair} of {@link AlgId}s for compound keys.
   *
   * @throws CryptoException if key is not compound.
   */
  Pair<AlgId, AlgId> getSignerKeysAlgIds() throws CryptoException {
    switch (this) {
      case CURVE25519_ED25519:
        return new Pair<>(AlgId.ED25519, AlgId.NONE);
      case CURVE25519_ROUND5_ED25519_FALCON:
        return new Pair<>(AlgId.ED25519, AlgId.FALCON);
      case CURVE25519:
      case ED25519:
      case RSA_2048:
      case RSA_4096:
      case RSA_8192:
      case SECP256R1:
        throw new CryptoException("Key is not compound.");
      default:
        throw new IllegalStateException("Impossible to get here. Just removing compiler error.");
    }
  }

  /**
   * Gets cipher keys algorithm Ids.
   *
   * @return {@link Pair} of {@link AlgId}s for compound keys.
   *
   * @throws CryptoException if key is not compound.
   */
  Pair<AlgId, AlgId> getCipherKeysAlgIds() throws CryptoException {
    switch (this) {
      case CURVE25519_ED25519:
        return new Pair<>(AlgId.CURVE25519, AlgId.NONE);
      case CURVE25519_ROUND5_ED25519_FALCON:
        return new Pair<>(AlgId.CURVE25519, AlgId.ROUND5_ND_1CCA_5D);
      case CURVE25519:
      case ED25519:
      case RSA_2048:
      case RSA_4096:
      case RSA_8192:
      case SECP256R1:
        throw new CryptoException("Key is not compound.");
      default:
        throw new IllegalStateException("Impossible to get here. Just removing compiler error.");
    }
  }
}
