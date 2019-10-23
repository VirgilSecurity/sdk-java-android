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

import com.virgilsecurity.crypto.foundation.AlgId;

/**
 * KeyType class with key types supported by Crypto.
 */
public enum KeyType {

  /**
   * Diffie–Hellman X25519.
   */
  CURVE25519(AlgId.CURVE25519),
  /**
   * EdDSA Ed25519.
   */
  ED25519(AlgId.ED25519),
  /**
   * SECP256R1 (NIST P-256).
   */
  SECP256R1(AlgId.SECP256R1),
  /**
   * RSA 2048 bit.
   */
  RSA_2048(2048),
  /**
   * RSA 4096 bit.
   */
  RSA_4096(4096),
  /**
   * RSA 8192 bit.
   */
  RSA_8192(8192);

  private AlgId algId;
  private int rsaBitLen;

  KeyType(AlgId algId) {
    this.algId = algId;
  }

  KeyType(int rsaBitLen) {
    this.algId = AlgId.RSA;
    this.rsaBitLen = rsaBitLen;
  }

  public AlgId getAlgId() {
    return algId;
  }

  /**
   * Get key len.
   *
   * @return Key length in bits if key of RSA, -1 otherwise.
   */
  public int getRsaBitLen() {
    switch (this) {
      case RSA_2048:
      case RSA_4096:
      case RSA_8192:
        return rsaBitLen;
      case CURVE25519:
      case ED25519:
      case SECP256R1:
        return -1;
      default:
        return -1;
    }
  }
}
