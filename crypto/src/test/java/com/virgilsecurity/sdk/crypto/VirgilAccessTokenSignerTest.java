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

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link VirgilAccessTokenSigner}.
 *
 * @author Andrii Iakovenko
 */
public class VirgilAccessTokenSignerTest {

  private static final byte[] TOKEN = "the token".getBytes(StandardCharsets.UTF_8);

  private VirgilAccessTokenSigner signer;
  private VirgilPublicKey publicKey;
  private VirgilPrivateKey privateKey;

  @Test
  public void generateTokenSignature() throws CryptoException {
    byte[] signature = this.signer.generateTokenSignature(TOKEN, this.privateKey);

    assertNotNull(signature);
  }

  @Test
  public void generateTokenSignature_nullKey() {
    assertThrows(NullArgumentException.class, () -> {
      this.signer.generateTokenSignature(TOKEN, null);
    });
  }

  @Test
  public void generateTokenSignature_nullToken() {
    assertThrows(NullArgumentException.class, () -> {
      this.signer.generateTokenSignature(null, this.privateKey);
    });
  }

  @Test
  public void getAlgorithm() {
    assertEquals("VEDS512", this.signer.getAlgorithm());
  }

  @Test
  public void getVirgilCrypto() {
    assertNotNull(this.signer.getVirgilCrypto());
  }

  @BeforeEach
  public void setup() throws CryptoException {
    this.signer = new VirgilAccessTokenSigner();

    VirgilKeyPair keyPair = this.signer.getVirgilCrypto().generateKeyPair();
    this.privateKey = keyPair.getPrivateKey();
    this.publicKey = keyPair.getPublicKey();
  }

  @Test
  public void verifyTokenSignature() throws CryptoException {
    byte[] signature = this.signer.generateTokenSignature(TOKEN, this.privateKey);
    assertTrue(this.signer.verifyTokenSignature(signature, TOKEN, this.publicKey));
  }

  @Test
  public void verifyTokenSignature_nullKey() {
    assertThrows(NullArgumentException.class, () -> {
      this.signer.generateTokenSignature(TOKEN, null);
    });
  }

  @Test
  public void verifyTokenSignature_nullToken() {
    assertThrows(NullArgumentException.class, () -> {
      this.signer.generateTokenSignature(null, this.privateKey);
    });
  }

  @Test
  public void verifyTokenSignature_wrongSignature() throws CryptoException {
    byte[] signature = this.signer.generateTokenSignature(TOKEN, this.privateKey);
    assertFalse(this.signer.verifyTokenSignature(signature,
        ArrayUtils.subarray(TOKEN, 0, TOKEN.length - 2), this.publicKey));
  }
}
