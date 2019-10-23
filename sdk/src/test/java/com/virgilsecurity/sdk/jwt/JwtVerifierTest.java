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

package com.virgilsecurity.sdk.jwt;

import com.virgilsecurity.sdk.CompatibilityDataProvider;
import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link JwtVerifier}.
 *
 * @author Andrii Iakovenko
 */
public class JwtVerifierTest {

  private CompatibilityDataProvider dataProvider;
  private FakeDataFactory fake;
  private JwtVerifier verifier;

  @BeforeEach
  public void setup() throws CryptoException {
    this.dataProvider = new CompatibilityDataProvider();
    this.fake = new FakeDataFactory();

    VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
    this.verifier = new JwtVerifier(fake.getApiPublicKey(), fake.getApiPublicKeyId(),
        accessTokenSigner);
  }

  @Test
  public void stc_22() throws CryptoException {
    // STC_22
    VirgilAccessTokenSigner signer = new VirgilAccessTokenSigner();
    VirgilCrypto crypto = new VirgilCrypto();
    String apiPublicKeyId = dataProvider.getString("STC-22.api_key_id");
    String apiPublicKeyBase64 = dataProvider.getString("STC-22.api_public_key_base64");

    VirgilPublicKey apiPublicKey = crypto
        .importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKeyBase64));
    Jwt token = new Jwt(dataProvider.getString("STC-22.jwt"));

    JwtVerifier jwtVerifier = new JwtVerifier(apiPublicKey, apiPublicKeyId, signer);

    assertTrue(jwtVerifier.verifyToken(token));
  }

  @Test
  public void verifyToken() throws CryptoException {
    Jwt token = fake.generateToken();

    assertTrue(this.verifier.verifyToken(token));
  }

}
