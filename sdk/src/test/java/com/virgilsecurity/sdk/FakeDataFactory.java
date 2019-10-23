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

package com.virgilsecurity.sdk;

import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @author Andrii Iakovenko
 */
public class FakeDataFactory {

  private VirgilCrypto crypto;
  private String applicationId;
  private VirgilPrivateKey apiPrivateKey;
  private VirgilPublicKey apiPublicKey;
  private String apiPublicKeyId;
  private JwtGenerator jwtGenerator;
  private JwtGenerator jwtGeneratorFiveSeconds;
  private String identity;

  /**
   * Create new instance of {@link FakeDataFactory}.
   *
   * @throws CryptoException if any crypto operation on fake data failed.
   */
  public FakeDataFactory() throws CryptoException {
    this.crypto = new VirgilCrypto();

    this.applicationId = ConvertionUtils
        .toHex(ConvertionUtils.toBytes(UUID.randomUUID().toString()));
    this.identity = "IDENTITY_" + this.applicationId;

    VirgilKeyPair keyPair = this.crypto.generateKeyPair();
    this.apiPrivateKey = keyPair.getPrivateKey();
    this.apiPublicKey = keyPair.getPublicKey();
    this.apiPublicKeyId = ConvertionUtils.toHex(this.crypto.exportPublicKey(apiPublicKey));

    this.jwtGenerator = new JwtGenerator(this.applicationId, apiPrivateKey, apiPublicKeyId,
        TimeSpan.fromTime(10, TimeUnit.MINUTES), new VirgilAccessTokenSigner());

    this.jwtGeneratorFiveSeconds = new JwtGenerator(this.applicationId, apiPrivateKey,
        apiPublicKeyId, TimeSpan.fromTime(5, TimeUnit.SECONDS), new VirgilAccessTokenSigner());
  }

  public Jwt generateToken() throws CryptoException {
    Map<String, String> additionalData = new HashMap<>();
    additionalData.put("username", "fake_username");
    Jwt token = this.jwtGenerator.generateToken("fake_identity", additionalData);

    return token;
  }

  /**
   * @return the apiPrivateKey
   */
  public VirgilPrivateKey getApiPrivateKey() {
    return apiPrivateKey;
  }

  /**
   * @return the apiPublicKey
   */
  public VirgilPublicKey getApiPublicKey() {
    return apiPublicKey;
  }

  /**
   * @return the apiPublicKeyId
   */
  public String getApiPublicKeyId() {
    return apiPublicKeyId;
  }

  /**
   * @return the applicationId
   */
  public String getApplicationId() {
    return applicationId;
  }

  /**
   * @return the crypto
   */
  public VirgilCrypto getCrypto() {
    return crypto;
  }

  /**
   * @return the identity
   */
  public String getIdentity() {
    return identity;
  }

  /**
   * @return the jwtGenerator
   */
  public JwtGenerator getJwtGenerator() {
    return jwtGenerator;
  }

  /**
   * @return the getJwtGeneratorFiveSeconds
   */
  public JwtGenerator getJwtGeneratorFiveSeconds() {
    return jwtGeneratorFiveSeconds;
  }

}
