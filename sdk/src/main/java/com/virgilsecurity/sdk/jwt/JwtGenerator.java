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

import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64Url;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;

/**
 * The {@link JwtGenerator} class is used for generation of {@link Jwt} with provided tools and
 * data.
 */
public class JwtGenerator {

  private final VirgilPrivateKey apiKey;
  private final String apiPublicKeyIdentifier;
  private final VirgilAccessTokenSigner accessTokenSigner;
  private final String appId;
  private final TimeSpan ttl;

  /**
   * Instantiates a new Jwt generator.
   *
   * @param appId                  The application identifier.
   * @param apiKey                 The api private key.
   * @param apiPublicKeyIdentifier The api public key identifier.
   * @param ttl                    The lifetime of token - when it expires at.
   * @param accessTokenSigner      The access token signer.
   */
  public JwtGenerator(String appId, VirgilPrivateKey apiKey, String apiPublicKeyIdentifier, TimeSpan ttl,
                      VirgilAccessTokenSigner accessTokenSigner) {
    this.appId = appId;
    this.apiKey = apiKey;
    this.apiPublicKeyIdentifier = apiPublicKeyIdentifier;
    this.ttl = ttl;
    this.accessTokenSigner = accessTokenSigner;
  }

  /**
   * Generate token jwt.
   *
   * @param identity The identity.
   *
   * @return The generated Jwt.
   *
   * @throws CryptoException If issue occurred while generating token signature.
   */
  public Jwt generateToken(String identity) throws CryptoException {
    JwtHeaderContent jwtHeaderContent = new JwtHeaderContent(apiPublicKeyIdentifier);
    JwtBodyContent jwtBodyContent = new JwtBodyContent(appId, identity, ttl, new Date());

    Jwt jwtToken = new Jwt(jwtHeaderContent, jwtBodyContent);
    byte[] signature = this.accessTokenSigner
        .generateTokenSignature(ConvertionUtils.toBytes(jwtToken.unsigned()), apiKey);
    return new Jwt(jwtToken.stringRepresentation() + "." + Base64Url.encode(signature));
  }

  /**
   * Generate token jwt.
   *
   * @param identity       The identity.
   * @param additionalData The additional data associated with token.
   *
   * @return The generated Jwt.
   *
   * @throws CryptoException If issue occurred while generating token signature.
   */
  public Jwt generateToken(String identity, Map<String, String> additionalData)
      throws CryptoException {
    JwtHeaderContent jwtHeaderContent = new JwtHeaderContent(apiPublicKeyIdentifier);
    JwtBodyContent jwtBodyContent = new JwtBodyContent(appId, identity, additionalData, ttl,
        new Date());

    Jwt jwtToken = new Jwt(jwtHeaderContent, jwtBodyContent);
    byte[] signature = this.accessTokenSigner
        .generateTokenSignature(ConvertionUtils.toBytes(jwtToken.unsigned()), apiKey);
    return new Jwt(jwtToken.stringRepresentation() + "." + Base64Url.encode(signature));
  }
}
