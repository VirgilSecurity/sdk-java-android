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

package com.virgilsecurity.sdk.jwt.accessProviders;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.Validator;

import java.util.Map;

/**
 * The {@link GeneratorJwtProvider} class is implemented for generating
 * {@link com.virgilsecurity.sdk.jwt.Jwt} with provided {@link JwtGenerator}.
 */
public class GeneratorJwtProvider implements AccessTokenProvider {

  private JwtGenerator jwtGenerator;
  private Map<String, String> additionalData;
  private String defaultIdentity;

  /**
   * Instantiates a new Generator jwt provider.
   *
   * @param jwtGenerator    the jwt generator
   * @param defaultIdentity the default identity
   */
  public GeneratorJwtProvider(JwtGenerator jwtGenerator, String defaultIdentity) {
    Validator.checkNullAgrument(jwtGenerator,
        "GeneratorJwtProvider -> 'jwtGenerator' should not be null");
    Validator.checkNullAgrument(defaultIdentity,
        "GeneratorJwtProvider -> 'defaultIdentity' should not be null");

    this.jwtGenerator = jwtGenerator;
    this.defaultIdentity = defaultIdentity;
  }

  /**
   * Instantiates a new Generator jwt provider.
   *
   * @param jwtGenerator    the jwt generator
   * @param defaultIdentity the default identity
   * @param additionalData  the additional data
   */
  public GeneratorJwtProvider(JwtGenerator jwtGenerator, String defaultIdentity,
                              Map<String, String> additionalData) {
    Validator.checkNullAgrument(jwtGenerator,
        "GeneratorJwtProvider -> 'jwtGenerator' should not be null");
    Validator.checkNullAgrument(defaultIdentity,
        "GeneratorJwtProvider -> 'defaultIdentity' should not be null");
    Validator.checkNullAgrument(additionalData,
        "GeneratorJwtProvider -> 'additionalData' should not be null");

    this.jwtGenerator = jwtGenerator;
    this.defaultIdentity = defaultIdentity;
    this.additionalData = additionalData;
  }

  /**
   * Gets additional data.
   *
   * @return the additional data
   */
  public Map<String, String> getAdditionalData() {
    return additionalData;
  }

  /**
   * Gets jwt generator.
   *
   * @return the jwt generator
   */
  public JwtGenerator getJwtGenerator() {
    return jwtGenerator;
  }

  /*
   * (non-Javadoc)
   *
   * @see
   * com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider#getToken(com.virgilsecurity.sdk.jwt.
   * TokenContext)
   */
  @Override
  public AccessToken getToken(TokenContext context) throws CryptoException {
    return jwtGenerator.generateToken(
        context.getIdentity() != null ? context.getIdentity() : defaultIdentity, additionalData);
  }

  /**
   * Sets additional data.
   *
   * @param additionalData the additional data
   */
  public void setAdditionalData(Map<String, String> additionalData) {
    this.additionalData = additionalData;
  }
}
