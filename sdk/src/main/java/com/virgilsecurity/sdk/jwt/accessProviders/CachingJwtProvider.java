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

import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;

import java.util.Date;

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 5/3/18
 * at Virgil Security
 */

/**
 * The {@link CachingJwtProvider} class is implemented for usage of renew token callback mechanism
 * which should predefine implementation of renewing of token. Token is been cached.
 */
public class CachingJwtProvider implements AccessTokenProvider {

  /**
   * The interface Renew jwt callback.
   */
  public interface RenewJwtCallback {
    /**
     * <p>Implement the jwt renew mechanism.</p>
     * In this callback you should return valid JsonWebToken as base64 string in 2 or 3 parts
     * separated with dot ('.').
     *
     * @param tokenContext the tokenContext that is used to get token
     * @return the renewed jwt
     */
    Jwt renewJwt(TokenContext tokenContext);
  }

  private static final long TOKEN_FUTURE_EXPIRATION_TIME = 5 * 1000; // 5 seconds in milliseconds
  private volatile Jwt jwt;

  private final RenewJwtCallback renewJwtCallback;

  /**
   * Instantiates a new Caching jwt provider.
   *
   * @param renewJwtCallback the renew jwt callback
   */
  public CachingJwtProvider(RenewJwtCallback renewJwtCallback) {
    this.renewJwtCallback = renewJwtCallback;
  }

  /**
   * Instantiates a new Caching jwt provider.
   *
   * @param renewJwtCallback the renew jwt callback
   * @param initialJwt       the initial jwt that will be used until expired
   */
  public CachingJwtProvider(RenewJwtCallback renewJwtCallback, Jwt initialJwt) {
    this.renewJwtCallback = renewJwtCallback;
    this.jwt = initialJwt;
  }

  /**
   * Gets renew jwt callback.
   *
   * @return the renew jwt callback
   */
  public RenewJwtCallback getRenewJwtCallback() {
    return renewJwtCallback;
  }

  @Override
  public synchronized AccessToken getToken(TokenContext tokenContext) {
    if (jwt != null
        && !jwt.isExpired(new Date(System.currentTimeMillis() + TOKEN_FUTURE_EXPIRATION_TIME))) {
      return jwt;
    }

    return jwt = renewJwtCallback.renewJwt(tokenContext);
  }
}
