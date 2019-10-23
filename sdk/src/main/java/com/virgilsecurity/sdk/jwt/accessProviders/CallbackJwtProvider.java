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
import com.virgilsecurity.sdk.utils.Validator;

/**
 * The {@link CallbackJwtProvider} class is implemented for usage of get token callback mechanism
 * which should predefine implementation of generating/receiving/caching of token. Caching should be
 * implemented by user if needed.
 */
public class CallbackJwtProvider implements AccessTokenProvider {

  /**
   * The interface Get token callback.
   */
  public interface GetTokenCallback {
    /**
     * In this callback you should return valid JsonWebToken as base64 string in 2 or 3 parts
     * separated with dot ('.').
     *
     * @param tokenContext the tokenContext that is used to get token
     * @return the string
     */
    String onGetToken(TokenContext tokenContext);
  }

  private GetTokenCallback getTokenCallback;

  /**
   * Instantiates a new Callback jwt provider.
   *
   * @param getTokenCallback the get token callback
   */
  public CallbackJwtProvider(GetTokenCallback getTokenCallback) {
    this.getTokenCallback = getTokenCallback;
  }

  @Override
  public AccessToken getToken(TokenContext tokenContext) {
    Validator.checkNullAgrument(tokenContext,
        "CallbackJwtProvider -> 'tokenContext' should not be null");
    Validator.checkNullAgrument(getTokenCallback,
        "CallbackJwtProvider -> set getTokenCallback first");

    return new Jwt(getTokenCallback.onGetToken(tokenContext));
  }

  /**
   * Sets get token callback.
   *
   * @param getTokenCallback the get token callback
   */
  public void setGetTokenCallback(GetTokenCallback getTokenCallback) {
    Validator.checkNullAgrument(getTokenCallback,
        "CallbackJwtProvider -> 'getTokenCallback' should not be null");

    this.getTokenCallback = getTokenCallback;
  }
}
