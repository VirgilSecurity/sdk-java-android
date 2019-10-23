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

package com.virgilsecurity.sdk.examples;

import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.security.PrivateKey;
import java.util.concurrent.TimeUnit;

/**
 * @author Andrii Iakovenko
 */
public class AuthenticationJwtExample {

  public static void main(String[] args) throws CryptoException {
    new AuthenticationJwtExample().run();
    System.out.println("Done!");
  }

  private void jwtGeneration() throws CryptoException {
    // API_KEY
    String apiKeyBase64 = "MC4CAQAwBQYDK2VwBCIEINlK4BhgsijAbNmUqU6us0ZU9MGi+HxdYCA6TdZeHjR4";
    byte[] apiKeyData = ConvertionUtils.base64ToBytes(apiKeyBase64);

    // import a private key
    VirgilCrypto crypto = new VirgilCrypto();
    VirgilPrivateKey apiKey = crypto.importPrivateKey(apiKeyData).getPrivateKey();

    VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

    String appId = "be00e10e4e1f4bf58f9b4dc85d79c77a"; // APP_ID
    String apiKeyId = "70b447e321f3a0fd"; // API_KEY_ID
    TimeSpan ttl = TimeSpan.fromTime(1, TimeUnit.HOURS); // 1 hour

    // setup JWT generator
    JwtGenerator jwtGenerator = new JwtGenerator(appId, apiKey, apiKeyId, ttl, accessTokenSigner);

    // generate JWT for a user
    String identity = "Alice";
    Jwt aliceJwt = jwtGenerator.generateToken(identity);

    // Send to client-side
    String jwtString = aliceJwt.stringRepresentation();
  }

  private void run() throws CryptoException {
    setupJwt();
    jwtGeneration();
  }

  private void setupJwt() {
    // Get generated token from server-side
    final String authenticatedQueryToServerSide = "eyJraWQiOiI3MGI0NDdlMzIxZjNhMGZkIiwidHlwIjoiSldUIiwiYWxnIjoiVkVEUzUxMiIsImN0eSI6InZpcmdpbC1qd3Q7dj0xIn0.eyJleHAiOjE1MTg2OTg5MTcsImlzcyI6InZpcmdpbC1iZTAwZTEwZTRlMWY0YmY1OGY5YjRkYzg1ZDc5Yzc3YSIsInN1YiI6ImlkZW50aXR5LUFsaWNlIiwiaWF0IjoxNTE4NjEyNTE3fQ.MFEwDQYJYIZIAWUDBAIDBQAEQP4Yo3yjmt8WWJ5mqs3Yrqc_VzG6nBtrW2KIjP-kxiIJL_7Wv0pqty7PDbDoGhkX8CJa6UOdyn3rBWRvMK7p7Ak";

    // Setup AccessTokenProvider
    GetTokenCallback getTokenCallback = tokenContext -> authenticatedQueryToServerSide;
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(getTokenCallback);
  }
}