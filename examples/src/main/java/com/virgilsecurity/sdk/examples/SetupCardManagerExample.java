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

import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VerifierCredentials;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.cards.validation.Whitelist;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Arrays;

/**
 * @author Andrii Iakovenko
 */
public class SetupCardManagerExample {

  private static final String PUBLIC_KEY_STR = "Your public key as Base64 encoded string";

  public static void main(String[] args) {
    VirgilCardCrypto cardCrypto = setupCrypto();
    AccessTokenProvider accessTokenProvider = setupAccessTokenProvider();
    CardVerifier cardVerifier = setupCardVerifier(cardCrypto);
    CardManager cardManager = initializeCardManager(cardCrypto, accessTokenProvider, cardVerifier);
  }

  private static CardManager initializeCardManager(VirgilCardCrypto cardCrypto,
                                                   AccessTokenProvider accessTokenProvider, CardVerifier cardVerifier) {

    CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider, cardVerifier);

    return cardManager;
  }

  private static AccessTokenProvider setupAccessTokenProvider() {
    GetTokenCallback getTokenCallback = new GetTokenCallback() {

      @Override
      public String onGetToken(TokenContext tokenContext) {
        // Generate token here
        return null;
      }
    };
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(getTokenCallback);

    return accessTokenProvider;
  }

  private static CardVerifier setupCardVerifier(VirgilCardCrypto cardCrypto) {
    VerifierCredentials yourBackendVerifierCredenetials = new VerifierCredentials("YOUR_BACKEND",
        ConvertionUtils.base64ToBytes(PUBLIC_KEY_STR));

    Whitelist yourBackendWhitelist = new Whitelist(Arrays.asList(yourBackendVerifierCredenetials));

    CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto,
        Arrays.asList(yourBackendWhitelist));

    return cardVerifier;
  }

  private static VirgilCardCrypto setupCrypto() {
    // Setup Crypto
    VirgilCardCrypto cardCrypto = new VirgilCardCrypto();

    return cardCrypto;
  }

}
