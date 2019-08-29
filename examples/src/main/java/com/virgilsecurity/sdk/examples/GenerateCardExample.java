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

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider.GetTokenCallback;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.Base64;

import java.security.PrivateKey;
import java.util.concurrent.TimeUnit;

/**
 * @author Andrii Iakovenko
 */
public class GenerateCardExample {

  public static void main(String[] args) throws CryptoException {
    String identity = "Alice";
    VirgilCrypto virgilCrypto = new VirgilCrypto();
    VirgilCardCrypto cardCrypto = new VirgilCardCrypto(virgilCrypto);
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(null);
    CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider,
        new VirgilCardVerifier(cardCrypto, true, false));

    // generate a key pair
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();

    // generate card model
    RawSignedModel signedModel = cardManager.generateRawCard(keyPair.getPrivateKey(),
        keyPair.getPublicKey(), identity);
    String exportedSignedModel = signedModel.exportAsBase64String();
    System.out.println(String.format("Your card is: %s", exportedSignedModel));

    // attempt to import
    Card card = cardManager.importCardAsRawModel(signedModel);

    System.out.println("Done!");
  }

  public void generateCard() throws CryptoException {
    String identity = "Alice";

    VirgilCrypto virgilCrypto = new VirgilCrypto();
    VirgilCardCrypto cardCrypto = new VirgilCardCrypto(virgilCrypto);
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(null);
    CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider,
        new VirgilCardVerifier(cardCrypto));

    // generate a key pair
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();

    // generate card model
    RawSignedModel signedModel = cardManager.generateRawCard(keyPair.getPrivateKey(),
        keyPair.getPublicKey(), identity);
    String exportedSignedModel = signedModel.exportAsBase64String();
    System.out.println(String.format("Your card is: %s", exportedSignedModel));
  }

  public String jwtTokenGeneratorOnServer(TokenContext tokenContext) throws CryptoException {
    // This is SERVER side code, it's OK to implement it on client for non-production
    String appId = "Application ID";
    String apiKeyBase64 = "Base64 encoded API Key";
    String apiKeyId = "API Key identifier";

    VirgilCrypto virgilCrypto = new VirgilCrypto();
    // Import API Private key from string
    VirgilPrivateKey apiKey = virgilCrypto.importPrivateKey(Base64.decode(apiKeyBase64)).getPrivateKey();
    VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner(virgilCrypto);
    JwtGenerator jwtGenerator = new JwtGenerator(appId, apiKey, apiKeyId,
        TimeSpan.fromTime(1, TimeUnit.DAYS), accessTokenSigner);

    return jwtGenerator.generateToken(tokenContext.getIdentity()).stringRepresentation();
  }

  public void publishCard() throws CryptoException, VirgilServiceException {
    final String identity = "Alice";
    VirgilCrypto virgilCrypto = new VirgilCrypto();

    // Initialize CardManager
    VirgilCardCrypto cardCrypto = new VirgilCardCrypto(virgilCrypto);
    AccessTokenProvider accessTokenProvider = new CallbackJwtProvider(tokenContext -> {
      // Make call to your Server to obtain Jwt token
      try {
        return jwtTokenGeneratorOnServer(tokenContext);
      } catch (CryptoException e) {
        // Handle an error here
        return null;
      }
    });
    CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider,
        new VirgilCardVerifier(cardCrypto));

    // Generate a key pair
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();

    // Publish card
    cardManager.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(), identity);
  }

}
