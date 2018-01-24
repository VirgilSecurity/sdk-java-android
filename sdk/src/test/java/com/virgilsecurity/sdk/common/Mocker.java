/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

package com.virgilsecurity.sdk.common;

import com.sun.istack.internal.NotNull;
import com.virgilsecurity.sdk.cards.*;
import com.virgilsecurity.sdk.cards.validation.VerifierCredentials;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.model.RawCardContent;
import com.virgilsecurity.sdk.client.model.RawSignature;
import com.virgilsecurity.sdk.client.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jsonWebToken.Jwt;
import com.virgilsecurity.sdk.jsonWebToken.JwtGenerator;
import com.virgilsecurity.sdk.jsonWebToken.TimeSpan;
import com.virgilsecurity.sdk.jsonWebToken.contract.AccessToken;
import com.virgilsecurity.sdk.jsonWebToken.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import javafx.util.Pair;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class Mocker extends PropertyManager {

    private static final String IDENTITY = "TEST";
    private static final String PUBLIC_KEY = "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk=";

    private Random random;
    private JwtGenerator jwtGenerator;
    private VirgilCrypto crypto;
    private AccessTokenSigner accessTokenSigner;

    public Mocker() {
        random = new Random();
        crypto = new VirgilCrypto();
        accessTokenSigner = new VirgilAccessTokenSigner();

        VirgilPrivateKey privateKey;
        try {
            privateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(ACCESS_PRIVATE_KEY_BASE64));
        } catch (CryptoException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("Mocker -> 'ACCESS_PRIVATE_KEY_BASE64' seems to has wrong format");
        }

        jwtGenerator = new JwtGenerator(privateKey,
                                        ACCESS_PUBLIC_KEY_ID,
                                        accessTokenSigner,
                                        APP_ID,
                                        TimeSpan.fromTime(5, TimeUnit.MINUTES));
    }

    public Card card() {

        final String virgilCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";

        byte[] fingerprint = Generator.randomBytes(32);
        byte[] signatureSelf = Generator.randomBytes(64);
        byte[] signatureVirgil = Generator.randomBytes(64);

        String cardId = ConvertionUtils.toString(fingerprint, StringEncoding.HEX);

        List<CardSignature> signatures = new ArrayList<>();
        signatures.add(new CardSignature.CardSignatureBuilder()
                               .signerId(cardId)
                               .signerType(SignerType.SELF.getRawValue())
                               .signature(signatureSelf)
                               .build());

        signatures.add(new CardSignature.CardSignatureBuilder()
                               .signerId(cardId)
                               .signerType(SignerType.VIRGIL.getRawValue())
                               .signature(signatureVirgil)
                               .build());

        VirgilCrypto virgilCrypto = new VirgilCrypto();
        PublicKey somePublicKey = virgilCrypto.generateKeys().getPublicKey();

        return new Card(cardId,
                        Generator.firstName(),
                        somePublicKey,
                        Generator.randomArrayElement(Arrays.asList("4.0", "5.0")),
                        Generator.randomDate(),
                        signatures);
    }

    public Card card(boolean addSelfSignature,
                     boolean addVirgilSignature,
                     @NotNull List<CardSignature> signatures) {

        if (signatures == null)
            throw new IllegalArgumentException("Generator -> 'signatures' should not be null");

        final String virgilCardId = "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853";

        byte[] fingerprint = Generator.randomBytes(32);
        byte[] signatureSelf = Generator.randomBytes(64);
        byte[] signatureVirgil = Generator.randomBytes(64);

        String cardId = ConvertionUtils.toString(fingerprint, StringEncoding.HEX);

        if (addSelfSignature) {
            signatures.add(new CardSignature.CardSignatureBuilder()
                                   .signerId(cardId)
                                   .signerType(SignerType.SELF.getRawValue())
                                   .signature(signatureSelf)
                                   .build());
        }

        if (addVirgilSignature) {
            signatures.add(new CardSignature.CardSignatureBuilder()
                                   .signerId(cardId)
                                   .signerType(SignerType.VIRGIL.getRawValue())
                                   .signature(signatureVirgil)
                                   .build());
        }

        VirgilCrypto virgilCrypto = new VirgilCrypto();
        PublicKey somePublicKey = virgilCrypto.generateKeys().getPublicKey();

        return new Card(cardId,
                        Generator.firstName(),
                        somePublicKey,
                        Generator.randomArrayElement(Arrays.asList("4.0", "5.0")),
                        Generator.randomDate(),
                        signatures);
    }

    public String cardId() {
        byte[] fingerprint = Generator.randomBytes(32);

        return ConvertionUtils.toString(fingerprint, StringEncoding.HEX);
    }

    public Pair<VerifierCredentials, CardSignature> signerAndSignature() {
        String cardId = cardId();
        VirgilCrypto crypto = new VirgilCrypto();
        KeyPairVirgiled keyPair = crypto.generateKeys();
        byte[] exportPublicKey = crypto.exportPublicKey(keyPair.getPublicKey());

        return new Pair<>(new VerifierCredentials(cardId,
                                                  exportPublicKey),
                          new CardSignature.CardSignatureBuilder()
                                  .signerId(cardId)
                                  .signature(Generator.randomBytes(64))
                                  .build());
    }

    public RawSignedModel predefinedRawSignedModel(@NotNull String previousCardId) {
        if (previousCardId == null)
            throw new IllegalArgumentException("Mocker -> 'previousCardId' should not be null");

        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 6);
        calendar.set(Calendar.HOUR_OF_DAY, 10);

        RawCardContent rawCardContent = new RawCardContent(IDENTITY,
                                                           PUBLIC_KEY.getBytes(),
                                                           "5.0",
                                                           calendar.getTime(),
                                                           previousCardId);

        return new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));
    }

    public RawSignedModel predefinedRawSignedModel() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 6);
        calendar.set(Calendar.HOUR_OF_DAY, 10);

        RawCardContent rawCardContent = new RawCardContent(IDENTITY,
                                                           PUBLIC_KEY.getBytes(),
                                                           "5.0",
                                                           calendar.getTime());

        return new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));
    }

    public RawSignedModel generateCardModel() throws CryptoException {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 6);
        calendar.set(Calendar.HOUR_OF_DAY, 10);

        KeyPairVirgiled keyPairVirgiled = crypto.generateKeys();
        VirgilPublicKey publicKey = keyPairVirgiled.getPublicKey();
        VirgilPrivateKey privateKey = keyPairVirgiled.getPrivateKey();

        RawCardContent rawCardContent = new RawCardContent(IDENTITY,
                                                           crypto.exportPublicKey(publicKey),
                                                           "5.0",
                                                           calendar.getTime());

        RawSignedModel cardModel =
                new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));
        ModelSigner signer = new ModelSigner(new VirgilCardCrypto());
        signer.selfSign(cardModel, privateKey);

        return cardModel;
    }

    public RawSignedModel rawCard() {
        return new RawSignedModel(ConvertionUtils.captureSnapshot(new RawCardContent()));
    }

    public CardManager cardManager() {
        CardManager.SignCallback signCallback = new CardManager.SignCallback() {
            @Override public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                return null;
            }
        };

        AccessTokenProvider accessTokenProvider = new AccessTokenProvider() {
            @Override public AccessToken getToken(boolean forceReload) throws CryptoException {
                return null;
            }
        };

        return new CardManager(new VirgilCardCrypto(),
                               accessTokenProvider,
                               null,
                               new CardClient(),
                               signCallback);
    }

    public Jwt generateAccessToken(String identity) throws CryptoException {
        return jwtGenerator.generateToken(identity);
    }
}
