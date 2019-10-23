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

package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.JwtVerifier;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Calendar;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.fail;

public class Mocker extends PropertyManager {

  private static final String IDENTITY = "TEST";
  private static final String FAKE_PRIVATE_KEY_BASE64 = "MC4CAQAwBQYDK2VwBCIEIFxOB4ppNAm8J/C95hPiIJ/A9gPRoERMxjRQN7HcGYnW";

  private JwtGenerator jwtGenerator;
  private JwtGenerator jwtGeneratorSevenSeconds;
  private JwtGenerator jwtGeneratorFake;
  private final JwtGenerator jwtGeneratorExpired;
  private VirgilCrypto crypto;
  private JwtVerifier verifier;

  public Mocker() {
    this.crypto = new VirgilCrypto();
    VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

    VirgilPrivateKey privateKey = getApiPrivateKey();
    VirgilPrivateKey privateKeyFake = null;

    try {
      privateKeyFake = crypto
          .importPrivateKey(ConvertionUtils.base64ToBytes(FAKE_PRIVATE_KEY_BASE64)).getPrivateKey();
    } catch (CryptoException e) {
      fail("Mocker -> 'FAKE_PRIVATE_KEY_BASE64' seems to has wrong format");
    }

    jwtGenerator = initJwtGenerator(getAppId(), privateKey, getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), accessTokenSigner);

    jwtGeneratorSevenSeconds = initJwtGenerator(getAppId(), privateKey, getApiPublicKeyId(),
        TimeSpan.fromTime(7, TimeUnit.SECONDS), accessTokenSigner);

    jwtGeneratorFake = initJwtGenerator(getAppId(), privateKeyFake, getApiPublicKeyId(),
        TimeSpan.fromTime(1, TimeUnit.HOURS), accessTokenSigner);

    TimeSpan timeSpanExpired = TimeSpan.fromTime(1, TimeUnit.SECONDS);
    jwtGeneratorExpired = initJwtGenerator(getAppId(), privateKey, getApiPublicKeyId(),
        timeSpanExpired, accessTokenSigner);

    verifier = new JwtVerifier(getApiPublicKey(), getApiPublicKeyId(), accessTokenSigner);
  }

  public Jwt generateAccessToken(String identity) throws CryptoException {
    return jwtGenerator.generateToken(identity);
  }

  public RawSignedModel generateCardModel(String identity) throws CryptoException {
    Calendar calendar = Calendar.getInstance();
    calendar.set(Calendar.YEAR, 2018);
    calendar.set(Calendar.MONTH, 1);
    calendar.set(Calendar.DAY_OF_MONTH, 6);
    calendar.set(Calendar.HOUR_OF_DAY, 10);

    VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
    VirgilPublicKey publicKey = keyPairVirgiled.getPublicKey();
    VirgilPrivateKey privateKey = keyPairVirgiled.getPrivateKey();

    RawCardContent rawCardContent = new RawCardContent(identity,
        ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), "5.0",
        calendar.getTime());

    RawSignedModel cardModel = new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));

    ModelSigner signer = new ModelSigner(new VirgilCardCrypto());
    signer.selfSign(cardModel, privateKey);

    return cardModel;
  }

  public RawSignedModel generateCardModelSigned() throws CryptoException {
    Calendar calendar = Calendar.getInstance();
    calendar.set(Calendar.YEAR, 2018);
    calendar.set(Calendar.MONTH, 1);
    calendar.set(Calendar.DAY_OF_MONTH, 6);
    calendar.set(Calendar.HOUR_OF_DAY, 10);
    calendar.clear(Calendar.MILLISECOND);

    VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
    VirgilPublicKey publicKey = keyPairVirgiled.getPublicKey();
    VirgilPrivateKey privateKey = keyPairVirgiled.getPrivateKey();

    RawCardContent rawCardContent = new RawCardContent(Generator.identity(),
        ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), "5.0",
        calendar.getTime());

    RawSignedModel cardModel = new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));

    ModelSigner signer = new ModelSigner(new VirgilCardCrypto());
    signer.selfSign(cardModel, privateKey);

    return cardModel;
  }

  public RawSignedModel generateCardModelUnsigned(VirgilPublicKey publicKey)
      throws CryptoException {
    Calendar calendar = Calendar.getInstance();
    calendar.set(Calendar.YEAR, 2018);
    calendar.set(Calendar.MONTH, 1);
    calendar.set(Calendar.DAY_OF_MONTH, 6);
    calendar.set(Calendar.HOUR_OF_DAY, 10);
    calendar.clear(Calendar.MILLISECOND);

    RawCardContent rawCardContent = new RawCardContent(Generator.identity(),
        ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)), "5.0",
        calendar.getTime());

    return new RawSignedModel(ConvertionUtils.captureSnapshot(rawCardContent));
  }

  public Jwt generateExpiredAccessToken(String identity) throws CryptoException {
    return jwtGeneratorExpired.generateToken(identity);
  }

  public Jwt generateFakeAccessToken(String identity) throws CryptoException {
    return jwtGeneratorFake.generateToken(identity);
  }

  public VirgilPrivateKey generatePrivateKey() {
    try {
      return crypto.generateKeyPair().getPrivateKey();
    } catch (CryptoException e) {
      fail(e.getMessage());
      return null;
    }
  }

  public VirgilPublicKey generatePublicKey() {
    try {
      return crypto.generateKeyPair().getPublicKey();
    } catch (CryptoException e) {
      fail(e.getMessage());
      return null;
    }
  }

  public Jwt generateSevenSecondsAccessToken(String identity) throws CryptoException {
    return jwtGeneratorSevenSeconds.generateToken(identity);
  }

  public JwtGenerator getJwtGenerator() {
    return jwtGenerator;
  }

  public JwtGenerator getJwtGeneratorSevenSeconds() {
    return jwtGeneratorSevenSeconds;
  }

  public JwtGenerator getJwtGeneratorForSeconds(int seconds) {
    return jwtGeneratorSevenSeconds = initJwtGenerator(getAppId(), getApiPrivateKey(),
        getApiPublicKeyId(), TimeSpan.fromTime(seconds, TimeUnit.SECONDS),
        new VirgilAccessTokenSigner());
  }

  public JwtVerifier getVerifier() {
    return verifier;
  }

  private JwtGenerator initJwtGenerator(String appId, VirgilPrivateKey privateKey,
                                        String apiPublicKeyIdentifier, TimeSpan timeSpan,
                                        VirgilAccessTokenSigner accessTokenSigner) {
    return new JwtGenerator(appId, privateKey, apiPublicKeyIdentifier, timeSpan, accessTokenSigner);
  }
}
