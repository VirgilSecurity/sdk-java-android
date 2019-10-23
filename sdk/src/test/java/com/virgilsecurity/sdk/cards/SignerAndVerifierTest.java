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

package com.virgilsecurity.sdk.cards;

import com.virgilsecurity.crypto.foundation.CtrDrbg;
import com.virgilsecurity.sdk.CompatibilityDataProvider;
import com.virgilsecurity.sdk.cards.CardManager.SignCallback;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VerifierCredentials;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.cards.validation.Whitelist;
import com.virgilsecurity.sdk.client.VirgilCardClient;
import com.virgilsecurity.sdk.client.exceptions.SignatureNotUniqueException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.*;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class SignerAndVerifierTest extends PropertyManager {

  private static final String TEST_SIGNER_TYPE = "test_custom_type";

  private static final String TEST_KEY_ONE = "TEST_KEY_ONE";
  private static final String TEST_VALUE_ONE = "TEST_VALUE_ONE";
  private static final String TEST_KEY_TWO = "TEST_KEY_TWO";
  private static final String TEST_VALUE_TWO = "TEST_VALUE_TWO";

  private VirgilCrypto virgilCrypto;
  private VirgilCardCrypto cardCrypto;
  private ModelSigner modelSigner;
  private Mocker mocker;
  private CompatibilityDataProvider dataProvider;
  private CtrDrbg random;

  @BeforeEach
  public void setUp() {
    virgilCrypto = new VirgilCrypto();
    this.random = new CtrDrbg();
    this.random.setupDefaults();
    cardCrypto = new VirgilCardCrypto();
    modelSigner = new ModelSigner(cardCrypto);
    mocker = new Mocker();
    dataProvider = new CompatibilityDataProvider();
  }

  @Test
  public void stc_10_emptyVerifier_should_verifyCard() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        new ArrayList<Whitelist>());

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @SuppressWarnings("unused")
  @Test
  public void stc_10_verifier_should_verifyCard_ifCardHasAtLeastOneSignatureFromWhiteList()
      throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    final Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilPrivateKey privateKey1 = virgilCrypto
        .importPrivateKey(
            ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")))
        .getPrivateKey();
    VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);

    VirgilKeyPair keyPair2 = this.virgilCrypto.generateKeyPair();
    VirgilPrivateKey privateKey2 = keyPair2.getPrivateKey();
    VirgilPublicKey publicKey2 = keyPair2.getPublicKey();

    VirgilKeyPair keyPair3 = this.virgilCrypto.generateKeyPair();
    VirgilPrivateKey privateKey3 = keyPair3.getPrivateKey();
    VirgilPublicKey publicKey3 = keyPair3.getPublicKey();

    List<VerifierCredentials> verifierCredentialsList1 = new ArrayList<>();
    verifierCredentialsList1
        .add(new VerifierCredentials("extra", virgilCrypto.exportPublicKey(publicKey1)));
    verifierCredentialsList1
        .add(new VerifierCredentials("extra2", virgilCrypto.exportPublicKey(publicKey2)));
    Whitelist whitelist1 = new Whitelist(verifierCredentialsList1);

    List<VerifierCredentials> verifierCredentialsList2 = new ArrayList<>();
    verifierCredentialsList2
        .add(new VerifierCredentials("extra3", virgilCrypto.exportPublicKey(publicKey3)));
    Whitelist whitelist2 = new Whitelist(verifierCredentialsList2);

    List<Whitelist> whitelists = new ArrayList<>();
    whitelists.add(whitelist1);
    whitelists.add(whitelist2);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        whitelists);

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @Test
  public void stc_10_verifier_shouldNot_verifyCard_ifCardDoesntHaveSignatureOfAtLeastOneWhiteList()
      throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    final Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilPrivateKey privateKey1 = virgilCrypto
        .importPrivateKey(
            ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")))
        .getPrivateKey();
    VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);
    VirgilPublicKey publicKey2 = this.virgilCrypto.generateKeyPair().getPublicKey();

    List<VerifierCredentials> verifierCredentialsList1 = new ArrayList<>();
    verifierCredentialsList1.add(
        new VerifierCredentials("extra1", TestUtils.exportPublicKey(publicKey1.getPublicKey())));
    verifierCredentialsList1.add(
        new VerifierCredentials("extra2", TestUtils.exportPublicKey(publicKey2.getPublicKey())));
    Whitelist whitelist1 = new Whitelist(verifierCredentialsList1);
    List<Whitelist> whitelists = new ArrayList<>();
    whitelists.add(whitelist1);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        whitelists);

    assertFalse(virgilCardVerifier.verifyCard(card), "Card should NOT be verified");
  }

  @Test
  public void stc_10_verifier_shouldNot_verifyCard_ifMissedRequiredSelfSignature()
      throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    for (RawSignature signature : rawSignedModel.getSignatures()) {
      if (SignerType.SELF.getRawValue().equals(signature.getSigner())) {
        rawSignedModel.getSignatures().remove(signature);
        break;
      }
    }
    Card card = Card.parse(cardCrypto, rawSignedModel);

    List<Whitelist> whitelists = new ArrayList<>();
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false,
        whitelists);

    assertFalse(virgilCardVerifier.verifyCard(card), "Card should NOT be verified");
  }

  @Test
  public void stc_10_verifier_shouldNot_verifyCard_ifVerifierHasEmptyWhiteList()
      throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    List<Whitelist> whitelists = new ArrayList<>();
    whitelists.add(new Whitelist(new ArrayList<VerifierCredentials>()));
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        whitelists);

    assertFalse(virgilCardVerifier.verifyCard(card), "Card should NOT be verified");
  }

  @Test
  public void stc_10_verifier_shouldNot_verifyCard_ifWrongSelfSignature() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    for (RawSignature signature : rawSignedModel.getSignatures()) {
      if (SignerType.SELF.getRawValue().equals(signature.getSigner())) {
        String sign = ConvertionUtils
            .toBase64String(this.virgilCrypto.generateSignature(rawSignedModel.getContentSnapshot(),
                this.virgilCrypto.generateKeyPair().getPrivateKey()));
        signature.setSignature(sign);
        break;
      }
    }
    Card card = Card.parse(cardCrypto, rawSignedModel);

    List<Whitelist> whitelists = new ArrayList<>();
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false,
        whitelists);

    assertFalse(virgilCardVerifier.verifyCard(card), "Card should NOT be verified");
  }

  @Test
  public void stc_10_verifier_shouldNot_verifyCard_ifWrongVirgilSignature() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    for (RawSignature signature : rawSignedModel.getSignatures()) {
      if (SignerType.VIRGIL.getRawValue().equals(signature.getSigner())) {
        String sign = ConvertionUtils
            .toBase64String(this.virgilCrypto.generateSignature(rawSignedModel.getContentSnapshot(),
                this.virgilCrypto.generateKeyPair().getPrivateKey()));
        signature.setSignature(sign);
        break;
      }
    }
    Card card = Card.parse(cardCrypto, rawSignedModel);

    List<Whitelist> whitelists = new ArrayList<>();
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true,
        whitelists);

    assertFalse(virgilCardVerifier.verifyCard(card), "Card should NOT be verified");
  }

  @Test
  public void stc_10_verifySelfAndVirgilSignWithEmptyWhiteList() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, true,
        new ArrayList<Whitelist>());

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @Test
  public void stc_10_verifySelfSignWithEmptyWhiteList() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false,
        new ArrayList<Whitelist>());

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @Test
  public void stc_10_verifyVirgilSignWithEmptyWhiteList() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true,
        new ArrayList<Whitelist>());

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @Test
  public void stc_10_whiteList1Key() throws CryptoException {
    // STC-10
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(10, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilPrivateKey privateKey1 = virgilCrypto
        .importPrivateKey(
            ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")))
        .getPrivateKey();
    VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        new ArrayList<Whitelist>());

    List<VerifierCredentials> verifierCredentialsList = new ArrayList<>();
    verifierCredentialsList
        .add(new VerifierCredentials("extra", virgilCrypto.exportPublicKey(publicKey1)));
    Whitelist whitelist1 = new Whitelist(verifierCredentialsList);
    virgilCardVerifier.addWhiteList(whitelist1);

    assertTrue(virgilCardVerifier.verifyCard(card), "Card should be verified");
  }

  @Test
  public void stc_11() throws CryptoException {
    // STC-11
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(11, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        Collections.<Whitelist>emptyList());
    assertTrue(virgilCardVerifier.verifyCard(card));

    virgilCardVerifier.setVerifySelfSignature(true);
    assertFalse(virgilCardVerifier.verifyCard(card));
  }

  @Test
  public void stc_12() throws CryptoException {
    // STC-12
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(12, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);

    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false);
    assertTrue(virgilCardVerifier.verifyCard(card));

    virgilCardVerifier.setVerifyVirgilSignature(true);
    assertFalse(virgilCardVerifier.verifyCard(card));
  }

  @Test
  public void stc_14() throws CryptoException {
    // STC-14
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(14, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true);
    assertFalse(virgilCardVerifier.verifyCard(card));
  }

  @Test
  public void stc_15() throws CryptoException {
    // STC-15
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(15, STRING));
    Card card = Card.parse(cardCrypto, rawSignedModel);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false);
    assertFalse(virgilCardVerifier.verifyCard(card));
  }

  @Test
  public void stc_16() throws CryptoException {
    // STC-16
    RawSignedModel rawSignedModel = RawSignedModel
        .fromString(dataProvider.getTestDataAs(16, STRING));
    final VirgilPublicKey publicKey = (VirgilPublicKey) cardCrypto.importPublicKey(
        ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(16, "public_key1_base64")));

    VirgilPublicKey publicKeyTwo = mocker.generatePublicKey();
    List<VerifierCredentials> verifierCredentialsList = new ArrayList<>();
    verifierCredentialsList.add(new VerifierCredentials(TEST_SIGNER_TYPE,
        TestUtils.exportPublicKey(publicKeyTwo.getPublicKey())));
    Whitelist whitelistOne = new Whitelist(verifierCredentialsList);
    List<Whitelist> whitelists = new ArrayList<>();
    whitelists.add(whitelistOne);

    Card card = Card.parse(cardCrypto, rawSignedModel);
    VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
        whitelists);
    assertFalse(virgilCardVerifier.verifyCard(card));

    verifierCredentialsList
        .add(new VerifierCredentials("extra", virgilCrypto.exportPublicKey(publicKey)));

    assertTrue(virgilCardVerifier.verifyCard(card));
  }

  @Test
  public void stc_26() throws CryptoException, VirgilServiceException, InterruptedException {
    // STC-26
    AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
    final CardVerifier cardVerifier = new VirgilCardVerifier(this.cardCrypto, false, false);
    String cardsServiceUrl = getCardsServiceUrl();

    VirgilCardClient cardClient;
    if (StringUtils.isBlank(cardsServiceUrl)) {
      cardClient = new VirgilCardClient();
    } else {
      cardClient = new VirgilCardClient(cardsServiceUrl);
    }
    SignCallback signCallback = Mockito.mock(SignCallback.class);

    String identity = Generator.identity();
    RawSignedModel rawSignedModel = mocker.generateCardModel(identity);
    AccessToken expiredToken = mocker.generateExpiredAccessToken(identity);
    AccessToken token = mocker.generateAccessToken(identity);
    when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(expiredToken,
        token);
    when(signCallback.onSign(Mockito.any(RawSignedModel.class))).thenReturn(rawSignedModel);

    CardManager cardManager = new CardManager(this.cardCrypto, accessTokenProvider, cardVerifier,
        cardClient, signCallback, true);

    // Let expiredToken to expire
    Thread.sleep(2000);

    Card card = cardManager.publishCard(rawSignedModel);
    assertNotNull(card);

    Card loadedCard = cardManager.getCard(card.getIdentifier());
    assertNotNull(loadedCard);

    List<Card> foundCards = cardManager.searchCards(card.getIdentity());
    assertNotNull(foundCards);
    assertEquals(1, foundCards.size());
  }

  @Test
  public void stc_8_extraSign_should_addValidSignature() throws CryptoException {
    // STC-8
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

    VirgilKeyPair keyPair2 = virgilCrypto.generateKeyPair();
    modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());

    assertEquals(2, cardModel.getSignatures().size());
    RawSignature extraSignature = cardModel.getSignatures().get(1);
    assertEquals("test_id", extraSignature.getSigner());
    assertNull(extraSignature.getSnapshot());
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
            cardModel.getContentSnapshot(), keyPair2.getPublicKey()));
  }

  @Test
  public void stc_8_secondExtraSign_should_throwException() throws CryptoException {
    // STC-8
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

    VirgilKeyPair keyPair2 = virgilCrypto.generateKeyPair();
    modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());
    assertThrows(SignatureNotUniqueException.class, () -> {
      modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());
    });
  }

  @Test
  public void stc_8_secondSelfSign_should_throwException() throws CryptoException {
    // STC-8
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    assertTrue(cardModel.getSignatures().isEmpty());

    modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    assertThrows(SignatureNotUniqueException.class, () -> {
      modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    });
  }

  @Test
  public void stc_8_selfSign_should_addValidSignature() throws CryptoException {
    // STC-8
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    assertTrue(cardModel.getSignatures().isEmpty());

    modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    assertEquals(1, cardModel.getSignatures().size());

    RawSignature selfSignature = cardModel.getSignatures().get(0);
    assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
    assertNull(selfSignature.getSnapshot());
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
            cardModel.getContentSnapshot(), keyPair.getPublicKey()));
  }

  @Test
  public void stc_8_selfSignWithSignatureSnapshot_should_addValidSignature()
      throws CryptoException {
    // STC-8
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    assertTrue(cardModel.getSignatures().isEmpty());

    byte[] signatureSnapshot = new byte[32];
    new Random().nextBytes(signatureSnapshot);

    modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), signatureSnapshot);
    assertEquals(1, cardModel.getSignatures().size());

    RawSignature selfSignature = cardModel.getSignatures().get(0);
    assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
    assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

    byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        signatureSnapshot);

    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
            extendedSnapshot, keyPair.getPublicKey()));
  }

  @Test
  public void stc_9_extraSignWithExtraFields_should_addValidSignature() throws CryptoException {
    // STC-9
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

    Map<String, String> additionalData = new HashMap<>();
    additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
    additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);

    final byte[] signatureSnapshot = ConvertionUtils.captureSnapshot(additionalData);

    VirgilKeyPair keyPair2 = virgilCrypto.generateKeyPair();
    modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), additionalData);

    assertEquals(2, cardModel.getSignatures().size());
    RawSignature extraSignature = cardModel.getSignatures().get(1);
    assertEquals("test_id", extraSignature.getSigner());
    assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), extraSignature.getSnapshot());

    byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        signatureSnapshot);
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
            extendedSnapshot, keyPair2.getPublicKey()));
  }

  @Test
  public void stc_9_extraSignWithSignatureSnapshot_should_addValidSignature()
      throws CryptoException {
    // STC-9
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
    modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

    byte[] signatureSnapshot = new byte[32];
    new Random().nextBytes(signatureSnapshot);

    VirgilKeyPair keyPair2 = virgilCrypto.generateKeyPair();
    modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);

    assertEquals(2, cardModel.getSignatures().size());
    RawSignature extraSignature = cardModel.getSignatures().get(1);
    assertEquals("test_id", extraSignature.getSigner());
    assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), extraSignature.getSnapshot());

    byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        signatureSnapshot);
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
            extendedSnapshot, keyPair2.getPublicKey()));
  }

  @Test
  public void stc_9_secondExtraSignWithSignatureSnapshot_should_throwException()
      throws CryptoException {
    // STC-9
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

    byte[] signatureSnapshot = new byte[32];
    new Random().nextBytes(signatureSnapshot);

    VirgilKeyPair keyPair2 = virgilCrypto.generateKeyPair();
    modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);
    assertThrows(SignatureNotUniqueException.class, () -> {
      modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);
    });
  }

  @Test
  public void stc_9_selfSignWithExtraFields_should_addValidSignature() throws CryptoException {
    // STC-9
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

    Map<String, String> additionalData = new HashMap<>();
    additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
    additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);

    final byte[] signatureSnapshot = ConvertionUtils.captureSnapshot(additionalData);
    modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), additionalData);
    assertEquals(1, cardModel.getSignatures().size());

    RawSignature selfSignature = cardModel.getSignatures().get(0);
    assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
    assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

    byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        signatureSnapshot);
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
            extendedSnapshot, keyPair.getPublicKey()));
  }

  @Test
  public void stc_9_selfSignWithSignatureSnapshot_should_addValidSignature()
      throws CryptoException {
    // STC-9
    VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
    RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

    byte[] signatureSnapshot = new byte[32];
    new Random().nextBytes(signatureSnapshot);

    modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), signatureSnapshot);
    assertEquals(1, cardModel.getSignatures().size());

    RawSignature selfSignature = cardModel.getSignatures().get(0);
    assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
    assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

    byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        signatureSnapshot);
    assertTrue(
        virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
            extendedSnapshot, keyPair.getPublicKey()));
  }

}