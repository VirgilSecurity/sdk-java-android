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

import com.virgilsecurity.sdk.CompatibilityDataProvider;
import com.virgilsecurity.sdk.cards.CardManager.SignCallback;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.VirgilCardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.TestUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.HttpURLConnection;
import java.util.*;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.JSON;
import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static com.virgilsecurity.sdk.utils.TestUtils.assertCardModelsEquals;
import static com.virgilsecurity.sdk.utils.TestUtils.assertCardsEquals;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class CardsManagerTest extends PropertyManager {

  private static final String SIGNER_TYPE_EXTRA = "bestsignerever";

  private Mocker mocker;
  private VirgilCrypto crypto;
  private VirgilCardCrypto cardCrypto;
  private VirgilCardClient cardClient;
  private CardManager cardManager;
  private VirgilCardVerifier cardVerifier;
  private CompatibilityDataProvider dataProvider;

  @BeforeEach
  public void setUp() {
    mocker = new Mocker();
    crypto = new VirgilCrypto();
    cardCrypto = new VirgilCardCrypto();
    String url = getCardsServiceUrl();
    if (StringUtils.isBlank(url)) {
      cardClient = new VirgilCardClient();
    } else {
      cardClient = new VirgilCardClient(url);
    }
    cardVerifier = new VirgilCardVerifier(cardCrypto);
    if (!StringUtils.isBlank(getPropertyByName("CARDS_SERVICE_PUBLIC_KEY"))) {
      cardVerifier.setServiceKey(getPropertyByName("CARDS_SERVICE_PUBLIC_KEY"));
    }
    dataProvider = new CompatibilityDataProvider();
  }

  @Test
  public void stc_13_2() throws CryptoException, VirgilServiceException {
    // STC-13
    CardManager virgilCardManager = init_stc_13();
    assertThrows(VirgilCardVerificationException.class, () -> {
      virgilCardManager.importCardAsString(dataProvider.getTestDataAs(3, STRING));
    });
  }

  @Test
  public void stc_13_3() throws CryptoException, VirgilServiceException {
    // STC-13
    CardManager virgilCardManager = init_stc_13();
    assertThrows(VirgilCardVerificationException.class, () -> {
      virgilCardManager.importCardAsJson(dataProvider.getTestDataAs(3, JSON));
    });
  }

  @Test
  public void stc_13_4() throws CryptoException, VirgilServiceException {
    // STC-13
    CardManager virgilCardManager = init_stc_13();
    assertThrows(VirgilCardVerificationException.class, () -> {
      virgilCardManager.publishCard(RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
    });
  }

  @Test
  public void stc_13_5() throws CryptoException, VirgilServiceException {
    // STC-13
    CardManager virgilCardManager = init_stc_13();
    Card card = Card.parse(cardCrypto,
        RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
    assertThrows(VirgilCardVerificationException.class, () -> {
      virgilCardManager.getCard(card.getIdentifier());
    });
  }

  @Test
  public void stc_13_6() throws CryptoException, VirgilServiceException {
    // STC-13
    init_stc_13();
  }

  @Test
  public void stc_13_7() throws CryptoException, VirgilServiceException {
    // STC-13
    CardManager virgilCardManager = init_stc_13();
    Card card = Card.parse(cardCrypto,
        RawSignedModel.fromString(dataProvider.getTestDataAs(3, STRING)));
    assertThrows(VirgilCardVerificationException.class, () -> {
      virgilCardManager.searchCards(card.getIdentity());
    });
  }

  @Test
  public void stc_17() throws CryptoException, VirgilServiceException {
    // STC-17
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
    RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
        keyPairVirgiled.getPublicKey(), identity);
    Card generatedCard = Card.parse(cardCrypto, cardModel);
    Card publishedCard = cardManager.publishCard(cardModel);
    assertNotNull(publishedCard);

    assertFalse(publishedCard.isOutdated());
    assertCardsEquals(generatedCard, publishedCard);

    Card cardFromService = cardManager.getCard(generatedCard.getIdentifier());
    assertNotNull(cardFromService);
    assertFalse(cardFromService.isOutdated());
    assertCardsEquals(generatedCard, cardFromService);
  }

  @Test
  public void stc_18() throws CryptoException, VirgilServiceException {
    // STC-18
    String identity = Generator.identity();
    initCardManager(identity);

    Map<String, String> additionalData = new HashMap<>();
    additionalData.put("Sense of life", "42");
    additionalData.put("Secret but not secret", "idn");

    VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
    RawSignedModel cardModel = cardManager.generateRawCard(keyPairVirgiled.getPrivateKey(),
        keyPairVirgiled.getPublicKey(), identity, additionalData);
    Card generatedCard = Card.parse(cardCrypto, cardModel);
    Card publishedCard = cardManager.publishCard(cardModel);
    assertNotNull(publishedCard);

    assertFalse(publishedCard.isOutdated());
    assertCardsEquals(generatedCard, publishedCard);

    Card cardFromService = cardManager.getCard(generatedCard.getIdentifier());
    assertNotNull(cardFromService);
    assertFalse(cardFromService.isOutdated());
    assertCardsEquals(generatedCard, cardFromService);
  }

  @Test
  public void stc_19() throws CryptoException, VirgilServiceException, InterruptedException {
    // STC-19
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairVirgiled1 = crypto.generateKeyPair();
    RawSignedModel cardModel1 = cardManager.generateRawCard(keyPairVirgiled1.getPrivateKey(),
        keyPairVirgiled1.getPublicKey(), identity);
    Card generatedCard1 = Card.parse(cardCrypto, cardModel1);
    Card publishedCard1 = cardManager.publishCard(cardModel1);
    assertNotNull(publishedCard1);

    assertFalse(publishedCard1.isOutdated());
    assertCardsEquals(generatedCard1, publishedCard1);

    Card cardFromService1 = cardManager.getCard(generatedCard1.getIdentifier());
    assertNotNull(cardFromService1);
    assertFalse(cardFromService1.isOutdated());
    assertCardsEquals(generatedCard1, cardFromService1);

    // Generate KeyPair2
    VirgilKeyPair keyPairVirgiled2 = crypto.generateKeyPair();
    RawSignedModel cardModel2 = cardManager.generateRawCard(keyPairVirgiled2.getPrivateKey(),
        keyPairVirgiled2.getPublicKey(), identity, generatedCard1.getIdentifier());
    Card generatedCard2 = Card.parse(cardCrypto, cardModel2);

    // Call publishCard(privateKey2, publicKey2, Card1.identifier)
    Card publishedCard2 = cardManager.publishCard(cardModel2);
    // Card2 is successfully created and matches card that was generated on the client side
    assertNotNull(publishedCard2);
    assertFalse(publishedCard2.isOutdated());
    assertCardsEquals(generatedCard2, publishedCard2);
    assertEquals(cardFromService1.getIdentifier(), publishedCard2.getPreviousCardId());

    // Get Card2 using getCard
    Card cardFromService2 = cardManager.getCard(generatedCard2.getIdentifier());
    // Card2 is successfully retrieved and matches card that was generated on the client side
    // (including
    // previousCardId and isOutdated=false).
    assertNotNull(cardFromService2);
    assertFalse(cardFromService2.isOutdated());
    assertCardsEquals(generatedCard2, cardFromService2);
    assertEquals(cardFromService1.getIdentifier(), cardFromService2.getPreviousCardId());

    // Get Card1 using getCard
    Card outdatedCard = cardManager.getCard(generatedCard1.getIdentifier());
    // Card1 is successfully retrieved and matches card that was generated on the client side.
    // (isOutdated=true)
    assertNotNull(outdatedCard);
    assertTrue(outdatedCard.isOutdated());
    generatedCard1.setOutdated(true);
    assertCardsEquals(generatedCard1, outdatedCard);
  }

  @Test
  public void stc_20() throws CryptoException, VirgilServiceException {
    // STC-20
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairVirgiledOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
        keyPairVirgiledOne.getPublicKey(), identity);
    Card publishedCardOne = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCardOne);

    VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeyPair();
    RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
        keyPairVirgiledTwo.getPublicKey(), identity, publishedCardOne.getIdentifier());
    Card publishedCardTwo = cardManager.publishCard(cardModelTwo);
    assertNotNull(publishedCardTwo);

    VirgilKeyPair keyPairVirgiledThree = crypto.generateKeyPair();
    RawSignedModel cardModelThree = cardManager.generateRawCard(
        keyPairVirgiledThree.getPrivateKey(), keyPairVirgiledThree.getPublicKey(), identity);
    Card publishedCardThree = cardManager.publishCard(cardModelThree);
    assertNotNull(publishedCardThree);

    List<Card> searchedCards = cardManager.searchCards(identity);
    assertNotNull(searchedCards);
    assertEquals(2, searchedCards.size());

    Card singleCardFromChain = null;
    Card newCardFromChain = null;
    for (Card card : searchedCards) {
      if (card.getIdentifier().equals(publishedCardTwo.getIdentifier())) {
        newCardFromChain = card;
      } else if (card.getIdentifier().equals(publishedCardThree.getIdentifier())) {
        singleCardFromChain = card;
      } else {
        fail();
      }
    }

    assertNotNull(singleCardFromChain);
    assertNotNull(newCardFromChain);

    assertEquals(publishedCardOne.getIdentifier(), newCardFromChain.getPreviousCardId());
    assertCardModelsEquals(publishedCardOne.getRawCard(),
        newCardFromChain.getPreviousCard().getRawCard());
    assertFalse(newCardFromChain.isOutdated());

    assertCardsEquals(publishedCardThree, singleCardFromChain);
  }

  @Test
  public void stc_21() throws CryptoException, VirgilServiceException {
    // STC-21
    String identity = Generator.identity();

    CardManager cardManagerExtraSign = new CardManager(cardCrypto,
        new GeneratorJwtProvider(mocker.getJwtGenerator(), identity), cardVerifier, cardClient,
        new CardManager.SignCallback() {
          @Override
          public RawSignedModel onSign(RawSignedModel cardModel) {
            ModelSigner modelSigner = new ModelSigner(cardCrypto);
            try {
              VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
              modelSigner.sign(cardModel, SIGNER_TYPE_EXTRA, keyPairVirgiled.getPrivateKey());
            } catch (CryptoException e) {
              fail(e.getMessage());
            }

            return cardModel;
          }
        }, false);

    VirgilKeyPair keyPairVirgiled = crypto.generateKeyPair();
    RawSignedModel cardModel = cardManagerExtraSign.generateRawCard(keyPairVirgiled.getPrivateKey(),
        keyPairVirgiled.getPublicKey(), identity);
    Card generatedCard = Card.parse(cardCrypto, cardModel);

    Card publishedCard = cardManagerExtraSign.publishCard(cardModel);
    assertNotNull(publishedCard);
    assertEquals(publishedCard.getSignatures().size(), 3);

    assertCardsEquals(generatedCard, publishedCard);
  }

  @Test
  public void stc_34() throws CryptoException, VirgilServiceException {
    // STC-34
    ModelSigner modelSigner = new ModelSigner(this.cardCrypto);
    AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
    CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
    VirgilCardClient cardClient = Mockito.mock(VirgilCardClient.class);
    SignCallback signCallback = Mockito.mock(SignCallback.class);
    CardManager cardManager = new CardManager(this.cardCrypto, accessTokenProvider, cardVerifier,
        cardClient, signCallback, false);
    Jwt jwt = Mockito.mock(Jwt.class);

    when(jwt.stringRepresentation()).thenReturn("");
    when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

    String cardId = "375f795bf6799b18c4836d33dce5208daf0895a3f7aacbcd0366529aed2345d4";
    RawSignedModel cardModel = RawSignedModel
        .fromString(dataProvider.getString("STC-34.as_string"));
    Tuple<RawSignedModel, Boolean> tuple = new Tuple<RawSignedModel, Boolean>(cardModel, false);
    when(cardClient.getCard(Mockito.anyString(), Mockito.anyString())).thenReturn(tuple);

    try {
      cardManager.getCard(cardId);
      fail("Service returned wrong card, but we didn't recognized that");
    } catch (VirgilCardServiceException e) {
      // It's OK if Error is thrown
    }
  }

  @Test
  public void stc_35_1() throws VirgilServiceException, CryptoException {
    // STC-35
    CardManager virgilCardManager = init_stc_35();

    RawSignedModel modelFromString = RawSignedModel
        .fromString(dataProvider.getTestDataAs(34, STRING));
    String testIdentity = RawCardContent.fromJson(new String(modelFromString.getContentSnapshot()))
        .getIdentity();

    RawCardContent cardContent = new RawCardContent(testIdentity,
        dataProvider.getJsonByKey(34, "public_key_base64"), new Date());
    RawSignedModel rawSignedModelTwo =
        new RawSignedModel(ConvertionUtils.base64ToBytes(cardContent.exportAsBase64String()));

    ModelSigner signer = new ModelSigner(cardCrypto);
    VirgilPrivateKey privateKey = crypto.importPrivateKey(
        ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "private_key_base64")))
        .getPrivateKey();
    signer.selfSign(rawSignedModelTwo, privateKey, ConvertionUtils
        .base64ToBytes(dataProvider.getJsonByKey(34, "self_signature_snapshot_base64")));

    assertThrows(VirgilCardServiceException.class, () -> {
      virgilCardManager.publishCard(rawSignedModelTwo);
    });
  }

  @Test
  public void stc_35_2() throws VirgilServiceException, CryptoException {
    // STC-35
    CardManager virgilCardManager = init_stc_35();

    ModelSigner signer = new ModelSigner(cardCrypto);
    VirgilPrivateKey privateKey = crypto.importPrivateKey(
        ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "private_key_base64")))
        .getPrivateKey();

    RawSignedModel rawSignedModel = new RawSignedModel(
        ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(34, "content_snapshot_base64")));
    signer.selfSign(rawSignedModel, privateKey, Generator.randomBytes(64));

    assertThrows(VirgilCardServiceException.class, () -> {
      virgilCardManager.publishCard(rawSignedModel);
    });
  }

  @Test
  public void stc_42() throws CryptoException, VirgilServiceException {
    // STC-42
    String identity1 = Generator.identity();
    String identity2 = Generator.identity();
    CardManager cardManager1 = initCardManager(identity1);
    CardManager cardManager2 = initCardManager(identity2);

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    Card i1Card1 = cardManager1.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(),
        identity1);
    assertNotNull(i1Card1);

    keyPair = crypto.generateKeyPair();
    Card i1Card2 = cardManager1.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(),
        identity1, i1Card1.getIdentifier());
    assertNotNull(i1Card2);
    assertNotNull(i1Card2.getPreviousCardId());
    i1Card1.setOutdated(true);
    i1Card2.setPreviousCard(i1Card1);

    keyPair = crypto.generateKeyPair();
    Card i2Card = cardManager2.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(),
        identity2);
    assertNotNull(i2Card);

    List<Card> cards = cardManager1.searchCards(Arrays.asList(identity1, identity2));
    assertNotNull(cards);
    assertEquals(2, cards.size());

    Card i1CardFound = TestUtils.getCardByIdentity(cards, identity1);
    assertNotNull(i1CardFound);
    TestUtils.assertCardsEquals(i1Card2, i1CardFound);

    Card i2CardFound = TestUtils.getCardByIdentity(cards, identity2);
    assertNotNull(i2CardFound);
    TestUtils.assertCardsEquals(i2Card, i2CardFound);
  }

  @Test
  public void delete_card() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairVirgiledOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
        keyPairVirgiledOne.getPublicKey(),
        identity);
    Card publishedCardOne = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCardOne);

    Card receivedCard = cardManager.getCard(publishedCardOne.getIdentifier());
    assertNotNull(receivedCard);
    assertCardsEquals(publishedCardOne, receivedCard);

    List<Card> searchedCards = cardManager.searchCards(identity);
    assertNotNull(searchedCards);
    assertEquals(1, searchedCards.size());

    cardManager.revokeCard(publishedCardOne.getIdentifier());

    Card receivedCardAfterDelete = cardManager.getCard(publishedCardOne.getIdentifier());
    assertNotNull(receivedCardAfterDelete);
    assertCardModelsEquals(publishedCardOne.getRawCard(), receivedCardAfterDelete.getRawCard());

    List<Card> searchedCardsAfterDelete = cardManager.searchCards(identity);
    assertNotNull(searchedCardsAfterDelete);
    assertEquals(0, searchedCardsAfterDelete.size());
  }

  @Test
  public void delete_card_from_chain() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    initCardManager(identity);

    // Publish 3 cards chain
    VirgilKeyPair keyPairVirgiledOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
        keyPairVirgiledOne.getPublicKey(),
        identity);
    Card publishedCardOne = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCardOne);

    VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeyPair();
    RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
        keyPairVirgiledTwo.getPublicKey(),
        identity,
        publishedCardOne.getIdentifier());
    Card publishedCardTwo = cardManager.publishCard(cardModelTwo);
    assertNotNull(publishedCardTwo);

    VirgilKeyPair keyPairVirgiledThree = crypto.generateKeyPair();
    RawSignedModel cardModelThree = cardManager.generateRawCard(keyPairVirgiledThree.getPrivateKey(),
        keyPairVirgiledThree.getPublicKey(),
        identity,
        publishedCardTwo.getIdentifier());
    Card publishedCardThree = cardManager.publishCard(cardModelThree);
    assertNotNull(publishedCardThree);

    List<Card> searchedCards = cardManager.searchCards(identity);
    assertNotNull(searchedCards);
    assertEquals(1, searchedCards.size());

    // Delete cards chain
    cardManager.revokeCard(publishedCardThree.getIdentifier());

    // Check that cards still exist
    Card receivedCardAfterDeleteOne = cardManager.getCard(publishedCardOne.getIdentifier());
    assertNotNull(receivedCardAfterDeleteOne);
    assertCardModelsEquals(publishedCardOne.getRawCard(), receivedCardAfterDeleteOne.getRawCard());

    Card receivedCardAfterDeleteTwo = cardManager.getCard(publishedCardTwo.getIdentifier());
    assertNotNull(receivedCardAfterDeleteTwo);
    assertCardModelsEquals(publishedCardTwo.getRawCard(), receivedCardAfterDeleteTwo.getRawCard());

    Card receivedCardAfterDeleteThree = cardManager.getCard(publishedCardThree.getIdentifier());
    assertNotNull(receivedCardAfterDeleteThree);
    assertCardModelsEquals(publishedCardThree.getRawCard(),
        receivedCardAfterDeleteThree.getRawCard());

    // Cards chain deleted - nothing will appear in search
    List<Card> searchedCardsAfterDelete = cardManager.searchCards(identity);
    assertNotNull(searchedCardsAfterDelete);
    assertEquals(0, searchedCardsAfterDelete.size());
  }

  @Test
  public void delete_card_from_middle_chain() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    initCardManager(identity);

    // Publish 3 cards chain
    VirgilKeyPair keyPairVirgiledOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairVirgiledOne.getPrivateKey(),
        keyPairVirgiledOne.getPublicKey(),
        identity);
    Card publishedCardOne = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCardOne);

    VirgilKeyPair keyPairVirgiledTwo = crypto.generateKeyPair();
    RawSignedModel cardModelTwo = cardManager.generateRawCard(keyPairVirgiledTwo.getPrivateKey(),
        keyPairVirgiledTwo.getPublicKey(),
        identity,
        publishedCardOne.getIdentifier());
    Card publishedCardTwo = cardManager.publishCard(cardModelTwo);
    assertNotNull(publishedCardTwo);

    VirgilKeyPair keyPairVirgiledThree = crypto.generateKeyPair();
    RawSignedModel cardModelThree = cardManager.generateRawCard(keyPairVirgiledThree.getPrivateKey(),
        keyPairVirgiledThree.getPublicKey(),
        identity,
        publishedCardTwo.getIdentifier());
    Card publishedCardThree = cardManager.publishCard(cardModelThree);
    assertNotNull(publishedCardThree);

    List<Card> searchedCards = cardManager.searchCards(identity);
    assertNotNull(searchedCards);
    assertEquals(1, searchedCards.size());

    boolean failed = false;
    try {
      cardManager.revokeCard(publishedCardTwo.getIdentifier());
    } catch (VirgilServiceException e) {
      failed = true;
    }
    assertTrue(failed);
  }

  @Test
  public void revoke_card() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairOne.getPrivateKey(),
        keyPairOne.getPublicKey(),
        identity);
    Card publishedCard = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCard);
    TestUtils.assertCardModelsEquals(cardModelOne, publishedCard.getRawCard());

    cardManager.revokeCard(publishedCard.getIdentifier());

    Card revokedCard = cardManager.getCard(publishedCard.getIdentifier());
    assertTrue(revokedCard.isOutdated());

    List<Card> searchedModels = cardManager.searchCards(identity);
    assertEquals(searchedModels.size(), 0);
  }

  @Test
  public void revoke_other_unauthorized_id() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    initCardManager(identity);

    VirgilKeyPair keyPairOne = crypto.generateKeyPair();
    RawSignedModel cardModelOne = cardManager.generateRawCard(keyPairOne.getPrivateKey(),
        keyPairOne.getPublicKey(),
        identity);
    Card publishedCard = cardManager.publishCard(cardModelOne);
    assertNotNull(publishedCard);
    TestUtils.assertCardModelsEquals(cardModelOne, publishedCard.getRawCard());

    String identityTwo = Generator.identity();
    initCardManager(identityTwo);

    try {
      cardManager.revokeCard(publishedCard.getIdentifier());
    } catch (Throwable throwable) {
      assertTrue(throwable instanceof VirgilCardServiceException);
      assertEquals(HttpURLConnection.HTTP_BAD_REQUEST,
          ((VirgilCardServiceException) throwable).getHttpError().getCode());
      assertEquals(40032,
          ((VirgilCardServiceException) throwable).getErrorCode());
    }
  }

  private CardManager init_stc_13() throws CryptoException, VirgilServiceException {
    CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
    Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(false);

    RawSignedModel modelFromString = RawSignedModel
        .fromString(dataProvider.getTestDataAs(3, STRING));

    VirgilCardClient cardClientMock = Mockito.mock(VirgilCardClient.class);
    Mockito.when(cardClientMock.publishCard(Mockito.any(RawSignedModel.class), Mockito.anyString()))
        .thenReturn(modelFromString);
    Mockito.when(cardClientMock.getCard(Mockito.anyString(), Mockito.anyString()))
        .thenReturn(new Tuple<>(modelFromString, false));
    Mockito.when(cardClientMock.searchCards(Mockito.anyString(), Mockito.anyString()))
        .thenReturn(Collections.singletonList(modelFromString));

    AccessToken jwt = Mockito.mock(AccessToken.class);
    Mockito.when(jwt.getIdentity()).thenReturn(
        RawCardContent.fromJson(new String(modelFromString.getContentSnapshot())).getIdentity());
    Mockito.when(jwt.stringRepresentation()).thenReturn("");

    AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
    Mockito.when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

    return new CardManager(cardCrypto, accessTokenProvider, cardVerifier, cardClientMock,
        new CardManager.SignCallback() {
          @Override
          public RawSignedModel onSign(RawSignedModel rawSignedModel) {
            return rawSignedModel;
          }
        }, false);
  }

  private CardManager init_stc_35() throws CryptoException, VirgilServiceException {
    CardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
    Mockito.when(cardVerifier.verifyCard(Mockito.any(Card.class))).thenReturn(true);

    RawSignedModel modelFromString = RawSignedModel
        .fromString(dataProvider.getTestDataAs(34, STRING));

    VirgilCardClient cardClientMock = Mockito.mock(VirgilCardClient.class);
    Mockito.when(cardClientMock.publishCard(Mockito.any(RawSignedModel.class), Mockito.anyString()))
        .thenReturn(modelFromString);

    AccessToken jwt = Mockito.mock(AccessToken.class);
    Mockito.when(jwt.getIdentity()).thenReturn(
        RawCardContent.fromJson(new String(modelFromString.getContentSnapshot())).getIdentity());
    Mockito.when(jwt.stringRepresentation()).thenReturn(UUID.randomUUID().toString());

    AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
    Mockito.when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(jwt);

    return new CardManager(cardCrypto, accessTokenProvider, cardVerifier, cardClientMock,
        new CardManager.SignCallback() {
          @Override
          public RawSignedModel onSign(RawSignedModel rawSignedModel) {
            return rawSignedModel;
          }
        }, false);
  }

  private CardManager initCardManager(String identity) {
    CardManager cardManager = new CardManager(cardCrypto,
        new GeneratorJwtProvider(mocker.getJwtGenerator(), identity), cardVerifier, cardClient,
        new CardManager.SignCallback() {
          @Override
          public RawSignedModel onSign(RawSignedModel rawSignedModel) {
            return rawSignedModel;
          }
        }, false);
    this.cardManager = cardManager;
    return cardManager;
  }
}
