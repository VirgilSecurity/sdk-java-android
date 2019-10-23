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

package com.virgilsecurity.sdk.client;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.TestUtils;
import com.virgilsecurity.sdk.utils.Tuple;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class VirgilCardClientTest extends PropertyManager {

  private static final String IDENTITY = "SomeTestIdentity";

  private CardClient cardClient;
  private Mocker mocker;

  @BeforeEach
  public void setUp() {
    String url = getCardsServiceUrl();
    if (StringUtils.isBlank(url)) {
      cardClient = new VirgilCardClient();
    } else {
      cardClient = new VirgilCardClient(url);
    }
    mocker = new Mocker();
  }

  @Test
  public void stc_25_get() throws CryptoException {
    // STC-25
    try {
      cardClient.getCard(Generator.cardId(), "Try our fried tokens");
      fail();
    } catch (VirgilServiceException e) {
      assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpError().getCode());
      assertEquals(20303, e.getErrorCode());
    }
  }

  @Test
  public void stc_25_publish() throws CryptoException {
    // STC-25
    String identity = Generator.identity();

    try {
      cardClient.publishCard(mocker.generateCardModel(identity),
          mocker.generateFakeAccessToken(identity).stringRepresentation());
      fail();
    } catch (VirgilServiceException e) {
      assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpError().getCode());
      assertEquals(20303, e.getErrorCode());
    }
  }

  @Test
  public void stc_25_search() throws CryptoException {
    // STC-25
    String identity = Generator.identity();

    try {
      cardClient.searchCards(Generator.identity(),
          mocker.generateFakeAccessToken(identity).stringRepresentation());
      fail();
    } catch (VirgilServiceException e) {
      assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpError().getCode());
      assertEquals(20303, e.getErrorCode());
    }
  }

  @Test
  public void stc_27() throws CryptoException {
    // STC-27
    String identity = Generator.identity();
    String identitySecond = Generator.identity();

    try {
      cardClient.publishCard(mocker.generateCardModel(identity),
          mocker.generateAccessToken(identitySecond).stringRepresentation());
      fail();
    } catch (VirgilServiceException e) {
      assertEquals(40034, e.getErrorCode());
    }
  }

  @Test
  public void stc_41() throws CryptoException, VirgilServiceException {
    // STC-41
    String identity1 = Generator.identity();
    String identity2 = Generator.identity();

    RawSignedModel cardModel1 = cardClient.publishCard(mocker.generateCardModel(identity1),
        mocker.generateAccessToken(identity1).stringRepresentation());
    RawSignedModel cardModel2 = cardClient.publishCard(mocker.generateCardModel(identity2),
        mocker.generateAccessToken(identity2).stringRepresentation());

    List<RawSignedModel> foundCardModels = cardClient.searchCards(
        Arrays.asList(identity1, identity2),
        mocker.generateAccessToken(identity1).stringRepresentation());

    assertNotNull(foundCardModels);
    assertEquals(2, foundCardModels.size());

    RawSignedModel foundCardModel1 = TestUtils.getCardModelByIdentity(foundCardModels, identity1);
    assertNotNull(foundCardModel1);
    assertEquals(cardModel1, foundCardModel1);

    RawSignedModel foundCardModel2 = TestUtils.getCardModelByIdentity(foundCardModels, identity2);
    assertNotNull(foundCardModel2);
    assertEquals(cardModel2, foundCardModel2);
  }

  @Test
  public void tokenVerification() throws CryptoException {
    Jwt accessToken = mocker.generateAccessToken(IDENTITY);
    assertTrue(mocker.getVerifier().verifyToken(accessToken));
  }

  @Test
  public void validTokenPublish() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();

    RawSignedModel cardModelBeforePublish = mocker.generateCardModel(identity);

    RawSignedModel cardModelAfterPublish = cardClient.publishCard(cardModelBeforePublish,
        mocker.generateAccessToken(identity).stringRepresentation());

    TestUtils.assertCardModelsEquals(cardModelBeforePublish, cardModelAfterPublish);
  }

  @Test
  public void revoke_card() throws CryptoException, VirgilServiceException {
    String identity = Generator.identity();
    RawSignedModel cardModelBeforePublish = mocker.generateCardModel(identity);
    assertNotNull(cardModelBeforePublish);

    RawSignedModel cardModelAfterPublish =
        cardClient.publishCard(cardModelBeforePublish,
            mocker.generateAccessToken(identity).stringRepresentation());
    assertNotNull(cardModelAfterPublish);
    TestUtils.assertCardModelsEquals(cardModelBeforePublish, cardModelAfterPublish);

    Card publishedCard = Card.parse(new VirgilCardCrypto(), cardModelAfterPublish);
    assertNotNull(publishedCard);

    cardClient.revokeCard(publishedCard.getIdentifier(),
        mocker.generateAccessToken(identity).stringRepresentation());

    Tuple<RawSignedModel, Boolean> revokedTuple =
        cardClient.getCard(publishedCard.getIdentifier(),
            mocker.generateAccessToken(identity).stringRepresentation());

    assertTrue(revokedTuple.getRight());

    List<RawSignedModel> searchedModels =
        cardClient.searchCards(identity,
            mocker.generateAccessToken(identity).stringRepresentation());
    assertEquals(searchedModels.size(), 0);
  }
}
