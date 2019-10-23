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

package com.virgilsecurity.sdk.utils;

import com.virgilsecurity.crypto.foundation.*;
import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.SignerType;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;

import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.fail;

public class TestUtils {

  public static void assertCardContentsEquals(RawCardContent expectedCardContent,
                                              RawCardContent actualCardContent) {
    if (!cardContentsEqualsSelfSignOnly(expectedCardContent, actualCardContent)) {
      fail("\nExpected card:\n" + expectedCardContent.toString() + "\n\nActual card:\n"
          + actualCardContent.toString());
    }
  }

  public static void assertCardModelsEquals(RawSignedModel expectedCardModel,
                                            RawSignedModel actualCardModel) {
    if (!cardModelsEqualsSelfSignOnly(expectedCardModel, actualCardModel)) {
      fail("\nExpected card:\n" + expectedCardModel.toString() + "\n\nActual card:\n"
          + actualCardModel.toString());
    }
  }

  public static void assertCardsEquals(Card expectedCard, Card actualCard) {
    if (!cardsEqualsSelfSignOnly(expectedCard, actualCard)) {
      fail("\nExpected card:\n" + ConvertionUtils.getGson().toJson(expectedCard)
          + "\n\nActual card:\n" + ConvertionUtils.getGson().toJson(actualCard));
    }
  }

  public static boolean cardContentsEqualsSelfSignOnly(RawCardContent cardContentOne,
                                                       RawCardContent cardContentTwo) {
    return Objects.equals(cardContentOne.getIdentity(), cardContentTwo.getIdentity())
        && Objects.equals(cardContentOne.getPublicKey(), cardContentTwo.getPublicKey())
        && Objects.equals(cardContentOne.getVersion(), cardContentTwo.getVersion())
        && cardContentOne.getCreatedAtTimestamp() == cardContentTwo.getCreatedAtTimestamp()
        && Objects.equals(cardContentOne.getPreviousCardId(), cardContentTwo.getPreviousCardId());
  }

  public static boolean cardModelsEqualsSelfSignOnly(RawSignedModel cardModelOne,
                                                     RawSignedModel cardModelTwo) {
    RawCardContent rawCardContentOne = ConvertionUtils
        .deserializeFromJson(new String(cardModelOne.getContentSnapshot()), RawCardContent.class);
    RawCardContent rawCardContentTwo = ConvertionUtils
        .deserializeFromJson(new String(cardModelTwo.getContentSnapshot()), RawCardContent.class);

    return cardContentsEqualsSelfSignOnly(rawCardContentOne, rawCardContentTwo)
        && Objects.equals(getSelfSignature(cardModelOne), getSelfSignature(cardModelTwo));
  }

  public static boolean cardsEqualsSelfSignOnly(Card cardOne, Card cardTwo) {
    if (cardOne == null && cardTwo == null) {
      return true;
    }
    if (cardOne == null || cardTwo == null) {
      return false;
    }
    return cardOne.isOutdated() == cardTwo.isOutdated()
        && Objects.equals(cardOne.getIdentifier(), cardTwo.getIdentifier())
        && Objects.equals(cardOne.getIdentity(), cardTwo.getIdentity())
        && Objects.equals(cardOne.getPublicKey(), cardTwo.getPublicKey())
        && Objects.equals(cardOne.getVersion(), cardTwo.getVersion())
        && Objects.equals(cardOne.getCreatedAt(), cardTwo.getCreatedAt())
        && Objects.equals(cardOne.getPreviousCardId(), cardTwo.getPreviousCardId())
        && cardsEqualsSelfSignOnly(cardOne.getPreviousCard(), cardTwo.getPreviousCard())
        && Objects.equals(getSelfSignature(cardOne), getSelfSignature(cardTwo));
  }

  public static byte[] exportPrivateKey(PrivateKey privateKey) {
    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer();
         CtrDrbg random = new CtrDrbg()) {
      serializer.setupDefaults();
      random.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(privateKey, random);
      RawPrivateKey rawPrivateKey = keyAlg.exportPrivateKey(privateKey);

      return serializer.serializePrivateKey(rawPrivateKey);
    }
  }

  public static byte[] exportPublicKey(PublicKey publicKey) {
    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer();
         CtrDrbg random = new CtrDrbg()) {
      serializer.setupDefaults();
      random.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(publicKey, random);
      RawPublicKey rawPublicKey = keyAlg.exportPublicKey(publicKey);

      return serializer.serializePublicKey(rawPublicKey);
    }
  }

  public static RawSignedModel getCardModelByIdentity(List<RawSignedModel> cardModels,
                                                      String identity) {
    if (cardModels == null || cardModels.isEmpty()) {
      return null;
    }
    for (RawSignedModel cardModel : cardModels) {
      RawCardContent rawCardContent = ConvertionUtils
          .deserializeFromJson(new String(cardModel.getContentSnapshot()), RawCardContent.class);

      if (identity.equals(rawCardContent.getIdentity())) {
        return cardModel;
      }
    }
    return null;
  }

  public static Card getCardByIdentity(List<Card> cards, String identity) {
    if (cards == null || cards.isEmpty()) {
      return null;
    }
    for (Card card : cards) {
      if (identity.equals(card.getIdentity())) {
        return card;
      }
    }
    return null;
  }

  private static CardSignature getSelfSignature(Card card) {
    for (CardSignature cardSignature : card.getSignatures()) {
      if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue())) {
        return cardSignature;
      }
    }

    throw new NullPointerException("Card -> card must have at least 'self' signature");
  }

  private static RawSignature getSelfSignature(RawSignedModel cardModel) {
    for (RawSignature cardSignature : cardModel.getSignatures()) {
      if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue())) {
        return cardSignature;
      }
    }

    throw new NullPointerException("Card -> card must have at least 'self' signature");
  }

}
