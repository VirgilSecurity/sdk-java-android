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

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.common.StringEncoding;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

/**
 * This is utils class which implements Card-specific functionality.
 *
 * @author Andrii Iakovenko.
 */
public class CardUtils {
  private static final Logger LOGGER = Logger.getLogger(CardUtils.class.getName());

  /**
   * Generate Virgil Card identifier by card content snapshot.
   *
   * @param cardCrypto      The {@link VirgilCardCrypto}.
   * @param contentSnapshot The card content snapshot.
   *
   * @return The generated Virgil Card identifier.
   */
  public static String generateCardId(VirgilCardCrypto cardCrypto, byte[] contentSnapshot) {
    byte[] fingerprint = Arrays.copyOfRange(cardCrypto.computeSha512(contentSnapshot), 0, 32);
    String cardId = ConvertionUtils.toString(fingerprint, StringEncoding.HEX);

    return cardId;
  }

  /**
   * Parse Card models into Cards.
   *
   * @param crypto     The {@linkplain VirgilCardCrypto}.
   * @param cardModels Card models.
   *
   * @return List of {@linkplain Card}s.
   *
   * @throws CryptoException If parsing failed.
   */
  public static List<Card> parseCards(VirgilCardCrypto crypto, List<RawSignedModel> cardModels)
      throws CryptoException {
    List<Card> cards = new ArrayList<>();
    for (RawSignedModel cardModel : cardModels) {
      cards.add(Card.parse(crypto, cardModel));
    }
    return cards;
  }

  /**
   * Check if identities provided for search are equals to Cards identities.
   *
   * @param cards      The {@linkplain Card}s.
   * @param identities The identites.
   *
   * @throws VirgilCardServiceException If some service error has happened.
   */
  public static void validateCardsWithIdentities(Collection<Card> cards,
                                                 Collection<String> identities) throws VirgilCardServiceException {
    for (Card card : cards) {
      boolean found = false;
      for (String identity : identities) {
        if (identity.equals(card.getIdentity())) {
          found = true;
          break;
        }
      }
      if (!found) {
        String msg = String.format("Card '%s' verification was failed", card.getIdentifier());
        LOGGER.warning(msg);
        throw new VirgilCardServiceException(msg);
      }
    }
  }
}
