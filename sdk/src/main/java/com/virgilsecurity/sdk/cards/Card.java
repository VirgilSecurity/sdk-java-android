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

import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.CardUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

import java.util.*;
import java.util.logging.Logger;

/**
 * The {@link Card} class is the main entity of Virgil Services. Every user/device is represented
 * with a Virgil Card which contains a public key and information about identity.
 */
public class Card {
  private static final Logger LOGGER = Logger.getLogger(Card.class.getName());

  private String identifier;

  private String identity;
  private VirgilPublicKey publicKey;
  private String version;
  private Date createdAt;
  private String previousCardId;
  private Card previousCard;
  private List<CardSignature> signatures;
  private boolean isOutdated;
  private byte[] contentSnapshot;

  /**
   * Parse card from provided raw signed model.
   *
   * @param cardCrypto The card crypto.
   * @param cardModel  The card model to be parsed.
   *
   * @return The card that is parsed from provided {@link RawSignedModel}.
   *
   * @throws CryptoException If any crypto operation fails.
   */
  public static Card parse(VirgilCardCrypto cardCrypto, RawSignedModel cardModel) throws CryptoException {
    if (cardCrypto == null) {
      throw new NullArgumentException("Card -> 'crypto' should not be null");
    }
    if (cardModel == null) {
      throw new NullArgumentException("Card -> 'cardModel' should not be null");
    }

    RawCardContent rawCardContent = ConvertionUtils
        .deserializeFromJson(new String(cardModel.getContentSnapshot()), RawCardContent.class);

    String cardId = CardUtils.generateCardId(cardCrypto, cardModel.getContentSnapshot());

    VirgilPublicKey publicKey =
        cardCrypto.importPublicKey(ConvertionUtils.base64ToBytes(rawCardContent.getPublicKey()));

    // Converting RawSignatures to CardSignatures
    List<CardSignature> cardSignatures = new ArrayList<>();
    if (cardModel.getSignatures() != null) {
      for (RawSignature rawSignature : cardModel.getSignatures()) {
        CardSignature.CardSignatureBuilder cardSignature = new CardSignature.CardSignatureBuilder(
            rawSignature.getSigner(), ConvertionUtils.base64ToBytes(rawSignature.getSignature()));
        if (rawSignature.getSnapshot() != null) {
          String snapshot = rawSignature.getSnapshot();
          Map<String, String> additionalDataSignature = ConvertionUtils
              .deserializeMapFromJson(ConvertionUtils.base64ToString(snapshot));

          cardSignature.snapshot(ConvertionUtils.base64ToBytes(snapshot));
          cardSignature.extraFields(additionalDataSignature);
        } else {
          LOGGER.info(
              String.format("Signature '%s' has no additional data", rawSignature.getSigner()));
        }

        cardSignatures.add(cardSignature.build());
      }
    } else {
      throw new VirgilCardVerificationException("Card should have at least self signature");
    }

    return new Card(cardId, rawCardContent.getIdentity(), publicKey, rawCardContent.getVersion(),
        rawCardContent.getCreatedAtDate(), rawCardContent.getPreviousCardId(), cardSignatures,
        cardModel.getContentSnapshot());
  }

  /**
   * Instantiates a new Card.
   *
   * @param identifier      Uniquely identifies the Card in Virgil Services.
   * @param identity        Unique identity value.
   * @param publicKey       The public key.
   * @param version         The version of Card (ex. "5.0").
   * @param createdAt       When the Card was created at.
   * @param signatures      The list of signatures.
   * @param contentSnapshot The card content snapshot.
   */
  public Card(String identifier, String identity, VirgilPublicKey publicKey, String version,
              Date createdAt, List<CardSignature> signatures, byte[] contentSnapshot) {
    this.identifier = identifier;
    this.identity = identity;
    this.publicKey = publicKey;
    this.version = version;
    this.createdAt = createdAt;
    this.signatures = signatures;
    this.contentSnapshot = contentSnapshot;
  }

  /**
   * Instantiates a new Card.
   *
   * @param identifier      Uniquely identifies the Card in Virgil Services.
   * @param identity        Unique identity value.
   * @param publicKey       The public key.
   * @param version         The version of Card (ex. "5.0").
   * @param createdAt       When the Card was created at.
   * @param previousCardId  The previous Card identifier that current card is used to override.
   * @param previousCard    The previous Card that current card is used to override.
   * @param signatures      The list of signatures.
   * @param isOutdated      Whether the card is overridden by another card.
   * @param contentSnapshot The card content snapshot.
   */
  public Card(String identifier, String identity, VirgilPublicKey publicKey, String version,
              Date createdAt, String previousCardId, Card previousCard, List<CardSignature> signatures,
              boolean isOutdated, byte[] contentSnapshot) {
    this.identifier = identifier;
    this.identity = identity;
    this.publicKey = publicKey;
    this.version = version;
    this.createdAt = createdAt;
    this.previousCardId = previousCardId;
    this.previousCard = previousCard;
    this.signatures = signatures;
    this.isOutdated = isOutdated;
    this.contentSnapshot = contentSnapshot;
  }

  /**
   * Instantiates a new Card.
   *
   * @param identifier      Uniquely identifies the Card in Virgil Services.
   * @param identity        Unique identity value.
   * @param publicKey       The public key.
   * @param version         The version of Card (ex. "5.0").
   * @param createdAt       When the Card was created at.
   * @param previousCardId  The previous Card identifier that current card is used to override.
   * @param previousCard    The previous Card that current card is used to override.
   * @param signatures      The list of signatures.
   * @param contentSnapshot The card content snapshot.
   */
  public Card(String identifier, String identity, VirgilPublicKey publicKey, String version,
              Date createdAt, String previousCardId, Card previousCard, List<CardSignature> signatures,
              byte[] contentSnapshot) {
    this.identifier = identifier;
    this.identity = identity;
    this.publicKey = publicKey;
    this.version = version;
    this.createdAt = createdAt;
    this.previousCardId = previousCardId;
    this.previousCard = previousCard;
    this.signatures = signatures;
    this.contentSnapshot = contentSnapshot;
  }

  /**
   * Instantiates a new Card.
   *
   * @param identifier      Uniquely identifies the Card in Virgil Services.
   * @param identity        Unique identity value.
   * @param publicKey       The public key.
   * @param version         The version of Card (ex. "5.0").
   * @param createdAt       When the Card was created at.
   * @param previousCardId  The previous Card identifier that current card is used to override.
   * @param signatures      The list of signatures.
   * @param contentSnapshot The card content snapshot.
   */
  public Card(String identifier, String identity, VirgilPublicKey publicKey, String version,
              Date createdAt, String previousCardId, List<CardSignature> signatures,
              byte[] contentSnapshot) {
    this.identifier = identifier;
    this.identity = identity;
    this.publicKey = publicKey;
    this.version = version;
    this.createdAt = createdAt;
    this.previousCardId = previousCardId;
    this.signatures = signatures;
    this.contentSnapshot = contentSnapshot;
  } // TODO move to builder?

  /**
   * Get Card's content snapshot which is representation of {@link RawCardContent}.
   *
   * @return The content snapshot as byte [ ].
   */
  public byte[] getContentSnapshot() {
    return contentSnapshot;
  }

  /**
   * Gets the date and time fo card creation in UTC.
   *
   * @return The created at.
   */
  public Date getCreatedAt() {
    return createdAt;
  }

  /**
   * Gets the Card identifier that uniquely identifies the Card in Virgil Services.
   *
   * @return The Card identifier.
   */
  public String getIdentifier() {
    return identifier;
  }

  /**
   * Gets the identity value that can be anything which identifies the user in your application.
   *
   * @return The identity.
   */
  public String getIdentity() {
    return identity;
  }

  /**
   * Get previous Card that current card is used to override to.
   *
   * @return The previous card.
   */
  public Card getPreviousCard() {
    return previousCard;
  }

  /**
   * Get previous Card identifier that current card is used to override to.
   *
   * @return The previous card id.
   */
  public String getPreviousCardId() {
    return previousCardId;
  }

  /**
   * Gets the public key.
   *
   * @return The public key.
   */
  public VirgilPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Gets raw signed model from current Card.
   *
   * @return The {@link RawSignedModel} exported from this Card.
   */
  public RawSignedModel getRawCard() {
    RawSignedModel cardModel = new RawSignedModel(contentSnapshot);

    for (CardSignature signature : signatures) {
      if (signature.getSnapshot() != null) {
        cardModel
            .addSignature(new RawSignature(ConvertionUtils.toBase64String(signature.getSnapshot()),
                signature.getSigner(), ConvertionUtils.toBase64String(signature.getSignature())));
      } else {
        cardModel.addSignature(new RawSignature(signature.getSigner(),
            ConvertionUtils.toBase64String(signature.getSignature())));
      }
    }

    return cardModel;
  }

  /**
   * Gets self signature.
   *
   * @return The self {@link CardSignature}.
   *
   * @throws VirgilCardVerificationException If self signature was not found in signatures list.
   */
  public CardSignature getSelfSignature() throws VirgilCardVerificationException {
    for (CardSignature cardSignature : signatures) {
      if (cardSignature.getSigner().equals(SignerType.SELF.getRawValue())) {
        return cardSignature;
      }
    }

    LOGGER.warning("Card must have self signature");
    throw new VirgilCardVerificationException("Card -> card must have 'self' signature");
  }

  /**
   * Gets a list of signatures.
   *
   * @return the signatures
   */
  public List<CardSignature> getSignatures() {
    return signatures;
  }

  /**
   * Gets the version of the card.
   *
   * @return The version.
   */
  public String getVersion() {
    return version;
  }

  @Override
  public int hashCode() {

    return Objects.hash(identifier, identity, publicKey, version, createdAt, previousCardId,
        previousCard, signatures, isOutdated);
  }

  /**
   * Whether the card is overridden by another card.
   *
   * @return If the Card is outdated - {@code true}, otherwise {@code false}.
   */
  public boolean isOutdated() {
    return isOutdated;
  }

  /**
   * Sets Card's content snapshot which is representation of {@link RawCardContent}.
   *
   * @param contentSnapshot The content snapshot as byte [ ].
   */
  public void setContentSnapshot(byte[] contentSnapshot) {
    this.contentSnapshot = contentSnapshot;
  }

  /**
   * Sets whether the card is overridden by another card.
   *
   * @param outdated If the Card is outdated - {@code true}, otherwise {@code false}.
   */
  public void setOutdated(boolean outdated) {
    isOutdated = outdated;
  }

  /**
   * Set previous Card that current card is used to override to.
   *
   * @param previousCard The previous card.
   */
  public void setPreviousCard(Card previousCard) {
    Validator.checkNullAgrument(previousCard, "Card -> 'previousCard' should not be null");
    this.previousCard = previousCard;
  }
}
