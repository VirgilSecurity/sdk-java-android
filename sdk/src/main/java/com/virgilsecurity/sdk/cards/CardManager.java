/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

import com.virgilsecurity.common.util.Validator;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.client.VirgilCardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.CardUtils;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import com.virgilsecurity.sdk.utils.Tuple;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The {@link CardManager} class provides list of methods to work with {@link Card}.
 */
public class CardManager {
  /**
   * The interface that provides sign callback to let user perform some custom predefined signing
   * actions when generating raw card.
   */
  public interface SignCallback {
    /**
     * On sign raw signed model callback than will be called when raw card is about to be generated.
     *
     * @param rawSignedModel The raw signed model.
     *
     * @return The raw signed model.
     *
     * @see #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String, String, Map)
     */
    RawSignedModel onSign(RawSignedModel rawSignedModel);
  }

  private static final Logger LOGGER = Logger.getLogger(CardManager.class.getName());
  private static final String CURRENT_CARD_VERSION = "5.0";
  private static final String TOKEN_CONTEXT_OPERATION_DELETE = "delete";
  private static final String TOKEN_CONTEXT_OPERATION_PUBLISH = "publish";
  private static final String TOKEN_CONTEXT_OPERATION_GET = "get";
  private static final String TOKEN_CONTEXT_OPERATION_SEARCH = "search";
  private static final String TOKEN_CONTEXT_OPERATION_GET_OUTDATED = "get-outdated";

  private static final String TOKEN_CONTEXT_SERVICE = "cards";
  private ModelSigner modelSigner;
  private VirgilCardCrypto crypto;
  private AccessTokenProvider accessTokenProvider;
  private CardVerifier cardVerifier;
  private VirgilCardClient cardClient;
  private SignCallback signCallback;

  private boolean retryOnUnauthorized;

  /**
   * Instantiates a new Card manager.
   *
   * @param crypto              The crypto.
   * @param accessTokenProvider The access token provider.
   * @param cardVerifier        The card verifier.
   */
  public CardManager(VirgilCardCrypto crypto, AccessTokenProvider accessTokenProvider, CardVerifier cardVerifier) {
    com.virgilsecurity.common.util.Validator.checkNullAgrument(crypto, "CardManager -> 'crypto' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(accessTokenProvider,
        "CardManager -> 'accessTokenProvider' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardVerifier, "CardManager -> 'cardVerifier' should not be null");

    this.crypto = crypto;
    this.accessTokenProvider = accessTokenProvider;
    this.cardVerifier = cardVerifier;

    cardClient = new VirgilCardClient();
    modelSigner = new ModelSigner(crypto);
  }

  /**
   * Instantiates a new Card manager.
   *
   * @param crypto              The crypto.
   * @param accessTokenProvider The access token provider.
   * @param cardVerifier        The card verifier.
   * @param cardClient          The card client.
   */
  public CardManager(VirgilCardCrypto crypto, AccessTokenProvider accessTokenProvider,
                     CardVerifier cardVerifier, VirgilCardClient cardClient) {
    com.virgilsecurity.common.util.Validator.checkNullAgrument(crypto, "CardManager -> 'crypto' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(accessTokenProvider,
        "CardManager -> 'accessTokenProvider' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardVerifier, "CardManager -> 'cardVerifier' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardClient, "CardManager -> 'cardClient' should not be null");

    this.crypto = crypto;
    this.accessTokenProvider = accessTokenProvider;
    this.cardVerifier = cardVerifier;
    this.cardClient = cardClient;

    modelSigner = new ModelSigner(crypto);
  }

  /**
   * Instantiates a new Card manager.
   *
   * @param crypto              The crypto.
   * @param accessTokenProvider The access token provider.
   * @param cardClient          The card client.
   * @param cardVerifier        The card verifier.
   * @param signCallback        The sign callback.
   * @param retryOnUnauthorized Whether card manager should retry request with new token on
   *                            unauthorized http error.
   */
  public CardManager(VirgilCardCrypto crypto, AccessTokenProvider accessTokenProvider,
                     CardVerifier cardVerifier, VirgilCardClient cardClient,
                     SignCallback signCallback, boolean retryOnUnauthorized) {
    com.virgilsecurity.common.util.Validator.checkNullAgrument(crypto, "CardManager -> 'crypto' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(accessTokenProvider,
        "CardManager -> 'accessTokenProvider' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardVerifier, "CardManager -> 'cardVerifier' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardClient, "CardManager -> 'cardClient' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(signCallback, "CardManager -> 'signCallback' should not be null");

    this.crypto = crypto;
    this.accessTokenProvider = accessTokenProvider;
    this.cardVerifier = cardVerifier;
    this.cardClient = cardClient;
    this.signCallback = signCallback;
    this.retryOnUnauthorized = retryOnUnauthorized;

    modelSigner = new ModelSigner(crypto);
  }

  /**
   * Instantiates a new Card manager.
   *
   * @param crypto              The crypto.
   * @param accessTokenProvider The access token provider.
   * @param cardVerifier        The card verifier.
   * @param signCallback        The sign callback.
   */
  public CardManager(VirgilCardCrypto crypto, AccessTokenProvider accessTokenProvider,
                     CardVerifier cardVerifier, SignCallback signCallback) {
    com.virgilsecurity.common.util.Validator.checkNullAgrument(crypto, "CardManager -> 'crypto' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(accessTokenProvider,
        "CardManager -> 'accessTokenProvider' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(cardVerifier, "CardManager -> 'cardVerifier' should not be null");
    com.virgilsecurity.common.util.Validator.checkNullAgrument(signCallback, "CardManager -> 'signCallback' should not be null");

    this.crypto = crypto;
    this.accessTokenProvider = accessTokenProvider;
    this.cardVerifier = cardVerifier;

    cardClient = new VirgilCardClient();
    modelSigner = new ModelSigner(crypto);
  }

  /**
   * Export Card's raw signed model as json in string format.
   *
   * @param card The card.
   *
   * @return The string.
   */
  public static String exportCardAsJson(Card card) {
    return ConvertionUtils.serializeToJson(card.getRawCard());
  }

  /**
   * Export raw signed model from the provided card.
   *
   * @param card The card.
   *
   * @return The raw signed model.
   */
  public static RawSignedModel exportCardAsRawModel(Card card) {
    return card.getRawCard();
  }

  /**
   * Export Card's raw signed model as base64 string.
   *
   * @param card The card.
   *
   * @return Base64 String from exported card.
   */
  public static String exportCardAsString(Card card) {
    return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(card.getRawCard()));
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains
   * the public key for which the card should be registered, identity information (such as a user
   * name) and integrity protection in form of digital self signature.
   *
   * @param privateKey The private key that used to generate self signature.
   * @param publicKey  The public key.
   * @param identity   The unique identity value.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  public RawSignedModel generateRawCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity)
      throws CryptoException {

    RawSignedModel cardModel = generateRawSignedModel(publicKey, identity);
    modelSigner.selfSign(cardModel, privateKey);

    return cardModel;
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains
   * the public key for which the card should be registered, identity information (such as a user
   * name) and integrity protection in form of digital self signature.
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param additionalData The additional data associated with the card.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  public RawSignedModel generateRawCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                                        Map<String, String> additionalData) throws CryptoException {

    RawSignedModel cardModel = generateRawSignedModel(publicKey, identity);
    modelSigner.selfSign(cardModel, privateKey, ConvertionUtils.captureSnapshot(additionalData));

    return cardModel;
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration or deletion.
   * It contains the public key for which the card should be registered or *null* to delete
   * the card, identity information (such as a user name) and integrity protection in form of
   * digital self signature.
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param previousCardId The previous card id that current card is used to override.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  public RawSignedModel generateRawCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                                        String previousCardId) throws CryptoException {

    RawSignedModel cardModel = generateRawSignedModel(publicKey, identity, previousCardId);

    modelSigner.selfSign(cardModel, privateKey);

    return cardModel;
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration. It contains
   * the public key for which the card should be registered, identity information (such as a user
   * name) and integrity protection in form of digital self signature.
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param previousCardId The previous card id that current card is used to override.
   * @param additionalData The additional data associated with the card.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  public RawSignedModel generateRawCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                                        String previousCardId,
                                        Map<String, String> additionalData) throws CryptoException {

    RawSignedModel cardModel = generateRawSignedModel(publicKey, identity, previousCardId);
    modelSigner.selfSign(cardModel, privateKey, ConvertionUtils.captureSnapshot(additionalData));

    return cardModel;
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration.
   * It contains the public key for which the card should be registered, identity information
   * (such as a user name).
   *
   * @param publicKey The public key to register card.
   * @param identity  The unique identity value.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  private RawSignedModel generateRawSignedModel(VirgilPublicKey publicKey,
                                                String identity) throws CryptoException {
    RawCardContent cardContent =
        new RawCardContent(identity,
            ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey)),
            CURRENT_CARD_VERSION,
            new Date());

    byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);

    return new RawSignedModel(snapshot);
  }

  /**
   * Generates a new {@link RawSignedModel} in order to apply for a card registration or deletion.
   * It contains the public key for which the card should be registered or *null* to delete
   * the card, identity information (such as a user name).
   *
   * @param publicKey      The public key to register card or *null* to delete card.
   * @param identity       The unique identity value.
   * @param previousCardId The previous card id that current card is used to override.
   *
   * @return A new instance of {@link RawSignedModel}.
   *
   * @throws CryptoException If an issue occurred during exporting public key or self sign operation.
   */
  private RawSignedModel generateRawSignedModel(VirgilPublicKey publicKey,
                                                String identity,
                                                String previousCardId) throws CryptoException {

    String publicKeyB64 = ConvertionUtils.toBase64String(crypto.exportPublicKey(publicKey));

    RawCardContent cardContent = new RawCardContent(identity,
        publicKeyB64,
        CURRENT_CARD_VERSION,
        new Date(),
        previousCardId);

    byte[] snapshot = ConvertionUtils.captureSnapshot(cardContent);

    return new RawSignedModel(snapshot);
  }

  /**
   * Gets access token provider.
   *
   * @return The access token provider.
   */
  public AccessTokenProvider getAccessTokenProvider() {
    return accessTokenProvider;
  }

  /**
   * Gets the card by specified identifier. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   *
   * @param cardId The card identifier.
   *
   * @return Card from the Virgil Cards service.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If service call failed.
   */
  public Card getCard(String cardId) throws CryptoException, VirgilServiceException {
    AccessToken token = accessTokenProvider
        .getToken(new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_GET));
    Tuple<RawSignedModel, Boolean> response;

    try { // Hell is here (:
      response = cardClient.getCard(cardId, token.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
          && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
          && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        token = accessTokenProvider
            .getToken(new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_GET, true));
        try {
          response = cardClient.getCard(cardId, token.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error ocurred while retrieving a card", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
              exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
              exceptionOuter);
        }
        throw exceptionOuter;
      }
    }

    Card card = Card.parse(crypto, response.getLeft());
    if (!Objects.equals(cardId, card.getIdentifier())) {
      LOGGER.warning(String.format(
          "Card\'s id ('%s') that received from the Cards Service is not equal to the requested one ('%s')",
          card.getIdentifier(), cardId));
      throw new VirgilCardServiceException();
    }

    if (response.getRight()) {
      LOGGER.fine("Card is marked as outdated");
      card.setOutdated(true);
    }

    verifyCard(card);

    return card;
  }

  /**
   * Gets card client.
   *
   * @return The card client.
   */
  public VirgilCardClient getCardClient() {
    return cardClient;
  }

  /**
   * Gets card verifier.
   *
   * @return The card verifier.
   */
  public CardVerifier getCardVerifier() {
    return cardVerifier;
  }

  /**
   * Gets crypto.
   *
   * @return The crypto.
   */
  public VirgilCardCrypto getCrypto() {
    return crypto;
  }

  /**
   * Gets model signer.
   *
   * @return The model signer.
   */
  public ModelSigner getModelSigner() {
    return modelSigner;
  }

  /**
   * Gets sign callback.
   *
   * @return The sign callback.
   */
  public SignCallback getSignCallback() {
    return signCallback;
  }

  /**
   * Import card from json in string format.
   *
   * @param cardAsJson The card.
   *
   * @return The card.
   *
   * @throws CryptoException If card importing failed.
   */
  public Card importCardAsJson(String cardAsJson) throws CryptoException {
    RawSignedModel cardModel = RawSignedModel.fromJson(cardAsJson);
    Card card = Card.parse(crypto, cardModel);

    verifyCard(card);

    return card;
  }

  /**
   * Import Card's raw signed model from raw signed model.
   *
   * @param cardModel The card model.
   *
   * @return The card.
   *
   * @throws CryptoException If any crypto operation failed.
   */
  public Card importCardAsRawModel(RawSignedModel cardModel) throws CryptoException {
    Card card = Card.parse(crypto, cardModel);

    verifyCard(card);

    return Card.parse(crypto, cardModel);
  }

  /**
   * Import card from base64 string.
   *
   * @param cardAsString The card.
   *
   * @return Imported card from Base64 String.
   *
   * @throws CryptoException If card importing failed.
   */
  public Card importCardAsString(String cardAsString) throws CryptoException {
    RawSignedModel cardModel = RawSignedModel.fromString(cardAsString);
    Card card = Card.parse(crypto, cardModel);

    verifyCard(card);

    return card;
  }

  /**
   * See if the card manager should retry request with new token on {@code unauthorized} http error.
   *
   * @return {@code true} if retry is enabled, {@code false} otherwise.
   */
  public boolean isRetryOnUnauthorized() {
    return retryOnUnauthorized;
  }

  /**
   * Publish card to the Virgil Cards service. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   * <p>
   * Internally {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String)} method will be called to
   * generate {@link RawSignedModel} with provided parameters after that card model will be
   * published via {@link #publishCard(RawSignedModel)} method.
   * </p>
   *
   * @param privateKey The private key that used to generate self signature.
   * @param publicKey  The public key.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   */
  public Card publishCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
      throws CryptoException, VirgilServiceException {

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    RawSignedModel cardModel = generateRawCard(privateKey, publicKey, token.getIdentity());

    return publishRawSignedModel(cardModel, tokenContext, token);
  }

  /**
   * Publish card to the Virgil Cards service. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   * <p>
   * Internally {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String)} method will be called to
   * generate {@link RawSignedModel} with provided parameters after that card model will be
   * published via {@link #publishCard(RawSignedModel)} method.
   * </p>
   *
   * @param privateKey The private key that used to generate self signature.
   * @param publicKey  The public key.
   * @param identity   The unique identity value.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   */
  public Card publishCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity)
      throws CryptoException, VirgilServiceException {

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    RawSignedModel cardModel = generateRawCard(privateKey, publicKey, token.getIdentity());

    return publishCard(cardModel);
  }

  /**
   * Publish card to the Virgil Cards service. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   * <p>
   * Internally {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String, Map)} method will be called
   * to generate {@link RawSignedModel} with provided parameters after that card model will be
   * published via {@link #publishCard(RawSignedModel)} method.
   * </p>
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param additionalData The additional data associated with the card.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   */
  public Card publishCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                          Map<String, String> additionalData) throws CryptoException, VirgilServiceException {

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    RawSignedModel cardModel = generateRawCard(privateKey, publicKey, token.getIdentity(),
        additionalData);

    return publishCard(cardModel);
  }

  /**
   * Publish card to the Virgil Cards service. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   * <p>
   * Internally {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String, String)} method will be
   * called to generate {@link RawSignedModel} with provided parameters after that card model will
   * be published via {@link #publishCard(RawSignedModel)} method.
   * </p>
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param previousCardId The previous card id that current card is used to override.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   */
  public Card publishCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                          String previousCardId) throws CryptoException, VirgilServiceException {

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    RawSignedModel cardModel = generateRawCard(privateKey, publicKey, token.getIdentity(),
        previousCardId);

    return publishCard(cardModel);
  }

  /**
   * Publish card to the Virgil Cards service. You can use {@link #setRetryOnUnauthorized(boolean)}
   * method passing {@code true} to retry request with new token on {@code unauthorized} http error.
   * <p>
   * Internally {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String, String, Map)} method will be
   * called to generate {@link RawSignedModel} with provided parameters after that card model will
   * be published via {@link #publishCard(RawSignedModel)} method.
   * </p>
   *
   * @param privateKey     The private key that used to generate self signature.
   * @param publicKey      The public key.
   * @param identity       The unique identity value.
   * @param previousCardId The previous card id that current card is used to override.
   * @param additionalData The additional data associated with the card.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   */
  public Card publishCard(VirgilPrivateKey privateKey, VirgilPublicKey publicKey, String identity,
                          String previousCardId, Map<String, String> additionalData)
      throws CryptoException, VirgilServiceException {

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    RawSignedModel cardModel = generateRawCard(privateKey, publicKey, token.getIdentity(),
        previousCardId, additionalData);

    return publishCard(cardModel);
  }

  /**
   * Publishes card to the Virgil Cards service. You should use
   * {@link #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String)} method, or it's overridden variations.
   * You can use {@link #setRetryOnUnauthorized(boolean)} method passing {@code true} to retry
   * request with new token on {@code unauthorized} http error.
   *
   * @param cardModel The card model to publish.
   *
   * @return The card that is returned from the Virgil Cards service after successful publishing.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If card was not created by a service.
   *
   * @see #generateRawCard(VirgilPrivateKey, VirgilPublicKey, String)
   */
  public Card publishCard(RawSignedModel cardModel) throws CryptoException, VirgilServiceException {
    Validator.checkNullAgrument(cardModel, "CardManager -> 'cardModel' should not be null");

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_PUBLISH);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    String cardModelIdentity = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()))
        .getIdentity();

    // Possibly move this and bottom lines to Logs
    if (!cardModelIdentity.equals(token.getIdentity())) {
      throw new IllegalArgumentException(
          "Identity in provided RawSignedModel and in JWT must be equal."
              + "Identity specified in provided RawSignedModel: " + cardModelIdentity + ". "
              + "Identity specified in JWT: " + token.getIdentity() + ".");
    }

    return publishRawSignedModel(cardModel, tokenContext, token);
  }

  /**
   * Revokes card from Virgil Cards service. You should provide not empty {@code cardId}
   * of last card in chain that you want to revoke.
   * <p>
   * You can use {@link #setRetryOnUnauthorized(boolean)} method passing {@code true} to retry
   * request with new token on {@code unauthorized} http error.
   *
   * @param cardId Identifier of last Card in chain that is to revoke.
   *
   * @throws CryptoException                 If an issue occurred during get generating token or verifying card
   *                                         that was received from the Virgil Cards service.
   * @throws VirgilServiceException          If card was not created by a service.
   * @throws VirgilCardVerificationException If any of signatures wasn't valid.
   */
  public void revokeCard(String cardId)
      throws CryptoException, VirgilServiceException {
    if (StringUtils.isBlank(cardId)) {
      throw new IllegalArgumentException("'cardId' should not be empty");
    }

    TokenContext tokenContext = new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_DELETE);

    AccessToken token = accessTokenProvider.getToken(tokenContext);

    try {
      cardClient.revokeCard(cardId, token.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
          && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
          && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        token = accessTokenProvider.getToken(tokenContext);
        try {
          cardClient.revokeCard(cardId, token.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error occurred while revoking a card", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
              exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
              exceptionOuter);
        }
        throw exceptionOuter;
      }
    }
  }

  private Card publishRawSignedModel(RawSignedModel cardModel,
                                     TokenContext tokenContext,
                                     AccessToken initialToken) throws CryptoException, VirgilServiceException {

    RawSignedModel cardModelPublished;

    if (signCallback != null) {
      cardModel = signCallback.onSign(cardModel);
      LOGGER.fine("Card model was signed with signCallback");
    } else {
      LOGGER.fine("Card model was NOT signed with signCallback");
    }

    try {
      cardModelPublished = cardClient.publishCard(cardModel, initialToken.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
          && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
          && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        initialToken = accessTokenProvider.getToken(tokenContext);
        try {
          cardModelPublished = cardClient.publishCard(cardModel,
              initialToken.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error occurred while publishing a card", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
              exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
              exceptionOuter);
        }
        throw exceptionOuter;
      }
    }

    Card card = Card.parse(crypto, cardModelPublished);

    // Be sure that a card received from service is the same card we publishing
    if (!Arrays.equals(cardModel.getContentSnapshot(), cardModelPublished.getContentSnapshot())) {
      LOGGER.warning(
          "Card that is received from the Cards Service (during publishing) is not equal to the published one");
      throw new VirgilCardServiceException("Server returned a wrong card");
    }

    // Be sure that self signatures are equals
    RawSignature selfSignature = getSignature(SignerType.SELF.getRawValue(),
        cardModel.getSignatures());
    RawSignature responseSelfSignature = getSignature(SignerType.SELF.getRawValue(),
        cardModelPublished.getSignatures());
    if (selfSignature != null || responseSelfSignature != null) {
      if (selfSignature == null || responseSelfSignature == null) {
        String msg = String.format("Self signature is missing for card %s", card.getIdentifier());
        LOGGER.severe(msg);
        throw new VirgilCardServiceException(msg);
      }

      if (!StringUtils.equals(selfSignature.getSnapshot(), responseSelfSignature.getSnapshot())) {
        String msg = String.format("Self signature was changed by a service for card %s",
            card.getIdentifier());
        LOGGER.severe(msg);
        throw new VirgilCardServiceException(msg);
      }
    }

    verifyCard(card);

    return card;
  }

  /**
   * Search for all cards with specified identity. You can use
   * {@link #setRetryOnUnauthorized(boolean)} method passing {@code true} to retry request with new
   * token on {@code unauthorized} http error.
   *
   * @param identity The identity to search cards for.
   *
   * @return List of cards that corresponds to provided identity.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If service call failed.
   */
  public List<Card> searchCards(String identity) throws CryptoException, VirgilServiceException {
    AccessToken token = accessTokenProvider
        .getToken(new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_SEARCH));

    List<RawSignedModel> cardModels;
    try {
      cardModels = cardClient.searchCards(identity, token.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
          && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
          && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        token = accessTokenProvider.getToken(
            new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_SEARCH, true));
        try {
          cardModels = cardClient.searchCards(identity, token.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error occurred while searching for cards", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
              exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
              exceptionOuter);
        }
        throw exceptionOuter;
      }
    }

    List<Card> cards = CardUtils.parseCards(crypto, cardModels);
    List<Card> result = processOutdatedCards(cards);
    CardUtils.validateCardsWithIdentities(cards, Arrays.asList(identity));

    for (Card card : result) {
      verifyCard(card);
    }

    return result;
  }

  /**
   * Search for all cards with specified identities. You can use
   * {@link #setRetryOnUnauthorized(boolean)} method passing {@code true} to retry request with new
   * token on {@code unauthorized} http error.
   *
   * @param identities Identities to search cards for.
   *
   * @return List of cards that corresponds to provided identity.
   *
   * @throws CryptoException        If an issue occurred during get generating token or verifying card that was received
   *                                from the Virgil Cards service.
   * @throws VirgilServiceException If service call failed.
   */
  public List<Card> searchCards(Collection<String> identities)
      throws CryptoException, VirgilServiceException {
    AccessToken token = accessTokenProvider
        .getToken(new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_SEARCH));

    List<RawSignedModel> cardModels;
    try {
      cardModels = cardClient.searchCards(identities, token.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
          && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
          && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        token = accessTokenProvider.getToken(
            new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_SEARCH, true));
        try {
          cardModels = cardClient.searchCards(identities, token.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error occurred while searching for cards", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
              exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
              exceptionOuter);
        }
        throw exceptionOuter;
      }
    }

    List<Card> cards = CardUtils.parseCards(crypto, cardModels);
    List<Card> result = processOutdatedCards(cards);
    CardUtils.validateCardsWithIdentities(cards, identities);

    for (Card card : result) {
      verifyCard(card);
    }

    return result;
  }

  /**
   * Returns list of cards that were replaced with newer ones.
   *
   * @param cardIds card ids to check.
   * @return list of outdated cards.
   * @throws CryptoException
   * @throws VirgilServiceException
   */
  public List<String> getOutdated(Collection<String> cardIds) throws CryptoException, VirgilServiceException {
    AccessToken token = accessTokenProvider
            .getToken(new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_GET_OUTDATED));

    List<String> outdatedCards;
    try {
      outdatedCards = cardClient.getOutdated(cardIds, token.stringRepresentation());
    } catch (VirgilServiceException exceptionOuter) {
      if (exceptionOuter.getHttpError() != null
              && exceptionOuter.getHttpError().getCode() == HttpURLConnection.HTTP_UNAUTHORIZED
              && retryOnUnauthorized) {
        LOGGER.fine("Token is expired, trying to reload...");
        token = accessTokenProvider.getToken(
                new TokenContext(TOKEN_CONTEXT_SERVICE, TOKEN_CONTEXT_OPERATION_GET_OUTDATED, true));
        try {
          outdatedCards = cardClient.getOutdated(cardIds, token.stringRepresentation());
        } catch (VirgilServiceException exceptionInner) {
          LOGGER.log(Level.SEVERE, "An error occurred while searching for cards", exceptionOuter);
          throw exceptionInner;
        }
      } else {
        if (exceptionOuter.getHttpError() != null) {
          LOGGER.log(Level.SEVERE, "Http error code: " + exceptionOuter.getHttpError().getCode(),
                  exceptionOuter);
        } else {
          LOGGER.log(Level.SEVERE, "Virgil Service error: " + exceptionOuter.getErrorCode(),
                  exceptionOuter);
        }
        throw exceptionOuter;
      }
    }
    return outdatedCards;
  }

  /**
   * Sets if the card manager should retry request with new token on {@code unauthorized} http
   * error.
   *
   * @param retryOnUnauthorized Pass {@code true} to enable retry, {@code false} to disable retry.
   */
  public void setRetryOnUnauthorized(boolean retryOnUnauthorized) {
    this.retryOnUnauthorized = retryOnUnauthorized;
  }

  private RawSignature getSignature(String type, Collection<RawSignature> signatures) {
    if (signatures == null || signatures.isEmpty()) {
      return null;
    }
    for (RawSignature signature : signatures) {
      if (type.equalsIgnoreCase(signature.getSigner())) {
        return signature;
      }
    }
    return null;
  }

  /**
   * Verifies whether provided {@link Card} is valid with provided {@link CardVerifier}.
   *
   * @param card To verify.
   *
   * @throws CryptoException If verification of card issue occurred.
   */
  private void verifyCard(Card card) throws CryptoException {
    if (!cardVerifier.verifyCard(card)) {
      LOGGER.warning(String.format("Card '%s' verification was failed", card.getIdentifier()));
      throw new VirgilCardVerificationException();
    }
  }

  private List<Card> processOutdatedCards(List<Card> cards) {
    // Finding Cards that are outdated (if Card with equal previousCardId is found)
    // and setting them as previousCard for the newer one and marking them as outdated
    for (Card cardOuter : cards) {
      for (Card cardInner : cards) {
        if ((cardOuter.getPreviousCardId() != null || cardInner.getPreviousCardId() != null)
            && cardOuter.getIdentifier().equals(cardInner.getPreviousCardId())) {
          cardInner.setPreviousCard(cardOuter);
          cardOuter.setOutdated(true);
          break;
        }
      }
    }

    // Creating Card-chains - it's List of the newest Cards
    // which could have previousCard and is NOT outdated
    List<Card> result = new ArrayList<>();
    for (Card card : cards) {
      if (!card.isOutdated()) {
        result.add(card);
      }
    }

    return result;
  }
}
