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

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.common.exception.EmptyArgumentException;
import com.virgilsecurity.common.exception.NullArgumentException;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardIsOutdatedException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The {@link VirgilCardClient} class represents a Virgil Security service client and contains all
 * methods for interaction with server.
 */
public class VirgilCardClient implements CardClient {
  private static final Logger LOGGER = Logger.getLogger(VirgilCardClient.class.getName());

  private static final String BASE_URL = "https://api.virgilsecurity.com/card";
  private static final String SERVICE_VERSION = "/v5/";

  private URL serviceUrl;
  private HttpClient httpClient;

  /**
   * Create a new instance of {@code CardClient} with default HttpClient.
   */
  public VirgilCardClient() {
    this(BASE_URL + SERVICE_VERSION);
  }

  /**
   * Create a new instance of {@code CardClient}.
   *
   * @param httpClient http client that will be used for firing requests
   */
  public VirgilCardClient(HttpClient httpClient) {
    this(BASE_URL + SERVICE_VERSION, httpClient);
  }

  /**
   * Create a new instance of {@code CardClient} with default HttpClient.
   *
   * @param serviceUrl the service url to fire requests to
   */
  public VirgilCardClient(String serviceUrl) {
    try {
      this.serviceUrl = new URL(serviceUrl);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("CardClient -> 'serviceUrl' has wrong format");
    }
    httpClient = new HttpClient();
  }

  /**
   * Create a new instance of {@code CardClient}.
   *
   * @param serviceUrl the service url to fire requests to
   * @param httpClient http client that will be used for firing requests
   */
  public VirgilCardClient(String serviceUrl, HttpClient httpClient) {
    try {
      this.serviceUrl = new URL(serviceUrl);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("CardClient -> 'serviceUrl' has wrong format");
    }
    this.httpClient = httpClient;
  }

  /**
   * Create a new instance of {@code CardClient} with default HttpClient.
   *
   * @param serviceUrl the service url to fire requests to
   */
  public VirgilCardClient(URL serviceUrl) {
    this.serviceUrl = serviceUrl;
    httpClient = new HttpClient();
  }

  /**
   * Create a new instance of {@code CardClient}.
   *
   * @param serviceUrl the service url to fire requests to
   * @param httpClient http client that will be used for firing requests
   */
  public VirgilCardClient(URL serviceUrl, HttpClient httpClient) {
    this.serviceUrl = serviceUrl;
    this.httpClient = httpClient;
  }

  /**
   * Get card from Virgil Services by specified identifier.
   *
   * @param cardId the card identifier.
   * @param token  token to authorize the request.
   * @return the card loaded from Virgil Cards service.
   * @throws VirgilServiceException if service call failed
   */
  public Tuple<RawSignedModel, Boolean> getCard(String cardId, String token)
      throws VirgilServiceException {
    try {
      URL url = new URL(serviceUrl, cardId);

      return new Tuple<>(httpClient.execute(url, "GET", token, null, RawSignedModel.class), false);
    } catch (VirgilCardIsOutdatedException e) {
      LOGGER.fine("Outdated Card is received");
      return new Tuple<>(e.getCardModel(), true);
    } catch (VirgilServiceException e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some issue occurred during request executing", e);
      throw new VirgilCardServiceException(e);
    }
  }

  @Override
  public List<String> getOutdated(Collection<String> cardIds, String token) throws VirgilServiceException {
    if (cardIds == null) {
      throw new NullArgumentException("CardClient -> 'cardIds' should not be null");
    }

    try {
      URL url = new URL(serviceUrl, Endpoints.ACTIONS_GET_OUTDATED.path);
      GetOutdatedRequestData requestData = new GetOutdatedRequestData(cardIds);
      String body = ConvertionUtils.getGson().toJson(requestData);

      String[] cards = httpClient.execute(url, "POST", token,
              new ByteArrayInputStream(ConvertionUtils.toBytes(body)), String[].class);

      return Arrays.asList(cards);
    } catch (VirgilServiceException e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some issue occurred during request executing", e);
      throw new VirgilCardServiceException(e);
    }
  }

  /**
   * Gets http client that is used to fire requests.
   *
   * @return the http client
   */
  public HttpClient getHttpClient() {
    return httpClient;
  }

  /**
   * Gets service url that is used to fire requests to.
   *
   * @return the service url
   */
  public URL getServiceUrl() {
    return serviceUrl;
  }

  /**
   * Publishes card in Virgil Cards service.
   *
   * @param rawCard raw signed model of card to be published.
   * @param token   token to authorize the request.
   * @return the {@link RawSignedModel} of the Card that is published to Virgil Cards service.
   * @throws VirgilServiceException if an error occurred while publishing Card.
   */
  public RawSignedModel publishCard(RawSignedModel rawCard, String token)
      throws VirgilServiceException {
    try {
      URL url = serviceUrl;
      String body = rawCard.exportAsJson();

      return httpClient.execute(url, "POST", token,
          new ByteArrayInputStream(ConvertionUtils.toBytes(body)), RawSignedModel.class);
    } catch (VirgilServiceException e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some issue occurred during request executing", e);
      throw new VirgilCardServiceException(e);
    }
  }

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identity the identity for search.
   * @param token    token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed
   */
  public List<RawSignedModel> searchCards(String identity, String token)
      throws VirgilServiceException {
    if (identity == null) {
      throw new NullArgumentException("CardClient -> 'identity' should not be null");
    }

    if (identity.isEmpty()) {
      throw new EmptyArgumentException("CardClient -> 'identity' should not be empty");
    }

    return searchCards(Collections.singletonList(identity), token);
  }

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identities the identity for search.
   * @param token      token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed
   */
  public List<RawSignedModel> searchCards(Collection<String> identities, String token)
      throws VirgilServiceException {
    if (identities == null) {
      throw new NullArgumentException("CardClient -> 'identities' should not be null");
    }

    if (identities.isEmpty()) {
      throw new EmptyArgumentException("CardClient -> 'identities' should not be empty");
    }

    try {
      URL url = new URL(serviceUrl, Endpoints.ACTIONS_SEARCH.path);
      SearchCardsRequestData requestData = new SearchCardsRequestData(identities);
      String body = ConvertionUtils.getGson().toJson(requestData);

      RawSignedModel[] cardModels = httpClient.execute(url, "POST", token,
          new ByteArrayInputStream(ConvertionUtils.toBytes(body)), RawSignedModel[].class);

      return Arrays.asList(cardModels);
    } catch (VirgilServiceException e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some issue occurred during request executing", e);
      throw new VirgilCardServiceException(e);
    }
  }

  /**
   * Revokes card. Revoked card gets isOutdated flag to be set to true.
   * Also, such cards could be obtained using get query, but will be absent in search query result.
   *
   * @param cardId identifier of card to revoke.
   * @param token  token to authorize the request.
   * @throws VirgilServiceException if an error occurred while deleting Card.
   */
  public void revokeCard(String cardId, String token) throws VirgilServiceException {
    try {
      URL url = new URL(serviceUrl, Endpoints.ACTIONS_DELETE.path + "/" + cardId);

      httpClient.execute(url,
          "POST",
          token,
          null,
          RawSignedModel.class);
    } catch (VirgilServiceException e) {
      LOGGER.log(Level.SEVERE, "Some service issue occurred during request executing", e);
      throw e;
    } catch (Exception e) {
      LOGGER.log(Level.SEVERE, "Some issue occurred during request executing", e);
      throw new VirgilCardServiceException(e);
    }
  }

  /**
   * Sets http client that is used to fire requests.
   *
   * @param httpClient the http client
   */
  public void setHttpClient(HttpClient httpClient) {
    this.httpClient = httpClient;
  }

  private class SearchCardsRequestData {
    @SerializedName("identities")
    private List<String> identities;

    public SearchCardsRequestData() {
      this(Collections.EMPTY_LIST);
    }

    public SearchCardsRequestData(Collection<String> identities) {
      this.identities = new ArrayList<>(identities);
    }

    public List<String> getIdentities() {
      return identities;
    }
  }

  private class GetOutdatedRequestData {
    @SerializedName("card_ids")
    private List<String> cardIds;

    public GetOutdatedRequestData() {
      this(Collections.EMPTY_LIST);
    }

    public GetOutdatedRequestData(Collection<String> cardIds) {
      this.cardIds = new ArrayList<>(cardIds);
    }

    public List<String> getCardIds() {
      return cardIds;
    }
  }

  private enum Endpoints {
    ACTIONS_DELETE("actions/revoke"),
    ACTIONS_SEARCH("actions/search"),
    ACTIONS_GET_OUTDATED("actions/outdated");

    private final String path;

    Endpoints(String path) {
      this.path = path;
    }
  }
}
