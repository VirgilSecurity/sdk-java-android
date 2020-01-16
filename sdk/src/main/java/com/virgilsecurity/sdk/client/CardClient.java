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

package com.virgilsecurity.sdk.client;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.utils.Tuple;

import java.util.Collection;
import java.util.List;

/**
 * Interface representing operations with Virgil Cards service.
 */
public interface CardClient {

  /**
   * Get card from Virgil Services by specified identifier.
   *
   * @param cardId the card identifier.
   * @param token  token to authorize the request.
   * @return the card loaded from Virgil Cards service.
   * @throws VirgilServiceException if service call failed.
   */
  public Tuple<RawSignedModel, Boolean> getCard(String cardId, String token)
      throws VirgilServiceException;

  /**
   * Returns list of cards that were replaced with newer ones.
   *
   * @param  cardIds card ids to check.
   * @param token   token to authorize the request.
   * @return list of cards identifiers.
   */
  List<String> getOutdated(Collection<String> cardIds, String token) throws VirgilServiceException;

  /**
   * Publishes card in Virgil Cards service.
   *
   * @param rawCard raw signed model of card to be published.
   * @param token   token to authorize the request.
   * @return the {@link RawSignedModel} of the Card that is published to Virgil Cards service.
   * @throws VirgilServiceException if an error occurred while publishing Card.
   */
  public RawSignedModel publishCard(RawSignedModel rawCard, String token)
      throws VirgilServiceException;

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identity the identity for search.
   * @param token    token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed.
   */
  public List<RawSignedModel> searchCards(String identity, String token)
      throws VirgilServiceException;

  /**
   * Search cards Virgil Services by specified identity.
   *
   * @param identities the identity for search.
   * @param token      token to authorize the request.
   * @return A list of found cards.
   * @throws VirgilServiceException if service call failed.
   */
  public List<RawSignedModel> searchCards(Collection<String> identities, String token)
      throws VirgilServiceException;

  /**
   * Revokes card. Revoked card gets isOutdated flag to be set to true.
   * Also, such cards could be obtained using get query, but will be absent in search query result.
   *
   * @param cardId identifier of card to revoke.
   * @param token  token to authorize the request.
   * @throws VirgilServiceException if service call failed.
   */
  public void revokeCard(String cardId, String token) throws VirgilServiceException;
}
