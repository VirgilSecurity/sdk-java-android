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

package com.virgilsecurity.sdk.examples;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Andrii Iakovenko
 */
public class PublicKeyManagementExample {

  public void decryptThenVerify(PrivateKeyStorage privateKeyStorage, CardManager cardManager,
                                byte[] encryptedData) throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare a user's private key
    Tuple<VirgilPrivateKey, Map<String, String>> bobPrivateKeyEntry = privateKeyStorage.load("Bob");
    VirgilPrivateKey bobPrivateKey = bobPrivateKeyEntry.getLeft();

    try {
      // using cardManager search for user's cards on Cards Service
      List<Card> cards = cardManager.searchCards("Alice");
      // Cards are obtained
      List<VirgilPublicKey> aliceRelevantCardsPublicKeys = new ArrayList<>();
      for (Card card : cards) {
        if (!card.isOutdated()) {
          aliceRelevantCardsPublicKeys.add(card.getPublicKey());
        }
      }

      // decrypt with a private key and verify using a public key
      byte[] decryptedData = crypto.decryptThenVerify(encryptedData, bobPrivateKey,
          aliceRelevantCardsPublicKeys);
    } catch (CryptoException | VirgilServiceException e) {
      // Error occured
    }
  }

  public void searchCardByIdentity(CardManager cardManager) {
    try {
      List<Card> cards = cardManager.searchCards("Bob");
      // Cards are obtained
    } catch (CryptoException | VirgilServiceException e) {
      // Error occured
    }
  }

  public void signThenEncrypt(PrivateKeyStorage privateKeyStorage, CardManager cardManager)
      throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare a message
    String messageToEncrypt = "Hello, Bob!";
    byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

    // prepare a user's private key
    Tuple<VirgilPrivateKey, Map<String, String>> alicePrivateKeyEntry = privateKeyStorage.load("Alice");
    VirgilPrivateKey alicePrivateKey = alicePrivateKeyEntry.getLeft();

    // using cardManager search for user's cards on Cards Service
    try {
      List<Card> cards = cardManager.searchCards("Bob");
      // Cards are obtained
      List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
      for (Card card : cards) {
        if (!card.isOutdated()) {
          bobRelevantCardsPublicKeys.add(card.getPublicKey());
        }
      }
      // sign a message with a private key then encrypt on a public key
      byte[] encryptedData = crypto.signThenEncrypt(dataToEncrypt, alicePrivateKey,
          bobRelevantCardsPublicKeys);
    } catch (CryptoException | VirgilServiceException e) {
      // Error occured
    }
  }

  private void createCard(PrivateKeyStorage privateKeyStorage, CardManager cardManager)
      throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    // generate a key pair
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    // save a private key into key storage
    privateKeyStorage.store(keyPair.getPrivateKey(), "Alice", null);

    // publish user's on the Cards Service
    try {
      Card card = cardManager.publishCard(keyPair.getPrivateKey(), keyPair.getPublicKey(), "Alice");
      // // Card is created
    } catch (CryptoException | VirgilServiceException e) {
      // Error occured
    }
  }

  private void findCardById(CardManager cardManager) {
    // using cardManager get a user's card from the Cards Service
    try {
      Card card = cardManager
          .getCard("f4bf9f7fcbedaba0392f108c59d8f4a38b3838efb64877380171b54475c2ade8");
      // Card is obtained
    } catch (CryptoException | VirgilServiceException e) {
      // Error occured
    }
  }
}
