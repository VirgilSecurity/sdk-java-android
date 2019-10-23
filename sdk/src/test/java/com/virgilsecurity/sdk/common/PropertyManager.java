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

package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.apache.commons.lang3.StringUtils;

import static org.junit.jupiter.api.Assertions.fail;

public class PropertyManager {

  private VirgilCrypto crypto;
  private String accountId;
  private String appId;
  private VirgilPrivateKey apiPrivateKey;
  private VirgilPublicKey apiPublicKey;
  private String apiPublicKeyId;
  private String cardsServiceId;
  private VirgilPublicKey cardsServicePublicKey;

  /**
   * Create new instance of {@link PropertyManager}.
   */
  public PropertyManager() {
    super();
    this.crypto = new VirgilCrypto();
  }

  public String getAccountId() {
    if (this.accountId == null) {
      this.accountId = getPropertyByName("ACCOUNT_ID");
      if (this.accountId == null) {
        fail("Account ID is not defined");
      }
    }
    return this.accountId;
  }

  public VirgilPrivateKey getApiPrivateKey() {
    if (this.apiPrivateKey == null) {
      try {
        this.apiPrivateKey = this.crypto
            .importPrivateKey(ConvertionUtils.base64ToBytes(getPropertyByName("API_PRIVATE_KEY")))
            .getPrivateKey();
      } catch (CryptoException e) {
        fail("API Private Key is not defined");
      }
    }
    return this.apiPrivateKey;
  }

  public VirgilPublicKey getApiPublicKey() {
    if (this.apiPublicKey == null) {
      try {
        if (StringUtils.isNotBlank(getPropertyByName("API_PUBLIC_KEY"))) {
          this.apiPublicKey = this.crypto
              .importPublicKey(ConvertionUtils.base64ToBytes(getPropertyByName("API_PUBLIC_KEY")));
        } else {
          this.apiPublicKey = this.crypto.extractPublicKey(getApiPrivateKey());
        }
      } catch (CryptoException e) {
        fail("API Public Key is not defined");
      }
    }
    return this.apiPublicKey;
  }

  public String getApiPublicKeyAsString() {
    return getPropertyByName("API_PUBLIC_KEY");
  }

  public String getApiPublicKeyId() {
    if (this.apiPublicKeyId == null) {
      this.apiPublicKeyId = getPropertyByName("API_PUBLIC_KEY_ID");
      if (this.apiPublicKeyId == null) {
        fail("API Public Key ID is not defined");
      }
    }
    return this.apiPublicKeyId;
  }

  public String getAppId() {
    if (this.appId == null) {
      this.appId = getPropertyByName("APP_ID");
      if (this.appId == null) {
        fail("App ID is not defined");
      }
    }
    return this.appId;
  }

  public String getCardsServiceId() {
    if (this.cardsServiceId == null) {
      this.cardsServiceId = getPropertyByName("CARDS_SERVICE_ID");
      if (this.cardsServiceId == null) {
        fail("Cards Service ID is not defined");
      }
    }
    return this.cardsServiceId;
  }

  public VirgilPublicKey getCardsServicePublicKey() {
    if (this.cardsServicePublicKey == null) {
      try {
        this.cardsServicePublicKey = this.crypto.importPublicKey(
            ConvertionUtils.base64ToBytes(getPropertyByName("CARDS_SERVICE_PUBLIC_KEY")));
      } catch (CryptoException e) {
        fail("Cards Service Public Key is not defined");
      }
    }
    return this.cardsServicePublicKey;
  }

  public String getCardsServiceUrl() {
    return getPropertyByName("CARDS_SERVICE_ADDRESS");
  }

  public String getPropertyByName(String propertyName) {
    String result = System.getProperty(propertyName);
    if (StringUtils.isBlank(result)) {
      result = System.getenv(propertyName);
    }
    if (StringUtils.isBlank(result)) {
      return null;
    }
    return result;
  }

}
