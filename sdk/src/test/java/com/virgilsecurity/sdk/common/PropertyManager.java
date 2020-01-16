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

package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.testcommon.property.EnvPropertyReader;
import com.virgilsecurity.testcommon.utils.PropertyUtils;

public class PropertyManager {

  private static final String ENVIRONMENT_SYS_VAR = "environment";
  private static final String APP_ID = "APP_ID";
  private static final String APP_PRIVATE_KEY = "APP_PRIVATE_KEY";
  private static final String APP_PUBLIC_KEY = "APP_PUBLIC_KEY";
  private static final String APP_PUBLIC_KEY_ID = "APP_PUBLIC_KEY_ID";
  private static final String CARDS_SERVICE_ADDRESS = "CARDS_SERVICE_ADDRESS";

  private final EnvPropertyReader propertyReader;
  private final VirgilCrypto crypto;

  /**
   * Create new instance of {@link PropertyManager}.
   */
  public PropertyManager() {
    String environment = PropertyUtils.getSystemProperty(ENVIRONMENT_SYS_VAR);

    if (environment != null) {
      this.propertyReader = new EnvPropertyReader.Builder()
              .environment(EnvPropertyReader.Environment.fromType(environment))
              .isDefaultSubmodule(true)
              .build();
    } else {
      this.propertyReader = new EnvPropertyReader.Builder()
              .isDefaultSubmodule(true)
              .build();
    }

    this.crypto = new VirgilCrypto();
  }

  public String getAppId() {
    return propertyReader.getProperty(APP_ID);
  }

  public VirgilPrivateKey getAppPrivateKey() {
    String privateKeyString = propertyReader.getProperty(APP_PRIVATE_KEY);
    try {
      return crypto.importPrivateKey(ConvertionUtils.base64ToBytes(privateKeyString)).getPrivateKey();
    } catch (CryptoException e) {
      throw new IllegalStateException(e);
    }
  }

  public VirgilPublicKey getAppPublicKey() {
    String publicKeyString = propertyReader.getProperty(APP_PUBLIC_KEY);

    try {
      return crypto.importPublicKey(ConvertionUtils.base64ToBytes(publicKeyString));
    } catch (CryptoException e) {
      throw new IllegalStateException(e);
    }
  }

  public String getAppPublicKeyId() {
    return propertyReader.getProperty(APP_PUBLIC_KEY_ID);
  }

  public String getCardsServiceUrl() {
    return propertyReader.getProperty(CARDS_SERVICE_ADDRESS);
  }
}
