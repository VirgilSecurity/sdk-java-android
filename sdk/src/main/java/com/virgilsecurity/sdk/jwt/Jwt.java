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

package com.virgilsecurity.sdk.jwt;

import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.utils.Base64Url;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

import java.util.Arrays;
import java.util.Date;
import java.util.logging.Logger;

/**
 * The {@link Jwt} class implements {@link AccessToken} interface and is used to get access for
 * network requests.
 */
public class Jwt implements AccessToken {
  private static final Logger LOGGER = Logger.getLogger(Jwt.class.getName());

  private JwtHeaderContent headerContent;
  private JwtBodyContent bodyContent;
  private byte[] signatureData;
  private String stringRepresentation;
  private String unsignedStringRepresentation;

  /**
   * Instantiates a new Jwt.
   *
   * @param headerContent the header content
   * @param bodyContent   the body content
   */
  public Jwt(JwtHeaderContent headerContent, JwtBodyContent bodyContent) {
    this(headerContent, bodyContent, null);
  }

  /**
   * Instantiates a new Jwt.
   *
   * @param headerContent the header content
   * @param bodyContent   the body content
   * @param signatureData the signature data
   */
  public Jwt(JwtHeaderContent headerContent, JwtBodyContent bodyContent, byte[] signatureData) {
    Validator.checkNullAgrument(headerContent, "Jwt -> 'headerContent' should not be null");
    Validator.checkNullAgrument(bodyContent, "Jwt -> 'bodyContent' should not be null");

    this.headerContent = headerContent;
    this.bodyContent = bodyContent;
    this.signatureData = signatureData;

    StringBuilder sb = new StringBuilder();
    sb.append(this.headerBase64()).append(".").append(this.bodyBase64());
    this.unsignedStringRepresentation = sb.toString();

    if (signatureData != null) {
      sb.append(".").append(signatureBase64());
    } else {
      LOGGER.fine("Instantiated Jwt has not signature data");
    }

    this.stringRepresentation = sb.toString();
  }

  /**
   * Instantiates a new Jwt.
   *
   * @param jwtToken the jwt token in string representation. Should have at least two parts - header and
   *                 body. (ex. "***.***", where "***" is base64 encoded string)
   */
  public Jwt(String jwtToken) {
    if (jwtToken == null) {
      throw new IllegalArgumentException("'jwtToken' cannot be null");
    }

    String[] jwtParts = jwtToken.split("[.]");

    if (jwtParts.length < 2 || jwtParts.length > 3) {
      LOGGER.warning(String.format(
          "Jwt has wrong format. It has '%s' parts, while min is 2, max is 3", jwtParts.length));
      throw new IllegalArgumentException("Jwt -> 'jwtToken' has wrong format");
    }

    String headerJson = Base64Url.decode(jwtParts[0]);
    headerContent = JwtParser.parseJwtHeaderContent(headerJson);

    String bodyJson = Base64Url.decode(jwtParts[1]);
    bodyContent = JwtParser.parseJwtBodyContent(bodyJson);

    if (jwtParts.length == 3) {
      signatureData = Base64Url.decodeToBytes(jwtParts[2]);
    } else {
      LOGGER.info("Instantiated Jwt has not signature data");
    }

    this.unsignedStringRepresentation = jwtParts[0] + "." + jwtParts[1];
    this.stringRepresentation = jwtToken;
  }

  /*
   * (non-Javadoc)
   *
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    Jwt other = (Jwt) obj;
    if (bodyContent == null) {
      if (other.bodyContent != null) {
        return false;
      }
    } else if (!bodyContent.equals(other.bodyContent)) {
      return false;
    }
    if (headerContent == null) {
      if (other.headerContent != null) {
        return false;
      }
    } else if (!headerContent.equals(other.headerContent)) {
      return false;
    }
    return Arrays.equals(signatureData, other.signatureData);
  }

  /**
   * Gets body content.
   *
   * @return the body content
   */
  public JwtBodyContent getBodyContent() {
    return bodyContent;
  }

  /**
   * Gets header content.
   *
   * @return the header content
   */
  public JwtHeaderContent getHeaderContent() {
    return headerContent;
  }

  @Override
  public String getIdentity() {
    return bodyContent.getIdentity();
  }

  /**
   * Get signature data.
   *
   * @return the signature data in byte [ ]
   */
  public byte[] getSignatureData() {
    return signatureData;
  }

  /*
   * (non-Javadoc)
   *
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((bodyContent == null) ? 0 : bodyContent.hashCode());
    result = prime * result + ((headerContent == null) ? 0 : headerContent.hashCode());
    result = prime * result + Arrays.hashCode(signatureData);
    return result;
  }

  /**
   * Whether the token is expired comparing to current date.
   *
   * @return if the token is already expired then - {@code true}, otherwise {@code false}
   */
  public boolean isExpired() {
    long currentTimeStamp = new Date().getTime() / 1000;
    return currentTimeStamp >= bodyContent.getExpiresAt();
  }

  /**
   * Whether the token is expired comparing to some predefined date.
   *
   * @param lifeTimePredefined predefined date that will be used in comparison to check whether the token is expired.
   *                           For example to set expiration date in some near future (+5 seconds beyond current
   *                           time).
   * @return if the token is already expired then - {@code true}, otherwise {@code false}
   */
  public boolean isExpired(Date lifeTimePredefined) {
    long currentTimeStamp = lifeTimePredefined.getTime() / 1000;
    return currentTimeStamp >= bodyContent.getExpiresAt();
  }

  /*
   * (non-Javadoc)
   *
   * @see java.lang.Object#toString()
   */
  @Override
  public String stringRepresentation() {
    return stringRepresentation;
  }

  String unsigned() {
    return unsignedStringRepresentation;
  }

  private String bodyBase64() {
    return Base64Url.encode(ConvertionUtils.captureSnapshot(this.bodyContent));
  }

  private String headerBase64() {
    return Base64Url.encode(ConvertionUtils.captureSnapshot(this.headerContent));
  }

  private String signatureBase64() {
    return Base64Url.encode(this.signatureData);
  }
}
