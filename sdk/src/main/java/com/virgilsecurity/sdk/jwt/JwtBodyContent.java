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

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.common.TimeSpan;

import java.util.Date;
import java.util.Map;

/**
 * The {@link JwtBodyContent} represents contents of {@link Jwt} body.
 */
public class JwtBodyContent {

  private static final String ISSUER_PREFIX = "virgil-";
  private static final String SUBJECT_PREFIX = "identity-";

  @SerializedName("iss")
  private String issuer;

  @SerializedName("sub")
  private String subject;

  @SerializedName("ada")
  private Map<String, String> additionalData;

  @SerializedName("exp")
  private long expiresAt;

  @SerializedName("iat")
  private long issuedAt;

  /**
   * Instantiates a new Jwt body content.
   *
   * @param appId          the application identifier
   * @param identity       the identity
   * @param additionalData the additional data associated with token
   * @param expiresAt      a lifetime of token
   * @param issuedAt       when the token is issued at
   */
  public JwtBodyContent(String appId, String identity, Map<String, String> additionalData,
                        TimeSpan expiresAt, Date issuedAt) {
    this(appId, identity, expiresAt, issuedAt);

    this.additionalData = additionalData;
  }

  /**
   * Instantiates a new Jwt body content.
   *
   * @param appId     the application identifier
   * @param identity  the identity
   * @param expiresAt a lifetime of token
   * @param issuedAt  when the token is issued at
   */
  public JwtBodyContent(String appId, String identity, TimeSpan expiresAt, Date issuedAt) {
    if (appId != null) {
      this.issuer = ISSUER_PREFIX + appId;
    }
    if (identity != null) {
      this.subject = SUBJECT_PREFIX + identity;
    }
    this.issuedAt = issuedAt.getTime() / 1000;
    this.expiresAt = this.issuedAt + expiresAt.getSpanSeconds();
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
    JwtBodyContent other = (JwtBodyContent) obj;
    if (additionalData == null) {
      if (other.additionalData != null) {
        return false;
      }
    } else if (!additionalData.equals(other.additionalData)) {
      return false;
    }
    if (expiresAt != other.expiresAt) {
      return false;
    }
    if (issuedAt != other.issuedAt) {
      return false;
    }
    if (issuer == null) {
      if (other.issuer != null) {
        return false;
      }
    } else if (!issuer.equals(other.issuer)) {
      return false;
    }
    if (subject == null) {
      if (other.subject != null) {
        return false;
      }
    } else if (!subject.equals(other.subject)) {
      return false;
    }
    return true;
  }

  /**
   * Gets additional data.
   *
   * @return the additional data
   */
  public Map<String, String> getAdditionalData() {
    return additionalData;
  }

  /**
   * Gets application identifier.
   *
   * @return the application identifier
   */
  public String getAppId() {
    if (issuer == null) {
      return null;
    }
    return issuer.substring(ISSUER_PREFIX.length());
  }

  /**
   * Gets expires at - the lifetime of token.
   *
   * @return the expires at - the lifetime of token (Unix Timestamp)
   */
  public long getExpiresAt() {
    return expiresAt;
  }

  /**
   * Gets identity.
   *
   * @return the identity
   */
  public String getIdentity() {
    if (subject == null) {
      return null;
    }
    return subject.substring(SUBJECT_PREFIX.length());
  }

  /**
   * Gets issued at.
   *
   * @return the issued at
   */
  public Date getIssuedAt() {
    return new Date(issuedAt * 1000);
  }

  /**
   * @return the issuer
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * @return the subject
   */
  public String getSubject() {
    return subject;
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
    result = prime * result + ((additionalData == null) ? 0 : additionalData.hashCode());
    result = prime * result + (int) (expiresAt ^ (expiresAt >>> 32));
    result = prime * result + (int) (issuedAt ^ (issuedAt >>> 32));
    result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
    result = prime * result + ((subject == null) ? 0 : subject.hashCode());
    return result;
  }

}
