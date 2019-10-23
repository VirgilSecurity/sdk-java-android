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

/**
 * The {@link JwtHeaderContent} represents contents of {@link Jwt} header.
 */
public class JwtHeaderContent {

  public static final String VIRGIL_CONTENT_TYPE = "virgil-jwt;v=1";
  public static final String JWT_TYPE = "JWT";

  @SerializedName("alg")
  private String algorithm;

  @SerializedName("typ")
  private String type;

  @SerializedName("cty")
  private String contentType;

  @SerializedName("kid")
  private String keyIdentifier;

  /**
   * Create new instance of {@link JwtHeaderContent}.
   */
  public JwtHeaderContent() {
    this.algorithm = "VEDS512";
    this.type = JWT_TYPE;
    this.contentType = VIRGIL_CONTENT_TYPE;
  }

  /**
   * Instantiates a new Jwt header content.
   *
   * @param keyIdentifier the identifier of public key
   */
  public JwtHeaderContent(String keyIdentifier) {
    this();
    this.keyIdentifier = keyIdentifier;
  }

  /**
   * Instantiates a new Jwt header content.
   *
   * @param algorithm     the algorithm used in signature
   * @param keyIdentifier the identifier of public key
   */
  public JwtHeaderContent(String algorithm, String keyIdentifier) {
    this();
    this.algorithm = algorithm;
    this.keyIdentifier = keyIdentifier;
  }

  /**
   * Instantiates a new Jwt header content.
   *
   * @param algorithm     the algorithm used in signature
   * @param type          the token type (default is "JWT")
   * @param keyIdentifier the identifier of public key
   */
  public JwtHeaderContent(String algorithm, String type, String keyIdentifier) {
    this();
    this.algorithm = algorithm;
    this.type = type;
    this.keyIdentifier = keyIdentifier;
  }

  /**
   * Instantiates a new Jwt header content.
   *
   * @param algorithm     the algorithm used in signature
   * @param type          the token type (default is "JWT")
   * @param contentType   the content type for this Jwt
   * @param keyIdentifier the identifier of public key
   */
  public JwtHeaderContent(String algorithm, String type, String contentType, String keyIdentifier) {
    this.algorithm = algorithm;
    this.type = type;
    this.contentType = contentType;
    this.keyIdentifier = keyIdentifier;
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
    JwtHeaderContent other = (JwtHeaderContent) obj;
    if (algorithm == null) {
      if (other.algorithm != null) {
        return false;
      }
    } else if (!algorithm.equals(other.algorithm)) {
      return false;
    }
    if (contentType == null) {
      if (other.contentType != null) {
        return false;
      }
    } else if (!contentType.equals(other.contentType)) {
      return false;
    }
    if (keyIdentifier == null) {
      if (other.keyIdentifier != null) {
        return false;
      }
    } else if (!keyIdentifier.equals(other.keyIdentifier)) {
      return false;
    }
    if (type == null) {
      if (other.type != null) {
        return false;
      }
    } else if (!type.equals(other.type)) {
      return false;
    }
    return true;
  }

  /**
   * Gets algorithm used in signature.
   *
   * @return the algorithm used in signature
   */
  public String getAlgorithm() {
    return algorithm;
  }

  /**
   * Gets content type.
   *
   * @return the content type
   */
  public String getContentType() {
    return contentType;
  }

  /**
   * Gets identifier of public key.
   *
   * @return the identifier of public key
   */
  public String getKeyIdentifier() {
    return keyIdentifier;
  }

  /**
   * Gets token type.
   *
   * @return the token type
   */
  public String getType() {
    return type;
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
    result = prime * result + ((algorithm == null) ? 0 : algorithm.hashCode());
    result = prime * result + ((contentType == null) ? 0 : contentType.hashCode());
    result = prime * result + ((keyIdentifier == null) ? 0 : keyIdentifier.hashCode());
    result = prime * result + ((type == null) ? 0 : type.hashCode());
    return result;
  }

  /**
   * Sets algorithm used in signature.
   *
   * @param algorithm the algorithm used in signature
   */
  void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }

  /**
   * Sets content type.
   *
   * @param contentType the content type
   */
  void setContentType(String contentType) {
    this.contentType = contentType;
  }

  /**
   * Sets identifier of public key.
   *
   * @param keyIdentifier the identifier of public key
   */
  void setKeyIdentifier(String keyIdentifier) {
    this.keyIdentifier = keyIdentifier;
  }

  /**
   * Sets token type.
   *
   * @param type the token type
   */
  void setType(String type) {
    this.type = type;
  }

}
