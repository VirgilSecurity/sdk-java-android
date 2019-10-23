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

package com.virgilsecurity.sdk.cards.model;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Date;

/**
 * The {@linkplain RawCardContent} describes contents of Card.
 */
public class RawCardContent {

  @SerializedName("identity")
  private String identity;

  @SerializedName("public_key")
  private String publicKey;

  @SerializedName("version")
  private String version;

  @SerializedName("created_at")
  private long createdAt;

  @SerializedName("previous_card_id")
  private String previousCardId;

  /**
   * Instantiate {@linkplain RawCardContent} from the provided string.
   *
   * @param cardModel json serialized to string
   * @return the raw card content
   */
  public static RawCardContent fromJson(String cardModel) {
    return ConvertionUtils.deserializeFromJson(cardModel, RawCardContent.class);
  }

  /**
   * Instantiate {@linkplain RawCardContent} from the provided base64 string.
   *
   * @param cardModel base64-encoded json serialized to string
   * @return the raw card content
   */
  public static RawCardContent fromString(String cardModel) {
    return ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(cardModel),
        RawCardContent.class);
  }

  /**
   * Create new instance of {@link RawCardContent}.
   *
   * @param snapshot The raw card content snapshot.
   */
  public RawCardContent(byte[] snapshot) {
    RawCardContent content = ConvertionUtils.parseSnapshot(snapshot, RawCardContent.class);
    this.identity = content.identity;
    this.publicKey = content.publicKey;
    this.version = content.version;
    this.createdAt = content.createdAt;
    this.previousCardId = content.previousCardId;
  }

  /**
   * Instantiates a new Raw card content.
   *
   * @param identity  the identity
   * @param publicKey the public key
   * @param createdAt when the Card was created at
   */
  public RawCardContent(String identity, String publicKey, Date createdAt) {
    this(identity, publicKey, "5.0", createdAt);
  }

  /**
   * Instantiates a new Raw card content.
   *
   * @param identity  the identity
   * @param publicKey the public key
   * @param version   the version of Card (ex. "5.0")
   * @param createdAt when the Card was created at
   */
  public RawCardContent(String identity, String publicKey, String version, Date createdAt) {
    this(identity, publicKey, version, createdAt, null);
  }

  /**
   * Instantiates a new Raw card content.
   *
   * @param identity       the identity
   * @param publicKey      the public key
   * @param version        the version of Card (ex. "5.0")
   * @param createdAt      when the Card was created at
   * @param previousCardId the previous card id that is current Card used to override
   */
  public RawCardContent(String identity, String publicKey, String version, Date createdAt,
                        String previousCardId) {
    this.identity = identity;
    this.publicKey = publicKey;
    this.version = version;
    this.createdAt = createdAt.getTime() / 1000;
    this.previousCardId = previousCardId;
  }

  /**
   * Export as base64 string.
   *
   * @return the base64 string
   */
  public String exportAsBase64String() {
    return ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(this));
  }

  /**
   * Export as json in string format.
   *
   * @return the json in string format
   */
  public String exportAsJson() {
    return ConvertionUtils.serializeToJson(this);
  }

  /**
   * Gets created at date.
   *
   * @return the created at date
   */
  public Date getCreatedAtDate() {
    return new Date(createdAt * 1000);
  }

  /**
   * Gets created at timestamp.
   *
   * @return in seconds (Unix time)
   */
  public long getCreatedAtTimestamp() {
    return createdAt;
  }

  /**
   * Gets identity.
   *
   * @return the identity
   */
  public String getIdentity() {
    return identity;
  }

  /**
   * Gets previous card id.
   *
   * @return the previous card id
   */
  public String getPreviousCardId() {
    return previousCardId;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public String getPublicKey() {
    return publicKey;
  }

  /**
   * Gets version.
   *
   * @return the version
   */
  public String getVersion() {
    return version;
  }

  /**
   * Sets created at.
   *
   * @param createdAt in seconds (Unix time)
   */
  public void setCreatedAt(long createdAt) {
    this.createdAt = createdAt;
  }

  /**
   * Sets created at date.
   *
   * @param createdAt the created at
   */
  public void setCreatedAtDate(Date createdAt) {
    this.createdAt = createdAt.getTime() / 1000;
  }

  /**
   * Sets identity.
   *
   * @param identity the identity
   */
  public void setIdentity(String identity) {
    this.identity = identity;
  }

  /**
   * Sets previous card id.
   *
   * @param previousCardId the previous card id
   */
  public void setPreviousCardId(String previousCardId) {
    this.previousCardId = previousCardId;
  }

  /**
   * Sets public key.
   *
   * @param publicKeyData the public key data
   */
  public void setPublicKey(String publicKeyData) {
    this.publicKey = publicKeyData;
  }

  /**
   * Sets version.
   *
   * @param version the version
   */
  public void setVersion(String version) {
    this.version = version;
  }

  /**
   * Take snapshot.
   *
   * @return The snapshot.
   */
  public byte[] snapshot() {
    return ConvertionUtils.captureSnapshot(this);
  }
}
