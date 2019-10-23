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

import java.util.Objects;

/**
 * The {@link RawSignature} class represents raw model of digital signature.
 */
public class RawSignature {

  @SerializedName("snapshot")
  private String snapshot;

  @SerializedName("signer")
  private String signer;

  @SerializedName("signature")
  private String signature;

  /**
   * Instantiates a new Raw signature.
   *
   * @param signer    the signer type
   * @param signature the signature
   */
  public RawSignature(String signer, String signature) {
    this.signer = signer;
    this.signature = signature;
  }

  /**
   * Instantiates a new Raw signature.
   *
   * @param snapshot  the snapshot that contains additional data associated with signature
   * @param signer    the signer type
   * @param signature the signature
   */
  public RawSignature(String snapshot, String signer, String signature) {
    this.snapshot = snapshot;
    this.signer = signer;
    this.signature = signature;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RawSignature that = (RawSignature) o;
    return Objects.equals(snapshot, that.snapshot) && Objects.equals(signer, that.signer)
        && Objects.equals(signature, that.signature);
  }

  /**
   * Gets signature.
   *
   * @return the signature
   */
  public String getSignature() {
    return signature;
  }

  /**
   * Gets signer type.
   *
   * @return the signer
   */
  public String getSigner() {
    return signer;
  }

  /**
   * Gets snapshot that contains additional data associated with signature.
   *
   * @return the snapshot that contains additional data associated with signature
   */
  public String getSnapshot() {
    return snapshot;
  }

  @Override
  public int hashCode() {

    return Objects.hash(snapshot, signer, signature);
  }

  /**
   * Sets signature.
   *
   * @param signature the signature
   */
  public void setSignature(String signature) {
    this.signature = signature;
  }

  /**
   * Sets signer type.
   *
   * @param signer the signer
   */
  public void setSigner(String signer) {
    this.signer = signer;
  }

  /**
   * Sets snapshot that contains additional data associated with signature.
   *
   * @param snapshot the snapshot that contains additional data associated with signature
   */
  public void setSnapshot(String snapshot) {
    this.snapshot = snapshot;
  }
}
