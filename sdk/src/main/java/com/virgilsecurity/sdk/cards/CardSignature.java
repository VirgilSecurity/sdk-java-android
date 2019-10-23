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

package com.virgilsecurity.sdk.cards;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/**
 * The {@link CardSignature} class represents set of data that defines signature of Card.
 */
public class CardSignature {

  /**
   * The Card signature builder.
   */
  public static final class CardSignatureBuilder {
    private String signer;
    private byte[] signature;
    private byte[] snapshot;
    private Map<String, String> extraFields;

    /**
     * Create new instance of {@link CardSignatureBuilder}.
     *
     * @param signer    the signer type
     * @param signature the signature
     */
    public CardSignatureBuilder(String signer, byte[] signature) {
      this.signer = signer;
      this.signature = signature;
    }

    /**
     * Build {@link CardSignature}.
     *
     * @return the card signature
     */
    public CardSignature build() {
      CardSignature cardSignature = new CardSignature();
      cardSignature.signer = this.signer;
      cardSignature.signature = this.signature;
      cardSignature.snapshot = this.snapshot;
      cardSignature.extraFields = this.extraFields;

      return cardSignature;
    }

    /**
     * Sets extra fields. It's optional property.
     *
     * @param extraFields the extra fields
     * @return the card signature builder
     */
    public CardSignatureBuilder extraFields(Map<String, String> extraFields) {
      this.extraFields = extraFields;
      return this;
    }

    /**
     * Sets snapshot. It's optional property.
     *
     * @param snapshot the snapshot
     * @return the card signature builder
     */
    public CardSignatureBuilder snapshot(byte[] snapshot) {
      this.snapshot = snapshot;
      return this;
    }
  }

  private String signer;
  private byte[] signature;
  private byte[] snapshot;

  private Map<String, String> extraFields;

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CardSignature that = (CardSignature) o;
    return Objects.equals(signer, that.signer) && Arrays.equals(signature, that.signature)
        && Arrays.equals(snapshot, that.snapshot) && Objects.equals(extraFields, that.extraFields);
  }

  /**
   * Gets extra fields associated with the signature.
   *
   * @return the extra fields associated with the signature
   */
  public Map<String, String> getExtraFields() {
    return extraFields;
  }

  /**
   * Gets signer signature.
   *
   * @return the signature
   */
  public byte[] getSignature() {
    return signature;
  }

  /**
   * Gets signer.
   *
   * @return the signer identifier
   */
  public String getSigner() {
    return signer;
  }

  /**
   * Gets snapshot.
   *
   * @return the snapshot
   */
  public byte[] getSnapshot() {
    return snapshot;
  }

  @Override
  public int hashCode() {

    int result = Objects.hash(signer, extraFields);
    result = 31 * result + Arrays.hashCode(signature);
    result = 31 * result + Arrays.hashCode(snapshot);
    return result;
  }
}
