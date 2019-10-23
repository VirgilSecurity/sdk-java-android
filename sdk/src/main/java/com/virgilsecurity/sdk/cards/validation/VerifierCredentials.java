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

package com.virgilsecurity.sdk.cards.validation;

/**
 * The {@link VerifierCredentials} class represents data set of verifier.
 */
public class VerifierCredentials {
  private String signer;
  private byte[] publicKey;

  /**
   * Instantiates a new Verifier credentials.
   *
   * @param signer    the signer
   * @param publicKey the public key of verifier
   */
  public VerifierCredentials(String signer, byte[] publicKey) {
    this.signer = signer;
    this.publicKey = publicKey;
  }

  /**
   * Get public key of verifier.
   *
   * @return the public key in byte [ ]
   */
  public byte[] getPublicKey() {
    return publicKey;
  }

  /**
   * Gets signer.
   *
   * @return the signer
   */
  public String getSigner() {
    return signer;
  }

  /**
   * Sets public key of verifier.
   *
   * @param publicKey the public key
   */
  public void setPublicKey(byte[] publicKey) {
    this.publicKey = publicKey;
  }

  /**
   * Sets signer.
   *
   * @param signer the signer
   */
  public void setSigner(String signer) {
    this.signer = signer;
  }
}
