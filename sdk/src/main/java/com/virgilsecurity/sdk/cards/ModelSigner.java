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

import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Map;

/**
 * The {@link ModelSigner} provides cryptographic operation as signing.
 *
 * @see VirgilCardCrypto
 * @see RawSignedModel
 * @see RawSignature
 */
public class ModelSigner {

  private VirgilCardCrypto crypto;

  /**
   * Instantiates a new Model signer.
   *
   * @param crypto The crypto.
   */
  public ModelSigner(VirgilCardCrypto crypto) {
    this.crypto = crypto;
  }

  /**
   * Signing {@link RawSignedModel} using specified signer parameters and private key with self
   * signature type.
   *
   * @param cardModel  The card model to be signed.
   * @param privateKey The private key for signing.
   *
   * @throws CryptoException If signing issue occurred.
   *
   * @see #sign(RawSignedModel, String, VirgilPrivateKey)
   */
  public void selfSign(RawSignedModel cardModel, VirgilPrivateKey privateKey) throws CryptoException {
    sign(cardModel, SignerType.SELF.getRawValue(), privateKey);
  }

  /**
   * Signing {@link RawSignedModel} using specified signer parameters and private key with self
   * signature type.
   *
   * @param cardModel      The card model to be signed.
   * @param privateKey     The private key for signing.
   * @param additionalData The additional data to be stored in the signature.
   *
   * @throws CryptoException If signing issue occurred.
   *
   * @see #sign(RawSignedModel, String, VirgilPrivateKey, byte[])
   */
  public void selfSign(RawSignedModel cardModel, VirgilPrivateKey privateKey, byte[] additionalData)
      throws CryptoException {
    sign(cardModel, SignerType.SELF.getRawValue(), privateKey, additionalData);
  }

  /**
   * Signing {@link RawSignedModel} using specified signer parameters and private key with self
   * signature type.
   *
   * @param cardModel   The card model to be signed.
   * @param privateKey  The private key for signing.
   * @param extraFields The extra fields to be stored in the signature.
   *
   * @throws CryptoException If signing issue occurred.
   *
   * @see #sign(RawSignedModel, String, VirgilPrivateKey, byte[])
   */
  public void selfSign(RawSignedModel cardModel, VirgilPrivateKey privateKey,
                       Map<String, String> extraFields) throws CryptoException {
    byte[] additionalData = ConvertionUtils.captureSnapshot(extraFields);
    selfSign(cardModel, privateKey, additionalData);
  }

  /**
   * Signs the {@link RawSignedModel} using specified signer parameters and private key.
   *
   * @param cardModel  The card model to be signed.
   * @param signer     The type of sign.
   * @param privateKey The private key for signing.
   *
   * @throws CryptoException If signing issue occurred.
   */
  public void sign(RawSignedModel cardModel, String signer, VirgilPrivateKey privateKey)
      throws CryptoException {

    byte[] signature = crypto.generateSignature(cardModel.getContentSnapshot(), privateKey);

    RawSignature rawSignature = new RawSignature(signer, ConvertionUtils.toBase64String(signature));

    cardModel.addSignature(rawSignature);
  }

  /**
   * Signs the {@link RawSignedModel} using specified signer parameters and private key.
   *
   * @param cardModel      The card model to be signed.
   * @param signer         The type of sign.
   * @param privateKey     The private key for signing.
   * @param additionalData The additional data to be stored in the signature.
   *
   * @throws CryptoException If signing issue occurred.
   */
  public void sign(RawSignedModel cardModel, String signer, VirgilPrivateKey privateKey,
                   byte[] additionalData) throws CryptoException {

    byte[] combinedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(),
        additionalData);
    byte[] signature = crypto.generateSignature(combinedSnapshot, privateKey);

    RawSignature rawSignature = new RawSignature(ConvertionUtils.toBase64String(additionalData),
        signer, ConvertionUtils.toBase64String(signature));

    cardModel.addSignature(rawSignature);
  }

  /**
   * Signs the {@link RawSignedModel} using specified signer parameters and private key.
   *
   * @param cardModel   The card model to be signed.
   * @param signer      The type of sign.
   * @param privateKey  The private key for signing.
   * @param extraFields The extra fields to be stored in the signature.
   *
   * @throws CryptoException If signing issue occurred.
   */
  public void sign(RawSignedModel cardModel, String signer, VirgilPrivateKey privateKey,
                   Map<String, String> extraFields) throws CryptoException {
    byte[] additionalData = ConvertionUtils.captureSnapshot(extraFields);
    sign(cardModel, signer, privateKey, additionalData);
  }
}
