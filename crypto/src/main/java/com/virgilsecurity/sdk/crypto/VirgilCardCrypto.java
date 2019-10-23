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

package com.virgilsecurity.sdk.crypto;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The {@link VirgilCardCrypto} class provides a cryptographic operations in applications, such as
 * hashing, signature generation and verification, and encryption and decryption.
 *
 * @see VirgilCardCrypto
 * @see VirgilPrivateKey
 * @see VirgilPublicKey
 * @see VirgilCrypto
 */
public class VirgilCardCrypto {

  private VirgilCrypto virgilCrypto;

  /**
   * Instantiates a new Virgil card crypto.
   */
  public VirgilCardCrypto() {
    this.virgilCrypto = new VirgilCrypto();
  }

  /**
   * Create new instance of {@link VirgilCardCrypto}.
   *
   * @param virgilCrypto The Virgil Crypto.
   */
  public VirgilCardCrypto(VirgilCrypto virgilCrypto) {
    this.virgilCrypto = virgilCrypto;
  }

  /**
   * Exports the {@code publicKey} into material representation.
   *
   * @param publicKey The public key.
   *
   * @return Public key in material representation of {@code byte[]}.
   *
   * @throws CryptoException If problems occurred while exporting key.
   */
  public byte[] exportPublicKey(VirgilPublicKey publicKey) throws CryptoException {
    if (publicKey == null) {
      throw new NullArgumentException("publicKey");
    }

    return virgilCrypto.exportPublicKey(publicKey);
  }

  /**
   * Generates the fingerprint(512-bit hash) for the specified {@code data}.
   *
   * @param data The input data for which to compute the fingerprint.
   *
   * @return The fingerprint for specified data.
   */
  public byte[] computeSha512(byte[] data) {
    return virgilCrypto.computeHash(data);
  }

  /**
   * Generates the digital signature for the specified {@code data} using the specified
   * {@link VirgilPrivateKey}.
   *
   * @param data       The input data for which to compute the signature.
   * @param privateKey The private key.
   *
   * @return The digital signature for the specified data.
   *
   * @throws CryptoException If problems occurred while generating signature.
   */
  public byte[] generateSignature(byte[] data, VirgilPrivateKey privateKey) throws CryptoException {
    return virgilCrypto.generateSignature(data, privateKey); // TODO test empty data signature
  }

  /**
   * Gets Virgil Crypto.
   *
   * @return The virgil crypto.
   */
  public VirgilCrypto getVirgilCrypto() {
    return virgilCrypto;
  }

  /**
   * Imports the public key from its material representation.
   *
   * @param data The public key material representation bytes.
   *
   * @return The instance of {@link VirgilPublicKey} imported.
   *
   * @throws CryptoException If problems occurred while importing key.
   */
  public VirgilPublicKey importPublicKey(byte[] data) throws CryptoException {
    return virgilCrypto.importPublicKey(data);
  }

  /**
   * Verifies that a digital signature is valid by checking the {@code signature}, with provided
   * {@code publicKey} and {@code data}.
   *
   * @param signature The digital signature for the {@code data}.
   * @param data      The input data for which the {@code signature} has been generated.
   * @param publicKey The {@link VirgilPublicKey}.
   *
   * @return {@code true} if signature is valid, {@code false} otherwise.
   *
   * @throws CryptoException If problems occurred while verifying signature.
   */
  public boolean verifySignature(byte[] signature, byte[] data, VirgilPublicKey publicKey) throws CryptoException {
    return virgilCrypto.verifySignature(signature, data, publicKey);
  }
}
