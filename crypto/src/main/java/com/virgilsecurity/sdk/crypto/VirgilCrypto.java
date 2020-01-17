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

package com.virgilsecurity.sdk.crypto;

import com.virgilsecurity.common.exception.NullArgumentException;
import com.virgilsecurity.common.model.Pair;
import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.AlgId;
import com.virgilsecurity.crypto.foundation.CtrDrbg;
import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.foundation.KeyAlg;
import com.virgilsecurity.crypto.foundation.KeyAlgFactory;
import com.virgilsecurity.crypto.foundation.KeyAsn1Deserializer;
import com.virgilsecurity.crypto.foundation.KeyAsn1Serializer;
import com.virgilsecurity.crypto.foundation.KeyMaterialRng;
import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.crypto.foundation.KeySigner;
import com.virgilsecurity.crypto.foundation.PaddingParams;
import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.Random;
import com.virgilsecurity.crypto.foundation.RandomPadding;
import com.virgilsecurity.crypto.foundation.RawPrivateKey;
import com.virgilsecurity.crypto.foundation.RawPublicKey;
import com.virgilsecurity.crypto.foundation.RecipientCipher;
import com.virgilsecurity.crypto.foundation.Sha224;
import com.virgilsecurity.crypto.foundation.Sha256;
import com.virgilsecurity.crypto.foundation.Sha384;
import com.virgilsecurity.crypto.foundation.Sha512;
import com.virgilsecurity.crypto.foundation.Signer;
import com.virgilsecurity.crypto.foundation.SignerInfo;
import com.virgilsecurity.crypto.foundation.SignerInfoList;
import com.virgilsecurity.crypto.foundation.Verifier;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The Virgil's implementation of Crypto.
 *
 * @see VirgilPublicKey
 * @see VirgilPrivateKey
 */
public class VirgilCrypto {

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;
  private static final int CHUNK_SIZE = 1024;
  private static final String KEY_DOESNT_SUPPORT_VERIFICATION = "This key doesn\'t support verification";
  private static final String KEY_DOESNT_SUPPORT_SIGNING = "This key doesn\'t support signing";

  public static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".getBytes(UTF8_CHARSET);
  public static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID".getBytes(UTF8_CHARSET);
  public static final int PADDING_LENGTH = 160;

  private Random rng;
  private KeyPairType defaultKeyPairType;
  private boolean useSHA256Fingerprints;

  interface InputOutput {
  }

  static class IOData implements InputOutput {
    private byte[] input;

    IOData(byte[] input) {
      this.input = input;
    }

    byte[] getInput() {
      return input;
    }
  }

  static class IOStream implements InputOutput {
    static final int STREAM_SIZE_UNDEFINED = -1;

    private InputStream inputStream;
    // Default *streamSize* value is -1 which means that *streamSize* is undefined.
    private int streamSize = STREAM_SIZE_UNDEFINED;
    private OutputStream outputStream;

    IOStream(InputStream inputStream, int streamSize, OutputStream outputStream) {
      this.inputStream = inputStream;
      this.streamSize = streamSize;
      this.outputStream = outputStream;
    }

    IOStream(InputStream inputStream, OutputStream outputStream) {
      this.inputStream = inputStream;
      this.outputStream = outputStream;
    }

    InputStream getInputStream() {
      return inputStream;
    }

    int getStreamSize() {
      return streamSize;
    }

    OutputStream getOutputStream() {
      return outputStream;
    }
  }

  static class SigningOptions {
    private VirgilPrivateKey privateKey;
    private SigningMode mode;

    SigningOptions(VirgilPrivateKey privateKey, SigningMode mode) {
      this.privateKey = privateKey;
      this.mode = mode;
    }

    public VirgilPrivateKey getPrivateKey() {
      return privateKey;
    }

    public SigningMode getMode() {
      return mode;
    }
  }

  static class VerifyingOptions {
    private List<VirgilPublicKey> publicKeys;
    private VerifyingMode mode;

    VerifyingOptions(List<VirgilPublicKey> publicKeys, VerifyingMode mode) {
      this.publicKeys = publicKeys;
      this.mode = mode;
    }

    public List<VirgilPublicKey> getPublicKeys() {
      return publicKeys;
    }

    public VerifyingMode getMode() {
      return mode;
    }
  }

  enum SigningMode {
    SIGN_AND_ENCRYPT,
    SIGN_THEN_ENCRYPT
  }

  enum VerifyingMode {
    DECRYPT_AND_VERIFY,
    DECRYPT_THEN_VERIFY,
    ANY
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   */
  public VirgilCrypto() {
    this(false);
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when calculating public key
   *                              identifier.
   */
  public VirgilCrypto(boolean useSHA256Fingerprints) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyPairType = KeyPairType.ED25519;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType the {@link KeyPairType} to be used by default for generating key pair.
   */
  public VirgilCrypto(KeyPairType keysType) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyPairType = keysType;
    this.useSHA256Fingerprints = false;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param rng Random number generator.
   */
  public VirgilCrypto(Random rng) {
    this.rng = rng;
    this.defaultKeyPairType = KeyPairType.ED25519;
    this.useSHA256Fingerprints = false;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType              the {@link KeyPairType} to be used by default for generating key pair.
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when calculating public key
   *                              identifier.
   */
  public VirgilCrypto(KeyPairType keysType, boolean useSHA256Fingerprints) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyPairType = keysType;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * @param rng      Random number generator.
   * @param keysType the {@link KeyPairType} to be used by default for generating key pair.
   */
  public VirgilCrypto(Random rng, KeyPairType keysType) {
    this.rng = rng;
    this.defaultKeyPairType = keysType;
    this.useSHA256Fingerprints = false;
  }

  /**
   * @param rng                   Random number generator.
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when calculating public key
   *                              identifier.
   */
  public VirgilCrypto(Random rng, boolean useSHA256Fingerprints) {
    this.rng = rng;
    this.defaultKeyPairType = KeyPairType.ED25519;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * @param rng                   Random number generator.
   * @param keysType              the {@link KeyPairType} to be used by default for generating key pair.
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when calculating public key
   *                              *                              identifier.
   */
  public VirgilCrypto(Random rng, KeyPairType keysType, boolean useSHA256Fingerprints) {
    this.rng = rng;
    this.defaultKeyPairType = keysType;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @param keyPairType Type of key to be generated.
   * @param seed Seed key material.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(KeyPairType keyPairType, byte[] seed) throws CryptoException {
    try (KeyMaterialRng keyMaterialRng = new KeyMaterialRng()) {

      if (!(seed.length >= keyMaterialRng.getKeyMaterialLenMin()
          && seed.length <= keyMaterialRng.getKeyMaterialLenMax())) {
        throw new CryptoException("Invalid seed size");
      }

      keyMaterialRng.resetKeyMaterial(seed);

      return generateKeyPair(keyPairType, keyMaterialRng);
    }
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @param seed Seed key material.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(byte[] seed) throws CryptoException {
    return generateKeyPair(this.defaultKeyPairType, seed);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys by specified
   * type.
   *
   * @param keyPairType Type of the generated keys. The possible values can be found in {@link KeyPairType}.
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(KeyPairType keyPairType) throws CryptoException {
    return generateKeyPair(keyPairType, this.rng);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair() throws CryptoException {
    return generateKeyPair(this.defaultKeyPairType);
  }

  private VirgilKeyPair generateKeyPair(KeyPairType keyPairType, Random rng) throws CryptoException {
    try (KeyProvider keyProvider = new KeyProvider()) {

      if (keyPairType.getRsaBitLen() != -1) {
        int rsaLength = keyPairType.getRsaBitLen();
        keyProvider.setRsaParams(rsaLength);
      }

      keyProvider.setRandom(rng);
      keyProvider.setupDefaults();

      PrivateKey privateKey;

      if (keyPairType.isCompound()) {
        Pair<AlgId, AlgId> cipherKeysAlgIds = keyPairType.getCipherKeysAlgIds();
        Pair<AlgId, AlgId> signerKeysAlgIds = keyPairType.getSignerKeysAlgIds();
        privateKey = keyProvider.generateCompoundHybridPrivateKey(cipherKeysAlgIds.getFirst(),
                cipherKeysAlgIds.getSecond(), signerKeysAlgIds.getFirst(), signerKeysAlgIds.getSecond());
      } else {
        privateKey = keyProvider.generatePrivateKey(keyPairType.getAlgId());
      }

      PublicKey publicKey = privateKey.extractPublicKey();
      byte[] keyId = computePublicKeyIdentifier(publicKey);

      VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyId, publicKey, keyPairType);
      VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyId, privateKey, keyPairType);

      return new VirgilKeyPair(virgilPublicKey, virgilPrivateKey);
    }
  }

  /**
   * Encrypts data for passed PublicKey.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data      Raw data bytes for encryption.
   * @param publicKey Recipient's public key.
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, VirgilPublicKey publicKey) throws EncryptionException {
    return encrypt(data, Collections.singletonList(publicKey), false);
  }

  /**
   * Encrypts data for passed PublicKey.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data      Raw data bytes for encryption.
   * @param publicKey Recipient's public key.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, VirgilPublicKey publicKey, boolean enablePadding) throws EncryptionException {
    return encrypt(data, Collections.singletonList(publicKey), enablePadding);
  }

  /**
   * Encrypts data for passed PublicKeys.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       Raw data bytes for encryption.
   * @param publicKeys List of recipients' public keys.
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try {
      return encrypt(new IOData(data), null, publicKeys, false);
    } catch (Exception exception) {
      throw new EncryptionException(exception);
    }
  }

  /**
   * Encrypts data for passed PublicKeys.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       Raw data bytes for encryption.
   * @param publicKeys List of recipients' public keys.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, List<VirgilPublicKey> publicKeys,
                        boolean enablePadding) throws EncryptionException {
    try {
      return encrypt(new IOData(data), null, publicKeys, enablePadding);
    } catch (Exception exception) {
      throw new EncryptionException(exception);
    }
  }

  /**
   * Encrypts the specified stream using recipient's Public key.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream for encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKey    Recipient's public key.
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey publicKey)
      throws EncryptionException {
    encrypt(inputStream, outputStream, Collections.singletonList(publicKey), false);
  }

  /**
   * Encrypts the specified stream using recipient's Public key.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream for encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKey    Recipient's public key.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey publicKey,
                      boolean enablePadding) throws EncryptionException {
    encrypt(inputStream, outputStream, Collections.singletonList(publicKey), enablePadding);
  }

  /**
   * Encrypts data stream for passed PublicKeys.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream to be encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKeys   List of recipients' public keys.
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream,
                      List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try {
      encrypt(new IOStream(inputStream, outputStream), null, publicKeys, false);
    } catch (Exception exception) {
      throw new EncryptionException(exception);
    }
  }

  /**
   * Encrypts data stream for passed PublicKeys.
   * <ol>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream to be encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKeys   List of recipients' public keys.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream,
                      List<VirgilPublicKey> publicKeys, boolean enablePadding) throws EncryptionException {
    try {
      encrypt(new IOStream(inputStream, outputStream), null, publicKeys, enablePadding);
    } catch (Exception exception) {
      throw new EncryptionException(exception);
    }
  }

  /**
   * Signs and encrypts the data.
   *
   * @deprecated This method doesn't encrypt signature itself. Please, use
   * {@link #authEncrypt(byte[], VirgilPrivateKey, VirgilPublicKey)} instead.
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKey  The recipient's Public key to encrypt the data.
   *
   * @return Signed and encrypted data bytes.
   *
   * @throws CryptoException if crypto sing or encrypt operation failed
   */
  @Deprecated
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
      throws CryptoException {
    return signThenEncrypt(data, privateKey, Collections.singletonList(publicKey), false);
  }

  /**
   * Signs (with Private key) Then Encrypts data for passed PublicKeys.
   *
   * @deprecated This method doesn't encrypt signature itself. Please, use
   * {@link #authEncrypt(byte[], VirgilPrivateKey, List)} instead.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts both data and signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKeys The list of Public key recipients to encrypt the data.
   *
   * @return Signed and encrypted data bytes.
   *
   * @throws CryptoException If crypto sing or encrypt operation failed.
   */
  @Deprecated
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey,
                                List<VirgilPublicKey> publicKeys) throws CryptoException {
    return encrypt(new IOData(data), new SigningOptions(privateKey, SigningMode.SIGN_AND_ENCRYPT), publicKeys, false);
  }

  /**
   * Signs (with Private key) Then Encrypts data for passed PublicKeys.
   *
   * @deprecated This method doesn't encrypt signature itself. Please, use
   * {@link #authEncrypt(byte[], VirgilPrivateKey, List)} instead.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts both data and signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key and each
   * ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKeys The list of Public key recipients to encrypt the data.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @return Signed and encrypted data bytes.
   *
   * @throws CryptoException If crypto sing or encrypt operation failed.
   */
  @Deprecated
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey,
                                List<VirgilPublicKey> publicKeys, boolean enablePadding) throws CryptoException {
    return encrypt(new IOData(data), new SigningOptions(privateKey, SigningMode.SIGN_AND_ENCRYPT), publicKeys,
            enablePadding);
  }

  /**
   * Decrypts data using passed PrivateKey.
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key and
   * recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data using KEY1 and AES-256-GCM</li>
   * </ol>
   *
   * @param data       The encrypted data bytes to decrypt.
   * @param privateKey The private key used for decryption.
   *
   * @return Decrypted data bytes.
   *
   * @throws DecryptionException If decryption failed.
   */
  public byte[] decrypt(byte[] data, VirgilPrivateKey privateKey) throws DecryptionException {
    try {
      return decrypt(new IOData(data), null, privateKey);
    } catch (Exception exception) {
        throw new DecryptionException(exception);
    }
  }

  /**
   * Decrypts the specified stream using Private key.
   *
   * @param inputStream  Encrypted stream for decryption.
   * @param outputStream Output stream for decrypted data.
   * @param privateKey   Private key for decryption.
   *
   * @throws DecryptionException If decryption failed.
   */
  public void decrypt(InputStream inputStream, OutputStream outputStream,
                      VirgilPrivateKey privateKey) throws DecryptionException {
    try {
      decrypt(new IOStream(inputStream, outputStream), null, privateKey);
    } catch (Exception exception) {
        throw new DecryptionException(exception);
    }
  }

  /**
   * Decrypts (with private key) Then Verifies data using signers PublicKey.
   *
   * @deprecated This method doesn't decrypt signature itself. Please, use
   * {@link #authDecrypt(byte[], VirgilPrivateKey, VirgilPublicKey)} instead.
   *
   * @param data             Signed Then Encrypted data.
   * @param privateKey       Receiver's private key.
   * @param signersPublicKey Signer's public keys. WARNING: Data should have signature of ANY public key from
   *                         array.
   * @return Decrypted then verified data.
   * @throws CryptoException if decryption or verification failed.
   */
  @Deprecated
  public byte[] decryptThenVerify(byte[] data, VirgilPrivateKey privateKey,
                                  VirgilPublicKey signersPublicKey) throws CryptoException {
    return decryptThenVerify(data, privateKey, Collections.singletonList(signersPublicKey));
  }

  /**
   * Decrypts (with private key) Then Verifies data using any of signers' PublicKeys.
   *
   * @deprecated This method doesn't decrypt signature itself. Please, use
   * {@link #authDecrypt(byte[], VirgilPrivateKey, List)} instead.
   *
   * @param data              Signed Then Encrypted data.
   * @param privateKey        Receiver's private key.
   * @param signersPublicKeys The list of possible signers' public keys. WARNING: Data should have signature of ANY
   *                          public key from array.
   * @return Decrypted then verified data.
   * @throws CryptoException if decryption or verification failed.
   */
  @Deprecated
  public byte[] decryptThenVerify(byte[] data, VirgilPrivateKey privateKey,
                                  List<VirgilPublicKey> signersPublicKeys) throws CryptoException {
    try {
      return decrypt(new IOData(data), new VerifyingOptions(signersPublicKeys, VerifyingMode.DECRYPT_AND_VERIFY),
              privateKey);
    } catch (Exception exception) {
        throw new DecryptionException(exception);
    }
  }

  /**
   * Signs (with private key) Then Encrypts data (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li> Generates signature depending on KeyType</li>
   * <li> Generates random AES-256 KEY1</li>
   * <li> Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li> Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li> Generates ephemeral key pair for each recipient</li>
   * <li> Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li> Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li> Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data Data to be signedThenEncrypted.
   * @param privateKey Sender private key.
   * @param recipient Recipient's public key.
   *
   * @return SignedThenEncrypted data.
   *
   * @throws SigningException If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] authEncrypt(byte[] data, VirgilPrivateKey privateKey,
                            VirgilPublicKey recipient) throws SigningException, EncryptionException {

    return authEncrypt(data, privateKey, Collections.singletonList(recipient), true);
  }

  /**
   * Signs (with private key) Then Encrypts data (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li> Generates signature depending on KeyType</li>
   * <li> Generates random AES-256 KEY1</li>
   * <li> Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li> Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li> Generates ephemeral key pair for each recipient</li>
   * <li> Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li> Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li> Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data Data to be signedThenEncrypted.
   * @param privateKey Sender private key.
   * @param recipient Recipient's public key.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @return SignedThenEncrypted data.
   *
   * @throws SigningException If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] authEncrypt(byte[] data, VirgilPrivateKey privateKey,
                            VirgilPublicKey recipient, boolean enablePadding) throws SigningException, EncryptionException {

    return authEncrypt(data, privateKey, Collections.singletonList(recipient), enablePadding);
  }

  /**
   * Signs (with private key) Then Encrypts data (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       Data to be signedThenEncrypted.
   * @param privateKey Sender private key.
   * @param recipients Recipients' public keys.
   *
   * @return SignedThenEncrypted data.
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] authEncrypt(byte[] data, VirgilPrivateKey privateKey,
                            List<VirgilPublicKey> recipients) throws EncryptionException, SigningException {

    return encrypt(new IOData(data), new SigningOptions(privateKey, SigningMode.SIGN_THEN_ENCRYPT), recipients, true);
  }

  /**
   * Signs (with private key) Then Encrypts data (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param data       Data to be signedThenEncrypted.
   * @param privateKey Sender private key.
   * @param recipients Recipients' public keys.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @return SignedThenEncrypted data.
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] authEncrypt(byte[] data, VirgilPrivateKey privateKey,
                            List<VirgilPublicKey> recipients, boolean enablePadding) throws EncryptionException, SigningException {

    return encrypt(new IOData(data), new SigningOptions(privateKey, SigningMode.SIGN_THEN_ENCRYPT), recipients,
            enablePadding);
  }

  /**
   * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys.
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature </li>
   * </ol>
   *
   * @param data             Signed Then Encrypted data.
   * @param privateKey       Receiver's private key.
   * @param signersPublicKey Possible signer's public key.
   *                         WARNING: Data should have signature of ANY public key from array.
   * @return Decrypted then verified data.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public byte[] authDecrypt(byte[] data, VirgilPrivateKey privateKey,
                            VirgilPublicKey signersPublicKey) throws VerificationException, DecryptionException {

    return authDecrypt(data, privateKey, Collections.singletonList(signersPublicKey));
  }

  /**
   * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys.
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature </li>
   * </ol>
   *
   * @param data              Signed Then Encrypted data.
   * @param privateKey        Receiver's private key.
   * @param signersPublicKeys Array of possible signers' public keys.
   *                          WARNING: Data should have signature of ANY public key from array.
   * @return Decrypted then verified data.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public byte[] authDecrypt(byte[] data, VirgilPrivateKey privateKey,
                            List<VirgilPublicKey> signersPublicKeys) throws VerificationException, DecryptionException {

    return authDecrypt(data, privateKey, signersPublicKeys, false);
  }

  /**
   * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys.
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature </li>
   * </ol>
   *
   * @param data                       Signed Then Encrypted data.
   * @param privateKey                 Receiver's private key.
   * @param signersPublicKey           Possible signer's public key.
   *                                   WARNING: Data should have signature of ANY public key from array.
   * @param allowNotEncryptedSignature Allows storing signature in plain text for compatibility with
   *                                   deprecated signAndEncrypt.
   * @return Decrypted then verified data.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public byte[] authDecrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey signersPublicKey,
                            boolean allowNotEncryptedSignature) throws VerificationException, DecryptionException {

    return authDecrypt(data, privateKey, Collections.singletonList(signersPublicKey), allowNotEncryptedSignature);
  }

  /**
   * Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys.
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature </li>
   * </ol>
   *
   * @param data                       Signed Then Encrypted data.
   * @param privateKey                 Receiver's private key.
   * @param signersPublicKeys          Array of possible signers' public keys.
   *                                   WARNING: Data should have signature of ANY public key from array.
   * @param allowNotEncryptedSignature Allows storing signature in plain text for compatibility with
   *                                   deprecated signAndEncrypt.
   * @return Decrypted then verified data.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public byte[] authDecrypt(byte[] data, VirgilPrivateKey privateKey, List<VirgilPublicKey> signersPublicKeys,
                            boolean allowNotEncryptedSignature) throws VerificationException, DecryptionException {

    VerifyingMode verifyingMode = allowNotEncryptedSignature ? VerifyingMode.ANY : VerifyingMode.DECRYPT_THEN_VERIFY;
    return decrypt(new IOData(data), new VerifyingOptions(signersPublicKeys, verifyingMode), privateKey);
  }

  /**
   * Signs (with private key) Then Encrypts stream (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream.
   * @param streamSize   Input stream size.
   * @param outputStream Output stream.
   * @param privateKey   Private key to generate signatures.
   * @param recipient    Recipient's public key.
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public void authEncrypt(InputStream inputStream, int streamSize, OutputStream outputStream,
                          VirgilPrivateKey privateKey, VirgilPublicKey recipient)
          throws SigningException, EncryptionException {

    authEncrypt(inputStream, streamSize, outputStream, privateKey, Collections.singletonList(recipient), false);
  }

  /**
   * Signs (with private key) Then Encrypts stream (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream.
   * @param streamSize   Input stream size.
   * @param outputStream Output stream.
   * @param privateKey   Private key to generate signatures.
   * @param recipient    Recipient's public key.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public void authEncrypt(InputStream inputStream, int streamSize, OutputStream outputStream,
                          VirgilPrivateKey privateKey, VirgilPublicKey recipient, boolean enablePadding)
          throws SigningException, EncryptionException {

    authEncrypt(inputStream, streamSize, outputStream, privateKey, Collections.singletonList(recipient), enablePadding);
  }

  /**
   * Signs (with private key) Then Encrypts stream (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream.
   * @param streamSize   Input stream size.
   * @param outputStream Output stream.
   * @param privateKey   Private key to generate signatures.
   * @param recipients   Recipients' public keys.
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public void authEncrypt(InputStream inputStream, int streamSize, OutputStream outputStream,
                          VirgilPrivateKey privateKey, List<VirgilPublicKey> recipients)
          throws EncryptionException, SigningException {

    encrypt(new IOStream(inputStream, streamSize, outputStream),
            new SigningOptions(privateKey, SigningMode.SIGN_THEN_ENCRYPT), recipients, false);
  }

  /**
   * Signs (with private key) Then Encrypts stream (and signature) for passed PublicKeys.
   *
   * <ol>
   * <li>Generates signature depending on KeyType</li>
   * <li>Generates random AES-256 KEY1</li>
   * <li>Encrypts data with KEY1 using AES-256-GCM and generates signature</li>
   * <li>Encrypts signature with KEY1 using AES-256-GCM</li>
   * <li>Generates ephemeral key pair for each recipient</li>
   * <li>Uses Diffie-Hellman to obtain shared secret with each recipient's public key &amp; each ephemeral private key</li>
   * <li>Computes KDF to obtain AES-256 key from shared secret for each recipient</li>
   * <li>Encrypts KEY1 with this key using AES-256-CBC for each recipient</li>
   * </ol>
   *
   * @param inputStream  Input stream.
   * @param streamSize   Input stream size.
   * @param outputStream Output stream.
   * @param privateKey   Private key to generate signatures.
   * @param recipients   Recipients' public keys.
   * @param enablePadding If true, will add padding to plain text before encryption. This is recommended for data for
   *                      which exposing length can cause security issues (e.g. text messages).
   *
   * @throws SigningException    If crypto sign operation failed.
   * @throws EncryptionException If encryption failed.
   */
  public void authEncrypt(InputStream inputStream, int streamSize, OutputStream outputStream,
                          VirgilPrivateKey privateKey, List<VirgilPublicKey> recipients, boolean enablePadding)
          throws EncryptionException, SigningException {

    encrypt(new IOStream(inputStream, streamSize, outputStream),
            new SigningOptions(privateKey, SigningMode.SIGN_THEN_ENCRYPT), recipients, enablePadding);
  }

  /**
   * Decrypts (using passed PrivateKey) then verifies (using one of public keys) stream.
   *
   * <div>NOTE: Decrypted stream should not be used until decryption of whole InputStream completed due to
   * security reasons.</div>
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature</li>
   * </ol>
   *
   * @param inputStream      Stream with encrypted data.
   * @param outputStream     Stream with decrypted data.
   * @param privateKey       Recipient's private key.
   * @param signersPublicKey Possible signer's public key.
   *                         WARNING: Stream should have signature of ANY public key from array.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public void authDecrypt(InputStream inputStream, OutputStream outputStream, VirgilPrivateKey privateKey,
                          VirgilPublicKey signersPublicKey) throws VerificationException, DecryptionException {

    authDecrypt(inputStream, outputStream, privateKey, Collections.singletonList(signersPublicKey));
  }

  /**
   * Decrypts (using passed PrivateKey) then verifies (using one of public keys) stream.
   *
   * <div>NOTE: Decrypted stream should not be used until decryption of whole InputStream completed due to
   * security reasons.</div>
   *
   * <ol>
   * <li>Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key &amp; recipient's private key</li>
   * <li>Computes KDF to obtain AES-256 KEY2 from shared secret</li>
   * <li>Decrypts KEY1 using AES-256-CBC</li>
   * <li>Decrypts data and signature using KEY1 and AES-256-GCM</li>
   * <li>Finds corresponding PublicKey according to signer id inside data</li>
   * <li>Verifies signature</li>
   * </ol>
   *
   * @param inputStream       Stream with encrypted data.
   * @param outputStream      Stream with decrypted data.
   * @param privateKey        Recipient's private key.
   * @param signersPublicKeys Array of possible signers' public keys.
   *                          WARNING: Stream should have signature of ANY public key from array.
   * @throws VerificationException If crypto verify operation failed.
   * @throws DecryptionException   If decryption failed.
   */
  public void authDecrypt(InputStream inputStream, OutputStream outputStream, VirgilPrivateKey privateKey,
                          List<VirgilPublicKey> signersPublicKeys) throws VerificationException, DecryptionException {

    decrypt(new IOStream(inputStream, outputStream),
            new VerifyingOptions(signersPublicKeys, VerifyingMode.DECRYPT_THEN_VERIFY), privateKey);
  }

  byte[] encrypt(InputOutput inputOutput, SigningOptions signingOptions,
                 List<VirgilPublicKey> recipients, boolean enablePadding) throws SigningException, EncryptionException {

    try (Aes256Gcm aesGcm = new Aes256Gcm(); RecipientCipher cipher = new RecipientCipher()) {
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(this.rng);

      if (enablePadding) {
        RandomPadding padding = new RandomPadding();
        padding.setRandom(this.rng);
        cipher.setEncryptionPadding(padding);
        PaddingParams paddingParams = new PaddingParams(PADDING_LENGTH, PADDING_LENGTH);
        cipher.setPaddingParams(paddingParams);
      }

      for (VirgilPublicKey recipient : recipients) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getPublicKey());
      }

      startEncryption(cipher, inputOutput, signingOptions);

      return processEncryption(cipher, inputOutput, signingOptions);
    } catch (IOException exception) {
      throw new EncryptionException(exception);
    }
  }

  byte[] decrypt(InputOutput inputOutput, VerifyingOptions verifyingOptions,
                 VirgilPrivateKey privateKey) throws VerificationException, DecryptionException {

    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.setRandom(this.rng);

      PaddingParams paddingParams = new PaddingParams(PADDING_LENGTH, PADDING_LENGTH);
      cipher.setPaddingParams(paddingParams);

      cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(), new byte[0]);

      byte[] result = processDecryption(cipher, inputOutput);

      finishDecryption(cipher, inputOutput, result, verifyingOptions);

      return result;
    } catch (IOException | FoundationException exception) {
      throw new DecryptionException(exception);
    }
  }

  /**
   * Generates digital signature of data using Private key.
   *
   * <blockquote> Note: Returned value contains only digital signature, not data itself
   * </blockquote>
   *
   * <blockquote> Note: Data inside this function is guaranteed to be hashed with SHA512 at least
   * one time. </blockquote>
   * <p>
   * It's secure to pass raw data here
   *
   * <blockquote> Note: Verification algorithm depends on Private Key type. Default: EdDSA for
   * ed25519 key. </blockquote>
   *
   * @param data       Data to sign.
   * @param privateKey Private key used to generate signature.
   *
   * @return The calculated signature data.
   *
   * @throws SigningException If crypto sign operation failed.
   */
  public byte[] generateSignature(byte[] data, VirgilPrivateKey privateKey) throws SigningException {
    if (data == null) {
      throw new NullArgumentException("data");
    }
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    PrivateKey key = privateKey.getPrivateKey();
    KeyAlg keyAlg = KeyAlgFactory.createFromKey(key, this.rng);
    if ((keyAlg instanceof KeySigner) && !((KeySigner) keyAlg).canSign(key)) {
      throw new SigningException(KEY_DOESNT_SUPPORT_SIGNING);
    }

    try (Signer signer = new Signer()) {
      signer.setRandom(this.rng);
      signer.setHash(new Sha512());

      signer.reset();
      signer.appendData(data);

      return signer.sign(key);
    } catch (Exception e) {
      throw new SigningException(e.getMessage());
    }
  }

  /**
   * Generates digital signature of data stream using Private key.
   *
   * <blockquote> Note: Returned value contains only digital signature, not data itself.
   * </blockquote>
   *
   * <blockquote> Note: Data inside this function is guaranteed to be hashed with SHA512 at least
   * one time. </blockquote>
   * <p>
   * It's secure to pass raw data here.
   *
   * @param stream     Data stream to sign
   * @param privateKey Private key used to generate signature
   * @return The calculated digital signature data.
   * @throws SigningException If crypto sign operation failed.
   */
  public byte[] generateSignature(InputStream stream, VirgilPrivateKey privateKey)
      throws SigningException {
    if (stream == null) {
      throw new NullArgumentException("stream");
    }
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    PrivateKey key = privateKey.getPrivateKey();
    KeyAlg keyAlg = KeyAlgFactory.createFromKey(key, this.rng);
    if ((keyAlg instanceof KeySigner) && !((KeySigner) keyAlg).canSign(key)) {
      throw new SigningException(KEY_DOESNT_SUPPORT_SIGNING);
    }

    try (Signer signer = new Signer()) {
      signer.setRandom(this.rng);
      signer.setHash(new Sha512());

      signer.reset();

      while (stream.available() > 0) {
        byte[] data;

        if (stream.available() >= CHUNK_SIZE) {
          data = new byte[CHUNK_SIZE];
          stream.read(data);
        } else {
          data = new byte[stream.available()];
          stream.read(data);
        }

        signer.appendData(data);
      }

      return signer.sign(key);
    } catch (IOException e) {
      throw new SigningException(e);
    }
  }

  /**
   * Verifies digital signature of data.
   *
   * <blockquote> Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519
   * key. </blockquote>
   *
   * @param signature Digital signature.
   * @param data      Data that was signed.
   * @param publicKey Signer's public key for verification.
   * @return {@code true} if signature is verified, {@code false} otherwise.
   * @throws VerificationException If signature verification operation failed.
   */
  public boolean verifySignature(byte[] signature, byte[] data, VirgilPublicKey publicKey)
      throws VerificationException {
    if (data == null) {
      throw new NullArgumentException("data");
    }
    if (signature == null) {
      throw new NullArgumentException("signature");
    }
    if (publicKey == null) {
      throw new NullArgumentException("publicKey");
    }

    PublicKey key = publicKey.getPublicKey();
    KeyAlg keyAlg = KeyAlgFactory.createFromKey(key, this.rng);
    if ((keyAlg instanceof KeySigner) && !((KeySigner) keyAlg).canVerify(key)) {
      throw new VerificationException(KEY_DOESNT_SUPPORT_VERIFICATION);
    }

    try (Verifier verifier = new Verifier()) {
      verifier.reset(signature);
      verifier.appendData(data);

      return verifier.verify(key);
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Verifies digital signature of data stream.
   *
   * <blockquote> Note: Verification algorithm depends on PublicKey type. Default: EdDSA.
   * </blockquote>
   *
   * @param signature Digital signature.
   * @param stream    Data stream that was signed.
   * @param publicKey Signed public key.
   * @return {@code true} if signature is verified, {@code false} otherwise.
   * @throws VerificationException If crypto verify operation failed.
   */
  public boolean verifySignature(byte[] signature, InputStream stream, VirgilPublicKey publicKey)
      throws VerificationException {
    if (stream == null) {
      throw new NullArgumentException("stream");
    }
    if (signature == null) {
      throw new NullArgumentException("signature");
    }
    if (publicKey == null) {
      throw new NullArgumentException("publicKey");
    }

    PublicKey key = publicKey.getPublicKey();
    KeyAlg keyAlg = KeyAlgFactory.createFromKey(key, this.rng);
    if ((keyAlg instanceof KeySigner) && !((KeySigner) keyAlg).canVerify(key)) {
      throw new VerificationException(KEY_DOESNT_SUPPORT_VERIFICATION);
    }

    try (Verifier verifier = new Verifier()) {
      verifier.reset(signature);

      while (stream.available() > 0) {
        byte[] data;

        if (stream.available() >= CHUNK_SIZE) {
          data = new byte[CHUNK_SIZE];
          stream.read(data);
        } else {
          data = new byte[stream.available()];
          stream.read(data);
        }

        verifier.appendData(data);
      }

      return verifier.verify(key);
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Exports the Private key into material representation.
   *
   * @param privateKey The private key for export.
   * @return Key material representation bytes.
   * @throws CryptoException if key couldn't be exported
   */
  public byte[] exportPrivateKey(VirgilPrivateKey privateKey) throws CryptoException {
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer()) {
      serializer.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(privateKey.getPrivateKey(), this.rng);
      try (RawPrivateKey rawPrivateKey = keyAlg.exportPrivateKey(privateKey.getPrivateKey())) {
        return serializer.serializePrivateKey(rawPrivateKey);
      }
      finally {
        if (keyAlg instanceof AutoCloseable) {
          ((AutoCloseable) keyAlg).close();
        }
      }
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Imports the Private key from material representation.
   *
   * @param data the private key material representation bytes
   * @return imported private key
   * @throws CryptoException if key couldn't be imported
   */
  public VirgilKeyPair importPrivateKey(byte[] data) throws CryptoException {
    if (data == null) {
      throw new NullArgumentException("data");
    }

    try (KeyProvider keyProvider = new KeyProvider()) {
      keyProvider.setRandom(rng);
      keyProvider.setupDefaults();

      PrivateKey privateKey = keyProvider.importPrivateKey(data);
      KeyPairType keyPairType = KeyPairType.fromKey(privateKey);

      PublicKey publicKey = privateKey.extractPublicKey();

      byte[] keyId = computePublicKeyIdentifier(publicKey);

      VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyId, publicKey, keyPairType);
      VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyId, privateKey, keyPairType);

      return new VirgilKeyPair(virgilPublicKey, virgilPrivateKey);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Exports the Public key into material representation.
   *
   * @param publicKey Public key for export.
   * @return Key material representation bytes.
   * @throws CryptoException if key couldn't be exported
   */
  public byte[] exportPublicKey(VirgilPublicKey publicKey) throws CryptoException {
    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer()) {
      serializer.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(publicKey.getPublicKey(), this.rng);
      RawPublicKey rawPublicKey = keyAlg.exportPublicKey(publicKey.getPublicKey());

      return serializer.serializePublicKey(rawPublicKey);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Imports the Public key from material representation.
   *
   * @param data the public key material representation bytes
   * @return an imported public key
   * @throws CryptoException if key couldn't be imported
   */
  public VirgilPublicKey importPublicKey(byte[] data) throws CryptoException {
    if (data == null) {
      throw new NullArgumentException("data");
    }

    try (KeyProvider keyProvider = new KeyProvider();
         KeyAsn1Deserializer deserializer = new KeyAsn1Deserializer()) {

      deserializer.setupDefaults();
      RawPublicKey rawKey = deserializer.deserializePublicKey(data);
      if (rawKey.cCtx == 0 || rawKey.algId() == AlgId.NONE) {
        throw new CryptoException("Wrong public key format");
      }

      keyProvider.setRandom(rng);
      keyProvider.setupDefaults();

      PublicKey publicKey = keyProvider.importPublicKey(data);
      KeyPairType keyPairType = KeyPairType.fromKey(publicKey);

      byte[] keyId = computePublicKeyIdentifier(publicKey);

      return new VirgilPublicKey(keyId, publicKey, keyPairType);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Extract public key from private key.
   *
   * @param privateKey the private key.
   * @return the extracted public key.
   */
  public VirgilPublicKey extractPublicKey(VirgilPrivateKey privateKey) {
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    return new VirgilPublicKey(privateKey.getIdentifier(),
            privateKey.getPrivateKey().extractPublicKey(), privateKey.getKeyPairType());
  }

  /**
   * Computes hash of given {@code data} with {@link HashAlgorithm#SHA512}.
   *
   * @param data data to be hashed.
   * @return hash value.
   */
  public byte[] computeHash(byte[] data) {
    return computeHash(data, HashAlgorithm.SHA512);
  }

  /**
   * Generates cryptographically secure random bytes. Uses CTR DRBG.
   *
   * @param size Size of random data needed.
   * @return Random data
   */
  public byte[] generateRandomData(int size) {
    return rng.random(size);
  }

  /**
   * Computes hash of given {@code data} according to {@code algorithm}.
   *
   * @param data      data to be hashed.
   * @param algorithm hash {@link HashAlgorithm} to use.
   * @return hash value.
   */
  public byte[] computeHash(byte[] data, HashAlgorithm algorithm) {
    if (data == null) {
      throw new NullArgumentException("data");
    }

    byte[] hashData;
    switch (algorithm) {
      case SHA224:
        try (Sha224 hash = new Sha224()) {
          hashData = hash.hash(data);
        }
        break;
      case SHA256:
        try (Sha256 hash = new Sha256()) {
          hashData = hash.hash(data);
        }
        break;
      case SHA384:
        try (Sha384 hash = new Sha384()) {
          hashData = hash.hash(data);
        }
        break;
      case SHA512:
        try (Sha512 hash = new Sha512()) {
          hashData = hash.hash(data);
        }
        break;
      default:
        throw new IllegalArgumentException("Please, choose one of: SHA224, SHA256, SHA384, SHA512");
    }
    return hashData;
  }

  /**
   * @return the useSHA256Fingerprints
   */
  public boolean isUseSHA256Fingerprints() {
    return useSHA256Fingerprints;
  }

  /**
   * @param useSHA256Fingerprints the useSHA256Fingerprints to set
   */
  public void setUseSHA256Fingerprints(boolean useSHA256Fingerprints) {
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Gets Random Number Generator.
   *
   * @return the Random Number Generator (RNG).
   */
  public Random getRng() {
    return rng;
  }

  /**
   * Gets default key type.
   *
   * @return the default key type
   */
  public KeyPairType getDefaultKeyPairType() {
    return defaultKeyPairType;
  }

  private void startEncryption(RecipientCipher cipher, InputOutput inputOutput) throws SigningException {
    startEncryption(cipher, inputOutput, null);
  }

  private void startEncryption(RecipientCipher cipher, InputOutput inputOutput,
                               SigningOptions signingOptions) throws SigningException {
    if (signingOptions != null) {
      switch (signingOptions.mode) {
        case SIGN_AND_ENCRYPT:
          if (inputOutput instanceof IOData) {
            byte[] signature = generateSignature(((IOData) inputOutput).getInput(), signingOptions.getPrivateKey());
            cipher.customParams().addData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature);
            cipher.customParams().addData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID,
                    signingOptions.privateKey.getIdentifier());
          } else if (inputOutput instanceof IOStream) {
            throw new IllegalStateException("signAndEncrypt is not supported for streams.");
          } else {
            throw new IllegalStateException("Only IOData and IOStream are supported.");
          }
          cipher.startEncryption();
          break;
        case SIGN_THEN_ENCRYPT:
          cipher.setSignerHash(new Sha512());
          cipher.addSigner(signingOptions.getPrivateKey().getIdentifier(),
                  signingOptions.getPrivateKey().getPrivateKey());

          int size;

          if (inputOutput instanceof IOData) {
            size = ((IOData) inputOutput).getInput().length;
          } else if (inputOutput instanceof IOStream) {
            if (((IOStream) inputOutput).getStreamSize() == IOStream.STREAM_SIZE_UNDEFINED) {
              throw new IllegalStateException("signThenEncrypt for streams with unknown size is not supported.");
            } else {
              size = ((IOStream) inputOutput).getStreamSize();
            }
          } else {
            throw new IllegalStateException("Only IOData and IOStream are supported.");
          }

          cipher.startSignedEncryption(size);
          break;
      }
    } else {
      cipher.startEncryption();
    }
  }

  private byte[] processEncryption(RecipientCipher cipher,
                                   InputOutput inputOutput) throws IOException, EncryptionException {

    return processEncryption(cipher, inputOutput, null);
  }

  private byte[] processEncryption(RecipientCipher cipher, InputOutput inputOutput, SigningOptions signingOptions)
          throws IOException, EncryptionException {

    if (inputOutput instanceof IOData) {
      byte[] messageInfo = cipher.packMessageInfo();
      byte[] processEncryption = cipher.processEncryption(((IOData) inputOutput).getInput());
      byte[] finishEncryption = cipher.finishEncryption();

      byte[] result = concatenate(messageInfo, processEncryption, finishEncryption);

      if (signingOptions != null && signingOptions.mode == SigningMode.SIGN_THEN_ENCRYPT) {
        byte[] messageInfoFooter = cipher.packMessageInfoFooter();
        result = concatenate(result, messageInfoFooter);
      }

      return result;
    } else if (inputOutput instanceof IOStream) {
      InputStream inputStream = ((IOStream) inputOutput).getInputStream();
      int streamSize = ((IOStream) inputOutput).getStreamSize() != IOStream.STREAM_SIZE_UNDEFINED
              ? ((IOStream) inputOutput).getStreamSize()
              : 0;
      OutputStream outputStream = ((IOStream) inputOutput).getOutputStream();

      byte[] messageInfo = cipher.packMessageInfo();
      outputStream.write(messageInfo);

      while (inputStream.available() > 0) {
        byte[] data;

        if (inputStream.available() >= CHUNK_SIZE) {
          data = new byte[CHUNK_SIZE];
        } else {
          data = new byte[inputStream.available()];
        }

        int dataRead = inputStream.read(data);

        if (((IOStream) inputOutput).getStreamSize() != IOStream.STREAM_SIZE_UNDEFINED) {
          streamSize -= dataRead;
        }

        byte[] encryptedData = cipher.processEncryption(data);
        outputStream.write(encryptedData);
      }

      if (streamSize != 0) {
        throw new EncryptionException("Invalid stream size");
      }

      byte[] finish = cipher.finishEncryption();
      outputStream.write(finish);

      if (signingOptions != null && signingOptions.mode == SigningMode.SIGN_THEN_ENCRYPT) {
        byte[] messageInfoFooter = cipher.packMessageInfoFooter();
        outputStream.write(messageInfoFooter);
      }

      return null;
    } else {
      throw new IllegalStateException("Only IOData and IOStream are supported.");
    }
  }

  private byte[] processDecryption(RecipientCipher cipher, InputOutput inputOutput) throws IOException {
    if (inputOutput instanceof IOData) {
      byte[] processDecryption = cipher.processDecryption(((IOData) inputOutput).getInput());
      byte[] finishDecryption = cipher.finishDecryption();

      return concatenate(processDecryption, finishDecryption);
    } else if (inputOutput instanceof IOStream) {
      InputStream inputStream = ((IOStream) inputOutput).getInputStream();
      OutputStream outputStream = ((IOStream) inputOutput).getOutputStream();

      while (inputStream.available() > 0) {
        byte[] data;

        if (inputStream.available() >= CHUNK_SIZE) {
          data = new byte[CHUNK_SIZE];
          inputStream.read(data);
        } else {
          data = new byte[inputStream.available()];
          inputStream.read(data);
        }

        byte[] decryptedChunk = cipher.processDecryption(data);
        outputStream.write(decryptedChunk);
      }

      byte[] finish = cipher.finishDecryption();
      outputStream.write(finish);

      return null;
    } else {
      throw new IllegalStateException("Only IOData and IOStream are supported.");
    }
  }

  private void verifyPlainSignature(RecipientCipher cipher, InputOutput inputOutput,
                                    List<VirgilPublicKey> publicKeys) throws VerificationException {
    verifyPlainSignature(cipher, inputOutput, null, publicKeys);
  }

  private void verifyPlainSignature(RecipientCipher cipher, InputOutput inputOutput, byte[] result,
                                    List<VirgilPublicKey> publicKeys) throws VerificationException {
    if (inputOutput instanceof IOStream) {
      throw new IllegalStateException("signAndEncrypt is not supported for streams.");
    }

    VirgilPublicKey signerPublicKey;

    if (publicKeys.size() == 1) {
      signerPublicKey = publicKeys.get(0);
    } else {
      byte[] signerId;

      try {
        signerId = cipher.customParams().findData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID);
      } catch (Throwable throwable) {
        throw new VerificationException("Signer has not been found.");
      }

      VirgilPublicKey publicKey = null;
      for (VirgilPublicKey publicKeyIterator : publicKeys) {
        if (Arrays.equals(publicKeyIterator.getIdentifier(), signerId)) {
          publicKey = publicKeyIterator;
          break;
        }
      }

      if (publicKey == null) {
        throw new VerificationException("Signer has not been found.");
      }

      signerPublicKey = publicKey;
    }

    byte[] signature;

    try {
      signature = cipher.customParams().findData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE);
    } catch (Throwable throwable) {
      throw new VerificationException("Signature has not been found.");
    }

    if (!verifySignature(signature, result, signerPublicKey)) {
      throw new VerificationException("Signature has not been verified.");
    }
  }

  private void verifyEncryptedSignature(RecipientCipher cipher,
                                        List<VirgilPublicKey> publicKeys) throws VerificationException {
    if (!cipher.isDataSigned()) {
      throw new VerificationException("Data is not signed.");
    }

    SignerInfoList signerInfoList = cipher.signerInfos();

    if (!signerInfoList.hasItem() && signerInfoList.hasNext()) {
      throw new VerificationException("Data is not signed.");
    }

    SignerInfo signerInfo = signerInfoList.item();

    VirgilPublicKey signerPublicKey = null;
    for (VirgilPublicKey publicKeyIterator : publicKeys) {
      if (Arrays.equals(publicKeyIterator.getIdentifier(), signerInfo.signerId())) {
        signerPublicKey = publicKeyIterator;
      }
    }

    if (signerPublicKey == null) {
      throw new VerificationException("Signer has not been found.");
    }

    if (!cipher.verifySignerInfo(signerInfo, signerPublicKey.getPublicKey())) {
      throw new VerificationException("Signature has not been verified.");
    }
  }

  private void finishDecryption(RecipientCipher cipher, InputOutput inputOutput) throws VerificationException {
    finishDecryption(cipher, inputOutput, null, null);
  }

  private void finishDecryption(RecipientCipher cipher, InputOutput inputOutput,
                                byte[] result) throws VerificationException {

    finishDecryption(cipher, inputOutput, result, null);
  }

  private void finishDecryption(RecipientCipher cipher, InputOutput inputOutput, byte[] result,
                                VerifyingOptions verifyingOptions) throws VerificationException {
    if (verifyingOptions == null) {
      return;
    }

    VerifyingMode mode = verifyingOptions.mode;

    if (mode == VerifyingMode.ANY) {
      mode = cipher.isDataSigned() ? VerifyingMode.DECRYPT_THEN_VERIFY : VerifyingMode.DECRYPT_AND_VERIFY;
    }

    switch (mode) {
      case DECRYPT_AND_VERIFY:
        verifyPlainSignature(cipher, inputOutput, result, verifyingOptions.publicKeys);
        break;

      case DECRYPT_THEN_VERIFY:
        verifyEncryptedSignature(cipher, verifyingOptions.publicKeys);
        break;
    }
  }

  private byte[] computePublicKeyIdentifier(PublicKey publicKey) throws CryptoException {
    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer()) {
      serializer.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(publicKey, this.rng);
      try (RawPublicKey rawPublicKey = keyAlg.exportPublicKey(publicKey)) {
        byte[] publicKeyDer = serializer.serializePublicKey(rawPublicKey);
        byte[] hash;
        if (useSHA256Fingerprints) {
          hash = computeHash(publicKeyDer, HashAlgorithm.SHA256);
        } else {
          hash = computeHash(publicKeyDer, HashAlgorithm.SHA512);
          hash = Arrays.copyOfRange(hash, 0, 8);
        }
        return hash;
      } finally {
        if (keyAlg instanceof AutoCloseable) {
          ((AutoCloseable) keyAlg).close();
        }
      }
    } catch (Exception e) {
      // This should never happen
      throw new CryptoException(e);
    }
  }

  /**
   * Encrypts data using provided {@link RecipientCipher}.
   *
   * @param data   Data to encrypt.
   * @param cipher To encrypt provided data.
   * @return Encrypted data.
   */
  private byte[] encryptData(byte[] data, RecipientCipher cipher) {
    cipher.startEncryption();

    byte[] messageInfo = cipher.packMessageInfo();
    byte[] processEncryption = cipher.processEncryption(data);
    byte[] finish = cipher.finishEncryption();

    return concatenate(messageInfo, processEncryption, finish);
  }

  private byte[] concatenate(byte[]... arrays) {
    int totalLength = 0;
    for (int i = 0; i < arrays.length; i++) {
      totalLength += arrays[i].length;
    }

    byte[] result = new byte[totalLength];

    int currentIndex = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, currentIndex, array.length);
      currentIndex += array.length;
    }

    return result;
  }
}
