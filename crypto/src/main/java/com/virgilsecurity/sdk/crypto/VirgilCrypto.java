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

import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.PublicKey;
import com.virgilsecurity.crypto.foundation.*;
import com.virgilsecurity.sdk.crypto.exceptions.*;
import com.virgilsecurity.sdk.exception.NullArgumentException;

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
 * @author Andrii Iakovenko
 * @see VirgilPublicKey
 * @see VirgilPrivateKey
 */
public class VirgilCrypto {

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;
  private static final int ERROR_CODE_WRONG_PRIVATE_KEY = -303;

  private static final int CHUNK_SIZE = 1024;
  private static final int RSA_2048_LENGTH = 1024;
  private static final int RSA_4096_LENGTH = 4096;
  private static final int RSA_8192_LENGTH = 8192;

  public static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE"
      .getBytes(UTF8_CHARSET);
  public static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID"
      .getBytes(UTF8_CHARSET);

  private static final String SIGNER_NOT_FOUND = "Signer not found";
  private static final String KEY_DOESNT_SUPPORT_VERIFICATION = "This key doesn\'t support verification";
  private static final String KEY_DOESNT_SUPPORT_SIGNING = "This key doesn\'t support signing";

  private Random rng;
  private KeyType defaultKeyType;
  private boolean useSHA256Fingerprints;

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
    this.defaultKeyType = KeyType.ED25519;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType the {@link KeyType} to be used by default for generating key pair.
   */
  public VirgilCrypto(KeyType keysType) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyType = keysType;
    this.useSHA256Fingerprints = false;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType              the {@link KeyType} to be used by default for generating key pair.
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when calculating public key
   *                              identifier.
   */
  public VirgilCrypto(KeyType keysType, boolean useSHA256Fingerprints) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyType = keysType;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(KeyType keyType, byte[] seed) throws CryptoException {
    try (KeyMaterialRng keyMaterialRng = new KeyMaterialRng()) {

      if (!(seed.length >= keyMaterialRng.getKeyMaterialLenMin()
          && seed.length <= keyMaterialRng.getKeyMaterialLenMax())) {
        throw new CryptoException("Invalid seed size");
      }

      keyMaterialRng.resetKeyMaterial(seed);

      return generateKeyPair(keyType, keyMaterialRng);
    }
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(byte[] seed) throws CryptoException {
    return generateKeyPair(this.defaultKeyType, seed);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys by specified
   * type.
   *
   * @param keyType Type of the generated keys. The possible values can be found in {@link KeyType}.
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair(KeyType keyType) throws CryptoException {
    return generateKeyPair(keyType, this.rng);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @return Generated key pair.
   * @throws CryptoException if crypto operation failed
   */
  public VirgilKeyPair generateKeyPair() throws CryptoException {
    return generateKeyPair(this.defaultKeyType);
  }

  private VirgilKeyPair generateKeyPair(KeyType keyType, Random rng) throws CryptoException {
    try (KeyProvider keyProvider = new KeyProvider()) {

      if (keyType.getRsaBitLen() != -1) {
        int rsaLength = keyType.getRsaBitLen();
        keyProvider.setRsaParams(rsaLength);
      }

      keyProvider.setRandom(rng);
      keyProvider.setupDefaults();

      AlgId algId = keyType.getAlgId();
      PrivateKey privateKey = keyProvider.generatePrivateKey(algId);
      PublicKey publicKey = privateKey.extractPublicKey();
      byte[] keyId = computePublicKeyIdentifier(publicKey);

      VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyId, publicKey, keyType);
      VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyId, privateKey, keyType);

      return new VirgilKeyPair(virgilPublicKey, virgilPrivateKey);
    }
  }

  /**
   * Encrypts data for passed PublicKey. // TODO review methods docs for uppercase letters in the
   * beginning.
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
   * @return Encrypted bytes.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, VirgilPublicKey publicKey) throws EncryptionException {
    return encrypt(data, Collections.singletonList(publicKey));
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
   * @return Encrypted bytes.
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try (RecipientCipher cipher = new RecipientCipher(); Aes256Gcm aesGcm = new Aes256Gcm()) {
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(this.rng);

      for (VirgilPublicKey recipient : publicKeys) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getPublicKey());
      }

      return encryptData(data, cipher);
    } catch (Exception e) {
      throw new EncryptionException(e);
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
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey publicKey)
      throws EncryptionException {
    encrypt(inputStream, outputStream, Collections.singletonList(publicKey));
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
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream,
                      List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try (RecipientCipher cipher = new RecipientCipher(); Aes256Gcm aesGcm = new Aes256Gcm()) {
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(rng);

      for (VirgilPublicKey recipient : publicKeys) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getPublicKey());
      }

      cipher.startEncryption();
      byte[] messageInfo = cipher.packMessageInfo();

      outputStream.write(messageInfo);

      while (inputStream.available() > 0) {
        byte[] data;

        if (inputStream.available() >= CHUNK_SIZE) {
          data = new byte[CHUNK_SIZE];
        } else {
          data = new byte[inputStream.available()];
        }
        inputStream.read(data);

        byte[] encryptedData = cipher.processEncryption(data);
        outputStream.write(encryptedData);
      }

      byte[] finish = cipher.finishEncryption();
      outputStream.write(finish);
    } catch (IOException e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Signs and encrypts the data.
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKey  The recipient's Public key to encrypt the data.
   * @return Signed and encrypted data bytes.
   * @throws CryptoException if crypto sing or encrypt operation failed
   */
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
      throws CryptoException {
    return signThenEncrypt(data, privateKey, Collections.singletonList(publicKey));
  }

  /**
   * Signs (with Private key) Then Encrypts data for passed PublicKeys.
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
   * @return Signed and encrypted data bytes.
   * @throws CryptoException If crypto sing or encrypt operation failed.
   */
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey,
                                List<VirgilPublicKey> publicKeys) throws CryptoException {
    try (RecipientCipher cipher = new RecipientCipher(); Aes256Gcm aesGcm = new Aes256Gcm()) {
      byte[] signature = generateSignature(data, privateKey);
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(rng);

      for (VirgilPublicKey publicKey : publicKeys) {
        cipher.addKeyRecipient(publicKey.getIdentifier(), publicKey.getPublicKey());
      }

      cipher.customParams().addData(CUSTOM_PARAM_SIGNATURE, signature);
      cipher.customParams().addData(CUSTOM_PARAM_SIGNER_ID, privateKey.getIdentifier());

      return encryptData(data, cipher);

    } catch (Exception e) {
      throw new CryptoException(e.getMessage());
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

    return concatenate(concatenate(messageInfo, processEncryption), finish);
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
   * @return Decrypted data bytes.
   * @throws DecryptionException If decryption failed.
   */
  public byte[] decrypt(byte[] data, VirgilPrivateKey privateKey) throws DecryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {

      cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(),
          new byte[0]);

      byte[] processDecryption = cipher.processDecryption(data);
      byte[] finish = cipher.finishDecryption();

      return concatenate(processDecryption, finish);
    } catch (Exception exception) {
      if (exception instanceof FoundationException) {
        throw new DecryptionException(processErrorCode((FoundationException) exception));
      } else {
        throw new DecryptionException(exception);
      }
    }
  }

  /**
   * Decrypts the specified stream using Private key.
   *
   * @param inputStream  Encrypted stream for decryption.
   * @param outputStream Output stream for decrypted data.
   * @param privateKey   Private key for decryption.
   * @throws DecryptionException if decryption failed
   */
  public void decrypt(InputStream inputStream, OutputStream outputStream,
                      VirgilPrivateKey privateKey) throws DecryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(),
          new byte[0]);

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
    } catch (Exception exception) {
      if (exception instanceof FoundationException) {
        throw new DecryptionException(processErrorCode((FoundationException) exception));
      } else {
        throw new DecryptionException(exception);
      }
    }
  }

  /**
   * Decrypts (with private key) Then Verifies data using signers PublicKey.
   *
   * @param data             Signed Then Encrypted data.
   * @param privateKey       Receiver's private key.
   * @param signersPublicKey Signer's public keys. WARNING: Data should have signature of ANY public key from
   *                         array.
   * @return Decrypted then verified data.
   * @throws CryptoException if decryption or verification failed.
   */
  public byte[] decryptThenVerify(byte[] data, VirgilPrivateKey privateKey,
                                  VirgilPublicKey signersPublicKey) throws CryptoException {
    return decryptThenVerify(data, privateKey, Collections.singletonList(signersPublicKey));
  }

  /**
   * Decrypts (with private key) Then Verifies data using any of signers' PublicKeys.
   *
   * @param data              Signed Then Encrypted data.
   * @param privateKey        Receiver's private key.
   * @param signersPublicKeys The list of possible signers' public keys. WARNING: Data should have signature of ANY
   *                          public key from array.
   * @return Decrypted then verified data.
   * @throws CryptoException if decryption or verification failed.
   */
  public byte[] decryptThenVerify(byte[] data, VirgilPrivateKey privateKey,
                                  List<VirgilPublicKey> signersPublicKeys) throws CryptoException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(),
          new byte[0]);

      byte[] processDecryption = cipher.processDecryption(data);
      byte[] finish = cipher.finishDecryption();

      byte[] decryptedData = concatenate(processDecryption, finish);

      VirgilPublicKey signerPublicKey = null;

      if (signersPublicKeys.size() == 1) {
        signerPublicKey = signersPublicKeys.get(0);
      } else {
        byte[] signerId;
        try {
          signerId = cipher.customParams().findData(CUSTOM_PARAM_SIGNER_ID);
        } catch (Throwable throwable) {
          throw new CryptoException(SIGNER_NOT_FOUND);
        }

        for (VirgilPublicKey publicKey : signersPublicKeys) {
          if (Arrays.equals(publicKey.getIdentifier(), signerId)) {
            signerPublicKey = publicKey;
            break;
          }
        }
        if (signerPublicKey == null) {
          throw new CryptoException(SIGNER_NOT_FOUND);
        }
      }

      byte[] signature;

      try {
        signature = cipher.customParams().findData(CUSTOM_PARAM_SIGNATURE);
      } catch (Throwable throwable) {
        throw new CryptoException("Signature not found");
      }

      boolean isValid = verifySignature(signature, decryptedData, signerPublicKey);
      if (!isValid) {
        throw new SignatureIsNotValidException();
      }

      return decryptedData;
    } catch (Exception exception) {
      if (exception instanceof FoundationException) {
        throw new DecryptionException(processErrorCode((FoundationException) exception));
      } else {
        throw new DecryptionException(exception);
      }
    }
  }

  /**
   * Gets message from provided {@link FoundationException}'s error code.
   *
   * @param exception To extract code from.
   * @return Error message corresponding to error code.
   */
  private String processErrorCode(FoundationException exception) {
    int errorCode = exception.getStatusCode();

    if (errorCode == ERROR_CODE_WRONG_PRIVATE_KEY) {
      return "Given Private key does not corresponds to any of "
          + "Public keys that were used for encryption.";
    } else {
      return exception.getMessage();
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
   * @return The calculated signature data.
   * @throws SigningException If crypto sign operation failed.
   */
  public byte[] generateSignature(byte[] data, VirgilPrivateKey privateKey)
      throws SigningException {
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
      RawPrivateKey rawPrivateKey = keyAlg.exportPrivateKey(privateKey.getPrivateKey());

      return serializer.serializePrivateKey(rawPrivateKey);
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
      KeyType keyType = getKeyType(privateKey);

      PublicKey publicKey = privateKey.extractPublicKey();

      byte[] keyId = computePublicKeyIdentifier(publicKey);

      VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyId, publicKey, keyType);
      VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyId, privateKey, keyType);

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

      KeyType keyType = getKeyType(publicKey);

      byte[] keyId = computePublicKeyIdentifier(publicKey);

      return new VirgilPublicKey(keyId, publicKey, keyType);
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
        privateKey.getPrivateKey().extractPublicKey(), privateKey.getKeyType());
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
  public KeyType getDefaultKeyType() {
    return defaultKeyType;
  }

  private byte[] computePublicKeyIdentifier(PublicKey publicKey) throws CryptoException {
    try (KeyAsn1Serializer serializer = new KeyAsn1Serializer()) {
      serializer.setupDefaults();

      KeyAlg keyAlg = KeyAlgFactory.createFromKey(publicKey, this.rng);
      RawPublicKey rawPublicKey = keyAlg.exportPublicKey(publicKey);

      byte[] publicKeyDer = serializer.serializePublicKey(rawPublicKey);
      byte[] hash;
      if (useSHA256Fingerprints) {
        hash = computeHash(publicKeyDer, HashAlgorithm.SHA256);
      } else {
        hash = computeHash(publicKeyDer, HashAlgorithm.SHA512);
        hash = Arrays.copyOfRange(hash, 0, 8);
      }
      return hash;
    } catch (Exception e) {
      // This should never happen
      throw new CryptoException(e);
    }
  }

  /**
   * Concatenate two byte arrays.
   *
   * @param first  the first array.
   * @param second the second array.
   * @return a byte array.
   */
  private byte[] concatenate(byte[] first, byte[] second) {
    byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);

    return result;
  }

  private KeyType getKeyType(Key key) throws CryptoException {
    switch (key.algId()) {
      case ED25519:
        return KeyType.ED25519;
      case CURVE25519:
        return KeyType.CURVE25519;
      case SECP256R1:
        return KeyType.SECP256R1;
      case RSA:
        switch (key.bitlen()) {
          case RSA_2048_LENGTH:
            return KeyType.RSA_2048;
          case RSA_4096_LENGTH:
            return KeyType.RSA_4096;
          case RSA_8192_LENGTH:
            return KeyType.RSA_8192;
          default:
            throw new CryptoException("Unsupported RSA length " + key.bitlen());
        }
      default:
        throw new CryptoException("Unsupported algorithm " + key.algId().name());
    }
  }
}
