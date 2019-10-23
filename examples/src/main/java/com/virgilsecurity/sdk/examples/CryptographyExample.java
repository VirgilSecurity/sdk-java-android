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

package com.virgilsecurity.sdk.examples;

import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.*;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Andrii Iakovenko
 */
public class CryptographyExample {

  public static void main(String[] args) {
    new CryptographyExample().run();
    System.out.println("Done!");
  }

  private byte[] createSignature(VirgilPrivateKey senderPrivateKey) throws SigningException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare a message
    String messageToSign = "Hello, Bob!";
    byte[] dataToSign = ConvertionUtils.toBytes(messageToSign);

    // generate a signature
    byte[] signature = crypto.generateSignature(dataToSign, senderPrivateKey);

    return signature;
  }

  private String dataDecryption(byte[] encryptedData, VirgilPrivateKey receiverPrivateKey)
      throws DecryptionException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare data to be decrypted
    byte[] decryptedData = crypto.decrypt(encryptedData, receiverPrivateKey);

    // decrypt the encrypted data using a private key
    String decryptedMessage = ConvertionUtils.toString(decryptedData);

    return decryptedMessage;
  }

  private byte[] dataEncryption(VirgilPublicKey receiverPublicKey) throws EncryptionException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare a message
    String messageToEncrypt = "Hello, Bob!";
    byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

    // encrypt the message
    byte[] encryptedData = crypto.encrypt(dataToEncrypt, receiverPublicKey);

    return encryptedData;
  }

  private String decryptThenVerify(byte[] encryptedData, VirgilPrivateKey receiverPrivateKey,
                                   VirgilPublicKey senderPublicKey) throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    // data to be decrypted and verified
    byte[] decryptedData = crypto.decryptThenVerify(encryptedData, receiverPrivateKey,
        Arrays.asList(senderPublicKey));

    // a decrypted message
    String decryptedMessage = ConvertionUtils.toString(decryptedData);

    return decryptedMessage;
  }

  private String exportPrivateKey() throws CryptoException {
    // generate a Key Pair
    VirgilCrypto crypto = new VirgilCrypto();
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    // export a Private key
    byte[] privateKeyData = crypto.exportPrivateKey(keyPair.getPrivateKey());
    String privateKeyStr = ConvertionUtils.toBase64String(privateKeyData);

    return privateKeyStr;
  }

  private String exportPublicKey() throws CryptoException {
    // generate a Key Pair
    VirgilCrypto crypto = new VirgilCrypto();
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    // export a Public key
    byte[] publicKeyData = crypto.exportPublicKey(keyPair.getPublicKey());
    String publicKeyStr = ConvertionUtils.toBase64String(publicKeyData);

    return publicKeyStr;
  }

  private VirgilPrivateKey importPrivateKey() throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    String privateKeyStr = "MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBtfBoM7VfmWPlvyHuGWvMSAgIZ6zAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECwaKJKWFNn3OMVoUXEcmqcEQMZ+WWkmPqzwzJXGFrgS/+bEbr2DvreVgEUiLKrggmXL9ZKugPKG0VhNY0omnCNXDzkXi5dCFp25RLqbbSYsCyw=";

    byte[] privateKeyData = ConvertionUtils.base64ToBytes(privateKeyStr);

    // import a Private key
    VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();

    return privateKey;
  }

  private VirgilPublicKey importPublicKey() throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    String publicKeyStr = "MCowBQYDK2VwAyEA9IVUzsQENtRVzhzraTiEZZy7YLq5LDQOXGQG/q0t0kE=";

    byte[] publicKeyData = ConvertionUtils.base64ToBytes(publicKeyStr);

    // import a Public key
    VirgilPublicKey publicKey = crypto.importPublicKey(publicKeyData);

    return publicKey;
  }

  private VirgilKeyPair keyGeneration() throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    return keyPair;
  }

  @SuppressWarnings("unused")
  private byte[] multipleEncryption() throws CryptoException {
    // specify participants public keys
    VirgilCrypto crypto = new VirgilCrypto();
    List<VirgilPublicKey> receiversPublicKeys = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      VirgilKeyPair keyPair = crypto.generateKeyPair();
      receiversPublicKeys.add(keyPair.getPublicKey());
    }

    // prepare a message to be encrypted for participants
    String messageToEncrypt = "Hello, Bob!";
    byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

    // encrypt the message
    byte[] encryptedData = crypto.encrypt(dataToEncrypt, receiversPublicKeys);

    return encryptedData;
  }

  @SuppressWarnings("unused")
  private void run() {
    try {
      // Generate keys
      VirgilKeyPair keyPair = keyGeneration();

      // Export private key
      String exportedPrivateKey = exportPrivateKey();
      System.out.println(String.format("Exported private key: %s", exportedPrivateKey));

      // Export public key
      String exportedPublicKey = exportPublicKey();
      System.out.println(String.format("Exported public key: %s", exportedPublicKey));

      // Import private key
      VirgilPrivateKey importedPrivateKey = importPrivateKey();

      // Import public key
      VirgilPublicKey importedPublicKey = importPublicKey();

      // Sign data wit private key
      byte[] signature = createSignature(keyPair.getPrivateKey());

      // Verify data signature
      String messageToSign = "Hello, Bob!";
      byte[] dataToSign = ConvertionUtils.toBytes(messageToSign);
      boolean valid = verifySignature(signature, dataToSign, keyPair.getPublicKey());
      System.out.println(valid ? "Signature is valid" : "Signature is not valid");

      // Encrypt data
      byte[] encryptedData = dataEncryption(keyPair.getPublicKey());

      // Decrypt data
      String decrypted = dataDecryption(encryptedData, keyPair.getPrivateKey());
      System.out.println(String.format("Data decrypted: %s", decrypted));

      // Sign and encrypt data
      VirgilKeyPair receiverKeyPair = keyGeneration();
      byte[] signedAndEncryptedData = signThenEncrypt(keyPair.getPrivateKey(),
          receiverKeyPair.getPublicKey());

      // Decrypt and verify data
      String decryptedAndVerified = decryptThenVerify(signedAndEncryptedData,
          receiverKeyPair.getPrivateKey(), keyPair.getPublicKey());
      System.out.println(String.format("Data decrypted and verified: %s", decryptedAndVerified));

    } catch (CryptoException e) {
      e.printStackTrace();
    }
  }

  private byte[] signThenEncrypt(VirgilPrivateKey senderPrivateKey,
                                 VirgilPublicKey receiverPublicKey) throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto();

    // prepare a message
    String messageToEncrypt = "Hello, Bob!";
    byte[] dataToEncrypt = ConvertionUtils.toBytes(messageToEncrypt);

    // use a private key to sign the message and a public key to decrypt it
    byte[] encryptedData = crypto.signThenEncrypt(dataToEncrypt, senderPrivateKey,
        receiverPublicKey);

    return encryptedData;
  }

  @SuppressWarnings("unused")
  private VirgilKeyPair specificGeneration() throws CryptoException {
    VirgilCrypto crypto = new VirgilCrypto(KeyType.RSA_4096);
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    return keyPair;
  }

  private boolean verifySignature(byte[] signature, byte[] dataToSign,
                                  VirgilPublicKey senderPublicKey) throws VerificationException {
    VirgilCrypto crypto = new VirgilCrypto();

    // verify a signature
    boolean verified = crypto.verifySignature(signature, dataToSign, senderPublicKey);

    return verified;
  }
}
