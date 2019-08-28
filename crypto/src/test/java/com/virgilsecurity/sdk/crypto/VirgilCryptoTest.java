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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * Unit tests for {@link VirgilCrypto}.
 *
 * @author Andrii Iakovenko
 *
 */
@RunWith(Parameterized.class)
public class VirgilCryptoTest {

  private static final String TEXT = "This text is used for unit tests";
  private static final byte[] INVALID_SIGNATURE = new byte[] { 48, 88, 48, 13, 6, 9, 96, -122, 72,
      1, 101, 3, 4, 2, 2, 5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101,
      76, -34, -53, -96, -70, 85, 80, 0, 88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108,
      14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30, 98, 20, -25, 60, 125, -19, 67, 12, -30, 65,
      93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36, 48, -20 };
  private static final int RECIPIENTS_NUMBER = 100;

  @org.junit.Rule
  public org.junit.rules.ExpectedException expectedException = org.junit.rules.ExpectedException.none();

  private KeyType keyType;
  private VirgilCrypto crypto;

  @Parameters(name = "keyType={0}")
  public static KeyType[] params() {
    Set<KeyType> values = new HashSet<>(Arrays.asList(KeyType.values()));
    // Skip RSA test because they are too slow
    values.remove(KeyType.RSA_2048);
    values.remove(KeyType.RSA_4096);
    values.remove(KeyType.RSA_8192);
    return values.toArray(new KeyType[0]);
  }

  @Before
  public void setup() {
    crypto = new VirgilCrypto(this.keyType);
  }

  /**
   * Create new instance of {@link VirgilCryptoTest}.
   */
  public VirgilCryptoTest(KeyType keyType) {
    this.keyType = keyType;
  }

  @Test(expected = NullArgumentException.class)
  public void computeHash() {
    for (HashAlgorithm algorithm : HashAlgorithm.values()) {
      byte[] hash = crypto.computeHash(null, algorithm);

      assertNotNull(hash);
      assertTrue(hash.length > 0);
    }
  }

  @Test(expected = NullArgumentException.class)
  public void computeHash_nullData() {
    crypto.computeHash(null, HashAlgorithm.SHA512);
  }

  @Test
  public void decrypt() throws VirgilException {
    List<VirgilPrivateKey> privateKeys = new ArrayList<>();
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      VirgilKeyPair keyPair = crypto.generateKeyPair();
      privateKeys.add(keyPair.getPrivateKey());
      recipients.add(keyPair.getPublicKey());
    }
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
    for (VirgilPrivateKey privateKey : privateKeys) {
      byte[] decrypted = crypto.decrypt(encrypted, privateKey);

      assertArrayEquals(TEXT.getBytes(), decrypted);
    }
  }

  @Test
  public void decrypt_verbose_error() throws VirgilException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), keyPair.getPublicKey());
    byte[] decrypted = crypto.decrypt(encrypted, keyPair.getPrivateKey());
    assertArrayEquals(TEXT.getBytes(), decrypted);

    VirgilKeyPair keyPairWrong = crypto.generateKeyPair();

    expectedException.expectMessage("Given Private key does not corresponds to any of " +
                                            "Public keys that were used for encryption.");
    crypto.decrypt(encrypted, keyPairWrong.getPrivateKey());
  }

  @Test
  public void decrypt_stream() throws IOException, VirgilException {
    List<VirgilPrivateKey> privateKeys = new ArrayList<>();
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      VirgilKeyPair keyPair = crypto.generateKeyPair();
      privateKeys.add(keyPair.getPrivateKey());
      recipients.add(keyPair.getPublicKey());
    }
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
    for (VirgilPrivateKey privateKey : privateKeys) {
      try (InputStream is = new ByteArrayInputStream(encrypted);
           ByteArrayOutputStream os = new ByteArrayOutputStream()) {

        crypto.decrypt(is, os, privateKey);

        byte[] decrypted = os.toByteArray();

        assertArrayEquals(TEXT.getBytes(), decrypted);
      }
    }
  }

  @Test
  public void encrypt_decrypt_stream() throws IOException, CryptoException {
    List<VirgilPrivateKey> privateKeys = new ArrayList<>();
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      VirgilKeyPair keyPair = crypto.generateKeyPair();

      privateKeys.add(keyPair.getPrivateKey());
      recipients.add(keyPair.getPublicKey());
    }

    for (VirgilPrivateKey privateKey : privateKeys) {
      try (ByteArrayOutputStream osOuter = new ByteArrayOutputStream();
           ByteArrayInputStream isOuter = new ByteArrayInputStream(TEXT.getBytes())) {
        crypto.encrypt(isOuter, osOuter, recipients);

        byte[] encrypted = osOuter.toByteArray();

        try (InputStream isInner = new ByteArrayInputStream(encrypted);
            ByteArrayOutputStream osInner = new ByteArrayOutputStream()) {
          crypto.decrypt(isInner, osInner, privateKey);

          byte[] decrypted = osInner.toByteArray();

          assertArrayEquals(TEXT.getBytes(), decrypted);
        }
      }
    }
  }

  @Test
  public void encrypt() throws VirgilException {
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      recipients.add(crypto.generateKeyPair().getPublicKey());
    }
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);

    assertNotNull(encrypted);
  }

  @Test
  public void encrypt_noRecipients_success() throws VirgilException {
    @SuppressWarnings("unchecked")
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), Collections.EMPTY_LIST);

    assertNotNull(encrypted);
  }

  @Test
  public void encrypt_stream() throws IOException, CryptoException {
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      recipients.add(crypto.generateKeyPair().getPublicKey());
    }
    try (OutputStream os = new ByteArrayOutputStream()) {
      crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients);
    }
  }

  @Test
  public void exportPrivateKey_noPassword() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey());

    assertNotNull(key);
    assertTrue(key.length > 0);
  }

  @Test
  public void exportPublicKey() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

    assertNotNull(key);
    assertTrue(key.length > 0);
  }

  @Test
  public void generateKeys() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    assertNotNull(keyPair);

    VirgilPublicKey publicKey = keyPair.getPublicKey();
    assertNotNull(publicKey);
    assertNotNull(publicKey.getIdentifier());
    assertTrue(publicKey.getPublicKey().isValid());

    VirgilPrivateKey privateKey = keyPair.getPrivateKey();
    assertNotNull(privateKey);
    assertNotNull(privateKey.getIdentifier());
    assertTrue(privateKey.getPrivateKey().isValid());
  }

  @Test
  public void generateSignature() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());

    assertNotNull(signature);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_nullData() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature((byte[]) null, keyPair.getPrivateKey());
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_nullPrivateKey() throws CryptoException {
    crypto.generateSignature(TEXT.getBytes(), null);
  }

  @Test
  public void generateSignature_stream() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPrivateKey());

    assertNotNull(signature);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_stream_nullPrivateKey() throws SigningException {
    crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), null);
  }

  @Test(expected = NullArgumentException.class)
  public void generateSignature_stream_nullStream() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature((InputStream) null, keyPair.getPrivateKey());
  }

  @Test
  public void importPrivateKey_noPassword() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey());

    VirgilPrivateKey importedKey = crypto.importPrivateKey(keyData).getPrivateKey();

    assertNotNull(importedKey);
    assertNotNull(importedKey.getIdentifier());
    assertTrue(importedKey.getPrivateKey().isValid());
    assertArrayEquals(keyPair.getPrivateKey().getIdentifier(), importedKey.getIdentifier());
    
    try (KeyProvider keyProvider = new KeyProvider()) {
      keyProvider.setupDefaults();
      
      byte[] originKeyData = keyProvider.exportPrivateKey(keyPair.getPrivateKey().getPrivateKey());
      byte[] importedKeyData = keyProvider.exportPrivateKey(importedKey.getPrivateKey());
      assertArrayEquals(originKeyData, importedKeyData);
    }
  }

  @Test
  public void importPublicKey() throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    byte[] keyData = crypto.exportPublicKey(keyPair.getPublicKey());
    VirgilPublicKey publicKey = crypto.importPublicKey(keyData);

    assertNotNull(publicKey);
    assertNotNull(publicKey.getIdentifier());
    assertTrue(publicKey.getPublicKey().isValid());
    assertArrayEquals(keyPair.getPublicKey().getIdentifier(), publicKey.getIdentifier());
    
    try (KeyProvider keyProvider = new KeyProvider()) {
      keyProvider.setupDefaults();
      
      byte[] originKeyData = keyProvider.exportPublicKey(keyPair.getPublicKey().getPublicKey());
      byte[] importedKeyData = keyProvider.exportPublicKey(publicKey.getPublicKey());
      assertArrayEquals(originKeyData, importedKeyData);
    }
  }

  @Test
  public void sign_stream_compareToByteArraySign() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    byte[] streamSignature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPrivateKey());

    assertNotNull(signature);
    assertNotNull(streamSignature);
    assertArrayEquals(signature, streamSignature);
  }

  @Test
  public void verifySignature() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(signature, TEXT.getBytes(), keyPair.getPublicKey());

    assertTrue(valid);
  }

  @Test
  public void verifySignature_invalidSignature() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(INVALID_SIGNATURE, TEXT.getBytes(),
        keyPair.getPublicKey());

    assertFalse(valid);
  }

  @Test
  public void verifySignature_stream() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(signature, new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPublicKey());

    assertTrue(valid);
  }

  @Test
  public void verifySignature_stream_invalidSignature() throws CryptoException {
    if (keyType == KeyType.CURVE25519) {
      return;
    }

    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(INVALID_SIGNATURE,
        new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPublicKey());

    assertFalse(valid);
  }

  @Test
  @Ignore
  public void encrypt_decrypt_benchmark() throws CryptoException {
    System.out.println("Key type: " + this.keyType);
    List<VirgilPublicKey> recipients = new ArrayList<>();
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    recipients.add(keyPair.getPublicKey());

    // Encrypt
    long startEnc = System.nanoTime();
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
    long endEnc = System.nanoTime();
    System.out.println(String.format("Encrypt: %f ms", (endEnc - startEnc) / 1e6));

    // Decrypt
    long startDec = System.nanoTime();
    crypto.decrypt(encrypted, keyPair.getPrivateKey());
    long endDec = System.nanoTime();
    System.out.println(String.format("Decrypt: %f ms", (endDec - startDec) / 1e6));
  }
}
