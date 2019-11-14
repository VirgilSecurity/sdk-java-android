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

import com.virgilsecurity.crypto.foundation.KeyProvider;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link VirgilCrypto}.
 *
 * @author Andrii Iakovenko
 */
public class VirgilCryptoTest {

  private static final String TEXT = "This text is used for unit tests";
  private static final byte[] INVALID_SIGNATURE = new byte[] {48, 88, 48, 13, 6, 9, 96, -122, 72,
      1, 101, 3, 4, 2, 2, 5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101,
      76, -34, -53, -96, -70, 85, 80, 0, 88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108,
      14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30, 98, 20, -25, 60, 125, -19, 67, 12, -30, 65,
      93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36, 48, -20};
  private static final int RECIPIENTS_NUMBER = 100;

  private static Stream<Arguments> allCryptos() {
    Set<KeyType> values = new HashSet<>(Arrays.asList(KeyType.values()));
    // Skip RSA test because they are too slow
    values.remove(KeyType.RSA_2048);
    values.remove(KeyType.RSA_4096);
    values.remove(KeyType.RSA_8192);

    return values.stream().map(key -> Arguments.of(new VirgilCrypto(key)));
  }

  private static Stream<Arguments> signVerifyCryptos() {
    Set<KeyType> values = new HashSet<>(Arrays.asList(KeyType.values()));
    values.remove(KeyType.CURVE25519);
    values.remove(KeyType.RSA_2048);
    values.remove(KeyType.RSA_4096);
    values.remove(KeyType.RSA_8192);

    return values.stream().map(key -> Arguments.of(new VirgilCrypto(key)));
  }

  @Retention(RetentionPolicy.RUNTIME)
  @ParameterizedTest
  @MethodSource("allCryptos")
  public @interface CryptoTest {
  }

  @Retention(RetentionPolicy.RUNTIME)
  @ParameterizedTest
  @MethodSource("signVerifyCryptos")
  public @interface SignCryptoTest {
  }

  @CryptoTest
  public void computeHash(VirgilCrypto crypto) {
    for (HashAlgorithm algorithm : HashAlgorithm.values()) {
      assertThrows(NullArgumentException.class, () -> {
        byte[] hash = crypto.computeHash(null, algorithm);
      });
    }
  }

  @CryptoTest
  public void computeHash_nullData(VirgilCrypto crypto) {
    assertThrows(NullArgumentException.class, () -> {
      crypto.computeHash(null, HashAlgorithm.SHA512);
    });
  }

  @CryptoTest
  public void decrypt(VirgilCrypto crypto) throws VirgilException {
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

  @CryptoTest
  public void decrypt_verbose_error(VirgilCrypto crypto) throws VirgilException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), keyPair.getPublicKey());
    byte[] decrypted = crypto.decrypt(encrypted, keyPair.getPrivateKey());
    assertArrayEquals(TEXT.getBytes(), decrypted);

    VirgilKeyPair keyPairWrong = crypto.generateKeyPair();

    assertEquals(assertThrows(DecryptionException.class, () -> {
      crypto.decrypt(encrypted, keyPairWrong.getPrivateKey());
    }).getMessage(), "Given Private key does not corresponds to any of " +
        "Public keys that were used for encryption.");
  }

  @CryptoTest
  public void decrypt_stream(VirgilCrypto crypto) throws IOException, VirgilException {
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

  @CryptoTest
  public void encrypt_decrypt_stream(VirgilCrypto crypto) throws IOException, CryptoException {
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

  @CryptoTest
  public void encrypt(VirgilCrypto crypto) throws VirgilException {
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      recipients.add(crypto.generateKeyPair().getPublicKey());
    }
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);

    assertNotNull(encrypted);
  }

  @CryptoTest
  public void encrypt_noRecipients_success(VirgilCrypto crypto) throws VirgilException {
    @SuppressWarnings("unchecked")
    byte[] encrypted = crypto.encrypt(TEXT.getBytes(), Collections.EMPTY_LIST);

    assertNotNull(encrypted);
  }

  @CryptoTest
  public void encrypt_stream(VirgilCrypto crypto) throws IOException, CryptoException {
    List<VirgilPublicKey> recipients = new ArrayList<>();
    for (int i = 0; i < RECIPIENTS_NUMBER; i++) {
      recipients.add(crypto.generateKeyPair().getPublicKey());
    }
    try (OutputStream os = new ByteArrayOutputStream()) {
      crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients);
    }
  }

  @CryptoTest
  public void exportPrivateKey_noPassword(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey());

    assertNotNull(key);
    assertTrue(key.length > 0);
  }

  @CryptoTest
  public void exportPublicKey(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();

    byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

    assertNotNull(key);
    assertTrue(key.length > 0);
  }

  @CryptoTest
  public void generateKeys(VirgilCrypto crypto) throws CryptoException {
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

  @SignCryptoTest
  public void generateSignature(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());

    assertNotNull(signature);
  }

  @CryptoTest
  public void generateSignature_nullData(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    assertThrows(NullArgumentException.class, () -> {
      crypto.generateSignature((byte[]) null, keyPair.getPrivateKey());
    });
  }

  @CryptoTest
  public void generateSignature_nullPrivateKey(VirgilCrypto crypto) throws CryptoException {
    assertThrows(NullArgumentException.class, () -> {
      crypto.generateSignature(TEXT.getBytes(), null);
    });
  }

  @SignCryptoTest
  public void generateSignature_stream(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPrivateKey());

    assertNotNull(signature);
  }

  @CryptoTest
  public void generateSignature_stream_nullPrivateKey(VirgilCrypto crypto) throws SigningException {
    assertThrows(NullArgumentException.class, () -> {
      crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), null);
    });
  }

  @CryptoTest
  public void generateSignature_stream_nullStream(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    assertThrows(NullArgumentException.class, () -> {
      crypto.generateSignature((InputStream) null, keyPair.getPrivateKey());
    });
  }

  @CryptoTest
  public void importPrivateKey_noPassword(VirgilCrypto crypto) throws CryptoException {
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

  @CryptoTest
  public void importPublicKey(VirgilCrypto crypto) throws CryptoException {
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

  @SignCryptoTest
  public void sign_stream_compareToByteArraySign(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    byte[] streamSignature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPrivateKey());

    assertNotNull(signature);
    assertNotNull(streamSignature);
    assertArrayEquals(signature, streamSignature);
  }

  @SignCryptoTest
  public void verifySignature(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(signature, TEXT.getBytes(), keyPair.getPublicKey());

    assertTrue(valid);
  }

  @SignCryptoTest
  public void verifySignature_invalidSignature(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(INVALID_SIGNATURE, TEXT.getBytes(),
        keyPair.getPublicKey());

    assertFalse(valid);
  }

  @SignCryptoTest
  public void verifySignature_stream(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(signature, new ByteArrayInputStream(TEXT.getBytes()),
        keyPair.getPublicKey());

    assertTrue(valid);
  }

  @SignCryptoTest
  public void verifySignature_stream_invalidSignature(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
    boolean valid = crypto.verifySignature(INVALID_SIGNATURE,
        new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPublicKey());

    assertFalse(valid);
  }

  @CryptoTest
  @Disabled
  public void encrypt_decrypt_benchmark(VirgilCrypto crypto) throws CryptoException {
    KeyType keyType = crypto.getDefaultKeyType();
    System.out.println("Key type: " + keyType);
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

  @CryptoTest
  public void generateKeyPair_exportPrivateKey_in_cycle(VirgilCrypto crypto) throws CryptoException {
    for (int i = 0; i < 1000; i++) {
      VirgilKeyPair kp = crypto.generateKeyPair(KeyType.SECP256R1);
      byte[] privateKeyData = crypto.exportPrivateKey(kp.getPrivateKey());
      assertNotNull(privateKeyData);
    }
  }

  @CryptoTest
  public void auth_encrypt_should_match(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair1 = crypto.generateKeyPair();
    VirgilKeyPair keyPair2 = crypto.generateKeyPair();
    VirgilKeyPair keyPair3 = crypto.generateKeyPair();

    byte[] encrypted = crypto.authEncrypt(TEXT.getBytes(), keyPair1.getPrivateKey(), keyPair2.getPublicKey());
    byte[] decrypted = crypto.authDecrypt(encrypted, keyPair2.getPrivateKey(), keyPair1.getPublicKey());

    assertArrayEquals(TEXT.getBytes(), decrypted);

    assertThrows(DecryptionException.class, () -> {
      crypto.authDecrypt(encrypted, keyPair3.getPrivateKey(), keyPair1.getPublicKey());
    });

    assertThrows(DecryptionException.class, () -> {
      crypto.authDecrypt(encrypted, keyPair2.getPrivateKey(), keyPair3.getPublicKey());
    });
  }

  @CryptoTest
  public void auth_encrypt_stream_should_match(VirgilCrypto crypto) throws IOException, CryptoException {
    VirgilKeyPair keyPair1 = crypto.generateKeyPair();
    VirgilKeyPair keyPair2 = crypto.generateKeyPair();
    VirgilKeyPair keyPair3 = crypto.generateKeyPair();

    ArrayList<VirgilPublicKey> publicKeys = new ArrayList<>();
    publicKeys.add(keyPair1.getPublicKey());
    publicKeys.add(keyPair2.getPublicKey());

    byte[] encrypted;
    try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
         ByteArrayInputStream inputStream = new ByteArrayInputStream(TEXT.getBytes())) {

      int streamSize = inputStream.available();

      crypto.authEncrypt(inputStream, streamSize, outputStream, keyPair1.getPrivateKey(), publicKeys);
      encrypted = outputStream.toByteArray();
    }
    assertNotNull(encrypted);

    try (ByteArrayInputStream inputStream1 = new ByteArrayInputStream(encrypted);
         ByteArrayInputStream inputStream2 = new ByteArrayInputStream(encrypted);
         ByteArrayInputStream inputStream3 = new ByteArrayInputStream(encrypted);
         ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
         ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream();
         ByteArrayOutputStream outputStream3 = new ByteArrayOutputStream()) {

      crypto.authDecrypt(inputStream1, outputStream1, keyPair1.getPrivateKey(), publicKeys);
      byte[] decrypted = outputStream1.toByteArray();

      assertArrayEquals(TEXT.getBytes(), decrypted);

      assertThrows(DecryptionException.class, () -> {
        crypto.authDecrypt(inputStream2, outputStream2, keyPair3.getPrivateKey(), publicKeys);
      });

      assertThrows(DecryptionException.class, () -> {
        crypto.authDecrypt(inputStream3, outputStream3, keyPair2.getPrivateKey(), keyPair3.getPublicKey());
      });
    }
  }

  @SignCryptoTest
  public void auth_decrypt_deprecated_should_work(VirgilCrypto crypto) throws CryptoException {
    VirgilKeyPair keyPair1 = crypto.generateKeyPair();
    VirgilKeyPair keyPair2 = crypto.generateKeyPair();

    byte[] encrypted1 = crypto.authEncrypt(TEXT.getBytes(), keyPair1.getPrivateKey(), keyPair2.getPublicKey());
//    byte[] encrypted2 = crypto.authEncrypt(TEXT.getBytes(), keyPair1.getPrivateKey(), keyPair2.getPublicKey());
    byte[] encrypted2 = crypto.signThenEncrypt(TEXT.getBytes(), keyPair1.getPrivateKey(), keyPair2.getPublicKey());

    byte[] decrypted1 = crypto.authDecrypt(encrypted1, keyPair2.getPrivateKey(), keyPair1.getPublicKey(), true);
    assertArrayEquals(TEXT.getBytes(), decrypted1);

    byte[] decrypted2 = crypto.authDecrypt(encrypted2, keyPair2.getPrivateKey(), keyPair1.getPublicKey(), true);
    assertArrayEquals(TEXT.getBytes(), decrypted2);
  }
}
