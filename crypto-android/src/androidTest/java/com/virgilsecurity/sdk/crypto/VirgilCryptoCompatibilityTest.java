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

import android.content.Context;
import android.support.test.InstrumentationRegistry;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for {@link VirgilCrypto} which tests cross-platform compatibility.
 */
@RunWith(Parameterized.class)
public class VirgilCryptoCompatibilityTest {

  private JsonObject sampleJson;
  private VirgilCrypto crypto;

  @Parameterized.Parameters
  public static Collection<Object[]> cryptos() {
    VirgilCrypto crypto = new VirgilCrypto();
    crypto.setUseSHA256Fingerprints(true);
    return Arrays.asList(new Object[][]{
            {crypto}, {new VirgilCrypto(true)}
    });
  }

  public VirgilCryptoCompatibilityTest(VirgilCrypto crypto) {
    this.crypto = crypto;
  }

  @Before
  public void setup() throws IOException {
    Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
    InputStream sampleAsset = appContext.getAssets().open("crypto_compatibility_data.json");
    sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(sampleAsset));
  }

  @Test
  public void dummy() {
    assertEquals(1, 1);
  }

  @Test
  public void decryptFromMultipleRecipients() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("encrypt_multiple_recipients");

    List<VirgilPrivateKey> privateKeys = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("private_keys")) {
      byte[] privateKeyData = Base64.decode(el.getAsString().getBytes());
      privateKeys.add(crypto.importPrivateKey(privateKeyData).getPrivateKey());
    }
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    for (VirgilPrivateKey privateKey : privateKeys) {
      byte[] decryptedData = crypto.decrypt(cipherData, privateKey);
      assertArrayEquals(originalData, decryptedData);
    }
  }

  @Test
  public void decryptFromSingleRecipient() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("encrypt_single_recipient");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();
    byte[] decryptedData = crypto.decrypt(cipherData, privateKey);

    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void sign_then_encrypt_decrypt_then_verify() throws CryptoException {
    String text = "text to encrypt";
    byte[] textData = "text to encrypt".getBytes();
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    VirgilKeyPair keyPairTwo = crypto.generateKeyPair();

    List<VirgilPublicKey> publicKeys = new ArrayList<>();
    publicKeys.add(keyPair.getPublicKey());
    publicKeys.add(keyPairTwo.getPublicKey());

    byte[] encrypted = crypto.signThenEncrypt(textData, keyPair.getPrivateKey(), publicKeys);
    assertNotNull(encrypted);

    byte[] decrypted = crypto.decryptThenVerify(encrypted, keyPairTwo.getPrivateKey(), keyPair.getPublicKey());
    String decryptedText = new String(decrypted);

    assertEquals(text, decryptedText);
  }

  @Test
  public void decryptThenVerifyMultipleRecipients() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_and_encrypt_multiple_recipients");

    List<VirgilKeyPair> keyPairs = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("private_keys")) {
      byte[] privateKeyData = Base64.decode(el.getAsString().getBytes());
      keyPairs.add(crypto.importPrivateKey(privateKeyData));
    }
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    byte[] publicKeyData = crypto.exportPublicKey(keyPairs.get(0).getPublicKey());
    VirgilPublicKey publicKey = crypto.importPublicKey(publicKeyData);

    for (VirgilKeyPair keyPair : keyPairs) {
      byte[] decryptedData = crypto.decryptThenVerify(cipherData, keyPair.getPrivateKey(),
          Collections.singletonList(publicKey));
      assertArrayEquals(originalData, decryptedData);
    }
  }

  @Test
  public void decryptThenVerifyMultipleSigners() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_and_encrypt_multiple_signers");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    List<VirgilPublicKey> publicKeys = new ArrayList<>();
    for (JsonElement el : json.getAsJsonArray("public_keys")) {
      byte[] publicKeyData = Base64.decode(el.getAsString().getBytes());
      publicKeys.add(crypto.importPublicKey(publicKeyData));
    }

    VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();

    boolean found = false;
    for (VirgilPublicKey publicKey : publicKeys) {
      if (publicKey.equals(crypto.importPrivateKey(privateKeyData).getPublicKey())) {
        found = true;
      }
    }
    assertTrue(found);

    byte[] decryptedData = crypto.decryptThenVerify(cipherData, privateKey, publicKeys);
    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void decryptThenVerifySingleRecipient() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("sign_and_encrypt_single_recipient");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilKeyPair keyPair = crypto.importPrivateKey(privateKeyData);
    VirgilPublicKey publicKey = keyPair.getPublicKey();

    byte[] decryptedData = crypto.decryptThenVerify(cipherData, keyPair.getPrivateKey(),
        Collections.singletonList(publicKey));
    assertArrayEquals(originalData, decryptedData);
  }

  @Test
  public void generateSignature() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("generate_signature");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
    byte[] signature = Base64.decode(json.get("signature").getAsString().getBytes());

    VirgilKeyPair keyPair = crypto.importPrivateKey(privateKeyData);
    byte[] generatedSignature = crypto.generateSignature(originalData,
        keyPair.getPrivateKey());

    assertArrayEquals(signature, generatedSignature);

    VirgilPublicKey publicKey = keyPair.getPublicKey();
    assertTrue(crypto.verifySignature(signature, originalData, publicKey));
  }

  @Test
  public void auth_encrypt_should_match() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("auth_encrypt");

    byte[] privateKey1Data = Base64.decode(json.get("private_key1").getAsString().getBytes());
    byte[] privateKey2Data = Base64.decode(json.get("private_key2").getAsString().getBytes());
    byte[] publicKeyData = Base64.decode(json.get("public_key").getAsString().getBytes());
    byte[] dataSha512 = Base64.decode(json.get("data_sha512").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilPrivateKey privateKey1 = crypto.importPrivateKey(privateKey1Data).getPrivateKey();
    VirgilKeyPair keyPair2 = crypto.importPrivateKey(privateKey2Data);
    VirgilPublicKey publicKey = crypto.importPublicKey(publicKeyData);

    byte[] data = crypto.authDecrypt(cipherData, privateKey1, publicKey);

    byte[] dataHash512 = crypto.computeHash(data, HashAlgorithm.SHA512);
    assertArrayEquals(dataSha512, dataHash512);

    try {
      crypto.authDecrypt(cipherData, keyPair2.getPrivateKey(), publicKey);
      fail();
    }
    catch (DecryptionException e) {
      // OK
    }

    try {
      crypto.authDecrypt(cipherData, privateKey1, keyPair2.getPublicKey());
      fail();
    }
    catch (VerificationException e) {
      //OK
    }
  }

  @Test
  public void auth_encrypt_PQ_should_match() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("auth_encrypt_pq");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] publicKeyData = Base64.decode(json.get("public_key").getAsString().getBytes());
    byte[] dataSha512 = Base64.decode(json.get("data_sha512").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();
    VirgilPublicKey publicKey = crypto.importPublicKey(publicKeyData);

    byte[] data = crypto.authDecrypt(cipherData, privateKey, publicKey);

    byte[] dataHash512 = crypto.computeHash(data, HashAlgorithm.SHA512);
    assertArrayEquals(dataSha512, dataHash512);
  }

  @Test
  public void auth_encrypt_padding_should_match() throws CryptoException {
    JsonObject json = sampleJson.getAsJsonObject("auth_encrypt_padding");

    byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
    byte[] publicKeyData = Base64.decode(json.get("public_key").getAsString().getBytes());
    byte[] dataSha512 = Base64.decode(json.get("data_sha512").getAsString().getBytes());
    byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

    VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();
    VirgilPublicKey publicKey = crypto.importPublicKey(publicKeyData);

    byte[] data = crypto.authDecrypt(cipherData, privateKey, publicKey);

    byte[] dataHash512 = crypto.computeHash(data, HashAlgorithm.SHA512);
    assertArrayEquals(dataSha512, dataHash512);
  }
}
