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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStreamReader;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link VirgilCrypto} which tests cross-platform compatibility.
 *
 * @author Andrii Iakovenko
 */
public class VirgilCryptoCompatibilityTest {

    private JsonObject sampleJson;

    private static Stream<Arguments> allCryptos() {
        VirgilCrypto crypto = new VirgilCrypto();
        crypto.setUseSHA256Fingerprints(true);
        return Stream.of(Arguments.of(crypto),
                Arguments.of(new VirgilCrypto(true)));
    }

    @Retention(RetentionPolicy.RUNTIME)
    @ParameterizedTest
    @MethodSource("allCryptos")
    public @interface CryptoTest {
    }

    @BeforeEach
    public void setup() {
        sampleJson = (JsonObject) new JsonParser()
                .parse(new InputStreamReader(Objects.requireNonNull(
                        this.getClass().getClassLoader()
                                .getResourceAsStream(
                                        "com/virgilsecurity/sdk/crypto/crypto_compatibility_data.json"))));
    }

    @CryptoTest
    public void decryptFromMultipleRecipients(VirgilCrypto crypto) throws CryptoException {
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

    @CryptoTest
    public void decryptFromSingleRecipient(VirgilCrypto crypto) throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("encrypt_single_recipient");

        byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
        byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
        byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

        VirgilPrivateKey privateKey = crypto.importPrivateKey(privateKeyData).getPrivateKey();
        byte[] decryptedData = crypto.decrypt(cipherData, privateKey);

        assertArrayEquals(originalData, decryptedData);
    }

    @CryptoTest
    public void decryptThenVerifyMultipleRecipients(VirgilCrypto crypto) throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_recipients");

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

    @CryptoTest
    public void decryptThenVerifyMultipleSigners(VirgilCrypto crypto) throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_multiple_signers");

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

    @CryptoTest
    public void decryptThenVerifySingleRecipient(VirgilCrypto crypto) throws CryptoException {
        JsonObject json = sampleJson.getAsJsonObject("sign_then_encrypt_single_recipient");

        byte[] privateKeyData = Base64.decode(json.get("private_key").getAsString().getBytes());
        byte[] originalData = Base64.decode(json.get("original_data").getAsString().getBytes());
        byte[] cipherData = Base64.decode(json.get("cipher_data").getAsString().getBytes());

        VirgilKeyPair keyPair = crypto.importPrivateKey(privateKeyData);
        VirgilPublicKey publicKey = keyPair.getPublicKey();

        byte[] decryptedData = crypto.decryptThenVerify(cipherData, keyPair.getPrivateKey(),
                Collections.singletonList(publicKey));
        assertArrayEquals(originalData, decryptedData);
    }

    @CryptoTest
    public void generateSignature(VirgilCrypto crypto) throws CryptoException {
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
}
