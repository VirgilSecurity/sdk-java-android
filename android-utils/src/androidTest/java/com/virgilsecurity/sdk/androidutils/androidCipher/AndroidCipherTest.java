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

package com.virgilsecurity.sdk.androidutils.androidCipher;

import android.app.KeyguardManager;
import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class AndroidCipherTest {

    private static final String TEXT = "This is the best text ever";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private String androidKeyStoreAlias = "AndroidKeyStoreTestAliasAuth4";

    @Before
    public void setup() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        androidKeyStoreAlias = UUID.randomUUID().toString().substring(0, 12);

        // Initial key generation
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(androidKeyStoreAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .setUnlockedDeviceRequired(true) // TODO check on device
                .setUserAuthenticationValidityDurationSeconds(5 * 60) // 5 minutes
                .setUserAuthenticationRequired(false)
                .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    @Ignore("Test manually on pattern-locked device. Hard to reproduce on emulator without UI.")
    @Test
    public void is_device_secure() {
        KeyguardManager keyguardManager = (KeyguardManager)
                InstrumentationRegistry.getContext().getSystemService(Context.KEYGUARD_SERVICE);

        assertTrue(keyguardManager.isDeviceSecure());
    }

    @Test
    public void encrypt_decrypt_with_android_aes_gcm()
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException,
            CertificateException, IOException, KeyStoreException, UnrecoverableEntryException {

        // Load secret key
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        assertTrue(keyStore.containsAlias(androidKeyStoreAlias));

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(androidKeyStoreAlias, null);

        final SecretKey secretKey = secretKeyEntry.getSecretKey();

        // Encryption
        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptionIv = cipher.getIV();

        byte[] encryptedData = cipher.doFinal(TEXT.getBytes(StandardCharsets.UTF_8));


        // Decryption
        final GCMParameterSpec spec = new GCMParameterSpec(128, encryptionIv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        final byte[] decodedData = cipher.doFinal(encryptedData);
        final String decryptedString = new String(decodedData, StandardCharsets.UTF_8);

        assertEquals(TEXT, decryptedString);
    }
}
