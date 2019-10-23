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

package com.virgilsecurity.sdk.androidutils.storage;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import com.google.gson.Gson;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

/**
 * AndroidKeyStorage class uses AndroidKeyStore to generate symmetric key with which it encrypts Virgil private key,
 * while Virgil private key is used to encrypt KeyStorage itself. Hence, to store/load key entry user has to be
 * authenticated on Android device. User authentication is up to developer, please see:
 * https://developer.android.com/training/articles/keystore#UserAuthentication
 */
public class AndroidKeyStorage implements KeyStorage {

    private static final String VIRGIL_PUBLIC_KEY = "VIRGIL_PUBLIC_KEY";
    private static final String VIRGIL_PRIVATE_KEY_ENCRYPTED = "VIRGIL_PRIVATE_KEY_ENCRYPTED";
    private static final String KEY_STORE_KEYS_SUFFIX = "KEY_STORE_KEYS_SUFFIX";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE_ALIAS = "VirgilAndroidKeyStore-";
    private static final String VIRGIL_SECURITY = "VirgilSecurity";
    private static final String KEYS = "Keys";
    private static final int KEY_VALIDITY_DURATION = 5 * 60; // 5 min
    private static final int INIT_VECTOR_LENGTH = 12; // 12 bytes
    private static final int AUTH_TAG_LENGTH = 128; // 128 bit

    private String keystorePath; // Where keys are saved
    private String keystoreKeysPath; // Where Virgil key pair is saved (to encrypt/decrypt key storage)
    private VirgilCrypto virgilCrypto;
    private String androidKeyStoreAlias;

    /**
     * Uses Builder pattern to instantiate AndroidKeyStorage class.
     */
    public static class Builder {

        private String alias;
        private int keyValidityDuration = KEY_VALIDITY_DURATION;
        private String rootPath;
        private boolean authenticationRequired = true;

        /**
         * Instantiates Builder.
         *
         * @param alias Is an alias with which current keystore will be saved. Cannot be empty or {@code null}.
         */
        public Builder(String alias) {
            this.alias = alias;
        }

        /**
         * Sets keyValidityDuration.
         *
         * @param keyValidityDuration Default duration is 5 minutes. You can specify other duration of key validity in
         * seconds. After the time specified has expired user has to be re-authenticated.
         * You can set requirement that every key usage will need authentication, for details
         * please, see {@link KeyGenParameterSpec.Builder#setUserAuthenticationRequired} docs.
         *
         * @return Builder object to continue setting up AndroidKeyStorage instance.
         */
        public Builder withKeyValidityDuration(int keyValidityDuration) {
            this.keyValidityDuration = keyValidityDuration;

            return this;
        }

        /**
         * Sets rootPath.
         *
         * @param rootPath Path which will be used to store keys.
         *
         * @return Builder object to continue setting up AndroidKeyStorage instance.
         */
        public Builder onPath(String rootPath) { // TODO test null/empty path
            this.rootPath = rootPath;

            return this;
        }

        /**
         * Sets authenticationRequired.
         *
         * @param authenticationRequired Is {@code true} by default. You can set it to {@code false} so the key storage
         *                               won't require user to be authenticated to use it. keyValidityDuration won't
         *                               work when authenticationRequired is {@code false}.
         *
         * @return Builder object to continue setting up AndroidKeyStorage instance.
         */
        public Builder isAuthenticationRequired(boolean authenticationRequired) {
            this.authenticationRequired = authenticationRequired;

            return this;
        }

        /**
         * Builds AndroidKeyStorage instance with provided with builder methods parameters.
         *
         * @return Initialized AndroidKeyStorage instance.
         *
         * @throws com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException
         * When {@code authenticationRequired} is {@code true} and key validity duration has been expired.
         * You have to re-authenticate user, please see the link:
         * https://developer.android.com/training/articles/keystore#UserAuthentication
         * @throws KeyStorageException When some error occurred while building AndroidKeyStorage.
         */
        public AndroidKeyStorage build() {
            if (alias == null) {
                throw new NullArgumentException("alias");
            }
            if (alias.isEmpty()) {
                throw new EmptyArgumentException("alias");
            }
            if (rootPath != null && rootPath.isEmpty()) {
                throw new EmptyArgumentException("rootPath");
            }

            if (rootPath == null) {
                rootPath = getRootPath();
            }

            return new AndroidKeyStorage(alias, authenticationRequired, keyValidityDuration, rootPath);
        }

        private String getRootPath() {
            String path;
            if (System.getProperty("user.home") != null) {
                path = System.getProperty("user.home");
            } else if (System.getenv("user.home") != null) {
                path = System.getenv("user.home");
            } else {
                throw new IllegalStateException("Cannot get default home path. Try to provide it with"
                        + "AndroidKeyStorage.Builder#onPath method.");
            }

            return path;
        }
    }

    /**
     * Instantiates AndroidKeyStorage class.
     *
     * @param alias                  Is an alias with which current keystore will be saved.
     * @param authenticationRequired Is {@code true} by default. You can set it to {@code false} so the key storage
     *                               won't require user to be authenticated to use it.
     * @param keyValidityDuration    Default duration is 5 minutes. You can specify other duration of key validity in
     *                               seconds. After the time specified has expired user has to be re-authenticated.
     *                               You can set requirement that every key usage will need authentication, for details
     *                               please, see {@link KeyGenParameterSpec.Builder#setUserAuthenticationRequired} docs.
     * @param rootPath               Path which will be used to store keys.
     *
     * @throws com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException
     * When {@code authenticationRequired} is {@code true} and key validity duration has been expired.
     * You have to re-authenticate user, please see the link:
     * https://developer.android.com/training/articles/keystore#UserAuthentication
     * @throws KeyStorageException When some error occurred while initializing AndroidKeyStorage.
     */
    private AndroidKeyStorage(String alias, boolean authenticationRequired, int keyValidityDuration, String rootPath) {
        this.keystorePath = rootPath + File.separator + VIRGIL_SECURITY + File.separator + KEYS
                + File.separator + alias;
        this.keystoreKeysPath = rootPath + File.separator + VIRGIL_SECURITY + File.separator + KEYS
                + File.separator + KEY_STORE_KEYS_SUFFIX;
        this.virgilCrypto = new VirgilCrypto();
        this.androidKeyStoreAlias = ANDROID_KEY_STORE_ALIAS + alias;

        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            if (!keyStore.containsAlias(androidKeyStoreAlias)) {
                generateAndSaveSymmetricKey(authenticationRequired, keyValidityDuration);
                generateAndSaveVirgilKeys();
            }
        } catch (Throwable throwable) {
            if (throwable instanceof UserNotAuthenticatedException) {
                // This can happen only on first init, so we can just reset key.
                resetSymmetricKey();
                throw new com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException(throwable);
            } else if (throwable instanceof CryptoException) {
                throw new KeyStorageException("Error occurred while generating Virgil keys");
            } else {
                throw new KeyStorageException(throwable.getMessage() == null
                        ? "Error occurred while initializing android key storage."
                        : throwable.getMessage());
            }
        }
    }

    @Override
    public synchronized void delete(String keyName) {
        if (!existsKey(keyName, keystorePath)) {
            throw new KeyEntryNotFoundException();
        }

        final File file = new File(keystorePath, keyName.toLowerCase());
        final boolean isDeleted = file.delete();

        if (!isDeleted) {
            throw new IllegalStateException("Cannot delete \'" + keyName + "\' key.");
        }
    }

    @Override
    public synchronized boolean exists(String keyName) {
        return existsKey(keyName, keystorePath);
    }

    /**
     * Loads the private key associated with the given alias.
     *
     * @param keyName the key name.
     * @return The requested private key, or null if the given alias does not exist or does not
     * identify a key-related entry.
     *
     * @throws KeyStorageException when some error occurred while loading key entry.
     * @throws com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException
     * when {@code authenticationRequired} is {@code true} and key validity duration has been expired.
     * You have to re-authenticate user, please see the link:
     * https://developer.android.com/training/articles/keystore#UserAuthentication
     */
    @Override
    public synchronized KeyEntry load(String keyName) {
        return loadKey(keyName, true, keystorePath);
    }

    @Override
    public synchronized Set<String> names() {
        final File dir = new File(keystorePath);
        final Set<String> names = new HashSet<>();
        if (dir.exists() && dir.isDirectory()) {
            for (File file : dir.listFiles()) {
                names.add(file.getName());
            }
        }
        return names;
    }

    @Override
    public synchronized void store(KeyEntry keyEntry) {
        storeKey(keyEntry, true, keystorePath);
    }

    @Override
    public KeyEntry createEntry(String name, byte[] value) {
        return new AndroidKeyEntry(name, value);
    }

    @Override
    public synchronized void update(KeyEntry keyEntry) {
        final String keyName = keyEntry.getName();
        if (!existsKey(keyName, keystorePath)) {
            throw new KeyEntryNotFoundException();
        }
        delete(keyName);
        storeKey(keyEntry, true, keystorePath);
    }

    private void generateAndSaveVirgilKeys()
            throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            IOException, CryptoException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        final VirgilKeyPair virgilKeyPair = virgilCrypto.generateKeyPair();

        final byte[] publicKeyData = virgilCrypto.exportPublicKey(virgilKeyPair.getPublicKey());
        final AndroidKeyEntry publicKeyEntry =
                new AndroidKeyEntry(VIRGIL_PUBLIC_KEY + androidKeyStoreAlias, publicKeyData);
        storeKey(publicKeyEntry, false, keystoreKeysPath);

        final SecretKey secretKey = loadSymmetricKey();
        final byte[] privateKeyData = virgilCrypto.exportPrivateKey(virgilKeyPair.getPrivateKey());
        byte[] encryptedPrivateKeyData = encryptWithSymmetricKey(secretKey, privateKeyData);
        final AndroidKeyEntry encryptedPrivateKeyEntry =
                new AndroidKeyEntry(VIRGIL_PRIVATE_KEY_ENCRYPTED + androidKeyStoreAlias, encryptedPrivateKeyData);
        storeKey(encryptedPrivateKeyEntry, false, keystoreKeysPath);
    }

    private void generateAndSaveSymmetricKey(boolean authenticationRequired, int keyValidityDuration)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final KeyGenerator keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        final KeyGenParameterSpec keyGenParameterSpec =
                new KeyGenParameterSpec.Builder(androidKeyStoreAlias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(false)
                        .setUserAuthenticationValidityDurationSeconds(keyValidityDuration)
                        .setUserAuthenticationRequired(authenticationRequired)
                        .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey(); // Generates and saves key
    }

    private byte[] encryptWithVirgilKey(byte[] data) throws CryptoException {
        final AndroidKeyEntry publicKeyEntry =
                (AndroidKeyEntry) loadKey(VIRGIL_PUBLIC_KEY + androidKeyStoreAlias, false, keystoreKeysPath);
        final VirgilPublicKey publicKey = virgilCrypto.importPublicKey(publicKeyEntry.getValue());

        return virgilCrypto.encrypt(data, publicKey);
    }

    private byte[] decryptWithVirgilKey(byte[] data)
            throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            IOException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException,
            InvalidAlgorithmParameterException, CryptoException {

        final AndroidKeyEntry encryptedPrivateKeyEntry =
                (AndroidKeyEntry) loadKey(VIRGIL_PRIVATE_KEY_ENCRYPTED + androidKeyStoreAlias, false, keystoreKeysPath);
        final byte[] encryptedPrivateKeyData = encryptedPrivateKeyEntry.getValue();
        final SecretKey secretKey = loadSymmetricKey();
        final byte[] privateKeyData = decryptWithSymmetricKey(secretKey, encryptedPrivateKeyData);
        final VirgilPrivateKey privateKey = virgilCrypto.importPrivateKey(privateKeyData).getPrivateKey();

        return virgilCrypto.decrypt(data, privateKey);
    }

    private byte[] encryptWithSymmetricKey(SecretKey secretKey, byte[] data)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final byte[] initVector = virgilCrypto.generateRandomData(INIT_VECTOR_LENGTH);

        final GCMParameterSpec parameterSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, initVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        final byte[] encryptedData = cipher.doFinal(data);

        final ByteBuffer byteBuffer = ByteBuffer.allocate(INIT_VECTOR_LENGTH + encryptedData.length);
        byteBuffer.put(initVector);
        byteBuffer.put(encryptedData);

        return byteBuffer.array();
    }

    private byte[] decryptWithSymmetricKey(SecretKey secretKey, byte[] data)
            throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        byte[] initVector = new byte[INIT_VECTOR_LENGTH];
        byteBuffer.get(initVector);
        byte[] encryptedData = new byte[byteBuffer.remaining()];
        byteBuffer.get(encryptedData);

        final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        final GCMParameterSpec parameterSpec = new GCMParameterSpec(AUTH_TAG_LENGTH, initVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        return cipher.doFinal(encryptedData);
    }

    private SecretKey loadSymmetricKey()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException {

        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        if (!keyStore.containsAlias(androidKeyStoreAlias)) {
            throw new IllegalStateException("Cannot load symmetric key. "
                    + "Possibly you have deleted it with KeyStore instance by yourself.");
        }

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(androidKeyStoreAlias, null);

        return secretKeyEntry.getSecretKey();
    }

    private void storeKey(KeyEntry keyEntry, boolean encrypt, String path) {
        final File dir = new File(path);

        if (dir.exists()) {
            if (!dir.isDirectory()) {
                throw new IllegalArgumentException("\'" + path + "\' is not a directory");
            }
        } else {
            boolean dirCreated = dir.mkdirs();

            if (!dirCreated) {
                throw new IllegalStateException("Cannot create directory in path: \'" + path + "\'");
            }
        }

        final String name = keyEntry.getName();
        if (existsKey(name, path)) {
            throw new KeyEntryAlreadyExistsException();
        }

        final KeyEntry entry;
        if (keyEntry instanceof AndroidKeyEntry) {
            entry = keyEntry;
        } else {
            entry = new AndroidKeyEntry(keyEntry.getName(), keyEntry.getValue());
            entry.setMeta(keyEntry.getMeta());
        }

        final String json = new Gson().toJson(entry);
        final File file = new File(dir, name.toLowerCase());
        try (FileOutputStream os = new FileOutputStream(file)) {
            final byte[] dataToWrite;

            if (encrypt) {
                dataToWrite = encryptWithVirgilKey(json.getBytes(Charset.forName("UTF-8")));
            } else {
                dataToWrite = json.getBytes(Charset.forName("UTF-8"));
            }

            os.write(dataToWrite);
        } catch (Throwable throwable) {
            throw new KeyStorageException(throwable);
        }
    }

    private KeyEntry loadKey(String keyName, boolean decrypt, String path) {
        if (!existsKey(keyName, path)) {
            throw new KeyEntryNotFoundException();
        }

        File file = new File(path, keyName.toLowerCase());
        try (FileInputStream is = new FileInputStream(file)) {
            final ByteArrayOutputStream os = new ByteArrayOutputStream();

            final byte[] buffer = new byte[4096];
            int n;
            while (-1 != (n = is.read(buffer))) {
                os.write(buffer, 0, n);
            }

            final byte[] entryData;

            if (decrypt) {
                entryData = decryptWithVirgilKey(os.toByteArray());
            } else {
                entryData = os.toByteArray();
            }

            final AndroidKeyEntry entry = new Gson().fromJson(new String(entryData, Charset.forName("UTF-8")),
                    AndroidKeyEntry.class);
            entry.setName(keyName);

            return entry;
        } catch (Throwable throwable) {
            if (throwable instanceof UserNotAuthenticatedException) {
                throw new com.virgilsecurity.sdk.androidutils.exception.UserNotAuthenticatedException(throwable);
            } else {
                throw new KeyStorageException(throwable);
            }
        }
    }

    private boolean existsKey(String keyName, String path) {
        if (keyName == null) {
            return false;
        }

        final File file = new File(path, keyName.toLowerCase());
        return file.exists();
    }

    private void resetSymmetricKey() {
        try {
            final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);

            keyStore.deleteEntry(androidKeyStoreAlias);
        } catch (Throwable throwable) {
            throw new KeyStorageException("Cannot reset symmetric key.");
        }
    }
}
