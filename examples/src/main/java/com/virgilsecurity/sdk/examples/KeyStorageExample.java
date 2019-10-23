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
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;
import com.virgilsecurity.sdk.utils.Tuple;

import java.util.Map;

/**
 * @author Andrii Iakovenko
 */
public class KeyStorageExample {

  @SuppressWarnings("unused")
  public static void main(String[] args) throws CryptoException {
    // Generate some private key
    VirgilCrypto crypto = new VirgilCrypto();
    VirgilKeyPair keyPair = crypto.generateKeyPair();
    VirgilPrivateKey privateKey = keyPair.getPrivateKey();

    // Setup PrivateKeyStorage
    VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(crypto);
    KeyStorage keyStorage = new JsonFileKeyStorage();
    PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

    // Store a private key
    privateKeyStorage.store(privateKey, "Alice", null);

    // Load a private key
    Tuple<VirgilPrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load("Alice");

    // Delete a private key
    privateKeyStorage.delete("Alice");

    System.out.println("Done!");
  }

}
