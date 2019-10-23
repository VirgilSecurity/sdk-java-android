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

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link VirgilPrivateKeyExporter}.
 *
 * @author Andrii Iakovenko
 */
public class VirgilPrivateKeyExporterTest {

  private VirgilCrypto crypto;
  private VirgilPrivateKey privateKey;

  private static Stream<Arguments> exporters() {
    return Stream.of(Arguments.of(new VirgilPrivateKeyExporter()),
        Arguments.of(new VirgilPrivateKeyExporter(new VirgilCrypto())));
  }

  @Retention(RetentionPolicy.RUNTIME)
  @ParameterizedTest
  @MethodSource("exporters")
  public @interface ExporterTest {
  }

  @BeforeEach
  public void setup() throws CryptoException {
    this.crypto = new VirgilCrypto();
    this.privateKey = this.crypto.generateKeyPair().getPrivateKey();
  }

  @ExporterTest
  public void exportPrivateKey(VirgilPrivateKeyExporter exporter) throws CryptoException {
    byte[] exportedKeyData = exporter.exportPrivateKey(privateKey);
    assertNotNull(exportedKeyData);
  }

  @ExporterTest
  public void importPrivateKey(VirgilPrivateKeyExporter exporter) throws CryptoException {
    byte[] exportedKeyData = exporter.exportPrivateKey(privateKey);

    VirgilPrivateKey importedKey = exporter.importPrivateKey(exportedKeyData);
    assertNotNull(importedKey);
    assertEquals(privateKey, importedKey);
  }

  @ExporterTest
  public void importPrivateKey_invalidData(VirgilPrivateKeyExporter exporter) {
    assertThrows(CryptoException.class, () -> {
      exporter.importPrivateKey("wrong_data".getBytes());
    });
  }

  @ExporterTest
  public void importPrivateKey_null(VirgilPrivateKeyExporter exporter) {
    assertThrows(NullArgumentException.class, () -> {
      exporter.importPrivateKey(null);
    });
  }

}
