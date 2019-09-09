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

package com.virgilsecurity.sdk.benchmark.crypto;

import com.virgilsecurity.sdk.crypto.KeyType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

/**
 * Benchmark for VirgilCrypto sign/verify operations.
 * 
 * @author Andrii Iakovenko
 *
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
public class VirgilCryptoSignatureBenchmark {

  private static final byte[] DATA = "this string will be signed".getBytes(StandardCharsets.UTF_8);

  @Param({ "ED25519", "SECP256R1", "RSA_4096" })
  private KeyType keyType;

  private VirgilCrypto crypto;
  private VirgilPrivateKey privateKey;
  private VirgilPublicKey publicKey;
  private byte[] signature;
  private InputStream inputStream;

  @Setup(Level.Invocation)
  public void setup() throws CryptoException {
    this.crypto = new VirgilCrypto(this.keyType);
    VirgilKeyPair keyPair = this.crypto.generateKeyPair(this.keyType);
    this.privateKey = keyPair.getPrivateKey();
    this.publicKey = keyPair.getPublicKey();

    this.signature = this.crypto.generateSignature(DATA, this.privateKey);
    this.inputStream = new ByteArrayInputStream(this.signature);
  }

  @Benchmark
  public void sign() throws SigningException {
    this.crypto.generateSignature(DATA, this.privateKey);
  }

  @Benchmark
  public void sign_stream() throws SigningException {
    this.crypto.generateSignature(this.inputStream, this.privateKey);
  }

  @Benchmark
  public void verify() throws VerificationException {
    this.crypto.verifySignature(this.signature, DATA, this.publicKey);
  }

  @Benchmark
  public void verify_stream() throws VerificationException {
    this.crypto.verifySignature(this.signature, this.inputStream, this.publicKey);
  }
}
