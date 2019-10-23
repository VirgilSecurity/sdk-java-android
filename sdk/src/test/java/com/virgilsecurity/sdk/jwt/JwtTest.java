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

package com.virgilsecurity.sdk.jwt;

import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;


/**
 * Unit tests for {@link Jwt}.
 *
 * @author Andrii Iakovenko
 */
public class JwtTest {
  private static final long FUTURE_TIME_EXPIRATION = 6 * 1000; // 6 sec

  private FakeDataFactory fake;
  private String identity;

  @Test
  public void future_expire() throws CryptoException, InterruptedException {
    JwtGenerator generator = fake.getJwtGeneratorFiveSeconds();
    Jwt jwt = generator.generateToken(this.identity);
    assertNotNull(jwt);

    assertFalse(jwt.isExpired());
    assertTrue(jwt.isExpired(new Date(System.currentTimeMillis() + FUTURE_TIME_EXPIRATION)));

    Thread.sleep(FUTURE_TIME_EXPIRATION);

    assertTrue(jwt.isExpired());
  }

  @Test
  public void generate_byIdentity() throws CryptoException {
    JwtGenerator generator = fake.getJwtGenerator();
    Jwt jwt = generator.generateToken(this.identity);

    assertNotNull(jwt);
    assertEquals(this.identity, jwt.getIdentity());
  }

  @Test
  public void instantiate_fromString() throws CryptoException {
    Jwt jwt = this.fake.generateToken();
    Jwt importedJwt = new Jwt(jwt.stringRepresentation());

    assertEquals(jwt, importedJwt);
    assertEquals(jwt.stringRepresentation(), importedJwt.stringRepresentation());
  }

  @BeforeEach
  public void setup() throws CryptoException {
    this.fake = new FakeDataFactory();
    this.identity = "IDENTITY_" + fake.getApplicationId();
  }
}
