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

package com.virgilsecurity.sdk.jwt;


import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Unit tests for {@link AccessTokenProvider}.
 */
public class AccessTokenProviderTest {
  private static final long SEVEN_SECONDS_MILLIS = 7 * 1000; // 7 seconds

  private static final String FAKE_IDENTITY = "FAKE_IDENTITY";
  private static final String TOKEN_OPERATION = "test";
  private static final boolean TOKEN_FORCE_RELOAD = false;
  private static final String TOKEN_SERVICE = "test_service";

  private Mocker mocker;
  private boolean failedConcurrency;

  @Test
  public void caching_jwt_provider_renew_test() throws InterruptedException {
    CachingJwtProvider jwtProvider = initCachingJwtProvider();

    TokenContext tokenContext = new TokenContext(TOKEN_SERVICE, TOKEN_OPERATION, TOKEN_FORCE_RELOAD);

    AccessToken token1 = jwtProvider.getToken(tokenContext);
    assertNotNull(token1);

    AccessToken token2 = jwtProvider.getToken(tokenContext);
    assertNotNull(token2);

    assertEquals(token1, token2);

    Thread.sleep(SEVEN_SECONDS_MILLIS);

    AccessToken token3 = jwtProvider.getToken(tokenContext);
    assertNotNull(token3);

    assertNotEquals(token1, token3);
  }

  @Test
  public void caching_jwt_provider_renew_test_concurrent() throws InterruptedException {
    final CachingJwtProvider jwtProvider = initCachingJwtProvider();
    final TokenContext tokenContext = new TokenContext(TOKEN_SERVICE, TOKEN_OPERATION, TOKEN_FORCE_RELOAD);
    ExecutorService exec = Executors.newFixedThreadPool(16);

    for (int i = 0; i < 10000; i++) {
      exec.execute(new Runnable() {
        @Override
        public void run() {
          try {
            AccessToken token1 = jwtProvider.getToken(tokenContext);
            if (token1 == null) {
              throw new NullPointerException();
            }

            AccessToken token2 = jwtProvider.getToken(tokenContext);
            if (token2 == null) {
              throw new NullPointerException();
            }

            if (!token1.equals(token2)) {
              throw new Exception();
            }

            try {
              Thread.sleep(2000);
            } catch (InterruptedException exception) {
              fail();
            }
          } catch (Exception e) {
            failedConcurrency = true;
          }
        }
      });
    }

    exec.shutdown();
    exec.awaitTermination(10, TimeUnit.SECONDS);

    if (failedConcurrency) {
      fail();
    }
  }

  @Test
  public void caching_jwt_provider_thread_safe() throws InterruptedException {
    final int[] counter = new int[1];

    final CachingJwtProvider jwtProvider = new CachingJwtProvider(new CachingJwtProvider.RenewJwtCallback() {
      @Override
      public Jwt renewJwt(TokenContext tokenContext) {
        try {
          counter[0]++;
          return mocker.generateSevenSecondsAccessToken(FAKE_IDENTITY);
        } catch (CryptoException e) {
          e.printStackTrace();
          throw new NullPointerException("Error generating token");
        }
      }
    });

    final TokenContext tokenContext = new TokenContext(TOKEN_SERVICE, TOKEN_OPERATION, TOKEN_FORCE_RELOAD);

    ExecutorService exec = Executors.newFixedThreadPool(6);

    for (int i = 0; i <= 5; i++) {
      exec.execute(new Runnable() {
        @Override
        public void run() {
          System.out.println("Thread id: " + Thread.currentThread().getName());

          AccessToken token1 = jwtProvider.getToken(tokenContext);
          if (token1 == null) {
            throw new NullPointerException();
          }
        }
      });
    }

    exec.shutdown();
    exec.awaitTermination(10, TimeUnit.SECONDS);

    assertEquals(1, counter[0]);
  }

  @Test
  public void stc_40_caching_token_provider_initial_value() throws CryptoException, InterruptedException {
    final int[] counter = new int[1];
    final String identity = Generator.identity();

    final JwtGenerator jwtGeneratorSevenSeconds = mocker.getJwtGeneratorForSeconds(10);
    Jwt tokenInitial = jwtGeneratorSevenSeconds.generateToken(identity);
    CachingJwtProvider cachingJwtProvider = new CachingJwtProvider(new CachingJwtProvider.RenewJwtCallback() {

      @Override
      public Jwt renewJwt(TokenContext tokenContext) {
        try {
          counter[0]++;
          return jwtGeneratorSevenSeconds.generateToken(identity);
        } catch (CryptoException e) {
          e.printStackTrace();
          return null;
        }
      }
    }, tokenInitial);

    AccessToken tokenOne = cachingJwtProvider.getToken(new TokenContext("test_operation", false));
    assertEquals(tokenInitial, tokenOne);

    Thread.sleep(3 * 1000);

    AccessToken tokenTwo = cachingJwtProvider.getToken(new TokenContext("test_operation", false));
    assertEquals(tokenInitial, tokenTwo);

    Thread.sleep(5 * 1000);

    AccessToken tokenThree = cachingJwtProvider.getToken(new TokenContext("test_operation", false));
    assertNotEquals(tokenInitial, tokenThree);

    assertEquals(1, counter[0]);
  }

  @BeforeEach
  public void setUp() {
    mocker = new Mocker();
  }

  private CachingJwtProvider initCachingJwtProvider() {
    return new CachingJwtProvider(new CachingJwtProvider.RenewJwtCallback() {
      @Override
      public Jwt renewJwt(TokenContext tokenContext) {
        try {
          return mocker.generateSevenSecondsAccessToken(FAKE_IDENTITY);
        } catch (CryptoException e) {
          e.printStackTrace();
          throw new NullPointerException("Error generating token");
        }
      }
    });
  }
}
