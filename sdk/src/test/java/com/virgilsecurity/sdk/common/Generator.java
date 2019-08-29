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

package com.virgilsecurity.sdk.common;

import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.*;

public class Generator {
  private static final String IDENTITY = "TEST-java-v5-";
  private static final String ALPHA_NUMERIC_STRING = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789";

  private static Random randomizer;

  public static String cardId() {
    byte[] fingerprint = randomBytes(32);
    VirgilCardCrypto crypto = new VirgilCardCrypto();

    return ConvertionUtils.toString(Arrays.copyOfRange(crypto.computeSha512(fingerprint), 0, 32),
          StringEncoding.HEX);
  }

  public static String firstName() {
    String[] names = new String[] {"Alice", "Bob", "Greg", "Jenny", "John", "Molly"};
    return names[randomInt(5)];
  }

  public static String identity() {
    return IDENTITY + randomAlphaNumeric(32);
  }

  public static String identity(String prefix) {
    return prefix + Arrays.toString(randomBytes(32));
  }

  public static String lastName() {
    String[] names = new String[] {"Archer", "Slater", "Cook", "Fisher", "Hunter", "Glover"};
    return names[randomInt(5)];
  }

  public static String randomAlphaNumeric(int count) {
    StringBuilder builder = new StringBuilder();
    while (count-- != 0) {
      int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
      builder.append(ALPHA_NUMERIC_STRING.charAt(character));
    }
    return builder.toString();
  }

  public static <T> T randomArrayElement(List<T> list) {
    return list.get(randomInt(list.size() - 1));
  }

  public static byte[] randomBytes(int length) {
    if (randomizer == null) {
      randomizer = new Random();
    }

    byte[] rndBytes = new byte[length];
    randomizer.nextBytes(rndBytes);

    return rndBytes;
  }

  public static Date randomDate() {
    Calendar calendar = Calendar.getInstance();
    calendar.set(Calendar.YEAR, randomInt(4000));
    calendar.set(Calendar.MONTH, randomInt(11));
    calendar.set(Calendar.DAY_OF_MONTH, randomInt(27));
    return calendar.getTime();
  }

  public static int randomInt(int bound) {
    if (randomizer == null) {
      randomizer = new Random();
    }

    return randomizer.nextInt(bound);
  }
}
