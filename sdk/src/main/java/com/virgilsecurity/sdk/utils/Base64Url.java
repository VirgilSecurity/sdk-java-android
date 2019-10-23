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

package com.virgilsecurity.sdk.utils;

/**
 * This class provides Base64url encoding functionality. See
 * <a href="https://www.rfc-editor.org/rfc/pdfrfc/rfc7515.txt.pdf">Appendix C</a> for details.
 *
 * @author Andrii Iakovenko
 */
public class Base64Url {

  /**
   * Decodes base64url string to base64.
   *
   * @param value base64url encoded string.
   * @return decoded string.
   */
  public static String decode(String value) {
    return ConvertionUtils.toString(decodeToBytes(value));
  }

  /**
   * Decodes base64url string to base64.
   *
   * @param value base64url encoded string.
   * @return decoded string.
   */
  public static byte[] decodeToBytes(String value) {
    String s = value;

    s = s.replace("-", "+");
    s = s.replace("_", "/");

    switch (s.length() % 4) {
      case 0:
        break;
      case 2:
        s += "==";
        break;
      case 3:
        s += "=";
        break;
      default:
        throw new IllegalArgumentException("ConvertionUtils -> 'input' has wrong base64url format");
    }

    return ConvertionUtils.base64ToBytes(s);
  }

  /**
   * Encodes bytes to base64url string.
   *
   * @param bytes The bytes for encoding.
   * @return base64url encoded string.
   */
  public static String encode(byte[] bytes) {
    String s = ConvertionUtils.toBase64String(bytes);
    return s.replace("=", "").replace("+", "-").replace("/", "_");
  }

  /**
   * Encodes string to base64url.
   *
   * @param value The string for encoding.
   * @return base64url encoded string.
   */
  public static String encode(String value) {
    return encode(ConvertionUtils.toBytes(value));
  }
}
