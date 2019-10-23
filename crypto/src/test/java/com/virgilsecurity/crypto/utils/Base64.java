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

package com.virgilsecurity.crypto.utils;

/**
 * This is utils class which implements Base64 encoding/decoding functionality.
 *
 * @author Andrii Iakovenko
 */
public class Base64 {

  // Mapping table from 6-bit nibbles to Base64 characters.
  private static final char[] map1 = new char[64];

  static {
    int i = 0;
    for (char c = 'A'; c <= 'Z'; c++) {
      map1[i++] = c;
    }
    for (char c = 'a'; c <= 'z'; c++) {
      map1[i++] = c;
    }
    for (char c = '0'; c <= '9'; c++) {
      map1[i++] = c;
    }
    map1[i++] = '+';
    map1[i++] = '/';
  }

  // Mapping table from Base64 characters to 6-bit nibbles.
  private static final byte[] map2 = new byte[128];

  static {
    for (int i = 0; i < map2.length; i++) {
      map2[i] = -1;
    }
    for (int i = 0; i < 64; i++) {
      map2[map1[i]] = (byte) i;
    }
  }

  /**
   * Decodes a byte array from Base64 format. No blanks or line breaks are allowed within the Base64
   * encoded input data.
   *
   * @param in A character array containing the Base64 encoded data.
   * @return An array containing the decoded data bytes.
   * @throws IllegalArgumentException If the input is not valid Base64 encoded data.
   */
  public static byte[] decode(char[] in) {
    return decode(in, 0, in.length);
  }

  /**
   * Decodes a byte array from Base64 format. No blanks or line breaks are allowed within the Base64
   * encoded input data.
   *
   * @param in     A character array containing the Base64 encoded data.
   * @param offset Offset of the first character in <code>in</code> to be processed.
   * @param len    Number of characters to process in <code>in</code>, starting at <code>iOff</code>.
   * @return An array containing the decoded data bytes.
   * @throws IllegalArgumentException If the input is not valid Base64 encoded data.
   */
  public static byte[] decode(char[] in, int offset, int len) {
    if (len % 4 != 0) {
      throw new IllegalArgumentException(
          "Length of Base64 encoded input string is not a multiple of 4.");
    }
    while (len > 0 && in[offset + len - 1] == '=') {
      len--;
    }
    int outputLen = (len * 3) / 4;
    byte[] out = new byte[outputLen];
    int ip = offset;
    int end = offset + len;
    int op = 0;
    while (ip < end) {
      int i0 = in[ip++];
      int i1 = in[ip++];
      int i2 = ip < end ? in[ip++] : 'A';
      int i3 = ip < end ? in[ip++] : 'A';
      if (i0 > 127 || i1 > 127 || i2 > 127 || i3 > 127) {
        throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
      }
      int b0 = map2[i0];
      int b1 = map2[i1];
      int b2 = map2[i2];
      int b3 = map2[i3];
      if (b0 < 0 || b1 < 0 || b2 < 0 || b3 < 0) {
        throw new IllegalArgumentException("Illegal character in Base64 encoded data.");
      }
      int o0 = (b0 << 2) | (b1 >>> 4);
      int o1 = ((b1 & 0xf) << 4) | (b2 >>> 2);
      int o2 = ((b2 & 3) << 6) | b3;
      out[op++] = (byte) o0;
      if (op < outputLen) {
        out[op++] = (byte) o1;
      }
      if (op < outputLen) {
        out[op++] = (byte) o2;
      }
    }
    return out;
  }

  /**
   * Decode Base64 string to byte array.
   *
   * @param base64String The string to be converted
   * @return the byte array
   */
  public static byte[] decode(String base64String) {
    return decode(base64String.toCharArray());
  }

  /**
   * Encode byte array to Base64 string.
   *
   * @param bytes the byte array to be converted
   * @return the base64 string
   */
  public static String encode(byte[] bytes) {
    return new String(encode(bytes, 0, bytes.length));
  }

  /**
   * Encodes a byte array into Base64 format. No blanks or line breaks are inserted in the output.
   *
   * @param in     An array containing the data bytes to be encoded.
   * @param offset Offset of the first byte in <code>in</code> to be processed.
   * @param len    Number of bytes to process in <code>in</code>, starting at <code>iOff</code>.
   * @return A character array containing the Base64 encoded data.
   */
  public static char[] encode(byte[] in, int offset, int len) {
    int outputDataLen = (len * 4 + 2) / 3; // output length without padding
    int outputLen = ((len + 2) / 3) * 4; // output length including padding
    char[] out = new char[outputLen];
    int ip = offset;
    int end = offset + len;
    int op = 0;
    while (ip < end) {
      int i0 = in[ip++] & 0xff;
      int i1 = ip < end ? in[ip++] & 0xff : 0;
      int i2 = ip < end ? in[ip++] & 0xff : 0;
      int o0 = i0 >>> 2;
      int o1 = ((i0 & 3) << 4) | (i1 >>> 4);
      int o2 = ((i1 & 0xf) << 2) | (i2 >>> 6);
      int o3 = i2 & 0x3F;
      out[op++] = map1[o0];
      out[op++] = map1[o1];
      out[op] = op < outputDataLen ? map1[o2] : '=';
      op++;
      out[op] = op < outputDataLen ? map1[o3] : '=';
      op++;
    }
    return out;
  }

}
