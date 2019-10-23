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

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.common.ClassForSerialization;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@linkplain ConvertionUtils}.
 *
 * @author Andrii Iakovenko
 * @author Danylo Oliinyk
 */
public class ConvertionUtilsTest {

  private static final String TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

  @Test
  public void autoByteToBase64StringSerialization() {
    ClassForSerialization classForSerialization = new ClassForSerialization("Petro",
        "Grigorovych".getBytes());

    String serialized = ConvertionUtils.serializeToJson(classForSerialization);

    Map<String, String> mapJson = ConvertionUtils.deserializeMapFromJson(serialized);
    String data = "";
    for (Map.Entry<String, String> entry : mapJson.entrySet()) {
      if (entry.getKey().equals("data")) {
        data = mapJson.get(entry.getKey());
      }
    }

    assertEquals(ConvertionUtils.base64ToString(data), "Grigorovych");
  }

  @Test
  public void backslashJsonSerialization() {
    String hello = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg=";
    String serializedToJson = ConvertionUtils.serializeToJson(hello);

    assertEquals(hello, serializedToJson.replace("\"", ""));
  }

  @Test
  public void base64ByteArray() {
    byte[] base64bytes = ConvertionUtils.toBase64Bytes(TEXT);
    String str = ConvertionUtils.base64ToString(base64bytes);

    assertEquals(TEXT, str);
  }

  @Test
  public void base64String() {
    String base64string = ConvertionUtils.toBase64String(TEXT);
    String str = ConvertionUtils.base64ToString(base64string);

    assertEquals(TEXT, str);
  }

  @Test
  public void deSerializationHashMap() {
    Map<String, String> additionalData = new HashMap<>();
    additionalData.put("Info", "best");
    additionalData.put("Hello", "Buddy");

    String hashMapSerialized = ConvertionUtils.serializeToJson(additionalData);
    Map<String, String> deserializeFromJson = ConvertionUtils
        .deserializeMapFromJson(hashMapSerialized);

    assertEquals(additionalData, deserializeFromJson);
  }

  @Test
  public void deSerializationJson() {
    String rawJson = "{ \"id\": \"12345\", \"content_snapshot\":\"AQIDBAU=\" }";
    RawSignedModel cardModel = ConvertionUtils.deserializeFromJson(rawJson, RawSignedModel.class);

    assertTrue(
        Arrays.equals(cardModel.getContentSnapshot(), ConvertionUtils.base64ToBytes("AQIDBAU=")));
  }

  @Test
  public void toBytes() {
    byte[] bytes = ConvertionUtils.toBytes(TEXT);
    String str = ConvertionUtils.toString(bytes);
    assertEquals(TEXT, str);
  }

  @Test
  public void toHex() {
    byte[] bytes = ConvertionUtils.toBytes(TEXT);
    String str = ConvertionUtils.toHex(bytes);
    bytes = ConvertionUtils.hexToBytes(str);
    str = ConvertionUtils.toString(bytes);
    assertEquals(TEXT, str);
  }
}
