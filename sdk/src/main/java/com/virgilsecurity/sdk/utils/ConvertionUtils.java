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

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import com.virgilsecurity.common.util.Base64;
import com.virgilsecurity.sdk.common.StringEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.Scanner;

/**
 * Utilities class for data conversion.
 *
 * @author Andrii Iakovenko
 * @author Danylo Oliinyk
 */
public class ConvertionUtils {

  private static class ByteArrayToBase64TypeAdapter
      implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
    public byte[] deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
        throws JsonParseException {
      return base64ToBytes(json.getAsString());
    }

    public JsonElement serialize(byte[] src, Type typeOfSrc, JsonSerializationContext context) {
      return new JsonPrimitive(toBase64String(src));
    }
  }

  private static class ClassTypeAdapter extends TypeAdapter<Class<?>> {
    @Override
    public Class<?> read(JsonReader jsonReader) throws IOException {
      if (jsonReader.peek() == JsonToken.NULL) {
        jsonReader.nextNull();
        return null;
      }
      Class<?> clazz = null;
      try {
        clazz = Class.forName(jsonReader.nextString());
      } catch (ClassNotFoundException exception) {
        throw new IOException(exception);
      }
      return clazz;
    }

    @Override
    public void write(JsonWriter jsonWriter, Class<?> clazz) throws IOException {
      if (clazz == null) {
        jsonWriter.nullValue();
        return;
      }
      jsonWriter.value(clazz.getName());
    }
  }

  private static class ClassTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
      if (!Class.class.isAssignableFrom(typeToken.getRawType())) {
        return null;
      }
      return (TypeAdapter<T>) new ClassTypeAdapter();
    }
  }

  private static Gson gson = null;

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

  private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

  /**
   * Decode Base64 string to byte array.
   *
   * @param value The string to be converted
   * @return the byte array
   */
  public static byte[] base64ToBytes(String value) { // FIXME remove
    return Base64.decode(value);
  }

  /**
   * Decode Base64 byte array to string.
   *
   * @param bytes the base64-encoded byte array
   * @return the decoded string
   */
  public static String base64ToString(byte[] bytes) {
    return toString(base64ToBytes(toString(bytes)));
  }

  /**
   * Decode Base64 string to string.
   *
   * @param value the base64-encoded string to be converted.
   * @return the decoded string.
   */
  public static String base64ToString(String value) {
    return toString(base64ToBytes(value));
  }

  /**
   * Take an accurate snapshot of the object, and convert it into the binary data.
   *
   * @param snapshotModel The snapshot model.
   * @return The taken snapshot.
   */
  public static byte[] captureSnapshot(Object snapshotModel) {
    String snapshotModelJson = serializeToJson(snapshotModel);
    return ConvertionUtils.toBytes(snapshotModelJson);
  }

  /**
   * Concatenate two byte arrays.
   *
   * @param first  the first array.
   * @param second the second array.
   * @return a byte array.
   */
  public static byte[] concatenate(byte[] first, byte[] second) {
    byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);

    return result;
  }

  /**
   * Deserialize object of <code>objectType</code> type from JSON String.
   *
   * @param serializedObject the string presentation of object serialized to JSON
   * @param objectType       the type of object
   * @return the {@code objectType} object deserialized from {@code serializedObject}
   */
  public static <T> T deserializeFromJson(String serializedObject, Class<T> objectType) {
    return getGson().fromJson(serializedObject, objectType);
  }

  /**
   * Deserialize from JSON String to Map.
   *
   * @param serializedObject object to be deserialized
   * @return Map object deserialized from JSON String
   */
  public static Map<String, String> deserializeMapFromJson(String serializedObject) {
    Type mapType = new TypeToken<Map<String, Object>>() {
    }.getType();
    return getGson().fromJson(serializedObject, mapType);
  }

  /**
   * Get {@link Gson} which supports Virgil rules for date and byte array conversions.
   *
   * @return the Gson instance.
   */
  public static synchronized Gson getGson() {
    if (gson == null) {
      GsonBuilder builder = new GsonBuilder();
      gson = builder.registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
          .registerTypeAdapterFactory(new ClassTypeAdapterFactory()).disableHtmlEscaping().create();
    }
    return gson;
  }

  /**
   * Decode HEX string to byte array.
   *
   * @param value The string to be converted.
   * @return the byte array.
   */
  public static byte[] hexToBytes(String value) {
    final int len = value.length();

    // "111" is not a valid hex encoding.
    if (len % 2 != 0) {
      throw new IllegalArgumentException("hexBinary needs to be even-length: " + value);
    }

    byte[] out = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
      int h = hexToBin(value.charAt(i));
      int l = hexToBin(value.charAt(i + 1));
      if (h == -1 || l == -1) {
        throw new IllegalArgumentException("contains illegal character for hexBinary: " + value);
      }

      out[i / 2] = (byte) (h * 16 + l);
    }

    return out;
  }

  /**
   * Deserialize object of <code>objectType</code> type from binary presentation of JSON String.
   *
   * @param snapshot   the object snapshot which is a binary presentation of JSON string
   * @param objectType the type of object
   * @return the {@code objectType} object deserialized from {@code snapshot}
   */
  public static <T> T parseSnapshot(byte[] snapshot, Class<T> objectType) {
    return deserializeFromJson(new String(snapshot, StandardCharsets.UTF_8), objectType);
  }

  /**
   * Serialize object to JSON representation in String.
   *
   * @param serializable object to convert to JSON representation in String
   * @return object converted to JSON in String
   */
  public static String serializeToJson(Object serializable) {
    return ConvertionUtils.getGson().toJson(serializable);
  }

  /**
   * Convert string to Base64 byte array.
   *
   * @param value the string to be converted.
   * @return the byte array.
   */
  public static byte[] toBase64Bytes(String value) {
    String str = toBase64String(value);
    return toBytes(str);
  }

  /**
   * Encode byte array as Base64 string.
   *
   * @param bytes the byte array to be encoded.
   * @return the base64-encoded string.
   */
  public static String toBase64String(byte[] bytes) {
    return Base64.encode(bytes);
  }

  /**
   * Encode string to Base64 string.
   *
   * @param value the string to be converted.
   * @return the base64 string.
   */
  public static String toBase64String(String value) {
    byte[] bytes = value.getBytes(UTF8_CHARSET);
    return Base64.encode(bytes);
  }

  /**
   * Convert {@code String} to byte array.
   *
   * @param string the string to converted.
   * @return the byte array.
   */
  public static byte[] toBytes(String string) {
    if (string == null) {
      return new byte[0];
    }
    return string.getBytes(UTF8_CHARSET);
  }

  /**
   * Convert byte array to HEX {@code String}.
   *
   * @param bytes the byte array to be converted.
   * @return the HEX string.
   */
  public static String toHex(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return "";
    }
    StringBuilder r = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      r.append(hexCode[(b >> 4) & 0xF]);
      r.append(hexCode[(b & 0xF)]);
    }
    return r.toString();
  }

  /**
   * Convert byte array to {@code String}.
   *
   * @param bytes the byte array to be converted.
   * @return the string.
   */
  public static String toString(byte[] bytes) {
    if (bytes == null || bytes.length == 0) {
      return "";
    }
    return new String(bytes, UTF8_CHARSET);
  }

  /**
   * Decodes the current bytes to a string according to the specified character encoding.
   *
   * @param inputBytes bytes to decode
   * @param encoding   The character encoding to decode to.
   * @return {@link String} that represents this instance.
   */
  public static String toString(byte[] inputBytes, StringEncoding encoding) {
    if (inputBytes == null) {
      throw new IllegalArgumentException("ConvertionUtils -> 'inputBytes' should not be null");
    }

    switch (encoding) {
      case BASE64:
        return toBase64String(inputBytes);
      case HEX:
        StringBuilder stringBuilder = new StringBuilder();
        for (byte inputByte : inputBytes) {
          stringBuilder.append(String.format("%02X", inputByte));
        }

        return stringBuilder.toString().replace("-", "").toLowerCase(Locale.getDefault());
      case UTF8:
        return new String(inputBytes, StandardCharsets.UTF_8);
      default:
        return new String(inputBytes, StandardCharsets.UTF_8);
    }
  }

  /**
   * Get the contents of an <code>InputStream</code> as a String using UTF-8 character encoding.
   *
   * @param is the input stream.
   * @return the input stream data as string.
   */
  public static String toString(InputStream is) {
    try (Scanner s = new Scanner(is, "UTF-8")) {
      s.useDelimiter("\\A");
      return s.hasNext() ? s.next() : "";
    }
  }

  private static int hexToBin(char ch) {
    if ('0' <= ch && ch <= '9') {
      return ch - '0';
    }
    if ('A' <= ch && ch <= 'F') {
      return ch - 'A' + 10;
    }
    if ('a' <= ch && ch <= 'f') {
      return ch - 'a' + 10;
    }
    return -1;
  }
}
