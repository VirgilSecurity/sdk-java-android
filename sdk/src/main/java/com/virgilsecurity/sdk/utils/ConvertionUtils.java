/*******************************************************************************
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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
 *******************************************************************************/
package com.virgilsecurity.sdk.utils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.Charset;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import com.virgilsecurity.crypto.VirgilBase64;

/**
 * Utilities class for data conversion.
 *
 * @author Andrii Iakovenko
 *
 */
public class ConvertionUtils {

    private static Gson gson = null;

    private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");

    public static synchronized Gson getGson() {
        if (gson == null) {
            GsonBuilder builder = new GsonBuilder();
            gson = builder.registerTypeHierarchyAdapter(byte[].class, new ByteArrayToBase64TypeAdapter())
                    .registerTypeAdapterFactory(new ClassTypeAdapterFactory())
                    .disableHtmlEscaping().create();
        }
        return gson;
    }

    /**
     * Convert {@code String} to byte array.
     * 
     * @param string
     *            the string to converted.
     * @return the byte array.
     */
    public static byte[] toBytes(String string) {
        if (string == null) {
            return new byte[0];
        }
        return string.getBytes(UTF8_CHARSET);
    }

    /**
     * Convert byte array to {@code String}.
     * 
     * @param bytes
     *            the byte array to be converted.
     * @return the string.
     */
    public static String toString(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, UTF8_CHARSET);
    }

    /**
     * Convert byte array to HEX {@code String}.
     * 
     * @param bytes
     *            the byte array to be converted.
     * @return the HEX string.
     */
    public static String toHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return DatatypeConverter.printHexBinary(bytes);
    }

    /**
     * Encode string to Base64 string.
     * 
     * @param value
     *            the string to be converted.
     * @return the base64 string.
     */
    public static String toBase64String(String value) {
        byte[] bytes = value.getBytes(UTF8_CHARSET);
        return VirgilBase64.encode(bytes);
    }

    /**
     * Convert string to Base64 byte array.
     * 
     * @param value
     *            the string to be converted.
     * @return the byte array.
     */
    public static byte[] toBase64Bytes(String value) {
        String str = VirgilBase64.encode(value.getBytes(UTF8_CHARSET));
        return toBytes(str);
    }

    /**
     * Encode byte array as Base64 string.
     * 
     * @param bytes
     *            the byte array to be encoded.
     * @return the base64-encoded string.
     */
    public static String toBase64String(byte[] bytes) {
        return VirgilBase64.encode(bytes);
    }

    /**
     * Decode Base64 string to string.
     * 
     * @param value
     *            the base64-encoded string to be converted.
     * @return the decoded string.
     */
    public static String base64ToString(String value) {
        return toString(VirgilBase64.decode(value));
    }

    /**
     * Decode Base64 string to byte array.
     * 
     * @param value
     *            The string to be converted.
     * @return the byte array.
     */
    public static byte[] base64ToBytes(String value) {
        return VirgilBase64.decode(value);
    }

    /**
     * Decode Base64 byte array to string.
     * 
     * @param bytes
     *            the base64-encoded byte array.
     * @return the decoded string.
     */
    public static String base64ToString(byte[] bytes) {
        return toString(VirgilBase64.decode(toString(bytes)));
    }

    /**
     * Decode HEX string to byte array.
     * 
     * @param value
     *            The string to be converted.
     * @return the byte array.
     */
    public static byte[] hexToBytes(String value) {
        return DatatypeConverter.parseHexBinary(value);
    }

    /**
     * Get the contents of an <code>InputStream</code> as a String using UTF-8 character encoding.
     * 
     * @param is
     *            the input stream.
     * @return the input stream data as string.
     */
    public static String toString(InputStream is) {
        try (Scanner s = new Scanner(is, "UTF-8")) {
            s.useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        }
    }

    /**
     * Take an accurate snapshot of the object, and convert it into the binary data.
     * 
     * @param snapshotModel The snapshot model.
     * @return The taken snapshot.
     */
    public static byte[] captureSnapshot(Object snapshotModel) {
        String snapshotModelJson = ConvertionUtils.getGson().toJson(snapshotModel);
        byte[] takenSnapshot = ConvertionUtils.toBytes(snapshotModelJson);

        return takenSnapshot;
    }

    private static class ByteArrayToBase64TypeAdapter implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {
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
        public void write(JsonWriter jsonWriter, Class<?> clazz) throws IOException {
            if(clazz == null){
                jsonWriter.nullValue();
                return;
            }
            jsonWriter.value(clazz.getName());
        }

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
    }

    private static class ClassTypeAdapterFactory implements TypeAdapterFactory {
        @Override
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> typeToken) {
            if(!Class.class.isAssignableFrom(typeToken.getRawType())) {
                return null;
            }
            return (TypeAdapter<T>) new ClassTypeAdapter();
        }
    }
}
