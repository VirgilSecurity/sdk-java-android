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

package com.virgilsecurity.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class CompatibilityDataProvider {

  public static final String JSON = "json";
  public static final String STRING = "string";

  private JsonObject sampleJson;

  public CompatibilityDataProvider() {
    sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(this.getClass()
        .getClassLoader().getResourceAsStream("com/virgilsecurity/sdk/test_data.txt")));
  }

  public CompatibilityDataProvider(JsonObject sampleJson) {
    this.sampleJson = sampleJson;
  }

  public String getJsonByKey(int number, String key) {
    return sampleJson.get("STC-" + number + "." + key).getAsString();
  }

  public JsonObject getJsonObject(int number) {
    return new Gson().fromJson(sampleJson.get("STC-" + number + ".as_" + JSON).getAsString(),
        JsonObject.class);
  }

  public JsonObject getJsonObjectByKey(int number, String key) {
    return sampleJson.get("STC-" + number + "." + key).getAsJsonObject();
  }

  public String getString(String key) {
    return sampleJson.get(key).getAsString();
  }

  public String getTestDataAs(int number, String type) {
    return sampleJson.get("STC-" + number + ".as_" + type).getAsString();
  }

  public String readFile(String name) throws IOException {
    try (InputStream is = this.getClass().getClassLoader().getResourceAsStream(name)) {
      return ConvertionUtils.toString(is);
    }
  }
}
