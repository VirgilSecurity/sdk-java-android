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

package com.virgilsecurity.sdk.client;

import com.virgilsecurity.sdk.VirgilInfo;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardIsOutdatedException;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardServiceException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.ErrorResponse;
import com.virgilsecurity.sdk.common.HttpError;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.OsUtils;
import com.virgilsecurity.sdk.utils.StreamUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HttpClient class intention is to handle http requests.
 *
 * @author Andrii Iakovenko
 */
public class HttpClient {

  private static final Logger LOGGER = Logger.getLogger(HttpClient.class.getName());

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String CONTENT_TYPE_HEADER = "Content-Type";
  private static final String VIRGIL_AGENT_HEADER = "virgil-agent";
  private static final String VIRGIL_SUPERSEEDED_HEADER = "X-Virgil-Is-Superseeded";

  private String virgilAgent;

  /**
   * Creating HttpClient with default virgil-agent header.
   */
  public HttpClient() {
    virgilAgent = VirgilInfo.PRODUCT + ';'
        + VirgilInfo.FAMILY + ';'
        + OsUtils.getOsAgentName() + ';'
        + VirgilInfo.VERSION;
  }

  /**
   * Creating HttpClient with custom virgil-agent header setting provided product and version.
   *
   * @param product custom product value for virgil-agent header.
   * @param version custom version value virgil-agent header.
   */
  public HttpClient(String product, String version) {
    virgilAgent = product + ';'
        + VirgilInfo.FAMILY + ';'
        + OsUtils.getOsAgentName() + ';'
        + version;
  }

  /**
   * Executes http requests.
   *
   * @param url         endpoint to make request to.
   * @param method      request method (POST, PUT, DELETE, GET).
   * @param token       authentication token.
   * @param inputStream data for the body of POST/PUT requests.
   * @param clazz       type of the return class.
   * @return the response that is parsed as a provided clazz argument.
   * @throws VirgilServiceException if any issue with request is happend.
   */
  public <T> T execute(URL url, String method, String token, InputStream inputStream,
                       Class<T> clazz) throws VirgilServiceException {
    try {
      HttpURLConnection urlConnection = createConnection(url, method, token);
      if (inputStream != null) {
        StreamUtils.copyStream(inputStream, urlConnection.getOutputStream());
      }
      try {
        if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
          LOGGER.warning("Http error occurred...");
          // Get error code from request
          try (InputStream in = new BufferedInputStream(urlConnection.getErrorStream())) {
            LOGGER.info("Trying to get error info...");
            String body = ConvertionUtils.toString(in);
            if (!StringUtils.isBlank(body)) {
              ErrorResponse error = ConvertionUtils.getGson().fromJson(body, ErrorResponse.class);
              HttpError httpError = new HttpError(urlConnection.getResponseCode(),
                  urlConnection.getResponseMessage());
              throw new VirgilCardServiceException(error.getCode(), error.getMessage(), httpError);
            } else {
              LOGGER.warning("Response error body is empty. Nothing to show");
            }
          }
          if (urlConnection.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
            LOGGER.warning("Http error code: " + HttpURLConnection.HTTP_NOT_FOUND);
            return null;
          }
          throw new VirgilCardServiceException(urlConnection.getResponseCode(),
              urlConnection.getResponseMessage());
        } else if (clazz.isAssignableFrom(Void.class)) {
          LOGGER.warning("Void is unacceptable type");
          return null;
        } else {
          LOGGER.fine("Trying to extract response body...");
          try (InputStream instream = new BufferedInputStream(urlConnection.getInputStream())) {
            String body = ConvertionUtils.toString(instream);
            T obj = ConvertionUtils.getGson().fromJson(body, clazz);
            if (isSuperseeded(urlConnection)) {
              throw new VirgilCardIsOutdatedException((RawSignedModel) obj);
            }

            return obj;
          }
        }
      } finally {
        LOGGER.info("Disconnecting...");
        urlConnection.disconnect();
      }
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "Connection error", e);
      throw new VirgilCardServiceException(e);
    }
  }

  /**
   * Create and configure http connection.
   *
   * @param url    The URL.
   * @param method The HTTP method.
   * @return The connection.
   * @throws IOException if connection couldn't be created.
   */
  private HttpURLConnection createConnection(URL url, String method, String token)
      throws IOException {
    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
    urlConnection.setRequestMethod(method);
    urlConnection.setUseCaches(false);

    switch (method) {
      case "DELETE":
      case "POST":
      case "PUT":
      case "PATCH":
        urlConnection.setDoOutput(true);
        break;
      default:
        // GET method used by default
    }

    if (!StringUtils.isBlank(token)) {
      urlConnection.setRequestProperty(AUTHORIZATION_HEADER, "Virgil " + token);
    } else {
      LOGGER.warning("Provided token is blank");
    }
    urlConnection.setRequestProperty(CONTENT_TYPE_HEADER, "application/json; charset=utf-8");
    urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER, virgilAgent);

    return urlConnection;
  }

  private boolean isSuperseeded(HttpURLConnection urlConnection) {
    String header = urlConnection.getHeaderField(VIRGIL_SUPERSEEDED_HEADER);
    if (header != null) {
      return Boolean.parseBoolean(header);
    }
    return false;
  }

}
