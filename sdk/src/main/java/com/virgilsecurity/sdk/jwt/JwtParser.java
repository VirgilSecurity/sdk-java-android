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

import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * The {@link JwtParser} class is used to parse Json Web Token from string representation and build
 * string representation from the corresponding objects.
 */
public class JwtParser {

  /**
   * Build jwt body string representation.
   *
   * @param jwtBodyContent the jwt body content
   * @return the string representation of jwt body
   */
  public static String buildJwtBody(JwtBodyContent jwtBodyContent) {
    return ConvertionUtils.serializeToJson(jwtBodyContent);
  }

  /**
   * Build jwt header string representation.
   *
   * @param jwtHeaderContent the jwt header content
   * @return the string representation of jwt header
   */
  public static String buildJwtHeader(JwtHeaderContent jwtHeaderContent) {
    return ConvertionUtils.serializeToJson(jwtHeaderContent);
  }

  /**
   * Parse jwt body content from its string representation.
   *
   * @param jsonWebTokenBody the json web token body
   * @return the jwt body content object
   */
  public static JwtBodyContent parseJwtBodyContent(String jsonWebTokenBody) {
    Validator.checkNullAgrument(jsonWebTokenBody,
        "JwtParser -> 'jsonWebTokenBody' should not be null");
    return ConvertionUtils.deserializeFromJson(jsonWebTokenBody, JwtBodyContent.class);
  }

  /**
   * Parse jwt header content from its string representation.
   *
   * @param jsonWebTokenHeader the json web token header
   * @return the jwt header content object
   */
  public static JwtHeaderContent parseJwtHeaderContent(String jsonWebTokenHeader) {
    Validator.checkNullAgrument(jsonWebTokenHeader,
        "JwtParser -> 'jsonWebTokenHeader' should not be null");
    return ConvertionUtils.deserializeFromJson(jsonWebTokenHeader, JwtHeaderContent.class);
  }
}
