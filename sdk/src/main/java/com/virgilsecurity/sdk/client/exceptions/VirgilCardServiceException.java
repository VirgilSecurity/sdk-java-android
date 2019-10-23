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

package com.virgilsecurity.sdk.client.exceptions;

import com.virgilsecurity.sdk.common.HttpError;

/**
 * Exception class for Virgil Cards Service operations.
 *
 * @author Andrii Iakovenko
 */
public class VirgilCardServiceException extends VirgilServiceException {

  private static final long serialVersionUID = -6168211821016742313L;

  /**
   * Create a new instance of {@code VirgilCardServiceException}.
   */
  public VirgilCardServiceException() {
  }

  /**
   * Create a new instance of {@code VirgilCardServiceException}.
   *
   * @param e the exception.
   */
  public VirgilCardServiceException(Exception e) {
    super(e);
  }

  /**
   * Create a new instance of {@code VirgilCardServiceException}.
   *
   * @param code the error code.
   */
  public VirgilCardServiceException(int code) {
    super(code);
  }

  /**
   * Create a new instance of {@code VirgilCardServiceException}.
   *
   * @param code    The error code.
   * @param message The error message.
   */
  public VirgilCardServiceException(int code, String message) {
    super(code, message);
  }

  /**
   * Create a new instance of {@code VirgilCardServiceException}.
   *
   * @param code      The error code from Virgil Services.
   * @param message   The error message from Virgil Services.
   * @param httpError the http error by itself
   */
  public VirgilCardServiceException(int code, String message, HttpError httpError) {
    super(code, message, httpError);
  }

  /**
   * Create new instance of {@link VirgilCardServiceException}.
   *
   * @param message the detail message
   */
  public VirgilCardServiceException(String message) {
    super(-1, message);
  }
}
