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
 * Base exception class for all Virgil Services operations.
 *
 * @author Andrii Iakovenko
 */
public abstract class VirgilServiceException extends Exception {

  private static final long serialVersionUID = -1143173438484224903L;

  private static final String ERROR_UNKNOWN = "Unknown error";

  /**
   * Because we have HttpUrlConnection response as well as Virgil Service exception in Http error
   * body. So we have to handle both.
   */
  private int errorCode = 0;
  private String messageError;
  private HttpError httpError;

  /**
   * Create a new instance of {@code VirgilServiceException}.
   */
  public VirgilServiceException() {
  }

  /**
   * Create a new instance of {@code VirgilServiceException}.
   *
   * @param cause the cause
   */
  public VirgilServiceException(Exception cause) {
    super(cause);
    this.errorCode = -1;
  }

  /**
   * Create a new instance of {@code VirgilServiceException}.
   *
   * @param code the error code
   */
  public VirgilServiceException(int code) {
    this.errorCode = code;
  }

  /**
   * Create a new instance of {@code VirgilServiceException}.
   *
   * @param code  the error code
   * @param cause the cause
   */
  public VirgilServiceException(int code, Exception cause) {
    super(cause);

    this.errorCode = code;
  }

  /**
   * Create a new instance of {@code VirgilServiceException}.
   *
   * @param code         the error code
   * @param messageError the error message
   */
  public VirgilServiceException(int code, String messageError) {
    this.errorCode = code;
    this.messageError = messageError;
  }

  /**
   * Create a new instance of {@code VirgilServiceException}.
   *
   * @param code         the error code from Virgil Service
   * @param messageError the error message from Virgil Service
   * @param httpError    the {@link HttpError} by itself
   */
  public VirgilServiceException(int code, String messageError, HttpError httpError) {
    this.errorCode = code;
    this.messageError = messageError;
    this.httpError = httpError;
  }

  /**
   * Get the error code.
   *
   * @return the error code
   */
  public int getErrorCode() {
    return errorCode;
  }

  /**
   * Gets http error.
   *
   * @return the http error
   */
  public HttpError getHttpError() {
    return httpError;
  }

  /*
   * (non-Javadoc)
   *
   * @see java.lang.Throwable#getMessage()
   */
  @Override
  public String getMessage() {
    String message = "\n";
    if (httpError != null) {
      message += "Http response:\n" + httpError.getCode();
      if (httpError.getMessage() != null && !httpError.getMessage().isEmpty()) {
        message += " : " + httpError.getMessage();
      }

      message += "\nService response:\n";
    }

    if (errorCode == -1) {
      return super.getMessage();
    }

    if (messageError != null) {
      return message + errorCode + " : " + messageError;
    }

    return ERROR_UNKNOWN + ": " + errorCode;
  }
}
