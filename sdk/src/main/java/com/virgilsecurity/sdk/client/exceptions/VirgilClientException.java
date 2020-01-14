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

import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * Represents errors occurred during interaction with SDK components.
 */
public class VirgilClientException extends VirgilException {

  private static final long serialVersionUID = -8369792754821656857L;

  private int code;

  /**
   * Create a new instance of {@code VirgilException}.
   */
  public VirgilClientException() {
  }

  /**
   * Create new instance of {@link VirgilClientException}.
   *
   * @param code the error code
   */
  public VirgilClientException(int code) {
    this.code = code;
  }

  /**
   * Create a new instance of {@code VirgilException}.
   *
   * @param message the detail message
   * @param code    the error code
   */
  public VirgilClientException(int code, String message) {
    super(message);
    this.code = code;
  }

  /**
   * Create a new instance of {@code VirgilException}.
   *
   * @param message the detail message
   */
  public VirgilClientException(String message) {
    super(message);
  }

  /**
   * Create new instance of {@link VirgilClientException}.
   *
   * @param message the detail message
   * @param cause   the cause
   */
  public VirgilClientException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Create new instance of {@link VirgilClientException}.
   *
   * @param cause the cause
   */
  public VirgilClientException(Throwable cause) {
    super(cause);
  }

  /**
   * Get the error code.
   *
   * @return the error code.
   */
  public int getCode() {
    return code;
  }

}
