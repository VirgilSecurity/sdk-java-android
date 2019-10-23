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

import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.util.List;

/**
 * The {@linkplain Validator} is used for validation purposes to make code cleaner.
 */
public class Validator {

  /**
   * Check whether provided byte[ ] is empty.
   *
   * @param data    the data to check
   * @param message the message that will be shown if provided byte[ ] is empty
   */
  public static void checkEmptyAgrument(byte[] data, String message) {
    if (data.length == 0) {
      throw new EmptyArgumentException(message);
    }
  }

  /**
   * Check whether provided list is empty.
   *
   * @param list    the list to check
   * @param message the message that will be shown if provided list is empty
   */
  public static void checkEmptyAgrument(List<?> list, String message) {
    if (list.isEmpty()) {
      throw new EmptyArgumentException(message);
    }
  }

  /**
   * Check whether provided string is empty.
   *
   * @param string  the string to check
   * @param message the message that will be shown if provided string is empty
   */
  public static void checkEmptyAgrument(String string, String message) {
    if (string.isEmpty()) {
      throw new EmptyArgumentException(message);
    }
  }

  /**
   * Check whether provided object is null.
   *
   * @param o       object to check
   * @param message the message that will be shown if provided object is null
   */
  public static void checkNullAgrument(Object o, String message) {
    if (o == null) {
      throw new NullArgumentException(message);
      // TODO: 1/18/18 replace in all places and check for references to other packages
    }
  }

  /**
   * Check whether provided byte[ ] is null or empty.
   *
   * @param data    the data to check
   * @param message the message that will be shown if provided byte[ ] is null or empty
   */
  public static void checkNullEmptyAgrument(byte[] data, String message) {
    checkNullAgrument(data, message);
    checkEmptyAgrument(data, message);
  }

  /**
   * Check whether provided List is null or empty.
   *
   * @param list    the list to check
   * @param message the message that will be shown if provided List is null or empty
   */
  public static void checkNullEmptyAgrument(List<?> list, String message) {
    checkNullAgrument(list, message);
    checkEmptyAgrument(list, message);
  }
}
