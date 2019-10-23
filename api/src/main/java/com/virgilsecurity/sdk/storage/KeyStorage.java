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

package com.virgilsecurity.sdk.storage;

import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException;

import java.util.Set;

/**
 * This interface describes a storage facility for cryptographic keys.
 *
 * @author Andrii Iakovenko
 */
public interface KeyStorage {

  /**
   * Factory method for creating {@linkplain KeyEntry}.
   *
   * @param name  the key name.
   * @param value the key value.
   * @return created {@linkplain KeyEntry instance}.
   */
  KeyEntry createEntry(String name, byte[] value);

  /**
   * Deletes the private key from key store by given Id.
   *
   * @param name the key name.
   */
  void delete(String name);

  /**
   * Checks if the private key exists in this storage by given alias.
   *
   * @param name the key name.
   * @return {@code true} if the private key exists, {@code false} otherwise.
   */
  boolean exists(String name);

  /**
   * Loads the private key associated with the given alias.
   *
   * @param name the key name.
   * @return The requested private key, or null if the given alias does not exist or does not
   * identify a key-related entry.
   */
  KeyEntry load(String name);

  /**
   * Get names of keys stored in key store.
   *
   * @return the set of key names.
   */
  Set<String> names();

  /**
   * Stores the private key (that has already been protected) to the given alias.
   *
   * @param keyEntry the key entry.
   * @throws KeyEntryAlreadyExistsException if key with the same name is already stored
   */
  void store(KeyEntry keyEntry);

  /**
   * Updates the private key (that has already been protected) to the given alias.
   *
   * @param keyEntry the key entry.
   * @throws KeyEntryNotFoundException if key with the same name doesn't exists.
   */
  void update(KeyEntry keyEntry);

}
