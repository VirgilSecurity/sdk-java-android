/*
 * Copyright (c) 2016, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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
package com.virgilsecurity.sdk.crypto;

/**
 * This interface describes a storage facility for cryptographic keys.
 *
 * @author Andrii Iakovenko
 *
 */
public interface KeyStorage {

	/**
	 * Stores the private key (that has already been protected) to the given
	 * alias.
	 * 
	 * @param keyEntry
	 *            The key entry.
	 */
	void store(KeyEntry keyEntry);

	/**
	 * Loads the private key associated with the given alias.
	 * 
	 * 
	 * @param keyName
	 *            The key name.
	 * @return The requested private key, or null if the given alias does not
	 *         exist or does not identify a key-related entry.
	 */
	KeyEntry load(String keyName);

	/**
	 * Checks if the private key exists in this storage by given alias.
	 * 
	 * @param keyName
	 *            The key name.
	 * @return {@code true} if the private key exists, {@code false} otherwise.
	 */
	boolean exists(String keyName);

	/**
	 * Deletes the private key from key store by given Id.
	 * 
	 * @param keyName
	 *            The key name.
	 */
	void delete(String keyName);

}
