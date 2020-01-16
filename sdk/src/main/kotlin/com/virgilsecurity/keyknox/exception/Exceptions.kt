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

package com.virgilsecurity.keyknox.exception

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException

open class KeyknoxCryptoException(message: String?) : CryptoException(message)

class DecryptionFailedException(message: String? = "Decryption failed") : KeyknoxCryptoException(message)

class SignerNotFoundException(message: String?) : KeyknoxCryptoException(message)

class SignatureVerificationException(message: String? = "Signature verification failed") : KeyknoxCryptoException(message)

class EmptyDataException(message: String?) : KeyknoxCryptoException(message)

class EmptyPublicKeysException(message: String? = "Public keys collection should NOT be empty") : KeyknoxCryptoException(message)

open class KeyknoxException(message: String? = "Unknown error") : Exception(message)

open class KeyknoxClientException(message: String? = "Unknown error") : KeyknoxException(message)
open class EmptyIdentitiesException : KeyknoxClientException("Identities should not be empty")
open class InvalidOptionsException : KeyknoxClientException("Internal invalid options error")

open class KeyknoxServerException(message: String? = "Unknown error") : KeyknoxException(message)
open class KeyknoxServiceException(val responseCode: Int, val errorCode: Int = -1, message: String? = "Unknown error") : KeyknoxServerException(message)

class TamperedServerResponseException(message: String? = "Server returned a tampered value") : KeyknoxServerException(message)

open class InvalidHashHeaderException : KeyknoxServerException("No Hash header in server response")


open class CloudKeyStorageException(message: String? = "CloudKey storage error") : KeyknoxServerException(message)

class CloudStorageOutOfSyncException : CloudKeyStorageException("CloudKey storage is out of sync")
class EntryAlreadyExistsException : CloudKeyStorageException("Entry is already exists")
class EntrySavingException : CloudKeyStorageException("Error while saving entry")
class EntryNotFoundException(entryName: String) : CloudKeyStorageException("CloudEntry ${entryName} not found")

open class KeychainStorageException(message: String? = "Keychain storage error") : KeyknoxException(message)
class ConvertKeychainEntryException : KeychainStorageException("Can't convert entry")

open class SyncKeyStorageException(message: String? = "Sync key storage error") : KeyknoxException(message)
class KeychainEntryNotFoundWhileUpdatingException : SyncKeyStorageException("KeychainEntry not found while updating")
class CloudEntryNotFoundWhileUpdatingException : SyncKeyStorageException("CloudEntry not found while updating")
class CloudEntryNotFoundWhileDeletingException : SyncKeyStorageException("CloudEntry notfound while deleting")
class KeychainEntryNotFoundWhileComparingException : SyncKeyStorageException("KeychainEntry not found while comparing")
class KeychainEntryAlreadyExistsWhileStoringException(name: String) : SyncKeyStorageException("KeychainEntry $name already exists while storing")
class CloudEntryAlreadyExistsWhileStoringException(name: String) : SyncKeyStorageException("CloudEntry $name already exists while storing")
class InvalidModificationDateInKeychainEntryException : SyncKeyStorageException("Invalid modificationDate in KeychainEntry")
class InvalidCreationDateInKeychainEntryException : SyncKeyStorageException("Invalid creationDate in KeychainEntry")
class NoMetaInKeychainEntryException : SyncKeyStorageException("No meta in keychainEntry")
class InvalidKeysInEntryMetaException : SyncKeyStorageException("Invalid keys in entry meta")
class InconsistentStateException : SyncKeyStorageException("Inconsistent state")

