/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class virgil_crypto_javaJNI {
	public final static native long VirgilVersion_asNumber();

	public final static native String VirgilVersion_asString();

	public final static native long VirgilVersion_majorVersion();

	public final static native long VirgilVersion_minorVersion();

	public final static native long VirgilVersion_patchVersion();

	public final static native String VirgilVersion_fullName();

	public final static native long new_VirgilVersion();

	public final static native void delete_VirgilVersion(long jarg1);

	public final static native boolean VirgilDataSource_hasData(long jarg1, VirgilDataSource jarg1_)
			throws java.io.IOException;

	public final static native byte[] VirgilDataSource_read(long jarg1, VirgilDataSource jarg1_)
			throws java.io.IOException;

	public final static native void delete_VirgilDataSource(long jarg1);

	public final static native long new_VirgilDataSource();

	public final static native void VirgilDataSource_director_connect(VirgilDataSource obj, long cptr, boolean mem_own,
			boolean weak_global);

	public final static native void VirgilDataSource_change_ownership(VirgilDataSource obj, long cptr,
			boolean take_or_release);

	public final static native boolean VirgilDataSink_isGood(long jarg1, VirgilDataSink jarg1_)
			throws java.io.IOException;

	public final static native void VirgilDataSink_write(long jarg1, VirgilDataSink jarg1_, byte[] jarg2)
			throws java.io.IOException;

	public final static native void delete_VirgilDataSink(long jarg1);

	public final static native long new_VirgilDataSink();

	public final static native void VirgilDataSink_director_connect(VirgilDataSink obj, long cptr, boolean mem_own,
			boolean weak_global);

	public final static native void VirgilDataSink_change_ownership(VirgilDataSink obj, long cptr,
			boolean take_or_release);

	public final static native byte[] VirgilAsn1Compatible_toAsn1(long jarg1, VirgilAsn1Compatible jarg1_);

	public final static native void VirgilAsn1Compatible_fromAsn1(long jarg1, VirgilAsn1Compatible jarg1_,
			byte[] jarg2);

	public final static native void delete_VirgilAsn1Compatible(long jarg1);

	public final static native long new_VirgilHash__SWIG_0();

	public final static native long new_VirgilHash__SWIG_1(int jarg1);

	public final static native long new_VirgilHash__SWIG_2(String jarg1);

	public final static native String VirgilHash_name(long jarg1, VirgilHash jarg1_);

	public final static native int VirgilHash_type(long jarg1, VirgilHash jarg1_);

	public final static native byte[] VirgilHash_hash(long jarg1, VirgilHash jarg1_, byte[] jarg2);

	public final static native void VirgilHash_start(long jarg1, VirgilHash jarg1_);

	public final static native void VirgilHash_update(long jarg1, VirgilHash jarg1_, byte[] jarg2);

	public final static native byte[] VirgilHash_finish(long jarg1, VirgilHash jarg1_);

	public final static native byte[] VirgilHash_hmac(long jarg1, VirgilHash jarg1_, byte[] jarg2, byte[] jarg3);

	public final static native void VirgilHash_hmacStart(long jarg1, VirgilHash jarg1_, byte[] jarg2);

	public final static native void VirgilHash_hmacReset(long jarg1, VirgilHash jarg1_);

	public final static native void VirgilHash_hmacUpdate(long jarg1, VirgilHash jarg1_, byte[] jarg2);

	public final static native byte[] VirgilHash_hmacFinish(long jarg1, VirgilHash jarg1_);

	public final static native void delete_VirgilHash(long jarg1);

	public final static native String VirgilBase64_encode(byte[] jarg1);

	public final static native byte[] VirgilBase64_decode(String jarg1);

	public final static native void delete_VirgilBase64(long jarg1);

	public final static native long VirgilPBKDF_kIterationCount_Default_get();

	public final static native long new_VirgilPBKDF__SWIG_0();

	public final static native long new_VirgilPBKDF__SWIG_1(byte[] jarg1, long jarg2);

	public final static native long new_VirgilPBKDF__SWIG_2(byte[] jarg1);

	public final static native byte[] VirgilPBKDF_getSalt(long jarg1, VirgilPBKDF jarg1_);

	public final static native long VirgilPBKDF_getIterationCount(long jarg1, VirgilPBKDF jarg1_);

	public final static native void VirgilPBKDF_setAlgorithm(long jarg1, VirgilPBKDF jarg1_, int jarg2);

	public final static native int VirgilPBKDF_getAlgorithm(long jarg1, VirgilPBKDF jarg1_);

	public final static native void VirgilPBKDF_setHashAlgorithm(long jarg1, VirgilPBKDF jarg1_, int jarg2);

	public final static native int VirgilPBKDF_getHashAlgorithm(long jarg1, VirgilPBKDF jarg1_);

	public final static native void VirgilPBKDF_enableRecommendationsCheck(long jarg1, VirgilPBKDF jarg1_);

	public final static native void VirgilPBKDF_disableRecommendationsCheck(long jarg1, VirgilPBKDF jarg1_);

	public final static native byte[] VirgilPBKDF_derive__SWIG_0(long jarg1, VirgilPBKDF jarg1_, byte[] jarg2,
			long jarg3);

	public final static native byte[] VirgilPBKDF_derive__SWIG_1(long jarg1, VirgilPBKDF jarg1_, byte[] jarg2);

	public final static native void delete_VirgilPBKDF(long jarg1);

	public final static native long new_VirgilRandom(String jarg1);

	public final static native byte[] VirgilRandom_randomize__SWIG_0(long jarg1, VirgilRandom jarg1_, long jarg2);

	public final static native long VirgilRandom_randomize__SWIG_1(long jarg1, VirgilRandom jarg1_);

	public final static native long VirgilRandom_randomize__SWIG_2(long jarg1, VirgilRandom jarg1_, long jarg2,
			long jarg3);

	public final static native void delete_VirgilRandom(long jarg1);

	public final static native boolean VirgilCustomParams_isEmpty(long jarg1, VirgilCustomParams jarg1_);

	public final static native void VirgilCustomParams_setInteger(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
			int jarg3);

	public final static native int VirgilCustomParams_getInteger(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

	public final static native void VirgilCustomParams_removeInteger(long jarg1, VirgilCustomParams jarg1_,
			byte[] jarg2);

	public final static native void VirgilCustomParams_setString(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native byte[] VirgilCustomParams_getString(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

	public final static native void VirgilCustomParams_removeString(long jarg1, VirgilCustomParams jarg1_,
			byte[] jarg2);

	public final static native void VirgilCustomParams_setData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native byte[] VirgilCustomParams_getData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

	public final static native void VirgilCustomParams_removeData(long jarg1, VirgilCustomParams jarg1_, byte[] jarg2);

	public final static native void VirgilCustomParams_clear(long jarg1, VirgilCustomParams jarg1_);

	public final static native long new_VirgilCustomParams__SWIG_0();

	public final static native long new_VirgilCustomParams__SWIG_1(long jarg1, VirgilCustomParams jarg1_);

	public final static native void delete_VirgilCustomParams(long jarg1);

	public final static native long VirgilKeyPair_generate__SWIG_0(int jarg1, byte[] jarg2);

	public final static native long VirgilKeyPair_generate__SWIG_1(int jarg1);

	public final static native long VirgilKeyPair_generateRecommended__SWIG_0(byte[] jarg1);

	public final static native long VirgilKeyPair_generateRecommended__SWIG_1();

	public final static native long VirgilKeyPair_generateFrom__SWIG_0(long jarg1, VirgilKeyPair jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native long VirgilKeyPair_generateFrom__SWIG_1(long jarg1, VirgilKeyPair jarg1_, byte[] jarg2);

	public final static native long VirgilKeyPair_generateFrom__SWIG_2(long jarg1, VirgilKeyPair jarg1_);

	public final static native boolean VirgilKeyPair_isKeyPairMatch__SWIG_0(byte[] jarg1, byte[] jarg2, byte[] jarg3);

	public final static native boolean VirgilKeyPair_isKeyPairMatch__SWIG_1(byte[] jarg1, byte[] jarg2);

	public final static native boolean VirgilKeyPair_checkPrivateKeyPassword(byte[] jarg1, byte[] jarg2);

	public final static native boolean VirgilKeyPair_isPrivateKeyEncrypted(byte[] jarg1);

	public final static native byte[] VirgilKeyPair_resetPrivateKeyPassword(byte[] jarg1, byte[] jarg2, byte[] jarg3);

	public final static native byte[] VirgilKeyPair_encryptPrivateKey(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_decryptPrivateKey(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_extractPublicKey(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_publicKeyToPEM(byte[] jarg1);

	public final static native byte[] VirgilKeyPair_publicKeyToDER(byte[] jarg1);

	public final static native byte[] VirgilKeyPair_privateKeyToPEM__SWIG_0(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_privateKeyToPEM__SWIG_1(byte[] jarg1);

	public final static native byte[] VirgilKeyPair_privateKeyToDER__SWIG_0(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_privateKeyToDER__SWIG_1(byte[] jarg1);

	public final static native long new_VirgilKeyPair__SWIG_0(byte[] jarg1, byte[] jarg2);

	public final static native byte[] VirgilKeyPair_publicKey(long jarg1, VirgilKeyPair jarg1_);

	public final static native byte[] VirgilKeyPair_privateKey(long jarg1, VirgilKeyPair jarg1_);

	public final static native long new_VirgilKeyPair__SWIG_1(long jarg1, VirgilKeyPair jarg1_);

	public final static native void delete_VirgilKeyPair(long jarg1);

	public final static native long new_VirgilCipherBase();

	public final static native void VirgilCipherBase_addKeyRecipient(long jarg1, VirgilCipherBase jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native void VirgilCipherBase_removeKeyRecipient(long jarg1, VirgilCipherBase jarg1_,
			byte[] jarg2);

	public final static native boolean VirgilCipherBase_keyRecipientExists(long jarg1, VirgilCipherBase jarg1_,
			byte[] jarg2);

	public final static native void VirgilCipherBase_addPasswordRecipient(long jarg1, VirgilCipherBase jarg1_,
			byte[] jarg2);

	public final static native void VirgilCipherBase_removePasswordRecipient(long jarg1, VirgilCipherBase jarg1_,
			byte[] jarg2);

	public final static native boolean VirgilCipherBase_passwordRecipientExists(long jarg1, VirgilCipherBase jarg1_,
			byte[] jarg2);

	public final static native void VirgilCipherBase_removeAllRecipients(long jarg1, VirgilCipherBase jarg1_);

	public final static native byte[] VirgilCipherBase_getContentInfo(long jarg1, VirgilCipherBase jarg1_);

	public final static native void VirgilCipherBase_setContentInfo(long jarg1, VirgilCipherBase jarg1_, byte[] jarg2);

	public final static native long VirgilCipherBase_defineContentInfoSize(byte[] jarg1);

	public final static native long VirgilCipherBase_customParams__SWIG_0(long jarg1, VirgilCipherBase jarg1_);

	public final static native byte[] VirgilCipherBase_computeShared__SWIG_0(byte[] jarg1, byte[] jarg2, byte[] jarg3);

	public final static native byte[] VirgilCipherBase_computeShared__SWIG_1(byte[] jarg1, byte[] jarg2);

	public final static native void delete_VirgilCipherBase(long jarg1);

	public final static native byte[] VirgilCipher_encrypt__SWIG_0(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
			boolean jarg3);

	public final static native byte[] VirgilCipher_encrypt__SWIG_1(long jarg1, VirgilCipher jarg1_, byte[] jarg2);

	public final static native byte[] VirgilCipher_decryptWithKey__SWIG_0(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
			byte[] jarg3, byte[] jarg4, byte[] jarg5);

	public final static native byte[] VirgilCipher_decryptWithKey__SWIG_1(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
			byte[] jarg3, byte[] jarg4);

	public final static native byte[] VirgilCipher_decryptWithPassword(long jarg1, VirgilCipher jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native long new_VirgilCipher();

	public final static native void delete_VirgilCipher(long jarg1);

	public final static native long VirgilChunkCipher_kPreferredChunkSize_get();

	public final static native void VirgilChunkCipher_encrypt__SWIG_0(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
			VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4, long jarg5);

	public final static native void VirgilChunkCipher_encrypt__SWIG_1(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
			VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4);

	public final static native void VirgilChunkCipher_encrypt__SWIG_2(long jarg1, VirgilChunkCipher jarg1_, long jarg2,
			VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_);

	public final static native void VirgilChunkCipher_decryptWithKey__SWIG_0(long jarg1, VirgilChunkCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5,
			byte[] jarg6);

	public final static native void VirgilChunkCipher_decryptWithKey__SWIG_1(long jarg1, VirgilChunkCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5);

	public final static native void VirgilChunkCipher_decryptWithPassword(long jarg1, VirgilChunkCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4);

	public final static native long new_VirgilChunkCipher();

	public final static native void delete_VirgilChunkCipher(long jarg1);

	public final static native long new_VirgilSigner__SWIG_0(int jarg1);

	public final static native long new_VirgilSigner__SWIG_1();

	public final static native byte[] VirgilSigner_sign__SWIG_0(long jarg1, VirgilSigner jarg1_, byte[] jarg2,
			byte[] jarg3, byte[] jarg4);

	public final static native byte[] VirgilSigner_sign__SWIG_1(long jarg1, VirgilSigner jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native boolean VirgilSigner_verify(long jarg1, VirgilSigner jarg1_, byte[] jarg2, byte[] jarg3,
			byte[] jarg4);

	public final static native void delete_VirgilSigner(long jarg1);

	public final static native long new_VirgilStreamSigner__SWIG_0(int jarg1);

	public final static native long new_VirgilStreamSigner__SWIG_1();

	public final static native byte[] VirgilStreamSigner_sign__SWIG_0(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
			VirgilDataSource jarg2_, byte[] jarg3, byte[] jarg4);

	public final static native byte[] VirgilStreamSigner_sign__SWIG_1(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
			VirgilDataSource jarg2_, byte[] jarg3);

	public final static native boolean VirgilStreamSigner_verify(long jarg1, VirgilStreamSigner jarg1_, long jarg2,
			VirgilDataSource jarg2_, byte[] jarg3, byte[] jarg4);

	public final static native void delete_VirgilStreamSigner(long jarg1);

	public final static native void VirgilStreamCipher_encrypt__SWIG_0(long jarg1, VirgilStreamCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, boolean jarg4);

	public final static native void VirgilStreamCipher_encrypt__SWIG_1(long jarg1, VirgilStreamCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_);

	public final static native void VirgilStreamCipher_decryptWithKey__SWIG_0(long jarg1, VirgilStreamCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5,
			byte[] jarg6);

	public final static native void VirgilStreamCipher_decryptWithKey__SWIG_1(long jarg1, VirgilStreamCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4, byte[] jarg5);

	public final static native void VirgilStreamCipher_decryptWithPassword(long jarg1, VirgilStreamCipher jarg1_,
			long jarg2, VirgilDataSource jarg2_, long jarg3, VirgilDataSink jarg3_, byte[] jarg4);

	public final static native long new_VirgilStreamCipher();

	public final static native void delete_VirgilStreamCipher(long jarg1);

	public final static native int VirgilTinyCipher_Min_get();

	public final static native int VirgilTinyCipher_Short_SMS_get();

	public final static native int VirgilTinyCipher_Long_SMS_get();

	public final static native long new_VirgilTinyCipher__SWIG_0(long jarg1);

	public final static native long new_VirgilTinyCipher__SWIG_1();

	public final static native void VirgilTinyCipher_reset(long jarg1, VirgilTinyCipher jarg1_);

	public final static native void VirgilTinyCipher_encrypt(long jarg1, VirgilTinyCipher jarg1_, byte[] jarg2,
			byte[] jarg3);

	public final static native void VirgilTinyCipher_encryptAndSign__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2, byte[] jarg3, byte[] jarg4, byte[] jarg5);

	public final static native void VirgilTinyCipher_encryptAndSign__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2, byte[] jarg3, byte[] jarg4);

	public final static native long VirgilTinyCipher_getPackageCount(long jarg1, VirgilTinyCipher jarg1_);

	public final static native byte[] VirgilTinyCipher_getPackage(long jarg1, VirgilTinyCipher jarg1_, long jarg2);

	public final static native void VirgilTinyCipher_addPackage(long jarg1, VirgilTinyCipher jarg1_, byte[] jarg2);

	public final static native boolean VirgilTinyCipher_isPackagesAccumulated(long jarg1, VirgilTinyCipher jarg1_);

	public final static native byte[] VirgilTinyCipher_decrypt__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2, byte[] jarg3);

	public final static native byte[] VirgilTinyCipher_decrypt__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2);

	public final static native byte[] VirgilTinyCipher_verifyAndDecrypt__SWIG_0(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2, byte[] jarg3, byte[] jarg4);

	public final static native byte[] VirgilTinyCipher_verifyAndDecrypt__SWIG_1(long jarg1, VirgilTinyCipher jarg1_,
			byte[] jarg2, byte[] jarg3);

	public final static native void delete_VirgilTinyCipher(long jarg1);

	public final static native byte[] VirgilByteArrayUtils_jsonToBytes(String jarg1);

	public final static native byte[] VirgilByteArrayUtils_stringToBytes(String jarg1);

	public final static native String VirgilByteArrayUtils_bytesToString(byte[] jarg1);

	public final static native byte[] VirgilByteArrayUtils_hexToBytes(String jarg1);

	public final static native String VirgilByteArrayUtils_bytesToHex__SWIG_0(byte[] jarg1, boolean jarg2);

	public final static native String VirgilByteArrayUtils_bytesToHex__SWIG_1(byte[] jarg1);

	public final static native void delete_VirgilByteArrayUtils(long jarg1);

	public final static native long VirgilHash_SWIGUpcast(long jarg1);

	public final static native long VirgilPBKDF_SWIGUpcast(long jarg1);

	public final static native long VirgilCustomParams_SWIGUpcast(long jarg1);

	public final static native long VirgilCipher_SWIGUpcast(long jarg1);

	public final static native long VirgilChunkCipher_SWIGUpcast(long jarg1);

	public final static native long VirgilStreamCipher_SWIGUpcast(long jarg1);

	public static boolean SwigDirector_VirgilDataSource_hasData(VirgilDataSource jself) throws java.io.IOException {
		return jself.hasData();
	}

	public static byte[] SwigDirector_VirgilDataSource_read(VirgilDataSource jself) throws java.io.IOException {
		return jself.read();
	}

	public static boolean SwigDirector_VirgilDataSink_isGood(VirgilDataSink jself) throws java.io.IOException {
		return jself.isGood();
	}

	public static void SwigDirector_VirgilDataSink_write(VirgilDataSink jself, byte[] data) throws java.io.IOException {
		jself.write(data);
	}

	private final static native void swig_module_init();

	static {
		try {
			loadNativeLibrary("virgil_crypto_java");
		} catch (Exception error) {
			System.err.println("Native code library failed to load. \n" + error);
		}
		swig_module_init();
	}

	public static void loadNativeLibrary(String libraryName) throws IOException {

		try {
			System.loadLibrary(libraryName);
			// Library is loaded (Android). We can exit
			return;
		} catch (Throwable e) {
			// Library couldn't be loaded (non-Android). We'll load it later.
		}

		// Build native library name according to current system
		String osName = System.getProperty("os.name").toLowerCase();
		String osArch = System.getProperty("os.arch").toLowerCase();
		String suffix = "";
		StringBuilder resourceName = new StringBuilder();
		for (String os : new String[] { "linux", "windows", "mac os" }) {
			if (osName.startsWith(os)) {
				resourceName.append(os);

				if ("windows".equals(os)) {
					resourceName.append("/").append(osArch);
					suffix = ".dll";
				}

				break;
			}
		}
		resourceName.append("/").append(libraryName);

		InputStream in = virgil_crypto_javaJNI.class.getClassLoader().getResourceAsStream(resourceName.toString());
		if (in == null) {
			throw new FileNotFoundException("Resource '" + resourceName.toString() + "' not found");
		}

		byte[] buffer = new byte[1024];
		int read = -1;
		File temp = File.createTempFile(libraryName, suffix);
		FileOutputStream fos = new FileOutputStream(temp);

		while ((read = in.read(buffer)) != -1) {
			fos.write(buffer, 0, read);
		}
		fos.close();
		in.close();

		System.load(temp.getAbsolutePath());
	}
}
