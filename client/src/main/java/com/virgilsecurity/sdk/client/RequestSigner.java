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
package com.virgilsecurity.sdk.client;

import com.virgilsecurity.sdk.client.requests.SignedRequest;
import com.virgilsecurity.sdk.client.utils.ConvertionUtils;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.PrivateKey;

/**
 * This class used for request signing.
 *
 * @author Andrii Iakovenko
 *
 */
public class RequestSigner {

	private final Crypto crypto;

	/**
	 * Create a new instance of {@code RequestSigner}
	 *
	 * @param crypto
	 */
	public RequestSigner(Crypto crypto) {
		this.crypto = crypto;
	}

	/**
	 * Sign request with a key.
	 * 
	 * @param request
	 *            the request to be signed.
	 * @param privateKey
	 *            the private key.
	 */
	public void selfSign(SignedRequest request, PrivateKey privateKey) {
		Fingerprint fingerprint = this.crypto
				.calculateFingerprint(ConvertionUtils.base64ToArray(request.getSnapshot()));
		byte[] signature = this.crypto.sign(fingerprint.getValue(), privateKey);

		request.appendSignature(fingerprint.toHex(), ConvertionUtils.toBase64String(signature));
	}

	/**
	 * Sign request with authority key.
	 * 
	 * @param request
	 *            the request to be signed.
	 * @param appdId
	 *            the application id.
	 * @param appKey
	 *            the application key.
	 */
	public void authoritySign(SignedRequest request, String appdId, PrivateKey appKey) {
		Fingerprint fingerprint = this.crypto
				.calculateFingerprint(ConvertionUtils.base64ToArray(request.getSnapshot()));
		byte[] signature = this.crypto.sign(fingerprint.getValue(), appKey);

		request.appendSignature(appdId, ConvertionUtils.toBase64String(signature));
	}

}
