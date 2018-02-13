/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

import com.virgilsecurity.sdk.crypto.AccessTokenSigner;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.logging.Logger;

/**
 * The {@link JwtVerifier} class is implemented for verification of {@link Jwt}.
 */
public class JwtVerifier {
    private static final Logger LOGGER = Logger.getLogger(JwtVerifier.class.getName());

    private PublicKey apiPublicKey;
    private String apiPublicKeyIdentifier;
    private AccessTokenSigner accessTokenSigner;

    /**
     * Instantiates a new Jwt verifier.
     *
     * @param apiPublicKey
     *            the api public key
     * @param apiPublicKeyIdentifier
     *            the api public key identifier
     * @param accessTokenSigner
     *            the access token signer
     */
    public JwtVerifier(PublicKey apiPublicKey, String apiPublicKeyIdentifier, AccessTokenSigner accessTokenSigner) {
        this.apiPublicKey = apiPublicKey;
        this.apiPublicKeyIdentifier = apiPublicKeyIdentifier;
        this.accessTokenSigner = accessTokenSigner;
    }

    /**
     * Checks whether the token's signature is valid.
     *
     * @param jwtToken
     *            the jwt token
     * @return {@code true} if the token's signature is valid, otherwise {@code false}
     * @throws CryptoException
     *             if issue occurred during token's signature verification
     */
    public boolean verifyToken(Jwt jwtToken) throws CryptoException {
        if (jwtToken == null) {
            throw new NullArgumentException("jwtToken");
        }

        JwtHeaderContent header = jwtToken.getHeaderContent();
        if (!this.apiPublicKeyIdentifier.equals(header.getKeyIdentifier())
                || !this.accessTokenSigner.getAlgorithm().equals(header.getAlgorithm())
                || !JwtHeaderContent.VIRGIL_CONTENT_TYPE.equals(header.getContentType())
                || !JwtHeaderContent.JWT_TYPE.equals(header.getType())) {
            LOGGER.info("Some of next args mismatches in Jwt header and provided data while instantiating JwtVerifier:\n" +
                                "api public key identifier, algorithm, content type, jwt type");
            return false;
        }

        byte[] jwtBytes = ConvertionUtils.toBytes(jwtToken.unsigned());
        return this.accessTokenSigner.verifyTokenSignature(jwtToken.getSignatureData(), jwtBytes, apiPublicKey);
    }
}
