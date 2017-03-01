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

/**
 * This class provides high-level interface to encrypt / decrypt data using Virgil Security keys.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCipher extends VirgilCipherBase implements java.lang.AutoCloseable {
    private transient long swigCPtr;

    protected VirgilCipher(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilCipher_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    protected static long getCPtr(VirgilCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    protected void finalize() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    @Override
    public void close() {
        delete();
    }

    /**
     * Encrypt given data.
     * 
     * @param data
     *            Data to be encrypted.
     * @param embedContentInfo
     *            Determines whether to embed content info the the encrypted data, or not.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] data, boolean embedContentInfo) {
        return virgil_crypto_javaJNI.VirgilCipher_encrypt__SWIG_0(swigCPtr, this, data, embedContentInfo);
    }

    /**
     * Encrypt given data.
     * 
     * @param data
     *            Data to be encrypted.
     * @return Encrypted data.
     */
    public byte[] encrypt(byte[] data) {
        return virgil_crypto_javaJNI.VirgilCipher_encrypt__SWIG_1(swigCPtr, this, data);
    }

    /**
     * Decrypt given data for recipient defined by id and private key.
     * 
     * @param encryptedData
     *            Data to be decrypted.
     * @param recipientId
     *            The recipient identifier.
     * @param privateKey
     *            Recipient's private key protected with password.
     * @param privateKeyPassword
     *            The private key password.
     * @return Decrypted data.
     */
    public byte[] decryptWithKey(byte[] encryptedData, byte[] recipientId, byte[] privateKey,
            byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilCipher_decryptWithKey__SWIG_0(swigCPtr, this, encryptedData, recipientId,
                privateKey, privateKeyPassword);
    }

    /**
     * Decrypt given data for recipient defined by id and private key.
     * 
     * @param encryptedData
     *            Data to be decrypted.
     * @param recipientId
     *            The recipient identifier.
     * @param privateKey
     *            Recipient's private key.
     * @return Decrypted data.
     */
    public byte[] decryptWithKey(byte[] encryptedData, byte[] recipientId, byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilCipher_decryptWithKey__SWIG_1(swigCPtr, this, encryptedData, recipientId,
                privateKey);
    }

    /**
     * Decrypt given data for recipient defined by password.
     * 
     * @param encryptedData
     *            Data to be decrypted.
     * @param pwd
     *            The password.
     * @return Decrypted data.
     */
    public byte[] decryptWithPassword(byte[] encryptedData, byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilCipher_decryptWithPassword(swigCPtr, this, encryptedData, pwd);
    }

    /**
     * Create a new instance of {@code VirgilCipher}
     *
     */
    public VirgilCipher() {
        this(virgil_crypto_javaJNI.new_VirgilCipher(), true);
    }

}
