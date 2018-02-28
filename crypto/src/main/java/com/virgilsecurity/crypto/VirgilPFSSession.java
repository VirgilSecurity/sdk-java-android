/*******************************************************************************
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
 *******************************************************************************/
package com.virgilsecurity.crypto;

public class VirgilPFSSession implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilPFSSession obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilPFSSession() {
        this(virgil_crypto_javaJNI.new_VirgilPFSSession__SWIG_0(), true);
    }

    public VirgilPFSSession(byte[] identifier, byte[] encryptionSecretKey, byte[] decryptionSecretKey,
            byte[] additionalData) {
        this(virgil_crypto_javaJNI.new_VirgilPFSSession__SWIG_1(identifier, encryptionSecretKey, decryptionSecretKey,
                additionalData), true);
    }

    protected VirgilPFSSession(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilPFSSession(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public byte[] getAdditionalData() {
        return virgil_crypto_javaJNI.VirgilPFSSession_getAdditionalData(swigCPtr, this);
    }

    public byte[] getDecryptionSecretKey() {
        return virgil_crypto_javaJNI.VirgilPFSSession_getDecryptionSecretKey(swigCPtr, this);
    }

    public byte[] getEncryptionSecretKey() {
        return virgil_crypto_javaJNI.VirgilPFSSession_getEncryptionSecretKey(swigCPtr, this);
    }

    public byte[] getIdentifier() {
        return virgil_crypto_javaJNI.VirgilPFSSession_getIdentifier(swigCPtr, this);
    }

    public boolean isEmpty() {
        return virgil_crypto_javaJNI.VirgilPFSSession_isEmpty(swigCPtr, this);
    }

    protected void finalize() {
        delete();
    }

}
