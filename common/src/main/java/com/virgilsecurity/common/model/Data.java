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

package com.virgilsecurity.common.model;

import com.virgilsecurity.crypto.foundation.Base64;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Data class that represents binary data with convenient transformations to/from Base64 string.
 */
public class Data {

    private byte[] data;

    /**
     * // TODO add descriptions
     *
     * @param data
     */
    public Data(byte[] data) {
        this.data = data;
    }

    /**
     *
     * @param base64
     * @return
     */
    public static Data fromBase64String(String base64) {
        return new Data(Base64.decode(base64.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     *
     * @param base64
     * @param charset
     * @return
     */
    public static Data fromBase64String(String base64, Charset charset) {
        return new Data(Base64.decode(base64.getBytes(charset)));
    }

    /**
     *
     * @return
     */
    public String toBase64String() {
        return new String(Base64.encode(data), StandardCharsets.UTF_8);
    }

    /**
     *
     * @param charset
     * @return
     */
    public String toBase64String(Charset charset) {
        return new String(Base64.encode(data), charset);
    }

    /**
     *
     * @return
     */
    public byte[] getData() {
        return data;
    }
}
