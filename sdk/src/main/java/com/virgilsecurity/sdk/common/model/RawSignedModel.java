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
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

package com.virgilsecurity.sdk.common.model;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

public class RawSignedModel implements Serializable {

    @SerializedName("content_snapshot")
    private byte[] contentSnapshot;

    @SerializedName("signatures")
    private List<RawSignature> signatures;

    public RawSignedModel(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;
    }

    public RawSignedModel(byte[] contentSnapshot,
                          List<RawSignature> signatures) {
        this.contentSnapshot = contentSnapshot;
        this.signatures = signatures;
    }

    public byte[] getContentSnapshot() {
        return contentSnapshot;
    }

    public void setContentSnapshot(byte[] contentSnapshot) {
        this.contentSnapshot = contentSnapshot;
    }

    public List<RawSignature> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<RawSignature> signatures) {
        this.signatures = signatures;
    }

    public String exportAsString() {
        String result = null;

        try {
            result = ConvertionUtils.toBase64String(ConvertionUtils.serializeObject(this));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    public String exportAsJson() {
        String result = null;

        try {
            result = ConvertionUtils.serializeObject(this);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    public void rawSignedModel(String model) {

    }

    public void rawSignedModel(Map<String, String> model) {

    }
}
