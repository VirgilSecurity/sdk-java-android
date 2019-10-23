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

package com.virgilsecurity.sdk.androidutils.storage;

import com.google.gson.annotations.SerializedName;
import com.virgilsecurity.sdk.storage.KeyEntry;

import java.util.HashMap;
import java.util.Map;

/**
 * AndroidKeyEntry class.
 */
public class AndroidKeyEntry implements KeyEntry {

    private transient String name;

    @SerializedName("value")
    private byte[] value;

    @SerializedName("meta_data")
    private Map<String, String> meta;

    /**
     * Create a new instance of {@code VirgilKeyEntry}.
     *
     */
    public AndroidKeyEntry() {
        meta = new HashMap<>();
    }

    /**
     * Create a new instance of {@code VirgilKeyEntry}.
     *
     * @param name
     *          The key name.
     * @param value
     *          The key value.
     */
    public AndroidKeyEntry(String name, byte[] value) {
        this();
        this.name = name;
        this.value = value;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.KeyEntry#getMeta()
     */
    @Override
    public Map<String, String> getMeta() {
        return meta;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.KeyEntry#getName()
     */
    @Override
    public String getName() {
        return name;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#getValue()
     */
    @Override
    public byte[] getValue() {
        return value;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#setMeta(java.util.Map)
     */
    @Override
    public void setMeta(Map<String, String> meta) {
        this.meta = meta;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.crypto.KeyEntry#setName(java.lang.String)
     */
    @Override
    public void setName(String name) {
        this.name = name;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.virgilsecurity.sdk.storage.KeyEntry#setValue(byte[])
     */
    @Override
    public void setValue(byte[] value) {
        this.value = value;
    }
}
