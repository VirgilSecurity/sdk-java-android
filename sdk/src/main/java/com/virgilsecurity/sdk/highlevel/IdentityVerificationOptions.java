/*
 * Copyright (c) 2017, Virgil Security, Inc.
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
package com.virgilsecurity.sdk.highlevel;

import java.util.Map;

/**
 * This class provides additional options for verification {@link VirgilCard}'s identity.
 * 
 * @author Andrii Iakovenko
 *
 */
public class IdentityVerificationOptions {

    private Map<String, String> extraFields;

    private long timeToLive;

    private long countToLive;

    /**
     * Gets a key/value dictionary that represents a user fields. In some cases it could be necessary to pass some
     * parameters to verification server and receive them back in an email. For this special case an optional extra
     * fields dictionary property can be used. If type of an identity is email, all values passed in extra fields will
     * be passed back in an email in a hidden form with extra hidden fields.
     * 
     * @return the extraFields
     */
    public Map<String, String> getExtraFields() {
        return extraFields;
    }

    /**
     * Sets a key/value dictionary that represents a user fields.
     * 
     * @param extraFields
     *            the extraFields to set
     */
    public void setExtraFields(Map<String, String> extraFields) {
        this.extraFields = extraFields;
    }

    /**
     * Gets the "time to live" value is used to limit the lifetime of the token in seconds.
     * 
     * @return the timeToLive
     */
    public long getTimeToLive() {
        return timeToLive;
    }

    /**
     * Sets the "time to live" value is used to limit the lifetime of the token in seconds (maximum value is 60 * 60 *
     * 24 * 365 = 1 year). Default time to live value is 3600.
     * 
     * @param timeToLive
     *            the timeToLive to set
     */
    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    /**
     * Gets the "count to live" parameter is used to restrict the number of validation token usages.
     * 
     * @return the countToLive
     */
    public long getCountToLive() {
        return countToLive;
    }

    /**
     * Sets the "count to live" parameter is used to restrict the number of validation token usages (maximum value is
     * 100).
     * 
     * @param countToLive
     *            the countToLive to set
     */
    public void setCountToLive(long countToLive) {
        this.countToLive = countToLive;
    }

}
