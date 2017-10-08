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
package com.virgilsecurity.sdk.client.requests;

import com.virgilsecurity.sdk.client.model.RevocationReason;
import com.virgilsecurity.sdk.client.model.RevokeCardSnapshotModel;

/**
 * Represents an information about revoking card request.
 * 
 * @author Andrii Iakovenko
 *
 */
public class RevokeGlobalCardRequest extends SignedRequest<RevokeCardSnapshotModel> {

    /**
     * Create new instance of {@link RevokeGlobalCardRequest}.
     * 
     * @param stringifiedRequest
     *            The stringified request.
     */
    public RevokeGlobalCardRequest(String stringifiedRequest) {
        super(stringifiedRequest);
    }

    /**
     * Create new instance of {@link RevokeGlobalCardRequest}.
     * 
     * @param cardId
     *            The card ID to be revoked.
     * @param reason
     *            The revocation reason.
     * @param validationToken
     *            The validation token.
     */
    public RevokeGlobalCardRequest(String cardId, RevocationReason reason, String validationToken) {
        RevokeCardSnapshotModel snapshotModel = new RevokeCardSnapshotModel();
        snapshotModel.setCardId(cardId);
        snapshotModel.setReason(reason);

        init(snapshotModel);

        this.validationToken = validationToken;
    }

}
