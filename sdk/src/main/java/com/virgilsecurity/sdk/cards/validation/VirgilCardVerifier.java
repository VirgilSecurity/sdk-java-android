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

package com.virgilsecurity.sdk.cards.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardSignature;
import com.virgilsecurity.sdk.cards.SignerType;
import com.virgilsecurity.sdk.crypto.CardCrypto;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Validator;

/**
 * The {@link VirgilCardVerifier} is used to verify cards.
 */
public class VirgilCardVerifier implements CardVerifier {
    private static final Logger LOGGER = Logger.getLogger(VirgilCardVerifier.class.getName());

    private String virgilPublicKeyBase64 = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg=";

    private CardCrypto cardCrypto;
    private boolean verifySelfSignature;
    private boolean verifyVirgilSignature;
    private List<WhiteList> whiteLists;

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *            the crypto
     */
    public VirgilCardVerifier(CardCrypto cardCrypto) {
        this(cardCrypto, new ArrayList<WhiteList>());
    }

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *            the card crypto
     * @param whiteLists
     *            the white lists that should contain Card signatures, otherwise Card validation will be failed
     */
    public VirgilCardVerifier(CardCrypto cardCrypto, List<WhiteList> whiteLists) {
        this(cardCrypto, true, true, whiteLists);
    }

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *            the card crypto
     * @param verifySelfSignature
     *            whether the self signature should be verified
     * @param verifyVirgilSignature
     *            whether the virgil signature should be verified
     */
    public VirgilCardVerifier(CardCrypto cardCrypto, boolean verifySelfSignature, boolean verifyVirgilSignature) {
        this(cardCrypto, verifySelfSignature, verifyVirgilSignature, new ArrayList<WhiteList>());
    }

    /**
     * Instantiates a new Virgil card verifier.
     *
     * @param cardCrypto
     *            the card crypto
     * @param verifySelfSignature
     *            whether the self signature should be verified
     * @param verifyVirgilSignature
     *            whether the virgil signature should be verified
     * @param whiteLists
     *            the white lists that should contain Card signatures, otherwise Card validation will be failed
     */
    public VirgilCardVerifier(CardCrypto cardCrypto, boolean verifySelfSignature, boolean verifyVirgilSignature,
            List<WhiteList> whiteLists) {
        Validator.checkNullAgrument(cardCrypto, "VirgilCardVerifier -> 'cardCrypto' should not be null");
        Validator.checkNullAgrument(whiteLists, "VirgilCardVerifier -> 'whiteLists' should not be null");

        this.cardCrypto = cardCrypto;
        this.whiteLists = whiteLists;
        this.verifySelfSignature = verifySelfSignature;
        this.verifyVirgilSignature = verifyVirgilSignature;
    }

    @Override
    public boolean verifyCard(Card card) throws CryptoException {
        if (verifySelfSignature && !verify(card, SignerType.SELF.getRawValue(), card.getPublicKey())) {
            LOGGER.info(String.format("Card '%s' self signature validation failed", card.getIdentifier()));
            return false;
        }

        if (verifyVirgilSignature) {
            byte[] publicKeyData = ConvertionUtils.base64ToBytes(virgilPublicKeyBase64);
            PublicKey publicKey = cardCrypto.importPublicKey(publicKeyData);

            if (!verify(card, SignerType.VIRGIL.getRawValue(), publicKey)) {
                LOGGER.info(String.format("Card '%s' Virgil signature validation failed", card.getIdentifier()));
                return false;
            }
        }

        boolean containsSignature = false;
        for (WhiteList whiteList : whiteLists) {
            // if whitelist doesn't have credentials then
            // this is to be regarded as a violation of the policy.
            if (whiteList.getVerifiersCredentials().isEmpty()) {
                LOGGER.warning("Whitelist doesn't have credentials then");
                return false;
            }
            for (VerifierCredentials verifierCredentials : whiteList.getVerifiersCredentials()) {
                for (CardSignature cardSignature : card.getSignatures()) {
                    if (Objects.equals(cardSignature.getSigner(), verifierCredentials.getSigner())) {
                        PublicKey publicKey = cardCrypto.importPublicKey(verifierCredentials.getPublicKey());
                        containsSignature = true;
                        String signer = cardSignature.getSigner();
                        if (!verify(card, signer, publicKey)) {
                            LOGGER.info(String.format("Card '%s' signer is '%s'. Signature validation failed",
                                    card.getIdentifier(), signer));
                            return false;
                        }
                    }
                }
            }
        }

        // if card doesn't contain signature from AT LEAST one verifier from a WhiteList then
        // this is to be regarded as a violation of the policy (at least one).
        if (!whiteLists.isEmpty() && !containsSignature) {
            LOGGER.info(String.format("The card '%s' does not contain signature from specified Whitelist",
                    card.getIdentifier()));
            return false;
        }

        return true;
    }

    /**
     * Verifies provided Card.
     *
     * @param card
     *            the card
     * @param signer
     *            the signer
     * @param signerPublicKey
     *            the signer's public key
     * @return {@code true} if Card is valid, otherwise {@code false}
     */
    private boolean verify(Card card, String signer, PublicKey signerPublicKey) {
        CardSignature cardSignature = null;
        for (CardSignature signature : card.getSignatures()) {
            if (Objects.equals(signature.getSigner(), signer)) {
                cardSignature = signature;
                break;
            }
        }

        if (cardSignature == null) {
            LOGGER.fine(String.format("The card %s does not contain the %s signature", card.getIdentifier(), signer));
            return false;
        }

        byte[] extendedSnapshot;
        if (cardSignature.getSnapshot() != null) {
            extendedSnapshot = ConvertionUtils.concatenate(card.getContentSnapshot(), cardSignature.getSnapshot());
        } else {
            extendedSnapshot = card.getContentSnapshot();
        }

        try {
            if (!cardCrypto.verifySignature(cardSignature.getSignature(), extendedSnapshot, signerPublicKey)) {
                LOGGER.fine(String.format("The card %s verification failed", card.getIdentifier()));
                return false;
            }
        } catch (CryptoException e) {
            LOGGER.log(Level.SEVERE, "Signature verification failed", e);
            return false;
        }

        return true;
    }

    /**
     * Gets card crypto.
     *
     * @return the card crypto
     */
    public CardCrypto getCardCrypto() {
        return cardCrypto;
    }

    /**
     * Gets whether the self signature verification should be verified.
     *
     * @return {@code true} if the self signature verification should be verified, otherwise {@code false}
     */
    public boolean isVerifySelfSignature() {
        return verifySelfSignature;
    }

    /**
     * Sets whether the self signature verification should be verified.
     *
     * @param verifySelfSignature
     *            {@code true} if the self signature verification should be verified, otherwise {@code false}
     */
    public void setVerifySelfSignature(boolean verifySelfSignature) {
        this.verifySelfSignature = verifySelfSignature;
    }

    /**
     * Gets whether the virgil signature verification should be verified.
     *
     * @return {@code true} if the virgil signature verification should be verified, otherwise {@code false}
     */
    public boolean isVerifyVirgilSignature() {
        return verifyVirgilSignature;
    }

    /**
     * Sets whether the virgil signature verification should be verified.
     *
     * @param verifyVirgilSignature
     *            {@code true} if the virgil signature verification should be verified, otherwise {@code false}
     */
    public void setVerifyVirgilSignature(boolean verifyVirgilSignature) {
        this.verifyVirgilSignature = verifyVirgilSignature;
    }

    /**
     * Gets white list.
     *
     * @return the white list
     */
    public List<WhiteList> getWhiteLists() {
        return whiteLists;
    }

    /**
     * Sets white lists.
     *
     * @param whiteLists
     *            the white lists
     */
    public void setWhiteLists(List<WhiteList> whiteLists) {
        this.whiteLists = whiteLists;
    }

    /**
     * Sets white lists.
     *
     * @param whiteList
     *            the white lists
     */
    public void addWhiteList(WhiteList whiteList) {
        this.whiteLists.add(whiteList);
    }

    public void setServiceKey(String publicKeyBase64) {
        this.virgilPublicKeyBase64 = publicKeyBase64;
    }

}
