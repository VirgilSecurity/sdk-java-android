/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.common.model

import com.virgilsecurity.common.callback.OnCompleteListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * Completable's class intent is to give possibility to call a completable operation that got only Success or Error
 * without actual result *synchronously* or *asynchronously*.
 */
interface Completable {

    /**
     * Call this method to complete operation *synchronously*.
     */
    fun execute()

    /**
     * Call this method to complete operation *asynchronously*. You'll get the completion status in the
     * [onCompleteListener]. Provided [scope] will be used to execute operation.
     */
    fun addCallback(onCompleteListener: OnCompleteListener, scope: CoroutineScope = GlobalScope) {
        scope.launch {
            try {
                execute()
                onCompleteListener.onSuccess()
            } catch (throwable: Throwable) {
                onCompleteListener.onError(throwable)
            }
        }
    }

    /**
     * Call this method to complete operation *asynchronously*. You'll get the completion status in the
     * [onCompleteListener].
     */
    fun addCallback(onCompleteListener: OnCompleteListener) =
            addCallback(onCompleteListener, GlobalScope)

}