/*******************************************************************************
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 ******************************************************************************/

package org.eclipse.tractusx.bpdm.common.config

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import mu.withLoggingContext
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.core.task.TaskDecorator
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.*

@Component
class UserLoggingFilter(
    private val logConfigProperties: LogConfigProperties
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(UserLoggingFilter::class.java)

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val userName = request.userPrincipal?.name ?: logConfigProperties.unknownUser
        // Sanitize user-controlled values inline to prevent log injection (CWE-117).
        // Stripping control characters that could forge log entries.
        val sanitizedUserName = userName.replace("\r", "_").replace("\n", "_").replace("\t", "_")
        val sanitizedRequest = request.requestURI.replace("\r", "_").replace("\n", "_").replace("\t", "_")
        val sanitizedMethod = request.method.replace("\r", "_").replace("\n", "_").replace("\t", "_")

        withLoggingContext(
            "user" to sanitizedUserName,
        ) {
            log.info("User '{}' requests {} {}...", sanitizedUserName, sanitizedMethod, sanitizedRequest)
            filterChain.doFilter(request, response)
            log.info("Response with status {}", response.status)
        }
    }
}

@Component
class RequestLoggingFilter : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val requestId = UUID.randomUUID().toString()

        withLoggingContext(
            "request" to requestId
        ) {
            filterChain.doFilter(request, response)
        }
    }
}

/**
 * Util class for copying the Mapped Diagnostic Context from an invoking thread to the invoked thread
 */
@Component
class MdcTaskDecorator : TaskDecorator {

    private val emptyContext = HashMap<String, String>()

    override fun decorate(runnable: Runnable): Runnable {
        val mdcCopy = MDC.getCopyOfContextMap() ?: emptyContext

        return Runnable {
            withLoggingContext(mdcCopy) {
                runnable.run()
            }
        }
    }
}