/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.util;

import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.client.AuthenticationContext;

/**
 * A delegating {@link SaslClient} which establishes a specific {@link AuthenticationContext} for the duration
 * of the authentication process.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @deprecated Use {@link org.wildfly.security.sasl.auth.util.AuthenticationContextSaslClient org.wildfly.security.sasl.auth.util.AuthenticationContextSaslClient} instead.
 */
@Deprecated
public final class AuthenticationContextSaslClient extends AbstractDelegatingSaslClient {

    private AuthenticationContext context;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client
     * @param context the authentication context to use
     */
    public AuthenticationContextSaslClient(final SaslClient delegate, final AuthenticationContext context) {
        super(delegate);
        this.context = context;
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client
     */
    public AuthenticationContextSaslClient(final SaslClient delegate) {
        super(delegate);
        context = AuthenticationContext.captureCurrent();
    }

    public byte[] evaluateChallenge(final byte[] challenge) throws SaslException {
        return context.runExBiFunction(SaslClient::evaluateChallenge, delegate, challenge);
    }

    public void dispose() throws SaslException {
        try {
            super.dispose();
        } finally {
            context = null;
        }
    }
}
