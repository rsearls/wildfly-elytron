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

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.client.AuthenticationContext;

/**
 * A delegating {@link SaslServerFactory} which establishes a specific {@link AuthenticationContext} for the duration
 * of the authentication process.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @deprecated Use {@link org.wildfly.security.sasl.auth.util.AuthenticationContextSaslServerFactory org.wildfly.security.sasl.auth.util.AuthenticationContextSaslServerFactory} instead.
 */
@Deprecated
public final class AuthenticationContextSaslServerFactory extends AbstractDelegatingSaslServerFactory {
    private final AuthenticationContext context;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     */
    public AuthenticationContextSaslServerFactory(final SaslServerFactory delegate) {
        super(delegate);
        context = AuthenticationContext.captureCurrent();
    }

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param context the authentication context to use
     */
    public AuthenticationContextSaslServerFactory(final SaslServerFactory delegate, final AuthenticationContext context) {
        super(delegate);
        this.context = context;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final SaslServer delegate = super.createSaslServer(mechanism, protocol, serverName, props, cbh);
        if (delegate == null) {
            return null;
        }
        return new AuthenticationContextSaslServer(delegate, context);
    }
}
