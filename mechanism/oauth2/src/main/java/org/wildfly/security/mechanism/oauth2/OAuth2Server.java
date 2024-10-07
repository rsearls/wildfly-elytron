/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism.oauth2;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;

import java.io.IOException;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.BearerTokenCredential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

/**
 * An OAuth2 Server based on RFC-7628.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OAuth2Server {

    public static final String CONFIG_OPENID_CONFIGURATION_URL = "openid-configuration";
    private static final String KV_DELIMITER = "%x01";

    private final CallbackHandler callbackHandler;
    private final Map<String, ?> serverConfig;
    private ElytronMessages log;

    /**
     * Constructs a new {@code OAuth2Server} instance.
     *
     * @param callbackHandler the callback handler for verifying the Bearer token.
     * @param serverConfig the server configuration.
     * @param log the logger to use.
     */
    public OAuth2Server(CallbackHandler callbackHandler, Map<String, ?> serverConfig, ElytronMessages log) {
        this.callbackHandler = callbackHandler;
        this.serverConfig = serverConfig;
        this.log = log;
    }

    /**
     * Parses the initial client's message in OAuth2 protocol.
     *
     * @param fromBytes the initial client's message.
     * @return parsed client's message.
     * @throws AuthenticationMechanismException if an error occurs during the parsing or the message is invalid.
     */
    public OAuth2InitialClientMessage parseInitialClientMessage(byte[] fromBytes) throws AuthenticationMechanismException {
        byte[] messageBytes = fromBytes.clone();
        ByteIterator byteIterator = ByteIterator.ofBytes(fromBytes.clone());

        try {
            final char cbindFlag = (char) byteIterator.next();

            if (cbindFlag != 'n') {
                throw log.mechChannelBindingNotSupported();
            }

            String authorizationID = null;

            if (byteIterator.next() == ',') {
                final int c = byteIterator.next();

                if (c == 'a') {
                    if (byteIterator.next() != '=') {
                        throw log.mechInvalidClientMessage();
                    }
                    authorizationID = byteIterator.delimitedBy(',').asUtf8String().drainToString();
                    if (byteIterator.next() != ',') {
                        throw ElytronMessages.log.mechInvalidClientMessage();
                    }
                }
            }

            String auth = getValue("auth", byteIterator.asUtf8String().drainToString());

            if (auth == null) {
                throw log.mechInvalidClientMessage();
            }

            return new OAuth2InitialClientMessage(authorizationID, auth, messageBytes);
        } catch (NoSuchElementException ignored) {
            throw ElytronMessages.log.mechInvalidMessageReceived();
        }
    }

    /**
     * Returns the value associated with a key from an OAuth2 message.
     *
     * @param key the key for which the value is extracted.
     * @param keyValuesPart the String containing key-value pairs in form of OAuth2 message.
     * @return the value of the key-value pair, {@code null} if the key is not found.
     */
    private String getValue(String key, String keyValuesPart) {
        for (String current : keyValuesPart.split(KV_DELIMITER)) {
            String[] keyValue = current.split("=");

            if (keyValue[0].equals(key)) {
                return keyValue[1];
            }
        }

        return null;
    }

    /**
     * Evaluates the initial response sent by the client and verifies if the Bearer token is valid.
     * If so, authorizes the user.
     *
     * @param initialClientMessage the initial client's message containing the Bearer token.
     * @return an empty byte array if the token was authorized, error message otherwise.
     * @throws AuthenticationMechanismException if an error occurs during the evaluation or the message doesn't contain the Bearer token.
     */
    public byte[] evaluateInitialResponse(OAuth2InitialClientMessage initialClientMessage) throws AuthenticationMechanismException {
        if (initialClientMessage.isBearerToken()) {
            String auth = initialClientMessage.getAuth();
            String token = auth.substring(auth.indexOf(" ") + 1);
            BearerTokenEvidence evidence = new BearerTokenEvidence(token);
            EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

            try {
                MechanismUtil.handleCallbacks(log, this.callbackHandler, evidenceVerifyCallback);
            } catch (UnsupportedCallbackException e) {
                throw log.mechAuthorizationUnsupported(e);
            }

            // successful verification, token is supposed to be valid and just respond with an empty message
            if (evidenceVerifyCallback.isVerified()) {
                AuthorizeCallback authorizeCallback = new AuthorizeCallback(null, null);

                try {
                    MechanismUtil.handleCallbacks(log, this.callbackHandler, authorizeCallback);
                } catch (UnsupportedCallbackException e) {
                    throw log.mechAuthorizationUnsupported(e);
                }

                if (authorizeCallback.isAuthorized()) {
                    try {
                        callbackHandler.handle(new Callback[]{new IdentityCredentialCallback(new BearerTokenCredential(evidence.getToken()), true)});
                    } catch (UnsupportedCallbackException ignore) {
                        // ignored
                    } catch (AuthenticationMechanismException e) {
                        throw e;
                    } catch (IOException e) {
                        throw log.mechServerSideAuthenticationFailed(e);
                    }
                    return new byte[0];
                }
            }

            return createErrorMessage();
        }

        throw log.mechInvalidClientMessage();
    }

    /**
     * Creates an error message in the format of a json object.
     *
     * @return The error message containing a "status" field with the value "invalid_token"
     * and an optional field "openid-configuration" with {@code CONFIG_OPENID_CONFIGURATION_URL} value.
     */
    private byte[] createErrorMessage() {
        JsonObjectBuilder objectBuilder = Json.createObjectBuilder();

        objectBuilder.add("status", "invalid_token");

        Object asDiscoveryUrl = serverConfig.get(CONFIG_OPENID_CONFIGURATION_URL);

        if (asDiscoveryUrl != null) {
            objectBuilder.add(CONFIG_OPENID_CONFIGURATION_URL, asDiscoveryUrl.toString());
        }

        return ByteIterator.ofBytes(objectBuilder.build().toString().getBytes()).base64Encode().asUtf8().drain();
    }
}
