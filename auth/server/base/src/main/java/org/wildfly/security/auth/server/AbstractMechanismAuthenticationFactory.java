/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.function.UnaryOperator;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;

public abstract class AbstractMechanismAuthenticationFactory<M, F, E extends Exception> implements MechanismAuthenticationFactory<M, F, E> {

    private final SecurityDomain securityDomain;
    private final MechanismConfigurationSelector mechanismConfigurationSelector;
    private final F factory;

    protected AbstractMechanismAuthenticationFactory(final SecurityDomain securityDomain, final MechanismConfigurationSelector mechanismConfigurationSelector, final F factory) {
        this.securityDomain = securityDomain;
        this.mechanismConfigurationSelector = mechanismConfigurationSelector;
        this.factory = factory;
    }

    public MechanismConfigurationSelector getMechanismConfigurationSelector() {
        return mechanismConfigurationSelector;
    }

    public SecurityDomain getSecurityDomain() {
        return securityDomain;
    }

    public F getFactory() {
        return factory;
    }

    public M createMechanism(final String name, final UnaryOperator<F> factoryTransformation) throws E {
        return doCreate(name, new ServerAuthenticationContext(securityDomain, mechanismConfigurationSelector).createCallbackHandler(), factoryTransformation);
    }

    protected abstract M doCreate(String name, CallbackHandler callbackHandler, final UnaryOperator<F> factoryTransformation) throws E;

    protected abstract Collection<Class<? extends Evidence>> getSupportedEvidenceTypes(String mechName);

    protected abstract Collection<String> getSupportedEvidenceAlgorithmNames(Class<? extends AlgorithmEvidence> evidenceType, String mechName);

    protected abstract Collection<Class<? extends Credential>> getSupportedCredentialTypes(String mechName);

    protected abstract Collection<String> getSupportedCredentialAlgorithmNames(Class<? extends AlgorithmCredential> credentialType, String mechName);

    /**
     * Determine whether the given mechanism name needs credentials from a realm in order to authenticate.
     *
     * @param mechName the mechanism name
     * @return {@code true} if the mechanism requires realm credential support, {@code false} if it does not
     */
    protected abstract boolean usesCredentials(String mechName);

    /**
     * Determine whether the given mechanism name is known to WildFly Elytron.
     *
     * If it is not known we can't filter it out as we can not rely upon the other methods being able to
     * return accurate responses about the mechanisms requirements.
     *
     * As this is a new method and other implementations may not know to override this has a default
     * implementation to match the current behaviour i.e. assume we know about all mechanisms.
     *
     * @param mechName the mechanism name
     * @return {@code true} if the mechanism is known to WildFly Elytron, {@code false} if it is not
     */
    protected boolean isKnownMechanism(String mechName) {
        return true;
    };

    public Collection<String> getMechanismNames() {
        final Collection<String> names = new LinkedHashSet<>();
        top: for (String mechName : getAllSupportedMechNames()) {
            // If we don't know about the mech we have to support it as it is likely
            // a custom mechanism so our filtering rules will not be correct.
            if ((! isKnownMechanism(mechName)) ||
                 // if the mech doesn't need credentials, then we support it for sure
                 (! usesCredentials(mechName))) {
                names.add(mechName);
                continue;
            }

            final SecurityDomain securityDomain = this.securityDomain;

            // if the mech supports verification for a type of evidence we have, we support it
            for (Class<? extends Evidence> evidenceType : getSupportedEvidenceTypes(mechName)) {
                if (AlgorithmEvidence.class.isAssignableFrom(evidenceType)) {
                    for (String algorithmName : getSupportedEvidenceAlgorithmNames(evidenceType.asSubclass(AlgorithmEvidence.class), mechName)) {
                        if ("*".equals(algorithmName) && securityDomain.getEvidenceVerifySupport(evidenceType).mayBeSupported() || securityDomain.getEvidenceVerifySupport(evidenceType, algorithmName).mayBeSupported()) {
                            names.add(mechName);
                            continue top;
                        }
                    }
                } else {
                    if (securityDomain.getEvidenceVerifySupport(evidenceType).mayBeSupported()) {
                        names.add(mechName);
                        continue top;
                    }
                }
            }
            // if the mech supports a type of credential we have, we support it
            for (Class<? extends Credential> credentialType : getSupportedCredentialTypes(mechName)) {
                if (AlgorithmCredential.class.isAssignableFrom(credentialType)) {
                    for (String algorithmName : getSupportedCredentialAlgorithmNames(credentialType.asSubclass(AlgorithmCredential.class), mechName)) {
                        if ("*".equals(algorithmName) && securityDomain.getCredentialAcquireSupport(credentialType).mayBeSupported() || securityDomain.getCredentialAcquireSupport(credentialType, algorithmName).mayBeSupported()) {
                            names.add(mechName);
                            continue top;
                        }
                    }
                } else {
                    if (securityDomain.getCredentialAcquireSupport(credentialType).mayBeSupported()) {
                        names.add(mechName);
                        continue top;
                    }
                }
            }
        }
        return names;
    }

    protected abstract Collection<String> getAllSupportedMechNames();

    protected abstract static class Builder<M, F, E extends Exception> implements MechanismAuthenticationFactory.Builder<M, F, E> {
        private SecurityDomain securityDomain;
        private MechanismConfigurationSelector mechanismConfigurationSelector;
        private F factory;

        protected Builder() {
        }

        public Builder<M, F, E> setSecurityDomain(final SecurityDomain securityDomain) {
            Assert.checkNotNullParam("securityDomain", securityDomain);
            this.securityDomain = securityDomain;
            return this;
        }

        public Builder<M, F, E> setMechanismConfigurationSelector(final MechanismConfigurationSelector mechanismConfigurationSelector) {
            this.mechanismConfigurationSelector = mechanismConfigurationSelector;
            return this;
        }

        public Builder<M, F, E> setFactory(final F factory) {
            Assert.checkNotNullParam("factory", factory);
            this.factory = factory;
            return this;
        }

        public SecurityDomain getSecurityDomain() {
            return securityDomain;
        }

        public MechanismConfigurationSelector getMechanismConfigurationSelector() {
            return mechanismConfigurationSelector;
        }

        public F getFactory() {
            return factory;
        }
    }


}
