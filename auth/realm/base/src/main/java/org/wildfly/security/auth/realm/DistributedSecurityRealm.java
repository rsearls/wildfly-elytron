/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.realm;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Consumer;

/**
 * A realm for authentication and authorization of identities distributed between multiple realms.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class DistributedSecurityRealm implements SecurityRealm {
    private final boolean ignoreUnavailableRealms;
    private final SecurityRealm[] securityRealms;
    private final Consumer<Integer> unavailableRealmCallback;

    public DistributedSecurityRealm(final SecurityRealm... securityRealms) {
        this(false, null, securityRealms);
    }

    /**
     * Construct a new instance.
     *
     * @param ignoreUnavailableRealms allow to specify that the search should continue on to the next realm if a realm happens to be unavailable
     * @param unavailableRealmCallback a callback that can be used to emit realm unavailability, can be {@code null}
     * @param securityRealms references to one or more security realms for authentication and authorization
     */
    public DistributedSecurityRealm( final boolean ignoreUnavailableRealms, final Consumer<Integer> unavailableRealmCallback, final SecurityRealm... securityRealms) {
        Assert.checkNotNullParam("securityRealms", securityRealms);
        this.ignoreUnavailableRealms = ignoreUnavailableRealms;
        this.unavailableRealmCallback = unavailableRealmCallback;
        this.securityRealms = securityRealms;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Evidence evidence) throws RealmUnavailableException {
        return new EvidenceDistributedIdentity(evidence);
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) throws RealmUnavailableException {
        return new PrincipalDistributedIdentity(principal);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        SupportLevel max = SupportLevel.UNSUPPORTED;
        for (SecurityRealm r : securityRealms) {
            max = SupportLevel.max(max, r.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec));
        }
        return max;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        SupportLevel max = SupportLevel.UNSUPPORTED;
        for (SecurityRealm r : securityRealms) {
            max = SupportLevel.max(max, r.getEvidenceVerifySupport(evidenceType, algorithmName));
        }
        return max;
    }

    final class EvidenceDistributedIdentity implements RealmIdentity {
        private final Evidence evidence;
        private final String evidenceAlgorithm;
        private RealmIdentity currentIdentity = RealmIdentity.NON_EXISTENT;
        private int nextRealm = 0;

        private EvidenceDistributedIdentity(Evidence evidence) throws RealmUnavailableException {
            this.evidence = evidence;
            if (evidence instanceof AlgorithmEvidence) {
                evidenceAlgorithm = ((AlgorithmEvidence) evidence).getAlgorithm();
            } else {
                evidenceAlgorithm = null;
            }
            nextIdentity();
        }

        private boolean nextIdentity() throws RealmUnavailableException {
            currentIdentity.dispose();
            if (nextRealm >= securityRealms.length) {
                currentIdentity = RealmIdentity.NON_EXISTENT;
                return false;
            }
            if (securityRealms[nextRealm].getEvidenceVerifySupport(evidence.getClass(), evidenceAlgorithm).mayBeSupported()) {
                currentIdentity = securityRealms[nextRealm].getRealmIdentity(evidence);
                nextRealm++;
                if (currentIdentity.getEvidenceVerifySupport(evidence.getClass(), evidenceAlgorithm).isNotSupported()) {
                    return nextIdentity();
                }
            } else {
                nextRealm++;
                return nextIdentity();
            }
            return true;
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            return currentIdentity.getRealmIdentityPrincipal();
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            // Identity created from evidence will be verified using the evidence
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            //as server verifies evidence with same evidence used for creating realm identity, we dont have to look into remaining realms for support (currentIdentity will always support evidence verification, unless none of the possible does)
            return currentIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return null;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return null;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            do {
                if (currentIdentity.verifyEvidence(evidence)) {
                    return true;
                }
            } while (nextIdentity());
            return false;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return currentIdentity.exists();
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return currentIdentity.getAuthorizationIdentity();
        }

        @Override
        public void dispose() {
            currentIdentity.dispose();
        }
    }

    final class PrincipalDistributedIdentity implements RealmIdentity {

        private final Principal principal;
        private RealmIdentity currentIdentity = RealmIdentity.NON_EXISTENT;
        private int nextRealm = 0;

        PrincipalDistributedIdentity(Principal principal) throws RealmUnavailableException {
            this.principal = principal;
            nextIdentity();
        }

        private boolean nextIdentity() throws RealmUnavailableException {
            currentIdentity.dispose();
            if (nextRealm >= securityRealms.length) {
                currentIdentity = RealmIdentity.NON_EXISTENT;
                return false;
            }

            boolean doesIdentityExist = false;
            try {
                currentIdentity = securityRealms[nextRealm].getRealmIdentity(principal);
                doesIdentityExist = currentIdentity.exists();
            } catch (RealmUnavailableException e) {
                if (!ignoreUnavailableRealms) {
                    throw e;
                }
                ElytronMessages.log.realmIsNotAvailable(e);
                if (unavailableRealmCallback != null) {
                    unavailableRealmCallback.accept(nextRealm);
                }
            }
            nextRealm++;
            if (!doesIdentityExist) {
                return nextIdentity();
            }
            return true;
        }

        @Override
        public Principal getRealmIdentityPrincipal() {
            return currentIdentity.getRealmIdentityPrincipal();
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return currentIdentity.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            return currentIdentity.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            do {
                C credential = currentIdentity.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    return credential;
                }
            } while (nextIdentity());

            return null;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            do {
                C credential = currentIdentity.getCredential(credentialType, algorithmName);
                if (credential != null) {
                    return credential;
                }
            } while (nextIdentity());

            return null;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            do {
                C credential = currentIdentity.getCredential(credentialType);
                if (credential != null) {
                    return credential;
                }
            } while (nextIdentity());

            return null;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            return currentIdentity.verifyEvidence(evidence);
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            return currentIdentity.exists();
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return currentIdentity.getAuthorizationIdentity();
        }

        @Override
        public void dispose() {
            currentIdentity.dispose();
        }
    }

}
