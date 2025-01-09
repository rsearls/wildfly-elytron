/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.checkCachedAccountMatchesRequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpScopeNotification;
import org.wildfly.security.http.Scope;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcSessionTokenStore implements OidcTokenStore {

    private final OidcHttpFacade httpFacade;

    public OidcSessionTokenStore(OidcHttpFacade httpFacade) {
        this.httpFacade = httpFacade;
    }

    @Override
    public void checkCurrentToken() {
        log.trace("## OidcSessionTokenStore.checkCurrentToken");
        HttpScope session = httpFacade.getScope(Scope.SESSION);
        if (session == null || ! session.exists()) {
            log.trace("## OidcSessionTokenStore.checkCurrentToken  no session found");
            return;
        }
        RefreshableOidcSecurityContext securityContext = (RefreshableOidcSecurityContext) session.getAttachment(OidcSecurityContext.class.getName());
        if (securityContext == null) {
            log.trace("## OidcSessionTokenStore.checkCurrentToken  no securityContext");
            return;
        }

        // just in case session got serialized
        if (securityContext.getOidcClientConfiguration() == null) {
            log.trace("## OidcSessionTokenStore.checkCurrentToken  no OidcClientConfiguration set to current");
            securityContext.setCurrentRequestInfo(httpFacade.getOidcClientConfiguration(), this);
        }

        if (securityContext.isActive() && ! securityContext.getOidcClientConfiguration().isAlwaysRefreshToken()) {
            log.trace("## OidcSessionTokenStore.checkCurrentToken  not isAlwaysRefreshToken");
            return;
        }

        // FYI: A refresh requires same scope, so same roles will be set.  Otherwise, refresh will fail and token will
        // not be updated
        boolean success = securityContext.refreshToken(false);
        if (success && securityContext.isActive()) {
            log.trace("## OidcSessionTokenStore.checkCurrentToken  could not refresh token");
            return;
        }

        // Refresh failed, so user is already logged out from keycloak. Cleanup and expire our session
        session.setAttachment(OidcSecurityContext.class.getName(), null);
        session.invalidate();
        log.trace("## OidcSessionTokenStore.checkCurrentToken invalidate session");
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        HttpScope session = this.httpFacade.getScope(Scope.SESSION);

        if (session == null || !session.supportsAttachments()) {
            log.debug("session was null, returning null");
            return false;
        }

        OidcAccount account;

        try {
            account = (OidcAccount) session.getAttachment(OidcAccount.class.getName());
        } catch (IllegalStateException e) {
            log.debug("session was invalidated.  Return false.");
            return false;
        }
        if (account == null) {
            log.debug("Account was not in session, returning null");
            return false;
        }

        OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
        if (! checkCachedAccountMatchesRequest(account, deployment)) {
            log.trace("## OidcSessionTokenStore.isCached no  CachedAccountMatchesRequest");
            return false;
        }

        boolean active = account.checkActive();

        if (! active) {
            active = account.tryRefresh();
        }

        if (active) {
            log.debug("Cached account found");
            restoreRequest();
            httpFacade.authenticationComplete(account, true);
            return true;
        } else {
            log.debug("Refresh failed. Account was not active. Returning null and invalidating Http session");
            try {
                session.setAttachment(OidcSecurityContext.class.getName(), null);
                session.setAttachment(OidcAccount.class.getName(), null);
                session.invalidate();
            } catch (Exception e) {
                log.debug("Failed to invalidate session, might already be invalidated");
            }
            return false;
        }
    }

    @Override
    public void saveAccountInfo(OidcAccount account) {
        log.trace("## OidcSessionTokenStore.saveAccountInfo ");
        HttpScope session = this.httpFacade.getScope(Scope.SESSION);
        if (! session.exists()) {
            session.create();
            log.trace("## OidcSessionTokenStore.saveAccountInfo create session");
            session.registerForNotification(httpScopeNotification -> {
                if (! httpScopeNotification.isOfType(HttpScopeNotification.SessionNotificationType.UNDEPLOY)) {
                    HttpScope invalidated = httpScopeNotification.getScope(Scope.SESSION);
                    if (invalidated != null) {
                        log.trace("## OidcSessionTokenStore.saveAccountInfo set attachement OidcAccount NULL");
                        invalidated.setAttachment(OidcAccount.class.getName(), null);
                        invalidated.setAttachment(OidcSecurityContext.class.getName(), null);
                    }
                }
            });
        }
        log.trace("## OidcSessionTokenStore.saveAccountInfo set session attachement OidcAccount to account");
        session.setAttachment(OidcAccount.class.getName(), account);
        session.setAttachment(OidcSecurityContext.class.getName(), account.getOidcSecurityContext());

        HttpScope scope = this.httpFacade.getScope(Scope.EXCHANGE);

        scope.setAttachment(OidcSecurityContext.class.getName(), account.getOidcSecurityContext());
    }

    @Override
    public void logout() {
        logout(false);
    }

    @Override
    public void refreshCallback(RefreshableOidcSecurityContext securityContext) {
        log.trace("## OidcSessionTokenStore.refreshCallback ");
        OidcPrincipal<RefreshableOidcSecurityContext> principal = new OidcPrincipal<>(securityContext.getIDToken().getPrincipalName(this.httpFacade.getOidcClientConfiguration()), securityContext);
        saveAccountInfo(new OidcAccount(principal));
    }

    @Override
    public void saveRequest() {
        log.trace("## OidcSessionTokenStore.saveRequest ");
        this.httpFacade.suspendRequest();
    }

    @Override
    public boolean restoreRequest() {
        log.trace("## OidcSessionTokenStore.restoreRequest ");
        return this.httpFacade.restoreRequest();
    }

    @Override
    public void logout(boolean glo) {
        log.trace("## OidcSessionTokenStore.logout ");
        HttpScope session = this.httpFacade.getScope(Scope.SESSION);

        if (! session.exists()) {
            log.trace("## OidcSessionTokenStore.logout  session does not exist");
            return;
        }

        OidcSecurityContext securityContext = (OidcSecurityContext) session.getAttachment(OidcSecurityContext.class.getName());

        try {
            if (glo && securityContext != null) {
                OidcClientConfiguration deployment = httpFacade.getOidcClientConfiguration();
                session.invalidate();
                log.trace("## OidcSessionTokenStore.logout invalidate session ");
                if (! deployment.isBearerOnly() && securityContext != null && securityContext instanceof RefreshableOidcSecurityContext) {
                    ((RefreshableOidcSecurityContext) securityContext).logout(deployment);
                }
            } else {
                log.trace("## OidcSessionTokenStore.logout add session attachment OidcAccount as NULL ");
                session.setAttachment(OidcAccount.class.getName(), null);
                session.setAttachment(OidcSecurityContext.class.getName(), null);
            }
        } catch (IllegalStateException ise) {
            // Session may be already logged-out in case that app has adminUrl
            log.debugf("Session %s logged-out already", session.getID());
        }
    }

    @Override
    public void logoutAll() {
        log.trace("## OidcSessionTokenStore.logoutAll ");
        Collection<String> sessions = httpFacade.getScopeIds(Scope.SESSION);
        logoutHttpSessions(new ArrayList<>(sessions));
    }

    @Override
    public void logoutHttpSessions(List<String> ids) {
        log.trace("## OidcSessionTokenStore.logoutHttpSessions  ids #: " + ids.size());
        for (String id : ids) {
            HttpScope session = httpFacade.getScope(Scope.SESSION, id);
            if (session != null) {
                session.invalidate();
            }
        }
    }
}
