/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.http.oidc.Oidc.ALLOW_QUERY_PARAMS_PROPERTY_NAME;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests enabling query params via the oidc json property, allow-query-params.
 * There is an order of precedence. The value from the deployment's oidc.json file takes
 * priority over the system property setting.
 */
public class AllowQueryParamsEnabledTest extends QueryParamsBaseTest {

    private static String ALLOW_QUERY_PARAMS_PROPERTY;

    @BeforeClass
    public static void beforeClass() {
        ALLOW_QUERY_PARAMS_PROPERTY = System.setProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME, "true");
    }

    @AfterClass
    public static void afterClass() {
        if (ALLOW_QUERY_PARAMS_PROPERTY == null) {
            System.clearProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME);
        } else {
            System.setProperty(ALLOW_QUERY_PARAMS_PROPERTY_NAME, ALLOW_QUERY_PARAMS_PROPERTY);
        }
    }

    /**
     * Test the oidc.json value, false, overrides the system property, true.
     * Test successfully logging in with query params included in the URL.
     * The query params should not be present upon redirect.
     */
    @Test
    public void testSuccessfulAuthenticationWithQueryParamsWithAllowQueryParmasEnabled() throws Exception {
        // TODO add query params
        String queryParams = "?myparam=abc";
        String baselUrl = getClientUrl();
        String expectedUrlAfterRedirect = baselUrl;
        String originalUrl = getClientUrl() + queryParams;
        performAuthentication(getOidcConfigInputStreamWithAllowQueryParamsFalse(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY, originalUrl,
                expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);
    }

    /**
     * Test the oidc.json value not present. The system property, true.
     * Test successfully logging in with query params included in the URL.
     * The query params should be present upon redirect.
     */
    @Test
    public void testSuccessfulAuthenticationWithQueryParamsWithAllowQueryParmasDisabled() throws Exception {
        String queryParams = "?myparam=abc";
        String originalUrl = getClientUrl() + queryParams;
        String expectedUrlAfterRedirect = originalUrl;
        performAuthentication(getOidcConfigInputStreamWithAllowQueryParamsNotSet(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY, originalUrl,
                expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);

        queryParams = "?one=abc&two=def&three=ghi";
        originalUrl = getClientUrl() + queryParams;
        expectedUrlAfterRedirect = originalUrl;
        performAuthentication(getOidcConfigurationInputStreamWithProviderUrl(), KeycloakConfiguration.ALICE,
                KeycloakConfiguration.ALICE_PASSWORD, true, HttpStatus.SC_MOVED_TEMPORARILY, originalUrl,
                expectedUrlAfterRedirect, CLIENT_PAGE_TEXT);
    }

    @Test
    public void testClientConfigAllowQueryParamsDeclared () throws Exception {
        OidcClientConfiguration clientConfigurationAllowQueryParamsDeclared =
        OidcClientConfigurationBuilder.build(getOidcConfigInputStreamWithAllowQueryParamsFalse());

        assertTrue(clientConfigurationAllowQueryParamsDeclared.isAllowQueryParamsDeclared());
        assertFalse(clientConfigurationAllowQueryParamsDeclared.getAllowQueryParams());
    }

    @Test
    public void testClientConfigAllowQueryParamsNotDeclared () throws Exception {
        OidcClientConfiguration clientConfigurationAllowQueryParamsNotDeclared =
        OidcClientConfigurationBuilder.build(getOidcConfigInputStreamWithAllowQueryParamsNotSet());

        assertFalse(clientConfigurationAllowQueryParamsNotDeclared.isAllowQueryParamsDeclared());
        assertFalse(clientConfigurationAllowQueryParamsNotDeclared.getAllowQueryParams());
    }
}
