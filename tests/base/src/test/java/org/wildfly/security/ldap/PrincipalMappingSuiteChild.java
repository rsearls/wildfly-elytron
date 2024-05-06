/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.ldap;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * Test case to test different principal mapping configurations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PrincipalMappingSuiteChild {

    @Test
    public void testLdapRealmPrincipalMapping() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .setRdnIdentifier("uid")
                    .build()
                .build();

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("plainUser"));
        assertTrue("Exists", identity.exists());

        identity = realm.getRealmIdentity(new NamePrincipal("nobody"));
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testDnToSimple() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setRdnIdentifier("uid")
                    .build()
                .build();

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("uid=plainUser,dc=elytron,dc=wildfly,dc=org"));
        assertTrue("Exists", identity.exists());

        identity = realm.getRealmIdentity(new NamePrincipal("uid=nobody,dc=elytron,dc=wildfly,dc=org"));
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testDnToDnNoLookup() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setRdnIdentifier("uid")
                    .build()
                .build();

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("uid=plainUser,dc=elytron,dc=wildfly,dc=org"));
        assertTrue("Exists", identity.exists());
    }

    @Test
    public void testDnToDnVerify() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setRdnIdentifier("uid")
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .build()
                .build();

        RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal("uid=PlainUser,dc=elytron,dc=wildfly,dc=org"));
        assertTrue("Exists", identity.exists());

        int tryNumber = 0;
        int maxTries = 2;
        while(true) {
            try {
                identity = realm.getRealmIdentity(new NamePrincipal("uid=nobody,dc=elytron,dc=wildfly,dc=org"));
                break;
            } catch (RealmUnavailableException e) {
                tryNumber++;
                if (tryNumber == maxTries) {
                    throw e;
                }
            }
        }
        assertFalse("Exists", identity.exists());
    }

}
