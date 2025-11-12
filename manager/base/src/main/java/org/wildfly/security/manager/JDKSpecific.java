/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2018 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.manager;


/**
 * JDK-specific classes which are replaced for different JDK major versions. This class has been
 * updated from using JDK 8's Reflection class to using JDK 11+ current Thread's stackTrace array.
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
final class JDKSpecific {

    private static boolean active;
    private static int offset;

    static {

        boolean active = false;
        // offset inside the StackTrace
        // [0] the stackTrace itself (e.g getStackTrace())
        // [1] The class containing this global static block
        // [2] The method being called from inside this static block (e.g. getCallerClass())
        // [3] The class we are interested in
        int offset = 3;

        try {
            Class<?> clazz1 = getCallerClass(0, offset);
            active = clazz1 == WildFlySecurityManager.class || getCallerClass(1, offset) == WildFlySecurityManager.class;
            offset = offset + (clazz1 == WildFlySecurityManager.class ? 0 : 1);
        } catch (Throwable ignored) {}

        JDKSpecific.active = active;
        JDKSpecific.offset = offset;
    }

    public static Class<?> getCallerClass(int n) {
        if (active) {
            try {
                return getCallerClass(n, offset);
            } catch(ClassNotFoundException e ) {
                throw new IllegalStateException("Class not found in StackTraceElement[int].");
            }
        } else {
            throw new IllegalStateException("StackTraceElement[int] not available.");
        }
    }

    public static Class<?> getCallerClass(int indx, int offset) throws ClassNotFoundException{
        int pos = indx+offset;
        StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
        // offset inside the StackTrace
        // [0] the stackTrace itself (e.g getStackTrace())
        // [1] The class containing this global static block
        // [2] The method being called from inside this static block (e.g. getCallerClass())
        // [3] The class we are interested in
        if ((stackTraceElements.length > 3) && (pos <= stackTraceElements.length)) {
                return Class.forName(stackTraceElements[pos].getClassName());
        }
        return null;
    }

    public static boolean usingStackWalker() {
        return false;
    }

}
