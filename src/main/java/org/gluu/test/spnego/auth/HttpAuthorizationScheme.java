package org.gluu.test.spnego.auth;


public enum HttpAuthorizationScheme {

    BASIC_SCHEME("Basic"),
    BEARER_SCHEME("Bearer"),
    NEGOTIATE_SCHEME("Negotiate");

    private final String schemeName;

    private HttpAuthorizationScheme(String schemeName) {
        this.schemeName = schemeName;
    }

    public String getSchemeName() {

        return this.schemeName;
    }
}