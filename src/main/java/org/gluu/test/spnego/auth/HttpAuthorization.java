package org.gluu.test.spnego.auth;

import org.apache.commons.codec.binary.Base64;

public class HttpAuthorization {

    private HttpAuthorizationScheme scheme;
    private String credentials;

    public HttpAuthorization(HttpAuthorizationScheme scheme,String credentials) {

        this.scheme = scheme;
        this.credentials = credentials;
    }

    public HttpAuthorizationScheme getScheme() {

        return this.scheme;
    }

    public void setScheme(HttpAuthorizationScheme scheme) {

        this.scheme = scheme;
    }

    public String getCredentials() {

        return this.credentials;
    }

    public byte [] getBase64Credentials() {

        return Base64.decodeBase64(this.credentials);
    }

    public boolean hasCredentials() {

        return this.credentials != null && this.credentials.length() > 0 ;
    }

    public void setCredentials(String credentials) {

        this.credentials = credentials;
    }
}