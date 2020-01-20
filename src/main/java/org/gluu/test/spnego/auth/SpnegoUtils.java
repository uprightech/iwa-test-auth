package org.gluu.test.spnego.auth;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

public class SpnegoUtils {

    public static final HttpAuthorization parseAuthorizationResponse(HttpServletRequest request) {

        String header = request.getHeader(SpnegoConstants.AUTHORIZATION_HEADER_NAME);
        if(header == null || header.isEmpty())
            return null;
        
        String [] headerparts = header.split(":");
        if(headerparts.length != 2) {
            return null;
        }

        String [] headervalueparts = headerparts[1].trim().split("\\s+");
        if(headervalueparts.length != 2) {
            return null;
        }
        
        String authscheme = headervalueparts[0].trim();
        String creds = headervalueparts[1].trim();
        if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.BASIC_SCHEME.getSchemeName())) {
           return new HttpAuthorization(HttpAuthorizationScheme.BASIC_SCHEME,creds);
        }else if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.BEARER_SCHEME.getSchemeName())) {
            return new HttpAuthorization(HttpAuthorizationScheme.BEARER_SCHEME,creds);
        }else if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.NEGOTIATE_SCHEME.getSchemeName())) {
            return new HttpAuthorization(HttpAuthorizationScheme.NEGOTIATE_SCHEME,creds);
        }else {
            return null;
        }

    }

    public static final HttpResponseHeader createSpnegoAuthHeader() {

        return createSpnegoAuthHeader(null);
    }

    public static final HttpResponseHeader createSpnegoHeader(byte [] credentials) {

        return createSpnegoAuthHeader(Base64.encodeBase64String(credentials));
    }

    public static final HttpResponseHeader createSpnegoAuthHeader(String credentials) {

        String name = SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME;
        String value = null;
        if(credentials == null)
            value = SpnegoConstants.NEGOTIATE_AUTHORIZATION_TYPE;
        else
            value = String.format("%s %s",SpnegoConstants.NEGOTIATE_AUTHORIZATION_TYPE,credentials);
        
        return new HttpResponseHeader(name, value);
    }


}