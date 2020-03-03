package org.gluu.test.spnego.auth;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class SpnegoUtils {

    private static final Logger log = LogManager.getRootLogger();

    public static final HttpAuthorization parseAuthorizationResponse(HttpServletRequest request) {

        java.util.Enumeration<String> headernames = request.getHeaderNames();
        while(headernames.hasMoreElements()) {
            String headername = headernames.nextElement();
            log.info(String.format("%s: %s",headername,request.getHeader(headername)));
        }
        String header = request.getHeader(SpnegoConstants.AUTHORIZATION_HEADER_NAME);
        if(header == null || header.isEmpty())
            return null;
        
        

        String [] headervalueparts = header.trim().split("\\s+");
        if(headervalueparts.length != 2) {
            log.info("No header value parts were gotten");
            return null;
        }
        
        String authscheme = headervalueparts[0].trim();
        String creds = headervalueparts[1].trim();
        if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.BASIC_SCHEME.getSchemeName())) {
            log.info("Basic auth scheme parsed");
           return new HttpAuthorization(HttpAuthorizationScheme.BASIC_SCHEME,creds);
        }else if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.BEARER_SCHEME.getSchemeName())) {
            log.info("Bearer auth scheme parsed");
            return new HttpAuthorization(HttpAuthorizationScheme.BEARER_SCHEME,creds);
        }else if(authscheme.equalsIgnoreCase(HttpAuthorizationScheme.NEGOTIATE_SCHEME.getSchemeName())) {
            log.info("Negotiate auth schem parsed");
            return new HttpAuthorization(HttpAuthorizationScheme.NEGOTIATE_SCHEME,creds);
        }else {
            log.info("No auth scheme parsed");
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
        
        log.info("Spnego header created: "+credentials);
        return new HttpResponseHeader(name, value);
    }


}