package org.gluu.test.spnego.auth;

import java.util.ArrayList;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ietf.jgss.GSSCredential;

public class SpnegoAuthContext {

    private int httpResponseCode;
    private List<HttpResponseHeader> responseHeaders; 
    private HttpAuthorization authorization;
    private String principal;
    private GSSCredential delegationCredential;

    public SpnegoAuthContext(HttpServletRequest request) {

        this.authorization = SpnegoUtils.parseAuthorizationResponse(request);
        this.httpResponseCode = HttpServletResponse.SC_OK;
        this.responseHeaders = new ArrayList<HttpResponseHeader>();
    }


    public HttpAuthorization getAuthorization() {

        return this.authorization;
    }

    public int getHttpResponseCode() {

        return this.httpResponseCode;
    }

    public void setHttpResponseCode(int httpResponseCode) {

        this.httpResponseCode = httpResponseCode;
    }

    public void addHttpResponseHeader(HttpResponseHeader header) {
        this.responseHeaders.add(header);
    }

    public List<HttpResponseHeader> getHttpResponseHeaders() {

        return this.responseHeaders;
    }   

    public String getPrincipal() {

        return this.principal;
    }

    public void setPrincipal(String principal) {

        this.principal = principal;
    }

    public GSSCredential getDelegationCredential() {

        return this.delegationCredential;
    }

    public void setDelegationCredential(GSSCredential delegationCredential) {

        this.delegationCredential = delegationCredential;
    }
}