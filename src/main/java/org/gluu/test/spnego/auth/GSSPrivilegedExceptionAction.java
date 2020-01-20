package org.gluu.test.spnego.auth;

import java.security.PrivilegedExceptionAction;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

public class GSSPrivilegedExceptionAction implements PrivilegedExceptionAction<GSSCredential> {
    
    private GSSManager gssManager;
    private Oid oid;

    public GSSPrivilegedExceptionAction(GSSManager gssManager, Oid oid) {

        this.gssManager = gssManager;
        this.oid = oid;
    }

    public GSSCredential run() throws GSSException {

        return gssManager.createCredential(
                null,
                GSSCredential.INDEFINITE_LIFETIME,
                oid,
                GSSCredential.ACCEPT_ONLY);
    }
}