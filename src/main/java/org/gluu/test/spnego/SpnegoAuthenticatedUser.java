package org.gluu.test.spnego;

import org.ietf.jgss.GSSCredential;

public class SpnegoAuthenticatedUser {

    private final String username;
    private final GSSCredential delegationCredential;

    public SpnegoAuthenticatedUser(String username, GSSCredential delegationCredential) {

        this.username = username;
        this.delegationCredential = delegationCredential;
    }

    public String getUsername() {

        return this.username;
    }

    public GSSCredential getDelegationCredential() {

        return this.delegationCredential;
    }

}