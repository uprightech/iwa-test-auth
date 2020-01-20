package org.gluu.test.spnego.auth;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

public class SpnegoCredentialsCallbackHandler implements CallbackHandler {
    
    private String username;
    private String password;

    public SpnegoCredentialsCallbackHandler(String username, String password) {

        this.username = username;
        this.password = password;
    }


    @Override
    public void handle(final Callback[] callbacks) {
        for(int i = 0; i < callbacks.length; i++ ){
            if(callbacks[i] instanceof NameCallback) {
                final NameCallback nameCallback = (NameCallback) callbacks[i];
                nameCallback.setName(username);
                return;
            }

            if(callbacks[i] instanceof PasswordCallback && password != null ) {
                final PasswordCallback passwordCallback = (PasswordCallback) callbacks[i];
                passwordCallback.setPassword(password.toCharArray());
                return;
            }

            //TODO add code here for other supported callbacks and a catch-all for unsupported 
            //callbacks
        }
    }

}