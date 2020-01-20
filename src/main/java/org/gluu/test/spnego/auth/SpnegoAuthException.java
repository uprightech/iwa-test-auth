package org.gluu.test.spnego.auth;

public class SpnegoAuthException extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    

    public SpnegoAuthException(String msg) {
        super(msg);
    } 

    public SpnegoAuthException(String msg,Throwable cause) {
        super(msg,cause);
    }
}