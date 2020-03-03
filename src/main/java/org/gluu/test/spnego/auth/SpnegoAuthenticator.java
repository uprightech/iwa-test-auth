package org.gluu.test.spnego.auth;

import java.security.PrivilegedActionException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;


public class SpnegoAuthenticator {
    
    private static final Logger log = LogManager.getRootLogger();
    private static final GSSManager GSS_MANAGER = GSSManager.getInstance();
    private static final Lock AUTHENTICATOR_LOCK = new ReentrantLock();

    private static final String SPNEGO_OID_STR = "1.3.6.1.5.5.2";
    private static final Oid SPNEGO_OID = createOid();

    private LoginContext loginContext;

    private GSSCredential credential;

    private static final Oid createOid() {

        Oid oid = null;
        try{
            oid = new Oid(SPNEGO_OID_STR);
        }catch(GSSException e) {
            log.fatal("Creating Spnego OID failed",e);
        }
        return oid;
    }

    //Call this method to initialize the authenticator before using it 
    public void init(SpnegoConfiguration config) {

        try {

            if(!config.hasKerberosConfigFile())
                throw new SpnegoAuthException("Kerberos configuration file (krb5.conf) not specified");
            
            if(!config.hasLoginConfigFile())
                throw new SpnegoAuthException("JAAS login configuration file (login.conf) not specified");
            
            System.setProperty("java.security.krb5.conf",config.getKerberosConfigFile());
            System.setProperty("java.security.auth.login.config",config.getLoginConfigFile());
                
            if(config.getServerAuthMethod() == SpnegoServerAuthMethod.USE_KEYTAB_FILE) {
                loginContext = new LoginContext(config.getLoginModule());
            }else {
                final CallbackHandler cbHandler = new SpnegoCredentialsCallbackHandler(
                    config.getServerUsername(),config.getServerPassword());
                
                this.loginContext = new LoginContext(config.getLoginModule(),cbHandler);
            }

            this.loginContext.login();
            this.credential = createCredential();
        }catch(LoginException e) {
            throw new SpnegoAuthException("SpnegoAuthenticator init() failed",e);            
        }catch(PrivilegedActionException e) {
            throw new SpnegoAuthException("SpnegoAuthenticator init() failed",e);
        }
    }

    //Call this method to shutdown the authenticator in order to release any allocated 
    //resources
    public void shutdown() {

    }

    //Call this method to perform authentication 
    public boolean authenticate(SpnegoAuthContext authcontext) {

        if(authcontext.getAuthorization() == null) {

            HttpResponseHeader header = SpnegoUtils.createSpnegoAuthHeader();
            authcontext.setHttpResponseCode(HttpServletResponse.SC_UNAUTHORIZED);
            authcontext.addHttpResponseHeader(header);
            log.info("No authorization header found");
            return false;
        }

        // we will support only SPNEGO right now 
        if(authcontext.getAuthorization().getScheme() != HttpAuthorizationScheme.NEGOTIATE_SCHEME) {

            HttpResponseHeader header = SpnegoUtils.createSpnegoAuthHeader();
            authcontext.setHttpResponseCode(HttpServletResponse.SC_UNAUTHORIZED);  
            authcontext.addHttpResponseHeader(header);
            log.info("Only SPNEGO supported");
            return false;
        }

        try {
            return performSpnegoAuth(authcontext);
        }catch(GSSException e) {
            throw new SpnegoAuthException("An error occured during spnego authentication",e);
        }
    }

    private GSSCredential createCredential() throws PrivilegedActionException {

        GSSPrivilegedExceptionAction action = new GSSPrivilegedExceptionAction(GSS_MANAGER,SPNEGO_OID);
        return Subject.doAs(loginContext.getSubject(), action);
    }

    private boolean performSpnegoAuth(SpnegoAuthContext authcontext) throws GSSException {

        if(authcontext.getAuthorization() == null || !authcontext.getAuthorization().hasCredentials()) {

            return false;
        }
        
        
        byte [] gssdata  = authcontext.getAuthorization().getBase64Credentials();
        GSSContext context = null;
        
        try {
            AUTHENTICATOR_LOCK.lock();
            byte [] token = null;

            try {
                context = GSS_MANAGER.createContext(credential);
                token  = context.acceptSecContext(gssdata,0,gssdata.length);
            }finally {
                AUTHENTICATOR_LOCK.unlock();
            }

            if(token == null) {

                return false;
            }

            authcontext.addHttpResponseHeader(SpnegoUtils.createSpnegoHeader(token));
            if(!context.isEstablished() && !context.isProtReady()) {
                log.info("Context is not fully established yet.");
                authcontext.setHttpResponseCode(HttpServletResponse.SC_UNAUTHORIZED);
                return false;
            }

            authcontext.setPrincipal(context.getSrcName().toString());
            log.info("Principal : " + context.getSrcName().toString());
            try {
                authcontext.setDelegationCredential(context.getDelegCred());
            }catch(GSSException e) {
                log.info("A non-fatal error occured. "+e.getMessage(),e);
            }
            return true;
        }finally {
            if(null != context) {
                AUTHENTICATOR_LOCK.lock();
                try {
                    context.dispose();
                }finally {
                    AUTHENTICATOR_LOCK.unlock();
                }
            }
        }
    }


}