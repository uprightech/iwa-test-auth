package org.gluu.test.spnego;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.gluu.test.spnego.auth.HttpResponseHeader;
import org.gluu.test.spnego.auth.SpnegoAuthContext;
import org.gluu.test.spnego.auth.SpnegoAuthException;
import org.gluu.test.spnego.auth.SpnegoAuthenticator;
import org.gluu.test.spnego.auth.SpnegoConfiguration;
import org.gluu.test.spnego.auth.SpnegoConstants;
import org.gluu.test.spnego.auth.SpnegoServerAuthMethod;
import org.ietf.jgss.GSSCredential;


@WebFilter(description="spnego auth filter",displayName = "spnego-auth-filter",urlPatterns = {"/*"})
public class SpnegoFilter implements Filter {

    private static final String DUMMY_LOGIN_PAGE = "/login.jsp";
    private static final String AUTHENTICATED_USER = "authenticated_user";
    private Logger log = LogManager.getRootLogger();
    private SpnegoAuthenticator authenticator;

    @Override
    public void init(FilterConfig config) {
        
        try {
            authenticator = new SpnegoAuthenticator();
            authenticator.init(createSpnegoConfiguration(config));
        }catch(Exception e) {
            log.fatal("Could not instantiate authenticator",e);
            authenticator = null;
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpreq = (HttpServletRequest) request;
        HttpServletResponse httpresp = (HttpServletResponse) response;
        SpnegoAuthContext context = new SpnegoAuthContext(httpreq);
        String uri = parseRequestUri(httpreq);
        try {
           if(!uri.equalsIgnoreCase(DUMMY_LOGIN_PAGE)) {
               if(isUnauthenticatedSession(httpreq)) {
                   log.trace("No session found");
                   if(authenticate(context)) {
                       String principal = context.getPrincipal();
                       GSSCredential delegcred = context.getDelegationCredential();
                       SpnegoAuthenticatedUser user = new SpnegoAuthenticatedUser(principal,delegcred);
                       httpreq.getSession().setAttribute(AUTHENTICATED_USER,user);
                       chain.doFilter(request, response);
                       return;
                   }
                   // authentication failed 
                   for(HttpResponseHeader header : context.getHttpResponseHeaders()) {
                       httpresp.addHeader(header.getName(),header.getValue());
                   }
                   httpresp.setStatus(context.getHttpResponseCode());
                   return;
               }
           }
        }catch(SpnegoAuthException e) {
           log.error(e.getMessage(),e);
           httpresp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,"An internal error occured during SPNEGO authentication");
           return;
        }
        chain.doFilter(request,response);
    }

    @Override
    public void destroy() {
        log.info("SpnegoFilter::destroy()");
    }

    private final String parseRequestUri(HttpServletRequest request) {

        String contextpath = request.getContextPath();
        int context_pos = request.getRequestURI().indexOf(contextpath);
        return request.getRequestURI().substring(context_pos + contextpath.length());
    }

    private final boolean authenticate(SpnegoAuthContext authcontext) {

        boolean ret = authenticator.authenticate(authcontext);
        return ret;
    }

    private final SpnegoConfiguration createSpnegoConfiguration(FilterConfig filterconfig) {

        SpnegoConfiguration spnegoconfig = new SpnegoConfiguration();
        String loginmodule = filterconfig.getInitParameter(SpnegoConstants.SPNEGO_CONFIG_LOGIN_MODULE);
        spnegoconfig.setLoginModule(loginmodule);
        String keytab = filterconfig.getInitParameter(SpnegoConstants.SPNEGO_CONFIG_KEYTAB_FILE);
        if(keytab != null && !keytab.isEmpty()) {
            spnegoconfig.setServerAuthMethod(SpnegoServerAuthMethod.USE_KEYTAB_FILE);
            spnegoconfig.setKeyTabFile(keytab);
        }else {
            String username = filterconfig.getInitParameter(SpnegoConstants.SPNEGO_CONFIG_SERVER_USERNAME);
            String password = filterconfig.getInitParameter(SpnegoConstants.SPNEGO_CONFIG_SERVER_PASSWORD);
            spnegoconfig.setServerAuthMethod(SpnegoServerAuthMethod.USE_USER_PASSWORD_CREDENTIALS);
            spnegoconfig.setServerUsername(username);
            spnegoconfig.setServerPassword(password);
        }

        return spnegoconfig;
    }

    

    private final boolean isUnauthenticatedSession(HttpServletRequest request) {

        HttpSession session = request.getSession();
        if(session == null)  {
            return false;
        }

        if(session.getAttribute(AUTHENTICATED_USER) == null) {
            return false;
        }

        return true;
    }

}