package me.dvrkn.springbootkerberosldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class KerberosAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final Log logger = LogFactory.getLog(getClass());

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, IOException {
        logger.warn("Kerberos Auth Failure from ip: " + request.getRemoteAddr());
        response.setCharacterEncoding("UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        String responseToClient= "Authentication failed";
        response.getWriter().write(responseToClient);
        response.getWriter().flush();
        response.flushBuffer();
    }
}
