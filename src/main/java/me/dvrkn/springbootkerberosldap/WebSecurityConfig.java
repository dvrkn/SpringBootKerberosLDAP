package me.dvrkn.springbootkerberosldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final Log logger = LogFactory.getLog(getClass());

    @Value("${app.kerberos.principal}")
    private String principal;
    @Value("${app.kerberos.keytab-location}")
    private String keytabLocation;

    @Autowired
    private LdapTemplate ldapTemplate;
    @Autowired
    private String grantedAuthority;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .exceptionHandling()
                .authenticationEntryPoint(entryPoint())
                .and()
                .authorizeRequests()
                .anyRequest().hasAuthority("ROLE_USER")
                .and()
                .addFilterBefore(
                        spnegoAuthenticationProcessingFilter(),
                        BasicAuthenticationFilter.class
                )
                .csrf().disable();
    }

    @Bean
    public SpnegoEntryPoint entryPoint() {
        return new SpnegoEntryPoint();
    }

    @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter() {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        try {
            AuthenticationManager authenticationManager = authenticationManagerBean();
            filter.setAuthenticationManager(authenticationManager);
            filter.setFailureHandler(new KerberosAuthenticationFailureHandler());
        } catch (Exception e) {
            logger.warn("Kerberos authentication failed.");
            //e.printStackTrace();
        }
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(kerberosServiceAuthenticationProvider());
    }

    @Bean
    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(new AppUserDetailsService(ldapTemplate, grantedAuthority));
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(principal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
        ticketValidator.setDebug(true);
        return ticketValidator;
    }
}
