package me.dvrkn.springbootkerberosldap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
public class LdapConfig {
    @Value("${app.ldap.url}")
    private String ldapUrl;
    @Value("${app.ldap.base}")
    private String searchBase;
    @Value("${app.ldap.username}")
    private String ldapUser;
    @Value("${app.ldap.password}")
    private String ldapPassword;
    @Value("${app.ldap.grantedAuthority}")
    private String grantedAuthority;

    @Bean
    public LdapContextSource contextSource () {
        LdapContextSource contextSource= new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setBase(searchBase);
        contextSource.setUserDn(ldapUser);
        contextSource.setPassword(ldapPassword);
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }

    @Bean
    public String grantedAuthority() {
        return grantedAuthority;
    }
}
