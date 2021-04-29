package me.dvrkn.springbootkerberosldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import static org.springframework.ldap.query.LdapQueryBuilder.query;

public class AppUserDetailsService implements UserDetailsService {

    private final Log logger = LogFactory.getLog(getClass());

    private final LdapTemplate ldapTemplate;
    private final String grantedAuthority;

    public AppUserDetailsService(LdapTemplate ldapTemplate, String grantedAuthority) {
        this.ldapTemplate = ldapTemplate;
        this.grantedAuthority = grantedAuthority;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userCN = username.substring(0, username.indexOf('@'));
        logger.info("User " + userCN + " passed Kerberos auth");
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (isUserGranted(userCN)) {
            logger.info("User " + userCN + " granted.");
            grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        return new User(username, "notUsed", true, true, true, true, grantedAuthorities);
    }

    public Boolean isUserGranted(String userCN) {
        boolean userNotGranted = this.ldapTemplate.search(
                query().where("objectCategory").is("user").and(
                        query().where("sAMAccountName").is(userCN)
                                .or(query().where("userPrincipalName").is(userCN))
                ).and(
                        query().where("memberOf").is(grantedAuthority)
                ),
                (AttributesMapper<String>) attrs -> {
                    logger.info(attrs.get("memberOf").toString());
                    return attrs.get("distinguishedName").get().toString();
                }
        ).isEmpty();

        if (userNotGranted) {
            throw new UsernameNotFoundException("User " + userCN + " not recognized in LDAP or not member of security group.");
        }

        return true;
    }
}
