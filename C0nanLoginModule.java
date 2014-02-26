package net.c0nan.authentication;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.spi.NamingManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;

/**
 * @author: c0nan
 *
 */
public class C0nanLoginModule extends AbstractServerLoginModule {

    private Principal identity;
    private String userDisplayName;
    private String userEmailAddress;
    private List<String> groups = new ArrayList<String>();

    @Override
    public boolean login() throws LoginException {
        super.loginOk = false;
        try {
            doLogin();
            super.loginOk = true;
        } catch (Exception e) {

        }
        return super.loginOk;
    }

    @Override
    protected Principal getIdentity() {
        if (identity != null){
           principal = new CBSPrincipal(identity.getName(), userDisplayName,userEmailAddress, getGroups());
        }
        return principal;
    }

    @Override
    public boolean commit() throws LoginException {
        return super.commit();
    }

    private void doLogin() throws Exception {

        if (this.callbackHandler == null) {
            throw new Exception("No callback handler is available");
        }

        Callback callbacks[] = new Callback[2];

        callbacks[0] = new NameCallback("Name :");
        callbacks[1] = new PasswordCallback("Password :", false);

        try {

            this.callbackHandler.handle(callbacks);
            String name = ((NameCallback) callbacks[0]).getName().trim();
            String domainName = (String) options.get("principalDNSuffix");
            String baseFilter = (String) options.get("baseFilter");
            String searchFilter = "(&(objectclass=user)" + baseFilter + ")";
            String searchName = (String) options.get("baseCtxDN");

            Hashtable<String, Object> props = new Hashtable<String, Object>();
            String principalName = name + domainName;
            props.put(Context.SECURITY_PRINCIPAL, principalName);
            props.put(Context.SECURITY_CREDENTIALS, new String(((PasswordCallback) callbacks[1]).getPassword()));
            props.put(Context.INITIAL_CONTEXT_FACTORY, options.get("java.naming.factory.initial"));
            props.put(Context.PROVIDER_URL, options.get("java.naming.provider.url"));
            DirContext context;

            try {

                context = (DirContext) NamingManager.getInitialContext(props);
                //At this point we are successfully logged in.

                SearchControls controls = new SearchControls();
                controls.setSearchScope(SUBTREE_SCOPE);
                Object[] filterArgs = {name};
                NamingEnumeration<SearchResult> renum = context.search(searchName, searchFilter, filterArgs, controls);
                if (!renum.hasMore()) {
                    throw new Exception("Cannot locate user information for " + name);
                } else {
                    SearchResult result = renum.next();

                    identity = new SimplePrincipal(name);
                    Attribute displayName = result.getAttributes().get("displayName");
                    userDisplayName = displayName == null ? null : (String) displayName.get(0);
                    Attribute mail = result.getAttributes().get("mail");
                    userEmailAddress = mail == null ? null : (String) mail.get(0);

                    groups = new ArrayList<String>();
                    Attribute memberOf = result.getAttributes().get("memberOf");
                    if (memberOf != null) {
                        for (int i = 0; i < memberOf.size(); i++) {
                            Attributes atts = context.getAttributes(memberOf.get(i).toString(), new String[]{"CN"});
                            Attribute att = atts.get("CN");
                            groups.add(att.get().toString());
                        }
                    }
                }

            } catch (AuthenticationException a) {
                throw new Exception("Authentication failed: " + a.getLocalizedMessage());
            } catch (NamingException e) {
                throw new Exception("Failed to bind to LDAP / get account information: " + e.getLocalizedMessage());
            }
        } catch (UnsupportedCallbackException e) {
            throw new Exception("Callback Exception: " + e.getLocalizedMessage());
        } catch (IOException e) {
            throw new Exception("IO Exception: " + e.getLocalizedMessage());
        }

    }

    @Override
    protected Group[] getRoleSets() throws LoginException {
        return getGroups();
    }

    protected Group[] getGroups() {

        Group rolesGroup = new SimpleGroup("Roles");

        for (String group : groups) {
            rolesGroup.addMember(new SimplePrincipal(group));
        }


        return new Group[]{rolesGroup};
    }
}
