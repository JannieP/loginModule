package net.c0nan.authentication;

import java.io.Serializable;
import java.security.Principal;
import java.security.acl.Group;

/**
 * @author: c0nan
 *
 */
public class C0nanPrincipal implements Principal, Serializable {
    private static final long serialVersionUID = 123L;
    private final String name;
    private final String displayName;
    private final String emailAddress;
    private Group[] groups;

    public C0nanPrincipal(String name, String displayName,String emailAddress,Group[] groups) {
        this.name = name;
        this.displayName = displayName;
        this.groups = groups;
        this.emailAddress = emailAddress;
    }

    @Override
    public boolean equals(Object another) {
        if (!(another instanceof Principal))
            return false;

        String anotherName = ((Principal) another).getName();
        boolean equals = false;
        if (name == null)
            equals = anotherName == null;
        else
            equals = name.equals(anotherName);
        return equals;
    }

    @Override
    public int hashCode() {
        return (name == null ? 0 : name.hashCode());
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public Group[] getGroups() {
        return groups;
    }
}
