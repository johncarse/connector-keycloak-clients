package net.flowbridge.connector.keycloak;

import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Translates ConnId filter queries into KeycloakClientFilter instances.
 */
public class KeycloakClientFilterTranslator extends AbstractFilterTranslator<KeycloakClientFilter> {

    @Override
    protected KeycloakClientFilter createEqualsExpression(EqualsFilter filter, boolean not) {
        if (not) {
            return null; // Not supported
        }

        Attribute attr = filter.getAttribute();
        if (attr == null || attr.getValue() == null || attr.getValue().isEmpty()) {
            return null;
        }

        String value = attr.getValue().get(0).toString();

        if (Uid.NAME.equals(attr.getName())) {
            return KeycloakClientFilter.byUid(value);
        }
        if (Name.NAME.equals(attr.getName())) {
            return KeycloakClientFilter.byName(value);
        }

        return null;
    }
}
