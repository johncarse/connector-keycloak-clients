package net.flowbridge.connector.keycloak;

import com.evolveum.polygon.rest.AbstractRestConfiguration;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * Configuration for the Keycloak Clients connector.
 * Extends AbstractRestConfiguration which provides serviceAddress, username, password, authMethod.
 */
public class KeycloakClientConfiguration extends AbstractRestConfiguration {

    private String realm = "ai-flowbridge";
    private String adminRealm = "master";
    private String clientId = "midpoint-admin";
    private String tokenEndpoint;

    @ConfigurationProperty(
            displayMessageKey = "keycloak.realm",
            helpMessageKey = "keycloak.realm.help",
            order = 10,
            required = true
    )
    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @ConfigurationProperty(
            displayMessageKey = "keycloak.adminRealm",
            helpMessageKey = "keycloak.adminRealm.help",
            order = 11
    )
    public String getAdminRealm() {
        return adminRealm;
    }

    public void setAdminRealm(String adminRealm) {
        this.adminRealm = adminRealm;
    }

    @ConfigurationProperty(
            displayMessageKey = "keycloak.clientId",
            helpMessageKey = "keycloak.clientId.help",
            order = 12,
            required = true
    )
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @ConfigurationProperty(
            displayMessageKey = "keycloak.tokenEndpoint",
            helpMessageKey = "keycloak.tokenEndpoint.help",
            order = 13
    )
    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Returns the computed token endpoint URL.
     * If not explicitly set, derives from serviceAddress and adminRealm.
     */
    public String getEffectiveTokenEndpoint() {
        if (StringUtil.isNotBlank(tokenEndpoint)) {
            return tokenEndpoint;
        }
        // Derive from base URL: https://auth.example.com → https://auth.example.com/realms/master/protocol/openid-connect/token
        String base = getServiceAddress();
        if (base != null && base.contains("/admin/realms/")) {
            base = base.substring(0, base.indexOf("/admin/realms/"));
        }
        return base + "/realms/" + adminRealm + "/protocol/openid-connect/token";
    }

    @Override
    public void validate() {
        super.validate();
        if (StringUtil.isBlank(realm)) {
            throw new IllegalArgumentException("Realm must be specified");
        }
        if (StringUtil.isBlank(clientId)) {
            throw new IllegalArgumentException("Client ID must be specified");
        }
    }
}
