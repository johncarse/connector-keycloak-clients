package net.flowbridge.connector.keycloak;

/**
 * Filter representation for Keycloak client searches.
 */
public class KeycloakClientFilter {

    public enum FilterType {
        BY_UID,      // Search by Keycloak internal UUID
        BY_NAME,     // Search by clientId
        ALL          // Return all clients
    }

    private final FilterType type;
    private final String value;

    private KeycloakClientFilter(FilterType type, String value) {
        this.type = type;
        this.value = value;
    }

    public static KeycloakClientFilter byUid(String uid) {
        return new KeycloakClientFilter(FilterType.BY_UID, uid);
    }

    public static KeycloakClientFilter byName(String clientId) {
        return new KeycloakClientFilter(FilterType.BY_NAME, clientId);
    }

    public static KeycloakClientFilter all() {
        return new KeycloakClientFilter(FilterType.ALL, null);
    }

    public FilterType getType() {
        return type;
    }

    public String getValue() {
        return value;
    }
}
