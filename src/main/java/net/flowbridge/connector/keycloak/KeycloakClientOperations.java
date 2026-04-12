package net.flowbridge.connector.keycloak;

import com.evolveum.polygon.rest.AbstractRestConnector;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Implements CRUD operations against the Keycloak Admin REST API for OAuth clients
 * and host connectors, including service account user attribute management.
 * <p>
 * Endpoints used:
 *   GET/POST/PUT/DELETE  /admin/realms/{realm}/clients[/{id}]
 *   GET                  /admin/realms/{realm}/clients/{id}/service-account-user
 *   PUT                  /admin/realms/{realm}/users/{userId}
 *   GET                  /admin/realms/{realm}/clients/{id}/client-secret
 */
public class KeycloakClientOperations {

    private static final Log LOG = Log.getLog(KeycloakClientOperations.class);

    // Service account user attributes that map to JWT claims
    private static final Set<String> SA_USER_ATTRS = Set.of(
            KeycloakClientConnector.ATTR_ORG_ID,
            KeycloakClientConnector.ATTR_AGENT_IDENTITY,
            KeycloakClientConnector.ATTR_HOST_ID,
            KeycloakClientConnector.ATTR_GROUP_ID,
            KeycloakClientConnector.ATTR_FRIENDLY_NAME
    );

    // Client-level attributes (stored in client.attributes, not SA user)
    private static final Set<String> CLIENT_ATTRS = Set.of(
            KeycloakClientConnector.ATTR_AGENT_MAILBOX,
            KeycloakClientConnector.ATTR_AGENT_CLASS
    );

    private final KeycloakClientConfiguration config;
    private final AbstractRestConnector<?> connector;
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient;

    private String cachedAccessToken;
    private long tokenExpiresAt;

    public KeycloakClientOperations(KeycloakClientConfiguration config,
                                    AbstractRestConnector<?> connector) {
        this.config = config;
        this.connector = connector;
        this.httpClient = createHttpClient(config);
    }

    // ---- SSL / HTTP Client ----

    private static HttpClient createHttpClient(KeycloakClientConfiguration config) {
        try {
            SSLContext sslContext;
            if (config.getTrustAllCertificates()) {
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new javax.net.ssl.TrustManager[]{
                        new javax.net.ssl.X509TrustManager() {
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        }
                }, new SecureRandom());
            } else {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore trustStore = null;
                String[] candidates = {
                        System.getProperty("javax.net.ssl.trustStore"),
                        "/etc/ssl/certs/java/cacerts",
                        "/etc/default/cacerts",
                        "/etc/pki/java/cacerts"
                };
                boolean loaded = false;
                for (String path : candidates) {
                    if (path == null || path.isEmpty()) continue;
                    File f = new File(path);
                    if (f.exists() && f.canRead()) {
                        for (String storeType : new String[]{"PKCS12", "JKS"}) {
                            try {
                                trustStore = KeyStore.getInstance(storeType);
                                try (InputStream is = new FileInputStream(f)) {
                                    trustStore.load(is, "changeit".toCharArray());
                                }
                                loaded = true;
                                break;
                            } catch (Exception ignored) {}
                        }
                        if (loaded) break;
                    }
                }
                if (!loaded) {
                    trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    trustStore.load(null, null);
                }
                tmf.init(trustStore);
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            }
            return HttpClient.newBuilder().sslContext(sslContext).build();
        } catch (Exception e) {
            LOG.warn("Failed to create SSL context, falling back to default: {0}", e.getMessage());
            return HttpClient.newHttpClient();
        }
    }

    // ---- Token Management ----

    private String getAccessToken() {
        long now = System.currentTimeMillis() / 1000;
        if (cachedAccessToken != null && now < tokenExpiresAt - 30) {
            return cachedAccessToken;
        }

        String tokenUrl = config.getEffectiveTokenEndpoint();
        StringBuilder body = new StringBuilder();
        body.append("grant_type=client_credentials");
        body.append("&client_id=").append(URLEncoder.encode(config.getClientId(), StandardCharsets.UTF_8));
        final StringBuilder secret = new StringBuilder();
        config.getPassword().access(chars -> secret.append(new String(chars)));
        body.append("&client_secret=").append(URLEncoder.encode(secret.toString(), StandardCharsets.UTF_8));

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new ConnectorException("Failed to obtain access token: HTTP "
                        + response.statusCode() + " " + response.body());
            }

            JsonNode tokenResponse = mapper.readTree(response.body());
            cachedAccessToken = tokenResponse.get("access_token").asText();
            int expiresIn = tokenResponse.get("expires_in").asInt(300);
            tokenExpiresAt = (System.currentTimeMillis() / 1000) + expiresIn;
            return cachedAccessToken;
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Failed to obtain access token", e);
        }
    }

    // ---- API Helpers ----

    private String adminBaseUrl() {
        String addr = config.getServiceAddress();
        if (!addr.contains("/admin/realms/")) {
            addr = addr + "/admin/realms/" + config.getRealm();
        }
        return addr;
    }

    private HttpRequest.Builder apiRequest(String path) {
        return HttpRequest.newBuilder()
                .uri(URI.create(adminBaseUrl() + path))
                .header("Authorization", "Bearer " + getAccessToken())
                .header("Content-Type", "application/json");
    }

    private JsonNode apiGet(String path) {
        try {
            HttpResponse<String> response = httpClient.send(
                    apiRequest(path).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) return null;
            if (response.statusCode() >= 400)
                throw new ConnectorException("Keycloak GET " + path + " → " + response.statusCode() + ": " + response.body());
            return mapper.readTree(response.body());
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak GET " + path + " failed", e);
        }
    }

    private String apiPost(String path, String jsonBody) {
        try {
            HttpResponse<String> response = httpClient.send(
                    apiRequest(path).POST(HttpRequest.BodyPublishers.ofString(jsonBody)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 409) throw new AlreadyExistsException("Client already exists");
            if (response.statusCode() == 201) {
                String location = response.headers().firstValue("Location")
                        .or(() -> response.headers().firstValue("location")).orElse("");
                if (!location.isEmpty()) return location.substring(location.lastIndexOf('/') + 1);
                return "";
            }
            if (response.statusCode() >= 400)
                throw new ConnectorException("Keycloak POST " + path + " → " + response.statusCode() + ": " + response.body());
            return response.body();
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak POST " + path + " failed", e);
        }
    }

    private void apiPut(String path, String jsonBody) {
        try {
            HttpResponse<String> response = httpClient.send(
                    apiRequest(path).PUT(HttpRequest.BodyPublishers.ofString(jsonBody)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) throw new UnknownUidException("Not found: " + path);
            if (response.statusCode() >= 400)
                throw new ConnectorException("Keycloak PUT " + path + " → " + response.statusCode() + ": " + response.body());
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak PUT " + path + " failed", e);
        }
    }

    private void apiDelete(String path) {
        try {
            HttpResponse<String> response = httpClient.send(
                    apiRequest(path).DELETE().build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) throw new UnknownUidException("Not found: " + path);
            if (response.statusCode() >= 400)
                throw new ConnectorException("Keycloak DELETE " + path + " → " + response.statusCode() + ": " + response.body());
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak DELETE " + path + " failed", e);
        }
    }

    // ---- Service Account User Attributes ----

    /**
     * Set attributes on the service account user for a client.
     * These are read by protocol mappers to populate JWT claims (org_id, host_id, agent_identity).
     */
    private void setServiceAccountAttributes(String clientUuid, Map<String, String> attrs) {
        if (attrs.isEmpty()) return;

        // Get the service account user
        JsonNode saUser = apiGet("/clients/" + clientUuid + "/service-account-user");
        if (saUser == null) {
            LOG.warn("No service account user for client {0}", clientUuid);
            return;
        }
        String userId = saUser.get("id").asText();

        // Build attributes map (Keycloak expects arrays of strings)
        ObjectNode userUpdate = mapper.createObjectNode();
        ObjectNode attrsNode = mapper.createObjectNode();
        for (Map.Entry<String, String> entry : attrs.entrySet()) {
            ArrayNode arr = mapper.createArrayNode();
            arr.add(entry.getValue());
            attrsNode.set(entry.getKey(), arr);
        }
        userUpdate.set("attributes", attrsNode);

        try {
            apiPut("/users/" + userId, mapper.writeValueAsString(userUpdate));
            LOG.info("Set service account attributes for client {0}: {1}", clientUuid, attrs.keySet());
        } catch (IOException e) {
            throw new ConnectorException("Failed to serialize SA user attributes", e);
        }
    }

    /**
     * Read service account user attributes for a client.
     */
    private Map<String, String> getServiceAccountAttributes(String clientUuid) {
        JsonNode saUser = apiGet("/clients/" + clientUuid + "/service-account-user");
        if (saUser == null) return Collections.emptyMap();

        Map<String, String> result = new HashMap<>();
        JsonNode attrs = saUser.path("attributes");
        if (attrs.isObject()) {
            for (String key : SA_USER_ATTRS) {
                JsonNode val = attrs.get(key);
                if (val != null && val.isArray() && val.size() > 0) {
                    result.put(key, val.get(0).asText());
                }
            }
        }
        return result;
    }

    // ---- Extract Attributes from ConnId Set ----

    private static String getStringAttr(Set<Attribute> attributes, String name) {
        for (Attribute attr : attributes) {
            if (name.equals(attr.getName())) return AttributeUtil.getStringValue(attr);
        }
        return null;
    }

    // ---- CRUD Operations ----

    /**
     * Create a Keycloak client (agent or host).
     * @param isHost true for HostConnector, false for OAuthClient
     */
    public Uid createClient(Set<Attribute> attributes, boolean isHost) {
        ObjectNode clientRep = mapper.createObjectNode();
        Map<String, String> saAttrs = new HashMap<>();

        String clientIdValue = null;
        for (Attribute attr : attributes) {
            String name = attr.getName();
            if (Name.NAME.equals(name)) {
                clientIdValue = AttributeUtil.getStringValue(attr);
                clientRep.put("clientId", clientIdValue);
            } else if (OperationalAttributes.ENABLE_NAME.equals(name)) {
                clientRep.put("enabled", AttributeUtil.getBooleanValue(attr));
            } else if (KeycloakClientConnector.ATTR_SERVICE_ACCOUNTS_ENABLED.equals(name)) {
                clientRep.put("serviceAccountsEnabled", AttributeUtil.getBooleanValue(attr));
            } else if (KeycloakClientConnector.ATTR_DESCRIPTION.equals(name)) {
                clientRep.put("description", AttributeUtil.getStringValue(attr));
            } else if (KeycloakClientConnector.ATTR_CLIENT_NAME.equals(name)) {
                clientRep.put("name", AttributeUtil.getStringValue(attr));
            } else if (KeycloakClientConnector.ATTR_DEFAULT_SCOPES.equals(name)) {
                ArrayNode scopes = mapper.createArrayNode();
                attr.getValue().forEach(v -> scopes.add(v.toString()));
                clientRep.set("defaultClientScopes", scopes);
            } else if (KeycloakClientConnector.ATTR_OPTIONAL_SCOPES.equals(name)) {
                ArrayNode scopes = mapper.createArrayNode();
                attr.getValue().forEach(v -> scopes.add(v.toString()));
                clientRep.set("optionalClientScopes", scopes);
            } else if (SA_USER_ATTRS.contains(name)) {
                // Service account user attributes → set after client creation
                String val = AttributeUtil.getStringValue(attr);
                if (val != null) saAttrs.put(name, val);
            } else if (CLIENT_ATTRS.contains(name)) {
                // Client-level attributes
                if (!clientRep.has("attributes")) {
                    clientRep.set("attributes", mapper.createObjectNode());
                }
                ((ObjectNode) clientRep.get("attributes"))
                        .put(name, AttributeUtil.getStringValue(attr));
            }
        }

        // Generate UUID clientId if not provided
        if (clientIdValue == null || clientIdValue.isEmpty()) {
            clientIdValue = UUID.randomUUID().toString();
            clientRep.put("clientId", clientIdValue);
        }

        // Defaults
        if (!clientRep.has("serviceAccountsEnabled")) clientRep.put("serviceAccountsEnabled", true);
        if (!clientRep.has("enabled")) clientRep.put("enabled", true);
        clientRep.put("standardFlowEnabled", false);
        clientRep.put("implicitFlowEnabled", false);
        clientRep.put("directAccessGrantsEnabled", false);
        clientRep.put("clientAuthenticatorType", "client-secret");

        // Default scopes based on type
        if (!clientRep.has("defaultClientScopes")) {
            ArrayNode scopes = mapper.createArrayNode();
            if (isHost) {
                scopes.add("relay:host");
            } else {
                scopes.add("relay:connect");
                scopes.add("jmap:read");
                scopes.add("jmap:send");
            }
            clientRep.set("defaultClientScopes", scopes);
        }

        try {
            String uuid = apiPost("/clients", mapper.writeValueAsString(clientRep));
            // Fallback: look up by clientId if Location header missing
            if (uuid == null || uuid.isEmpty()) {
                JsonNode clients = apiGet("/clients?clientId=" + URLEncoder.encode(clientIdValue, StandardCharsets.UTF_8));
                if (clients != null && clients.isArray() && clients.size() > 0) {
                    uuid = clients.get(0).get("id").asText();
                } else {
                    throw new ConnectorException("Created client but could not find it: " + clientIdValue);
                }
            }

            // Set service account user attributes
            if (!saAttrs.isEmpty()) {
                setServiceAccountAttributes(uuid, saAttrs);
            }

            LOG.info("Created {0} client {1} (UUID {2})", isHost ? "host" : "agent", clientIdValue, uuid);
            return new Uid(uuid);
        } catch (IOException e) {
            throw new ConnectorException("Failed to serialize client", e);
        }
    }

    public Uid replaceClient(Uid uid, Set<Attribute> replaceAttributes, boolean isHost) {
        JsonNode existing = apiGet("/clients/" + uid.getUidValue());
        if (existing == null) throw new UnknownUidException(uid.getUidValue());

        ObjectNode updated = (ObjectNode) existing;
        Map<String, String> saAttrs = new HashMap<>();

        for (Attribute attr : replaceAttributes) {
            String name = attr.getName();
            String val = AttributeUtil.getStringValue(attr);

            if (OperationalAttributes.ENABLE_NAME.equals(name)) {
                updated.put("enabled", AttributeUtil.getBooleanValue(attr));
            } else if (KeycloakClientConnector.ATTR_DEFAULT_SCOPES.equals(name)) {
                ArrayNode scopes = mapper.createArrayNode();
                attr.getValue().forEach(v -> scopes.add(v.toString()));
                updated.set("defaultClientScopes", scopes);
            } else if (KeycloakClientConnector.ATTR_OPTIONAL_SCOPES.equals(name)) {
                ArrayNode scopes = mapper.createArrayNode();
                attr.getValue().forEach(v -> scopes.add(v.toString()));
                updated.set("optionalClientScopes", scopes);
            } else if (KeycloakClientConnector.ATTR_DESCRIPTION.equals(name)) {
                updated.put("description", val);
            } else if (KeycloakClientConnector.ATTR_CLIENT_NAME.equals(name)) {
                updated.put("name", val);
            } else if (SA_USER_ATTRS.contains(name)) {
                if (val != null) saAttrs.put(name, val);
            } else if (CLIENT_ATTRS.contains(name)) {
                ObjectNode attrs = updated.has("attributes")
                        ? (ObjectNode) updated.get("attributes") : mapper.createObjectNode();
                attrs.put(name, val);
                updated.set("attributes", attrs);
            }
        }

        try {
            apiPut("/clients/" + uid.getUidValue(), mapper.writeValueAsString(updated));
        } catch (IOException e) {
            throw new ConnectorException("Failed to serialize client update", e);
        }

        // Update service account user attributes
        if (!saAttrs.isEmpty()) {
            setServiceAccountAttributes(uid.getUidValue(), saAttrs);
        }

        return uid;
    }

    public void deleteClient(Uid uid) {
        apiDelete("/clients/" + uid.getUidValue());
        LOG.info("Deleted Keycloak client {0}", uid.getUidValue());
    }

    public void searchClients(KeycloakClientFilter filter, ResultsHandler handler, String objectClassType) {
        if (filter != null && filter.getType() == KeycloakClientFilter.FilterType.BY_UID) {
            JsonNode client = apiGet("/clients/" + filter.getValue());
            if (client != null) {
                handler.handle(clientToConnectorObject(client, objectClassType));
            }
            return;
        }

        String path = "/clients";
        if (filter != null && filter.getType() == KeycloakClientFilter.FilterType.BY_NAME) {
            path += "?clientId=" + URLEncoder.encode(filter.getValue(), StandardCharsets.UTF_8);
        }

        JsonNode clients = apiGet(path);
        if (clients != null && clients.isArray()) {
            for (JsonNode client : clients) {
                if (!handler.handle(clientToConnectorObject(client, objectClassType))) break;
            }
        }
    }

    public void testConnection() {
        JsonNode result = apiGet("/clients?max=1");
        if (result == null) throw new ConnectorException("Failed to connect to Keycloak Admin API");
        LOG.info("Keycloak connection test successful");
    }

    // ---- Mapping ----

    private ConnectorObject clientToConnectorObject(JsonNode client, String objectClassType) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(new ObjectClass(objectClassType));

        String clientUuid = client.get("id").asText();
        builder.setUid(clientUuid);
        builder.setName(client.get("clientId").asText());

        builder.addAttribute(OperationalAttributes.ENABLE_NAME,
                client.path("enabled").asBoolean(true));
        builder.addAttribute(KeycloakClientConnector.ATTR_SERVICE_ACCOUNTS_ENABLED,
                client.path("serviceAccountsEnabled").asBoolean(false));

        if (client.has("description") && !client.get("description").isNull())
            builder.addAttribute(KeycloakClientConnector.ATTR_DESCRIPTION, client.get("description").asText());
        if (client.has("name") && !client.get("name").isNull())
            builder.addAttribute(KeycloakClientConnector.ATTR_CLIENT_NAME, client.get("name").asText());

        // Scopes
        if (client.has("defaultClientScopes")) {
            List<String> scopes = new ArrayList<>();
            client.get("defaultClientScopes").forEach(s -> scopes.add(s.asText()));
            builder.addAttribute(KeycloakClientConnector.ATTR_DEFAULT_SCOPES, scopes);
        }
        if (client.has("optionalClientScopes")) {
            List<String> scopes = new ArrayList<>();
            client.get("optionalClientScopes").forEach(s -> scopes.add(s.asText()));
            builder.addAttribute(KeycloakClientConnector.ATTR_OPTIONAL_SCOPES, scopes);
        }

        // Client attributes
        if (client.has("attributes") && client.get("attributes").isObject()) {
            JsonNode attrs = client.get("attributes");
            for (String key : CLIENT_ATTRS) {
                if (attrs.has(key)) builder.addAttribute(key, attrs.get(key).asText());
            }
        }

        // Service account user attributes (fetched from SA user entity)
        Map<String, String> saAttrs = getServiceAccountAttributes(clientUuid);
        for (Map.Entry<String, String> entry : saAttrs.entrySet()) {
            builder.addAttribute(entry.getKey(), entry.getValue());
        }

        return builder.build();
    }
}
