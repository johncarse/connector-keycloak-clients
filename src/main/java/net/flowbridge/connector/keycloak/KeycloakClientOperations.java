package net.flowbridge.connector.keycloak;

import com.evolveum.polygon.rest.AbstractRestConnector;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Implements CRUD operations against the Keycloak Admin REST API for OAuth clients.
 * <p>
 * API reference: https://www.keycloak.org/docs-api/latest/rest-api/index.html
 * <p>
 * Endpoints used:
 *   GET    /admin/realms/{realm}/clients?clientId={clientId}
 *   GET    /admin/realms/{realm}/clients/{id}
 *   POST   /admin/realms/{realm}/clients
 *   PUT    /admin/realms/{realm}/clients/{id}
 *   DELETE /admin/realms/{realm}/clients/{id}
 *   GET    /admin/realms/{realm}/clients/{id}/client-secret
 */
public class KeycloakClientOperations {

    private static final Log LOG = Log.getLog(KeycloakClientOperations.class);

    private final KeycloakClientConfiguration config;
    private final AbstractRestConnector<?> connector;
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private String cachedAccessToken;
    private long tokenExpiresAt;

    public KeycloakClientOperations(KeycloakClientConfiguration config,
                                    AbstractRestConnector<?> connector) {
        this.config = config;
        this.connector = connector;
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

        // Extract password from GuardedString
        final StringBuilder secret = new StringBuilder();
        config.getPassword().access(chars -> secret.append(new String(chars)));
        body.append("&client_secret=").append(URLEncoder.encode(secret.toString(), StandardCharsets.UTF_8));

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new ConnectorException("Failed to obtain access token: HTTP "
                        + response.statusCode() + " " + response.body());
            }

            JsonNode tokenResponse = mapper.readTree(response.body());
            cachedAccessToken = tokenResponse.get("access_token").asText();
            int expiresIn = tokenResponse.get("expires_in").asInt(300);
            tokenExpiresAt = (System.currentTimeMillis() / 1000) + expiresIn;

            LOG.info("Obtained Keycloak access token, expires in {0}s", expiresIn);
            return cachedAccessToken;

        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Failed to obtain access token", e);
        }
    }

    // ---- API Helpers ----

    private String adminBaseUrl() {
        String addr = config.getServiceAddress();
        // Ensure it ends with /admin/realms/{realm}
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
            HttpRequest request = apiRequest(path).GET().build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 404) {
                return null;
            }
            if (response.statusCode() >= 400) {
                throw new ConnectorException("Keycloak API error: HTTP "
                        + response.statusCode() + " on GET " + path + ": " + response.body());
            }
            return mapper.readTree(response.body());
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak API request failed: GET " + path, e);
        }
    }

    private String apiPost(String path, String jsonBody) {
        try {
            HttpRequest request = apiRequest(path)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 409) {
                throw new AlreadyExistsException("Client already exists");
            }
            if (response.statusCode() == 201) {
                // Extract UUID from Location header
                String location = response.headers().firstValue("Location").orElse("");
                return location.substring(location.lastIndexOf('/') + 1);
            }
            if (response.statusCode() >= 400) {
                throw new ConnectorException("Keycloak API error: HTTP "
                        + response.statusCode() + " on POST " + path + ": " + response.body());
            }
            return response.body();
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak API request failed: POST " + path, e);
        }
    }

    private void apiPut(String path, String jsonBody) {
        try {
            HttpRequest request = apiRequest(path)
                    .PUT(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 404) {
                throw new UnknownUidException("Client not found");
            }
            if (response.statusCode() >= 400) {
                throw new ConnectorException("Keycloak API error: HTTP "
                        + response.statusCode() + " on PUT " + path + ": " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak API request failed: PUT " + path, e);
        }
    }

    private void apiDelete(String path) {
        try {
            HttpRequest request = apiRequest(path).DELETE().build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 404) {
                throw new UnknownUidException("Client not found");
            }
            if (response.statusCode() >= 400) {
                throw new ConnectorException("Keycloak API error: HTTP "
                        + response.statusCode() + " on DELETE " + path + ": " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            throw new ConnectorException("Keycloak API request failed: DELETE " + path, e);
        }
    }

    // ---- CRUD Operations ----

    public Uid createClient(Set<Attribute> attributes) {
        ObjectNode clientRep = mapper.createObjectNode();

        String clientIdValue = null;
        for (Attribute attr : attributes) {
            switch (attr.getName()) {
                case Name.NAME:
                    clientIdValue = AttributeUtil.getStringValue(attr);
                    clientRep.put("clientId", clientIdValue);
                    break;
                case OperationalAttributes.ENABLE_NAME:
                    clientRep.put("enabled", AttributeUtil.getBooleanValue(attr));
                    break;
                case KeycloakClientConnector.ATTR_SERVICE_ACCOUNTS_ENABLED:
                    clientRep.put("serviceAccountsEnabled", AttributeUtil.getBooleanValue(attr));
                    break;
                case KeycloakClientConnector.ATTR_DESCRIPTION:
                    clientRep.put("description", AttributeUtil.getStringValue(attr));
                    break;
                case KeycloakClientConnector.ATTR_CLIENT_NAME:
                    clientRep.put("name", AttributeUtil.getStringValue(attr));
                    break;
                case KeycloakClientConnector.ATTR_DEFAULT_SCOPES:
                    ArrayNode defaultScopes = mapper.createArrayNode();
                    attr.getValue().forEach(v -> defaultScopes.add(v.toString()));
                    clientRep.set("defaultClientScopes", defaultScopes);
                    break;
                case KeycloakClientConnector.ATTR_OPTIONAL_SCOPES:
                    ArrayNode optScopes = mapper.createArrayNode();
                    attr.getValue().forEach(v -> optScopes.add(v.toString()));
                    clientRep.set("optionalClientScopes", optScopes);
                    break;
                case KeycloakClientConnector.ATTR_AGENT_MAILBOX:
                case KeycloakClientConnector.ATTR_AGENT_CLASS:
                    // Store as client attributes
                    if (!clientRep.has("attributes")) {
                        clientRep.set("attributes", mapper.createObjectNode());
                    }
                    ((ObjectNode) clientRep.get("attributes"))
                            .put(attr.getName(), AttributeUtil.getStringValue(attr));
                    break;
            }
        }

        // Defaults for agent clients
        if (!clientRep.has("serviceAccountsEnabled")) {
            clientRep.put("serviceAccountsEnabled", true);
        }
        if (!clientRep.has("enabled")) {
            clientRep.put("enabled", true);
        }
        // Client credentials only
        clientRep.put("standardFlowEnabled", false);
        clientRep.put("implicitFlowEnabled", false);
        clientRep.put("directAccessGrantsEnabled", false);
        clientRep.put("clientAuthenticatorType", "client-secret");

        try {
            String uuid = apiPost("/clients", mapper.writeValueAsString(clientRep));
            LOG.info("Created Keycloak client {0} with UUID {1}", clientIdValue, uuid);
            return new Uid(uuid);
        } catch (IOException e) {
            throw new ConnectorException("Failed to serialize client representation", e);
        }
    }

    public Set<AttributeDelta> updateClient(Uid uid, Set<AttributeDelta> modifications) {
        // Get current state
        JsonNode existing = apiGet("/clients/" + uid.getUidValue());
        if (existing == null) {
            throw new UnknownUidException(uid.getUidValue());
        }

        ObjectNode updated = (ObjectNode) existing;
        for (AttributeDelta delta : modifications) {
            switch (delta.getName()) {
                case OperationalAttributes.ENABLE_NAME:
                    if (delta.getValuesToReplace() != null && !delta.getValuesToReplace().isEmpty()) {
                        updated.put("enabled", (Boolean) delta.getValuesToReplace().get(0));
                    }
                    break;
                case KeycloakClientConnector.ATTR_DEFAULT_SCOPES:
                    if (delta.getValuesToReplace() != null) {
                        ArrayNode scopes = mapper.createArrayNode();
                        delta.getValuesToReplace().forEach(v -> scopes.add(v.toString()));
                        updated.set("defaultClientScopes", scopes);
                    }
                    break;
                case KeycloakClientConnector.ATTR_OPTIONAL_SCOPES:
                    if (delta.getValuesToReplace() != null) {
                        ArrayNode scopes = mapper.createArrayNode();
                        delta.getValuesToReplace().forEach(v -> scopes.add(v.toString()));
                        updated.set("optionalClientScopes", scopes);
                    }
                    break;
                case KeycloakClientConnector.ATTR_DESCRIPTION:
                    if (delta.getValuesToReplace() != null && !delta.getValuesToReplace().isEmpty()) {
                        updated.put("description", delta.getValuesToReplace().get(0).toString());
                    }
                    break;
                case KeycloakClientConnector.ATTR_AGENT_MAILBOX:
                case KeycloakClientConnector.ATTR_AGENT_CLASS:
                    if (delta.getValuesToReplace() != null && !delta.getValuesToReplace().isEmpty()) {
                        ObjectNode attrs = updated.has("attributes")
                                ? (ObjectNode) updated.get("attributes")
                                : mapper.createObjectNode();
                        attrs.put(delta.getName(), delta.getValuesToReplace().get(0).toString());
                        updated.set("attributes", attrs);
                    }
                    break;
            }
        }

        try {
            apiPut("/clients/" + uid.getUidValue(), mapper.writeValueAsString(updated));
        } catch (IOException e) {
            throw new ConnectorException("Failed to serialize client update", e);
        }
        return Collections.emptySet();
    }

    public Uid replaceClient(Uid uid, Set<Attribute> replaceAttributes) {
        Set<AttributeDelta> deltas = new HashSet<>();
        for (Attribute attr : replaceAttributes) {
            deltas.add(AttributeDeltaBuilder.build(attr.getName(), attr.getValue()));
        }
        updateClient(uid, deltas);
        return uid;
    }

    public void deleteClient(Uid uid) {
        apiDelete("/clients/" + uid.getUidValue());
        LOG.info("Deleted Keycloak client {0}", uid.getUidValue());
    }

    public void searchClients(KeycloakClientFilter filter, ResultsHandler handler) {
        if (filter != null && filter.getType() == KeycloakClientFilter.FilterType.BY_UID) {
            JsonNode client = apiGet("/clients/" + filter.getValue());
            if (client != null) {
                handler.handle(clientToConnectorObject(client));
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
                if (!handler.handle(clientToConnectorObject(client))) {
                    break;
                }
            }
        }
    }

    public void testConnection() {
        // Attempt to list clients — if auth or connectivity fails, this throws
        JsonNode result = apiGet("/clients?max=1");
        if (result == null) {
            throw new ConnectorException("Failed to connect to Keycloak Admin API");
        }
        LOG.info("Keycloak connection test successful");
    }

    // ---- Mapping ----

    private ConnectorObject clientToConnectorObject(JsonNode client) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(new ObjectClass(KeycloakClientConnector.OBJECT_CLASS_CLIENT));

        builder.setUid(client.get("id").asText());
        builder.setName(client.get("clientId").asText());

        builder.addAttribute(OperationalAttributes.ENABLE_NAME,
                client.path("enabled").asBoolean(true));

        builder.addAttribute(KeycloakClientConnector.ATTR_SERVICE_ACCOUNTS_ENABLED,
                client.path("serviceAccountsEnabled").asBoolean(false));

        if (client.has("description") && !client.get("description").isNull()) {
            builder.addAttribute(KeycloakClientConnector.ATTR_DESCRIPTION,
                    client.get("description").asText());
        }

        if (client.has("name") && !client.get("name").isNull()) {
            builder.addAttribute(KeycloakClientConnector.ATTR_CLIENT_NAME,
                    client.get("name").asText());
        }

        // Default client scopes
        if (client.has("defaultClientScopes")) {
            List<String> scopes = new ArrayList<>();
            client.get("defaultClientScopes").forEach(s -> scopes.add(s.asText()));
            builder.addAttribute(KeycloakClientConnector.ATTR_DEFAULT_SCOPES, scopes);
        }

        // Optional client scopes
        if (client.has("optionalClientScopes")) {
            List<String> scopes = new ArrayList<>();
            client.get("optionalClientScopes").forEach(s -> scopes.add(s.asText()));
            builder.addAttribute(KeycloakClientConnector.ATTR_OPTIONAL_SCOPES, scopes);
        }

        // Client attributes
        if (client.has("attributes") && client.get("attributes").isObject()) {
            JsonNode attrs = client.get("attributes");
            if (attrs.has("agent_mailbox")) {
                builder.addAttribute(KeycloakClientConnector.ATTR_AGENT_MAILBOX,
                        attrs.get("agent_mailbox").asText());
            }
            if (attrs.has("agent_class")) {
                builder.addAttribute(KeycloakClientConnector.ATTR_AGENT_CLASS,
                        attrs.get("agent_class").asText());
            }
        }

        return builder.build();
    }
}
