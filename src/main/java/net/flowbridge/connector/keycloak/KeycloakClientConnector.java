package net.flowbridge.connector.keycloak;

import com.evolveum.polygon.rest.AbstractRestConnector;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;

import java.util.Set;

/**
 * ConnId connector for managing Keycloak OAuth clients and host connectors.
 * <p>
 * Supports two object classes:
 * <ul>
 *   <li><b>OAuthClient</b> — Agent OAuth clients (client_credentials, JMAP + relay scopes)</li>
 *   <li><b>HostConnector</b> — Host connector clients (client_credentials, relay:host scope)</li>
 * </ul>
 * Both use UUID-based clientIds. Human-readable names go in the client {@code name} field
 * and service account user attributes.
 * <p>
 * Service account user attributes (org_id, agent_identity, host_id, etc.) are set on the
 * Keycloak service account user entity — not on the client attributes — because protocol
 * mappers read from user attributes to populate JWT claims.
 */
@ConnectorClass(
        displayNameKey = "connector.keycloak.clients.display",
        configurationClass = KeycloakClientConfiguration.class
)
public class KeycloakClientConnector
        extends AbstractRestConnector<KeycloakClientConfiguration>
        implements CreateOp, UpdateOp, DeleteOp, SearchOp<KeycloakClientFilter>, TestOp, SchemaOp {

    private static final Log LOG = Log.getLog(KeycloakClientConnector.class);

    // Object classes
    public static final String OBJECT_CLASS_CLIENT = "OAuthClient";
    public static final String OBJECT_CLASS_HOST = "HostConnector";

    // Shared attributes
    public static final String ATTR_ENABLED = OperationalAttributes.ENABLE_NAME;
    public static final String ATTR_SERVICE_ACCOUNTS_ENABLED = "serviceAccountsEnabled";
    public static final String ATTR_DEFAULT_SCOPES = "defaultClientScopes";
    public static final String ATTR_OPTIONAL_SCOPES = "optionalClientScopes";
    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_CLIENT_NAME = "clientName";
    public static final String ATTR_CLIENT_SECRET = "clientSecret";

    // Service account user attributes (mapped to JWT claims via protocol mappers)
    public static final String ATTR_ORG_ID = "org_id";
    public static final String ATTR_AGENT_IDENTITY = "agent_identity";
    public static final String ATTR_HOST_ID = "host_id";
    public static final String ATTR_GROUP_ID = "group_id";
    public static final String ATTR_FRIENDLY_NAME = "friendly_name";

    // Agent-specific client attributes (stored on client, not SA user)
    public static final String ATTR_AGENT_MAILBOX = "agent_mailbox";
    public static final String ATTR_AGENT_CLASS = "agent_class";

    private KeycloakClientOperations operations;

    @Override
    public void init(Configuration configuration) {
        super.init(configuration);
        this.operations = new KeycloakClientOperations(getConfiguration(), this);
        LOG.info("Keycloak Client connector initialized for realm: {0}",
                getConfiguration().getRealm());
    }

    @Override
    public Schema schema() {
        SchemaBuilder schemaBuilder = new SchemaBuilder(KeycloakClientConnector.class);

        // ---- OAuthClient (agent) ----
        schemaBuilder.defineObjectClass(buildAgentSchema());

        // ---- HostConnector ----
        schemaBuilder.defineObjectClass(buildHostSchema());

        return schemaBuilder.build();
    }

    private ObjectClassInfo buildAgentSchema() {
        ObjectClassInfoBuilder b = new ObjectClassInfoBuilder();
        b.setType(OBJECT_CLASS_CLIENT);

        // clientId (UUID)
        b.addAttributeInfo(AttributeInfoBuilder.build(Name.NAME, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(Uid.NAME, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_ENABLED, Boolean.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_SERVICE_ACCOUNTS_ENABLED, Boolean.class));

        // Scopes
        b.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DEFAULT_SCOPES)
                .setType(String.class).setMultiValued(true).build());
        b.addAttributeInfo(AttributeInfoBuilder.define(ATTR_OPTIONAL_SCOPES)
                .setType(String.class).setMultiValued(true).build());

        // Descriptive
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_DESCRIPTION, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_CLIENT_NAME, String.class));

        // Service account user attributes (JWT claims)
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_ORG_ID, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_AGENT_IDENTITY, String.class));

        // Client attributes
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_AGENT_MAILBOX, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_AGENT_CLASS, String.class));

        // Client secret (read-only)
        b.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CLIENT_SECRET)
                .setType(String.class).setReturnedByDefault(false)
                .setReadable(true).setCreateable(false).setUpdateable(false).build());

        return b.build();
    }

    private ObjectClassInfo buildHostSchema() {
        ObjectClassInfoBuilder b = new ObjectClassInfoBuilder();
        b.setType(OBJECT_CLASS_HOST);

        // clientId (UUID)
        b.addAttributeInfo(AttributeInfoBuilder.build(Name.NAME, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(Uid.NAME, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_ENABLED, Boolean.class));

        // Scopes
        b.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DEFAULT_SCOPES)
                .setType(String.class).setMultiValued(true).build());

        // Descriptive
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_DESCRIPTION, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_CLIENT_NAME, String.class));

        // Service account user attributes (JWT claims)
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_ORG_ID, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_HOST_ID, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_GROUP_ID, String.class));
        b.addAttributeInfo(AttributeInfoBuilder.build(ATTR_FRIENDLY_NAME, String.class));

        // Client secret (read-only)
        b.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CLIENT_SECRET)
                .setType(String.class).setReturnedByDefault(false)
                .setReadable(true).setCreateable(false).setUpdateable(false).build());

        return b.build();
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes,
                      OperationOptions options) {
        String oc = objectClass.getObjectClassValue();
        if (OBJECT_CLASS_CLIENT.equals(oc)) {
            LOG.info("Creating agent OAuth client");
            return operations.createClient(createAttributes, false);
        } else if (OBJECT_CLASS_HOST.equals(oc)) {
            LOG.info("Creating host connector client");
            return operations.createClient(createAttributes, true);
        }
        throw new ConnectorException("Unsupported object class: " + objectClass);
    }

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes,
                      OperationOptions options) {
        String oc = objectClass.getObjectClassValue();
        if (OBJECT_CLASS_CLIENT.equals(oc) || OBJECT_CLASS_HOST.equals(oc)) {
            LOG.info("Updating Keycloak client: {0}", uid.getUidValue());
            return operations.replaceClient(uid, replaceAttributes, OBJECT_CLASS_HOST.equals(oc));
        }
        throw new ConnectorException("Unsupported object class: " + objectClass);
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        String oc = objectClass.getObjectClassValue();
        if (OBJECT_CLASS_CLIENT.equals(oc) || OBJECT_CLASS_HOST.equals(oc)) {
            LOG.info("Deleting Keycloak client: {0}", uid.getUidValue());
            operations.deleteClient(uid);
            return;
        }
        throw new ConnectorException("Unsupported object class: " + objectClass);
    }

    @Override
    public FilterTranslator<KeycloakClientFilter> createFilterTranslator(
            ObjectClass objectClass, OperationOptions options) {
        return new KeycloakClientFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, KeycloakClientFilter query,
                             ResultsHandler handler, OperationOptions options) {
        String oc = objectClass.getObjectClassValue();
        if (OBJECT_CLASS_CLIENT.equals(oc) || OBJECT_CLASS_HOST.equals(oc)) {
            operations.searchClients(query, handler, oc);
            return;
        }
        throw new ConnectorException("Unsupported object class: " + objectClass);
    }

    @Override
    public void test() {
        LOG.info("Testing Keycloak connection");
        operations.testConnection();
    }
}
