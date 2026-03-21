package net.flowbridge.connector.keycloak;

import com.evolveum.polygon.rest.AbstractRestConnector;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;

import java.util.Set;

/**
 * ConnId connector for managing Keycloak OAuth clients (confidential clients with service accounts).
 * <p>
 * Designed for the Flowbridge Agent Identity Platform. Each agent gets a confidential client
 * in the ai-flowbridge realm with client_credentials grant and JMAP scopes.
 * <p>
 * Managed attributes:
 * - clientId (Name)
 * - enabled
 * - serviceAccountsEnabled
 * - defaultClientScopes
 * - optionalClientScopes
 * - client attributes (agent_mailbox, agent_class, etc.)
 */
@ConnectorClass(
        displayNameKey = "connector.keycloak.clients.display",
        configurationClass = KeycloakClientConfiguration.class
)
public class KeycloakClientConnector
        extends AbstractRestConnector<KeycloakClientConfiguration>
        implements CreateOp, UpdateOp, DeleteOp, SearchOp<KeycloakClientFilter>, TestOp, SchemaOp {

    private static final Log LOG = Log.getLog(KeycloakClientConnector.class);

    public static final String OBJECT_CLASS_CLIENT = "OAuthClient";

    // Attribute names
    public static final String ATTR_CLIENT_ID = Name.NAME; // maps to Keycloak clientId
    public static final String ATTR_ENABLED = OperationalAttributes.ENABLE_NAME;
    public static final String ATTR_SERVICE_ACCOUNTS_ENABLED = "serviceAccountsEnabled";
    public static final String ATTR_DEFAULT_SCOPES = "defaultClientScopes";
    public static final String ATTR_OPTIONAL_SCOPES = "optionalClientScopes";
    public static final String ATTR_DESCRIPTION = "description";
    public static final String ATTR_CLIENT_NAME = "clientName";
    public static final String ATTR_AGENT_MAILBOX = "agent_mailbox";
    public static final String ATTR_AGENT_CLASS = "agent_class";
    public static final String ATTR_CLIENT_SECRET = "clientSecret";

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

        ObjectClassInfoBuilder clientBuilder = new ObjectClassInfoBuilder();
        clientBuilder.setType(OBJECT_CLASS_CLIENT);

        // clientId — the unique identifier
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                Name.NAME, String.class));

        // Keycloak internal UUID
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                Uid.NAME, String.class));

        // enabled/disabled
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_ENABLED, Boolean.class));

        // Service accounts
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_SERVICE_ACCOUNTS_ENABLED, Boolean.class));

        // Scopes (multi-valued)
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_DEFAULT_SCOPES)
                .setType(String.class)
                .setMultiValued(true)
                .build());

        clientBuilder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_OPTIONAL_SCOPES)
                .setType(String.class)
                .setMultiValued(true)
                .build());

        // Descriptive fields
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_DESCRIPTION, String.class));
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_CLIENT_NAME, String.class));

        // Agent-specific attributes
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_AGENT_MAILBOX, String.class));
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.build(
                ATTR_AGENT_CLASS, String.class));

        // Client secret (read-only, returned after creation)
        clientBuilder.addAttributeInfo(AttributeInfoBuilder.define(ATTR_CLIENT_SECRET)
                .setType(String.class)
                .setReturnedByDefault(false)
                .setReadable(true)
                .setCreateable(false)
                .setUpdateable(false)
                .build());

        schemaBuilder.defineObjectClass(clientBuilder.build());
        return schemaBuilder.build();
    }

    @Override
    public Uid create(ObjectClass objectClass, Set<Attribute> createAttributes,
                      OperationOptions options) {
        validateObjectClass(objectClass);
        LOG.info("Creating Keycloak client");
        return operations.createClient(createAttributes);
    }

    @Override
    public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid,
                                           Set<AttributeDelta> modifications,
                                           OperationOptions options) {
        validateObjectClass(objectClass);
        LOG.info("Updating Keycloak client: {0}", uid.getUidValue());
        return operations.updateClient(uid, modifications);
    }

    @Override
    public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes,
                      OperationOptions options) {
        validateObjectClass(objectClass);
        LOG.info("Replacing Keycloak client attributes: {0}", uid.getUidValue());
        return operations.replaceClient(uid, replaceAttributes);
    }

    @Override
    public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
        validateObjectClass(objectClass);
        LOG.info("Deleting Keycloak client: {0}", uid.getUidValue());
        operations.deleteClient(uid);
    }

    @Override
    public FilterTranslator<KeycloakClientFilter> createFilterTranslator(
            ObjectClass objectClass, OperationOptions options) {
        return new KeycloakClientFilterTranslator();
    }

    @Override
    public void executeQuery(ObjectClass objectClass, KeycloakClientFilter query,
                             ResultsHandler handler, OperationOptions options) {
        validateObjectClass(objectClass);
        LOG.info("Searching Keycloak clients");
        operations.searchClients(query, handler);
    }

    @Override
    public void test() {
        LOG.info("Testing Keycloak connection");
        operations.testConnection();
    }

    private void validateObjectClass(ObjectClass objectClass) {
        if (!OBJECT_CLASS_CLIENT.equals(objectClass.getObjectClassValue())) {
            throw new ConnectorException("Unsupported object class: " + objectClass);
        }
    }
}
