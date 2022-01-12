package controllers;

import client.AuthServiceClient;
import com.datahub.authentication.Authentication;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.linkedin.common.AuditStamp;
import com.linkedin.common.urn.CorpuserUrn;
import com.linkedin.common.urn.Urn;
import com.linkedin.entity.Entity;
import com.linkedin.entity.client.EntityClient;
import com.linkedin.events.metadata.ChangeType;
import com.linkedin.identity.CorpUserInfo;
import com.linkedin.identity.CorpUserStatus;
import com.linkedin.metadata.Constants;
import com.linkedin.metadata.aspect.CorpUserAspect;
import com.linkedin.metadata.aspect.CorpUserAspectArray;
import com.linkedin.metadata.snapshot.CorpUserSnapshot;
import com.linkedin.metadata.snapshot.Snapshot;
import com.linkedin.metadata.utils.GenericAspectUtils;
import com.linkedin.mxe.MetadataChangeProposal;
import com.linkedin.r2.RemoteInvocationException;
import com.typesafe.config.Config;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Optional;

import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.client.Client;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.play.PlayWebContext;
import org.pac4j.play.http.PlayHttpActionAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.http.HttpEntity;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import auth.AuthUtils;
import auth.JAASConfigs;
import auth.sso.SsoManager;
import security.AuthenticationManager;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.naming.NamingException;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import static auth.AuthUtils.*;

// TODO add logging.
public class AuthenticationController extends Controller {

    private static final String AUTH_REDIRECT_URI_PARAM = "redirect_uri";

    private final Logger _logger = LoggerFactory.getLogger(AuthenticationController.class.getName());
    private final Config _configs;
    private final JAASConfigs _jaasConfigs;

    @Inject
    private org.pac4j.core.config.Config _ssoConfig;

    @Inject
    private SessionStore _playSessionStore;

    @Inject
    private SsoManager _ssoManager;

    @Inject
    AuthServiceClient _authClient;

    @Inject
    private EntityClient entityClient;

    @Inject
    private Authentication systemAuthentication;

    @Inject
    public AuthenticationController(@Nonnull Config configs) {
        _configs = configs;
        _jaasConfigs = new JAASConfigs(configs);
    }

    /**
     * Route used to perform authentication, or redirect to log in if authentication fails.
     *
     * If indirect SSO (eg. oidc) is configured, this route will redirect to the identity provider (Indirect auth).
     * If not, we will fallback to the default username / password login experience (Direct auth).
     */
    @Nonnull
    public Result authenticate() {

        // TODO: Call getAuthenticatedUser and then generate a session cookie for the UI if the user is authenticated.

        final Optional<String> maybeRedirectPath = Optional.ofNullable(ctx().request().getQueryString(AUTH_REDIRECT_URI_PARAM));
        final String redirectPath = maybeRedirectPath.orElse("/");

        if (AuthUtils.hasValidSessionCookie(ctx())) {
            return redirect(redirectPath);
        }

        // 1. Use mail id in header if the user is already authenticated in
        // engweb.
        Optional<String> email = ctx().request().header("X-User-Email");
        if (email.isPresent()) {
            CorpuserUrn userUrn = new CorpuserUrn(email.get());
            tryProvision(userUrn);
            final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
            session().put(ACCESS_TOKEN, accessToken);
            session().put(ACTOR, userUrn.toString());
            return redirect(redirectPath)
                    .withCookies(createActorCookie(userUrn.toString(), _configs.hasPath(SESSION_TTL_CONFIG_PATH)
                            ? _configs.getInt(SESSION_TTL_CONFIG_PATH)
                            : DEFAULT_SESSION_TTL_HOURS));
        }

        // 2. If SSO is enabled, redirect to IdP if not authenticated.
        if (_ssoManager.isSsoEnabled()) {
            return redirectToIdentityProvider();
        }

        // 3. If JAAS auth is enabled, fallback to it
        if (_jaasConfigs.isJAASEnabled()) {
            return redirect(LOGIN_ROUTE + String.format("?%s=%s", AUTH_REDIRECT_URI_PARAM,  encodeRedirectUri(redirectPath)));
        }

        return new Result(Http.Status.FORBIDDEN);
    }

    /**
     * Log in a user based on a username + password.
     *
     * TODO: Implement built-in support for LDAP auth. Currently dummy jaas authentication is the default.
     */
    @Nonnull
    public Result logIn() {
        if (!_jaasConfigs.isJAASEnabled()) {
            final ObjectNode error = Json.newObject();
            error.put("message", "JAAS authentication is not enabled on the server.");
            return badRequest(error);
        }

        final JsonNode json = request().body().asJson();
        final String username = json.findPath(USER_NAME).textValue();
        final String password = json.findPath(PASSWORD).textValue();

        if (StringUtils.isBlank(username)) {
            JsonNode invalidCredsJson = Json.newObject()
                .put("message", "User name must not be empty.");
            return badRequest(invalidCredsJson);
        }

        ctx().session().clear();

        try {
            AuthenticationManager.authenticateUser(username, password);
        } catch (NamingException e) {
            _logger.error("Authentication error", e);
            JsonNode invalidCredsJson = Json.newObject()
                .put("message", "Invalid Credentials");
            return badRequest(invalidCredsJson);
        }


        final Urn actorUrn = new CorpuserUrn(username);
        final String accessToken = _authClient.generateSessionTokenForUser(actorUrn.getId());
        ctx().session().put(ACTOR, actorUrn.toString());
        ctx().session().put(ACCESS_TOKEN, accessToken);
        return ok().withCookies(Http.Cookie.builder(ACTOR, actorUrn.toString())
            .withHttpOnly(false)
            .withMaxAge(Duration.of(30, ChronoUnit.DAYS))
            .build());
    }

    private Result redirectToIdentityProvider() {
        final PlayWebContext playWebContext = new PlayWebContext(ctx(), _playSessionStore);
        final Client client = _ssoManager.getSsoProvider().client();
        final HttpAction action = client.redirect(playWebContext);
        return new PlayHttpActionAdapter().adapt(action.getCode(), playWebContext);
    }

    private String encodeRedirectUri(final String redirectUri) {
        try {
            return URLEncoder.encode(redirectUri, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(String.format("Failed to encode redirect URI %s", redirectUri), e);
        }
    }

    /**
     * tryProvision provisions the given user if it is not already available,
     * and updates its last accessed timestamp.
     */
    @SneakyThrows
    private void tryProvision(CorpuserUrn urn) {
        CorpUserSnapshot corpUserSnapshot = new CorpUserSnapshot();
        corpUserSnapshot.setUrn(urn);
        CorpUserInfo corpUserInfo = new CorpUserInfo();
        corpUserInfo.setActive(true);
        corpUserInfo.setEmail(urn.getUsernameEntity());
        CorpUserAspectArray aspects = new CorpUserAspectArray();
        aspects.add(CorpUserAspect.create(corpUserInfo));
        corpUserSnapshot.setAspects(aspects);
        Entity corpUser = entityClient.get(corpUserSnapshot.getUrn(), systemAuthentication);
        CorpUserSnapshot existingUserSnapshot = corpUser.getValue().getCorpUserSnapshot();
        if (existingUserSnapshot.getAspects().size() <= 1) {
            Entity newEntity = new Entity();
            newEntity.setValue(Snapshot.create(corpUserSnapshot));
            entityClient.update(newEntity, systemAuthentication);
        }
        MetadataChangeProposal proposal = new MetadataChangeProposal();
        proposal.setEntityUrn(urn);
        proposal.setEntityType(Constants.CORP_USER_ENTITY_NAME);
        proposal.setAspectName(Constants.CORP_USER_STATUS_ASPECT_NAME);
        CorpUserStatus status = new CorpUserStatus()
                .setStatus(Constants.CORP_USER_STATUS_ACTIVE)
                .setLastModified(new AuditStamp()
                        .setActor(Urn.createFromString(Constants.SYSTEM_ACTOR))
                        .setTime(System.currentTimeMillis()));
        proposal.setAspect(GenericAspectUtils.serializeAspect(status));
        proposal.setChangeType(ChangeType.UPSERT);
        entityClient.ingestProposal(proposal, systemAuthentication);
    }
}
