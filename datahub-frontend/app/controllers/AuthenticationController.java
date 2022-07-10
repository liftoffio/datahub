package controllers;

import auth.AuthUtils;
import auth.JAASConfigs;
import auth.NativeAuthenticationConfigs;
import auth.sso.SsoManager;
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
import com.linkedin.metadata.utils.GenericRecordUtils;
import com.linkedin.mxe.MetadataChangeProposal;
import com.typesafe.config.Config;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.client.Client;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.play.PlayWebContext;
import org.pac4j.play.http.PlayHttpActionAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import security.AuthenticationManager;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static auth.AuthUtils.*;
import static org.pac4j.core.client.IndirectClient.ATTEMPTED_AUTHENTICATION_SUFFIX;


// TODO add logging.
public class AuthenticationController extends Controller {

    private static final String AUTH_REDIRECT_URI_PARAM = "redirect_uri";

    private final Logger _logger = LoggerFactory.getLogger(AuthenticationController.class.getName());
    private final Config _configs;
    private final JAASConfigs _jaasConfigs;
    private final NativeAuthenticationConfigs _nativeAuthenticationConfigs;

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
        _nativeAuthenticationConfigs = new NativeAuthenticationConfigs(configs);
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

        // 0. Use mail id in header if the user is already authenticated in
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

        // 1. If SSO is enabled, redirect to IdP if not authenticated.
        if (_ssoManager.isSsoEnabled()) {
            return redirectToIdentityProvider();
        }

        // 2. If either JAAS auth or Native auth is enabled, fallback to it
        if (_jaasConfigs.isJAASEnabled() || _nativeAuthenticationConfigs.isNativeAuthenticationEnabled()) {
            return redirect(
                    LOGIN_ROUTE + String.format("?%s=%s", AUTH_REDIRECT_URI_PARAM, encodeRedirectUri(redirectPath)));
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
        boolean jaasEnabled = _jaasConfigs.isJAASEnabled();
        _logger.debug(String.format("Jaas authentication enabled: %b", jaasEnabled));
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        boolean noAuthEnabled = !jaasEnabled && !nativeAuthenticationEnabled;
        if (noAuthEnabled) {
            String message = "Neither JAAS nor native authentication is enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return badRequest(error);
        }

        final JsonNode json = request().body().asJson();
        final String username = json.findPath(USER_NAME).textValue();
        final String password = json.findPath(PASSWORD).textValue();

        if (StringUtils.isBlank(username)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "User name must not be empty.");
            return badRequest(invalidCredsJson);
        }

        ctx().session().clear();

        JsonNode invalidCredsJson = Json.newObject().put("message", "Invalid Credentials");
        boolean loginSucceeded = tryLogin(username, password);

        if (!loginSucceeded) {
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

    /**
     * Sign up a native user based on a name, email, title, and password. The invite token must match the global invite
     * token stored for the DataHub instance.
     *
     */
    @Nonnull
    public Result signUp() {
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        if (!nativeAuthenticationEnabled) {
            String message = "Native authentication is not enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return badRequest(error);
        }

        final JsonNode json = request().body().asJson();
        final String fullName = json.findPath(FULL_NAME).textValue();
        final String email = json.findPath(EMAIL).textValue();
        final String title = json.findPath(TITLE).textValue();
        final String password = json.findPath(PASSWORD).textValue();
        final String inviteToken = json.findPath(INVITE_TOKEN).textValue();

        if (StringUtils.isBlank(fullName)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Full name must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(email)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Email must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(password)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Password must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(title)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Title must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(inviteToken)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Invite token must not be empty.");
            return badRequest(invalidCredsJson);
        }

        ctx().session().clear();

        final Urn userUrn = new CorpuserUrn(email);
        final String userUrnString = userUrn.toString();
        boolean isNativeUserCreated = _authClient.signUp(userUrnString, fullName, email, title, password, inviteToken);
        final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
        ctx().session().put(ACTOR, userUrnString);
        ctx().session().put(ACCESS_TOKEN, accessToken);
        return ok().withCookies(Http.Cookie.builder(ACTOR, userUrnString)
            .withHttpOnly(false)
            .withMaxAge(Duration.of(30, ChronoUnit.DAYS))
            .build());
    }

    /**
     * Create a native user based on a name, email, and password.
     *
     */
    @Nonnull
    public Result resetNativeUserCredentials() {
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        if (!nativeAuthenticationEnabled) {
            String message = "Native authentication is not enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return badRequest(error);
        }

        final JsonNode json = request().body().asJson();
        final String email = json.findPath(EMAIL).textValue();
        final String password = json.findPath(PASSWORD).textValue();
        final String resetToken = json.findPath(RESET_TOKEN).textValue();

        if (StringUtils.isBlank(email)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Email must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(password)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Password must not be empty.");
            return badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(resetToken)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Reset token must not be empty.");
            return badRequest(invalidCredsJson);
        }

        ctx().session().clear();

        final Urn userUrn = new CorpuserUrn(email);
        final String userUrnString = userUrn.toString();
        boolean areNativeUserCredentialsReset =
            _authClient.resetNativeUserCredentials(userUrnString, password, resetToken);
        _logger.debug(String.format("Are native user credentials reset: %b", areNativeUserCredentialsReset));
        final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
        ctx().session().put(ACTOR, userUrnString);
        ctx().session().put(ACCESS_TOKEN, accessToken);
        return ok().withCookies(Http.Cookie.builder(ACTOR, userUrnString)
            .withHttpOnly(false)
            .withMaxAge(Duration.of(30, ChronoUnit.DAYS))
            .build());
    }

    private Result redirectToIdentityProvider() {
        final PlayWebContext playWebContext = new PlayWebContext(ctx(), _playSessionStore);
        final Client<?, ?> client = _ssoManager.getSsoProvider().client();

        // This is to prevent previous login attempts from being cached.
        // We replicate the logic here, which is buried in the Pac4j client.
        if (_playSessionStore.get(playWebContext, client.getName() + ATTEMPTED_AUTHENTICATION_SUFFIX) != null) {
            _logger.debug("Found previous login attempt. Removing it manually to prevent unexpected errors.");
            _playSessionStore.set(playWebContext, client.getName() + ATTEMPTED_AUTHENTICATION_SUFFIX, "");
        }
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

    private boolean tryLogin(String username, String password) {
        JsonNode invalidCredsJson = Json.newObject().put("message", "Invalid Credentials");
        boolean loginSucceeded = false;

        // First try jaas login, if enabled
        if (_jaasConfigs.isJAASEnabled()) {
            try {
                _logger.debug("Attempting jaas authentication");
                AuthenticationManager.authenticateJaasUser(username, password);
                loginSucceeded = true;
                _logger.debug("Jaas authentication successful");
            } catch (Exception e) {
                _logger.debug("Jaas authentication error", e);
            }
        }

        // If jaas login fails or is disabled, try native auth login
        if (_nativeAuthenticationConfigs.isNativeAuthenticationEnabled() && !loginSucceeded) {
            final Urn userUrn = new CorpuserUrn(username);
            final String userUrnString = userUrn.toString();
            loginSucceeded = loginSucceeded || _authClient.verifyNativeUserCredentials(userUrnString, password);
        }

        return loginSucceeded;
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
        proposal.setAspect(GenericRecordUtils.serializeAspect(status));
        proposal.setChangeType(ChangeType.UPSERT);
        entityClient.ingestProposal(proposal, systemAuthentication);
    }
}
