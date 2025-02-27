package controllers;

import auth.AuthUtils;
import auth.CookieConfigs;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.inject.Inject;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.client.Client;
import org.pac4j.core.exception.http.FoundAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.play.PlayWebContext;
import org.pac4j.play.http.PlayHttpActionAdapter;
import org.pac4j.play.store.PlaySessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;
import security.AuthenticationManager;

import static auth.AuthUtils.*;
import static auth.CookieConfigs.*;
import static org.pac4j.core.client.IndirectClient.*;


// TODO add logging.
public class AuthenticationController extends Controller {
    public static final String AUTH_VERBOSE_LOGGING = "auth.verbose.logging";
    private static final String AUTH_REDIRECT_URI_PARAM = "redirect_uri";
    private static final String ERROR_MESSAGE_URI_PARAM = "error_msg";
    private static final String SSO_DISABLED_ERROR_MESSAGE = "SSO is not configured";

    private static final String SSO_NO_REDIRECT_MESSAGE = "SSO is configured, however missing redirect from idp";

    private final Logger _logger = LoggerFactory.getLogger(AuthenticationController.class.getName());
    private final CookieConfigs _cookieConfigs;
    private final JAASConfigs _jaasConfigs;
    private final NativeAuthenticationConfigs _nativeAuthenticationConfigs;
    private final boolean _verbose;
    private EntityClient _entityClient;
    private Authentication _systemAuthentication;

    @Inject
    private org.pac4j.core.config.Config _ssoConfig;

    @Inject
    private PlaySessionStore _playSessionStore;

    @Inject
    private SsoManager _ssoManager;

    @Inject
    AuthServiceClient _authClient;

    @Inject
    public AuthenticationController(@Nonnull Config configs, @Nonnull EntityClient entityClient, @Nonnull Authentication authentication) {
        _cookieConfigs = new CookieConfigs(configs);
        _jaasConfigs = new JAASConfigs(configs);
        _nativeAuthenticationConfigs = new NativeAuthenticationConfigs(configs);
        _verbose = configs.hasPath(AUTH_VERBOSE_LOGGING) && configs.getBoolean(AUTH_VERBOSE_LOGGING);
        _entityClient = entityClient;
        _systemAuthentication = authentication;
    }

    /**
     * Route used to perform authentication, or redirect to log in if authentication fails.
     *
     * If indirect SSO (eg. oidc) is configured, this route will redirect to the identity provider (Indirect auth).
     * If not, we will fall back to the default username / password login experience (Direct auth).
     */
    @Nonnull
    public Result authenticate(Http.Request request) {

        // TODO: Call getAuthenticatedUser and then generate a session cookie for the UI if the user is authenticated.

        final Optional<String> maybeRedirectPath = Optional.ofNullable(request.getQueryString(AUTH_REDIRECT_URI_PARAM));
        final String redirectPath = maybeRedirectPath.orElse("/");

        if (AuthUtils.hasValidSessionCookie(request)) {
            return Results.redirect(redirectPath);
        }

        Optional<String> email = request.header("X-User-Email");
        if (email.isPresent()) {
            CorpuserUrn userUrn = new CorpuserUrn(email.get());
            tryProvision(userUrn);
            final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
            return createSession(userUrn.toString(), accessToken);
        }

        // 1. If SSO is enabled, redirect to IdP if not authenticated.
        if (_ssoManager.isSsoEnabled()) {
            return redirectToIdentityProvider(request, redirectPath).orElse(
                    Results.redirect(LOGIN_ROUTE + String.format("?%s=%s", ERROR_MESSAGE_URI_PARAM, SSO_NO_REDIRECT_MESSAGE))
            );
        }

        // 2. If either JAAS auth or Native auth is enabled, fallback to it
        if (_jaasConfigs.isJAASEnabled() || _nativeAuthenticationConfigs.isNativeAuthenticationEnabled()) {
            return Results.redirect(
                LOGIN_ROUTE + String.format("?%s=%s", AUTH_REDIRECT_URI_PARAM, encodeRedirectUri(redirectPath)));
        }

        return new Result(Http.Status.FORBIDDEN);
    }

    /**
     * Redirect to the identity provider for authentication.
     */
    @Nonnull
    public Result sso(Http.Request request) {
        if (_ssoManager.isSsoEnabled()) {
            return redirectToIdentityProvider(request, "/").orElse(
                Results.redirect(LOGIN_ROUTE + String.format("?%s=%s", ERROR_MESSAGE_URI_PARAM, SSO_NO_REDIRECT_MESSAGE))
            );
        }
        return Results.redirect(LOGIN_ROUTE + String.format("?%s=%s", ERROR_MESSAGE_URI_PARAM, SSO_DISABLED_ERROR_MESSAGE));
    }

    /**
     * Log in a user based on a username + password.
     *
     * TODO: Implement built-in support for LDAP auth. Currently dummy jaas authentication is the default.
     */
    @Nonnull
    public Result logIn(Http.Request request) {
        boolean jaasEnabled = _jaasConfigs.isJAASEnabled();
        _logger.debug(String.format("Jaas authentication enabled: %b", jaasEnabled));
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        boolean noAuthEnabled = !jaasEnabled && !nativeAuthenticationEnabled;
        if (noAuthEnabled) {
            String message = "Neither JAAS nor native authentication is enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return Results.badRequest(error);
        }

        final JsonNode json = request.body().asJson();
        final String username = json.findPath(USER_NAME).textValue();
        final String password = json.findPath(PASSWORD).textValue();

        if (StringUtils.isBlank(username)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "User name must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        JsonNode invalidCredsJson = Json.newObject().put("message", "Invalid Credentials");
        boolean loginSucceeded = tryLogin(username, password);

        if (!loginSucceeded) {
            return Results.badRequest(invalidCredsJson);
        }

        final Urn actorUrn = new CorpuserUrn(username);
        final String accessToken = _authClient.generateSessionTokenForUser(actorUrn.getId());
        return createSession(actorUrn.toString(), accessToken);
    }

    /**
     * Sign up a native user based on a name, email, title, and password. The invite token must match an existing invite token.
     *
     */
    @Nonnull
    public Result signUp(Http.Request request) {
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        if (!nativeAuthenticationEnabled) {
            String message = "Native authentication is not enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return Results.badRequest(error);
        }

        final JsonNode json = request.body().asJson();
        final String fullName = json.findPath(FULL_NAME).textValue();
        final String email = json.findPath(EMAIL).textValue();
        final String title = json.findPath(TITLE).textValue();
        final String password = json.findPath(PASSWORD).textValue();
        final String inviteToken = json.findPath(INVITE_TOKEN).textValue();

        if (StringUtils.isBlank(fullName)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Full name must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(email)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Email must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(password)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Password must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(title)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Title must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(inviteToken)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Invite token must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        final Urn userUrn = new CorpuserUrn(email);
        final String userUrnString = userUrn.toString();
        _authClient.signUp(userUrnString, fullName, email, title, password, inviteToken);
        final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
        return createSession(userUrnString, accessToken);
    }

    /**
     * Reset a native user's credentials based on a username, old password, and new password.
     *
     */
    @Nonnull
    public Result resetNativeUserCredentials(Http.Request request) {
        boolean nativeAuthenticationEnabled = _nativeAuthenticationConfigs.isNativeAuthenticationEnabled();
        _logger.debug(String.format("Native authentication enabled: %b", nativeAuthenticationEnabled));
        if (!nativeAuthenticationEnabled) {
            String message = "Native authentication is not enabled on the server.";
            final ObjectNode error = Json.newObject();
            error.put("message", message);
            return badRequest(error);
        }

        final JsonNode json = request.body().asJson();
        final String email = json.findPath(EMAIL).textValue();
        final String password = json.findPath(PASSWORD).textValue();
        final String resetToken = json.findPath(RESET_TOKEN).textValue();

        if (StringUtils.isBlank(email)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Email must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(password)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Password must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        if (StringUtils.isBlank(resetToken)) {
            JsonNode invalidCredsJson = Json.newObject().put("message", "Reset token must not be empty.");
            return Results.badRequest(invalidCredsJson);
        }

        final Urn userUrn = new CorpuserUrn(email);
        final String userUrnString = userUrn.toString();
        _authClient.resetNativeUserCredentials(userUrnString, password, resetToken);
        final String accessToken = _authClient.generateSessionTokenForUser(userUrn.getId());
        return createSession(userUrnString, accessToken);
    }

    private Optional<Result> redirectToIdentityProvider(Http.RequestHeader request, String redirectPath) {
        final PlayWebContext playWebContext = new PlayWebContext(request, _playSessionStore);
        final Client client = _ssoManager.getSsoProvider().client();
        configurePac4jSessionStore(playWebContext, client, redirectPath);
        try {
            final Optional<RedirectionAction> action = client.getRedirectionAction(playWebContext);
            return action.map(act -> new PlayHttpActionAdapter().adapt(act, playWebContext));
        } catch (Exception e) {
            if (_verbose) {
                _logger.error("Caught exception while attempting to redirect to SSO identity provider! It's likely that SSO integration is mis-configured", e);
            } else {
                _logger.error("Caught exception while attempting to redirect to SSO identity provider! It's likely that SSO integration is mis-configured");
            }
            return Optional.of(Results.redirect(
                String.format("/login?error_msg=%s",
                URLEncoder.encode("Failed to redirect to Single Sign-On provider. Please contact your DataHub Administrator, "
                    + "or refer to server logs for more information.", StandardCharsets.UTF_8))));
        }
    }

    private void configurePac4jSessionStore(PlayWebContext context, Client client, String redirectPath) {
        // Set the originally requested path for post-auth redirection.
        _playSessionStore.set(context, Pac4jConstants.REQUESTED_URL, new FoundAction(redirectPath));
        // This is to prevent previous login attempts from being cached.
        // We replicate the logic here, which is buried in the Pac4j client.
        if (_playSessionStore.get(context, client.getName() + ATTEMPTED_AUTHENTICATION_SUFFIX) != null) {
            _logger.debug("Found previous login attempt. Removing it manually to prevent unexpected errors.");
            _playSessionStore.set(context, client.getName() + ATTEMPTED_AUTHENTICATION_SUFFIX, "");
        }
    }

    private String encodeRedirectUri(final String redirectUri) {
        return URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
    }

    private boolean tryLogin(String username, String password) {
        boolean loginSucceeded = false;

        // First try jaas login, if enabled
        if (_jaasConfigs.isJAASEnabled()) {
            try {
                _logger.debug("Attempting jaas authentication");
                AuthenticationManager.authenticateJaasUser(username, password);
                _logger.debug("Jaas authentication successful. Login succeeded");
                loginSucceeded = true;
            } catch (Exception e) {
                if (_verbose) {
                    _logger.debug("Jaas authentication error. Login failed", e);
                } else {
                    _logger.debug("Jaas authentication error. Login failed");
                }
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

    private Result createSession(String userUrnString, String accessToken) {
        return Results.ok().withSession(createSessionMap(userUrnString, accessToken))
            .withCookies(
                createActorCookie(
                    userUrnString,
                    _cookieConfigs.getTtlInHours(),
                    _cookieConfigs.getAuthCookieSameSite(),
                    _cookieConfigs.getAuthCookieSecure()
                )
            );

    }

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
        Entity corpUser = _entityClient.get(corpUserSnapshot.getUrn(), _systemAuthentication);
        CorpUserSnapshot existingUserSnapshot = corpUser.getValue().getCorpUserSnapshot();
        if (existingUserSnapshot.getAspects().size() <= 1) {
            Entity newEntity = new Entity();
            newEntity.setValue(Snapshot.create(corpUserSnapshot));
            _entityClient.update(newEntity, _systemAuthentication);
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
        _entityClient.ingestProposal(proposal, _systemAuthentication);
    }
}