package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.bootstrap.PassiveSessionAuthenticator;
import com.iflytek.skillhub.auth.direct.DirectAuthProvider;
import com.iflytek.skillhub.auth.local.LocalAuthProperties;
import com.iflytek.skillhub.auth.local.PasswordResetProperties;
import com.iflytek.skillhub.auth.oauth.OAuthLoginRedirectSupport;
import com.iflytek.skillhub.config.AuthSessionBootstrapProperties;
import com.iflytek.skillhub.config.DirectAuthProperties;
import com.iflytek.skillhub.config.OAuthVisibilityProperties;
import com.iflytek.skillhub.dto.AuthMethodResponse;
import com.iflytek.skillhub.dto.AuthProviderResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.stereotype.Service;

@Service
public class AuthMethodCatalog {

    private final OAuth2ClientProperties oAuth2ClientProperties;
    private final OAuthVisibilityProperties oauthVisibilityProperties;
    private final DirectAuthProperties directAuthProperties;
    private final AuthSessionBootstrapProperties sessionBootstrapProperties;
    private final LocalAuthProperties localAuthProperties;
    private final PasswordResetProperties passwordResetProperties;
    private final List<DirectAuthProvider> directAuthProviders;
    private final List<PassiveSessionAuthenticator> passiveSessionAuthenticators;

    public AuthMethodCatalog(OAuth2ClientProperties oAuth2ClientProperties,
                             OAuthVisibilityProperties oauthVisibilityProperties,
                             DirectAuthProperties directAuthProperties,
                             AuthSessionBootstrapProperties sessionBootstrapProperties,
                             LocalAuthProperties localAuthProperties,
                             PasswordResetProperties passwordResetProperties,
                             List<DirectAuthProvider> directAuthProviders,
                             List<PassiveSessionAuthenticator> passiveSessionAuthenticators) {
        this.oAuth2ClientProperties = oAuth2ClientProperties;
        this.oauthVisibilityProperties = oauthVisibilityProperties;
        this.directAuthProperties = directAuthProperties;
        this.sessionBootstrapProperties = sessionBootstrapProperties;
        this.localAuthProperties = localAuthProperties;
        this.passwordResetProperties = passwordResetProperties;
        this.directAuthProviders = directAuthProviders;
        this.passiveSessionAuthenticators = passiveSessionAuthenticators;
    }

    public List<AuthProviderResponse> listOAuthProviders(String returnTo) {
        if (!oauthVisibilityProperties.isEnabled()) {
            return List.of();
        }
        String sanitizedReturnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(returnTo);
        return new ArrayList<>(oAuth2ClientProperties.getRegistration().entrySet().stream()
            .sorted(Comparator.comparing(entry -> entry.getKey()))
            .map(entry -> new AuthProviderResponse(
                entry.getKey(),
                entry.getValue().getClientName() != null && !entry.getValue().getClientName().isBlank()
                    ? entry.getValue().getClientName()
                    : entry.getKey(),
                buildAuthorizationUrl(entry.getKey(), sanitizedReturnTo)
            ))
            .toList());
    }

    public List<AuthMethodResponse> listMethods(String returnTo) {
        String sanitizedReturnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(returnTo);
        List<AuthMethodResponse> methods = new ArrayList<>();

        methods.add(new AuthMethodResponse(
            "local-password",
            "PASSWORD",
            "local",
            "Local Account",
            "/api/v1/auth/local/login"
        ));

        if (localAuthProperties.isRegistrationEnabled()) {
            methods.add(new AuthMethodResponse(
                "local-registration",
                "REGISTRATION",
                "local",
                "Local Registration",
                "/api/v1/auth/local/register"
            ));
        }

        if (passwordResetProperties.isEnabled()) {
            methods.add(new AuthMethodResponse(
                "local-password-reset",
                "PASSWORD_RESET",
                "local",
                "Password Reset",
                "/api/v1/auth/local/password-reset/request"
            ));
        }

        if (oauthVisibilityProperties.isEnabled()) {
            oAuth2ClientProperties.getRegistration().entrySet().stream()
                .sorted(Comparator.comparing(entry -> entry.getKey()))
                .forEach(entry -> methods.add(new AuthMethodResponse(
                    "oauth-" + entry.getKey(),
                    "OAUTH_REDIRECT",
                    entry.getKey(),
                    entry.getValue().getClientName() != null && !entry.getValue().getClientName().isBlank()
                        ? entry.getValue().getClientName()
                        : entry.getKey(),
                    buildAuthorizationUrl(entry.getKey(), sanitizedReturnTo)
                )));
        }

        if (directAuthProperties.isEnabled()) {
            directAuthProviders.stream()
                .sorted(Comparator.comparing(DirectAuthProvider::providerCode))
                .forEach(provider -> methods.add(new AuthMethodResponse(
                    "direct-" + provider.providerCode(),
                    "DIRECT_PASSWORD",
                    provider.providerCode(),
                    provider.displayName(),
                    "/api/v1/auth/direct/login"
                )));
        }

        if (sessionBootstrapProperties.isEnabled()) {
            passiveSessionAuthenticators.stream()
                .sorted(Comparator.comparing(PassiveSessionAuthenticator::providerCode))
                .forEach(provider -> methods.add(new AuthMethodResponse(
                    "bootstrap-" + provider.providerCode(),
                    "SESSION_BOOTSTRAP",
                    provider.providerCode(),
                    provider.displayName(),
                    "/api/v1/auth/session/bootstrap"
                )));
        }

        return methods;
    }

    private String buildAuthorizationUrl(String registrationId, String returnTo) {
        String baseUrl = "/oauth2/authorization/" + registrationId;
        if (returnTo == null) {
            return baseUrl;
        }
        return baseUrl + "?returnTo=" + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
    }
}