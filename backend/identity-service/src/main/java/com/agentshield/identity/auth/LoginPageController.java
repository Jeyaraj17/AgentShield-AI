package com.agentshield.identity.auth;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.servlet.view.RedirectView;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;

@Controller
public class LoginPageController {

    private final String spaRedirectUri;

    public LoginPageController(@Value("${agentshield.security.spa.redirect-uri}") String spaRedirectUri) {
        this.spaRedirectUri = spaRedirectUri;
    }

    @GetMapping(value = "/login", produces = "text/html")
    public RedirectView loginPage(
            CsrfToken csrfToken,
            @RequestParam(name = "error", required = false) String error,
            HttpServletResponse response) {
        // Materialize the double-submit CSRF cookie before handing control to the SPA.
        // The OAuth authorization request remains in Identity's server-side session;
        // a successful form POST returns through SavedRequestAwareAuthenticationSuccessHandler.
        csrfToken.getToken();
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        URI callback = URI.create(spaRedirectUri);
        String spaOrigin = callback.getScheme() + "://" + callback.getRawAuthority();
        String location = spaOrigin + "/sign-in?identityLogin=1" + (error == null ? "" : "&loginError=1");
        return new RedirectView(location, true, true);
    }
}
