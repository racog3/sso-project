package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.idp.client.SAMLUtility;
import com.etfbl.ssoproject.idp.client.SSOUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Controller
public class LoginLogoutController {

    @Value("${sso.sp.path.assertionConsumer}")
    public String ASSERTION_CONSUMER_PATH;
    @Value("${sso.idp.address}")
    public String IDP_ADDRESS;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response) {

        // Get requested URL
        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);

        String redirectUrl = SSOUtility.generateAuthNRedirectionURL(request, savedRequest.getRedirectUrl(), ASSERTION_CONSUMER_PATH, IDP_ADDRESS);

        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = "${sso.sp.path.assertionConsumer}", method = RequestMethod.POST)
    public String loginReturn(@RequestParam(SSOUtility.RESPONSE_PARAM_NAME)String samlResponseString,
                              @RequestParam(SSOUtility.RELAY_STATE_PARAM_NAME) String relayState,
                              HttpServletRequest request) {

        // Convert raw response to Response object
        // TODO Implement SAML response validation
        Response samlResponse = SAMLUtility.convertToSamlResponse(samlResponseString);

        // Get authenticated username and roles from SAML response
        String username = SSOUtility.getAuthnUsername(samlResponse);
        List<String> roles = SSOUtility.getRoles(samlResponse);

        // Authenticate the user in Spring Security Context with previous roles
        Authentication auth =
                new UsernamePasswordAuthenticationToken(username, null, setAuthorities(roles));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Get target url for user redirection
        String targetUrl = SSOUtility.getTargetURLByRelyState(relayState);

        // Add to session map for logout
        SSOUtility.addToSessionMap(samlResponse.getID(), request.getSession());

        // Redirect the user to the requested resource
        return "redirect:" + targetUrl;
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        String redirectUrl = "/login?logout";
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null){
            String username = auth.getName().toString();

            redirectUrl = SSOUtility.generateLogoutRedirectionURL(request, username, IDP_ADDRESS);

            new CookieClearingLogoutHandler(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY).logout(request, response, auth);
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }

        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = SSOUtility.LOGOUTREQUEST_PROCESSING_PATH, method = RequestMethod.GET)
    @ResponseStatus(value = HttpStatus.OK)
    public void singleLogout(@RequestParam(SSOUtility.REQUEST_PARAM_NAME) String logoutRequestRaw, HttpServletRequest request, HttpServletResponse response) {
        // Convert raw SAML Logout request to object
        LogoutRequest logoutRequest = SAMLUtility.convertToSamlLogoutRequest(logoutRequestRaw);

        String username = logoutRequest.getNameID().getValue();

        Boolean fullSuccess = null;

        for (SessionIndex sessionIndex : logoutRequest.getSessionIndexes()) {
            HttpSession session = SSOUtility.getSessionBySessionIndex(sessionIndex.getSessionIndex(), true);
            if (session != null && username != null) {
                SecurityContext securityContext = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
                if (username.equals(securityContext.getAuthentication().getName())) {
                    securityContext.setAuthentication(null);
                    if (fullSuccess == null) {
                        fullSuccess = true;
                    }
                } else {
                    fullSuccess = false;
                }
            } else {
                fullSuccess = false;
            }
        }
    }

    private Collection<GrantedAuthority> setAuthorities(List<String> authorities) {
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        for (String authority : authorities) {
            GrantedAuthority grantedAuthority = new GrantedAuthority() {
                //anonymous inner type
                public String getAuthority() {
                    return authority;
                }
            };
            grantedAuthorities.add(grantedAuthority);
        }

        return grantedAuthorities;
    }

}
