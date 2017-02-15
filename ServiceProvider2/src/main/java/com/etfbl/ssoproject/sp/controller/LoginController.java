package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.idp.client.SAMLUtility;
import com.etfbl.ssoproject.idp.client.SSOUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Controller
public class LoginController {

    @Value("${sso.sp.path.assertionConsumer}")
    public String ASSERTION_CONSUMER_PATH;
    @Value("${sso.idp.address}")
    public String IDP_ADDRESS;
    @Value("${sso.idp.path.processing}")
    public String IDP_AUTHNREQUEST_PROCESSING_PATH;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response) {

        String redirectUrl = SSOUtility.generateRedirectionURL(request, response, ASSERTION_CONSUMER_PATH, IDP_ADDRESS, IDP_AUTHNREQUEST_PROCESSING_PATH);

        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = "${sso.sp.path.assertionConsumer}", method = RequestMethod.POST)
    public String loginReturn(@RequestParam("SAMLResponse")String samlResponseString, @RequestParam("RelayState") String relayState) {

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

        // Redirect the user to the requested resource
        return "redirect:" + targetUrl;
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
