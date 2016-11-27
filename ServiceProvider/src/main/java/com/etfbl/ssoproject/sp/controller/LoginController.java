package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.sp.util.SAMLUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Collection;


/**
 * Created by Rajo on 19.11.2016..
 */

@Controller
public class LoginController {

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response) {

        // TODO could be extracted to the method in the SAMLUtility class
        String serverAddress = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();

        AuthnRequest sampleReq = SAMLUtility.createSamlAuthNRequest(serverAddress);
        String authNRequest = SAMLUtility.prepareAuthnRequestForSending(sampleReq);

        // Get requested URL
        SavedRequest savedRequest =
                new HttpSessionRequestCache().getRequest(request, response);

        String relayState = SAMLUtility.saveRelayState(savedRequest.getRedirectUrl());

        String redirectUrl = SAMLUtility.IDP_ADDRESS + "/Redirect?SAMLRequest=" + authNRequest + "&RelayState=" + relayState;
        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = "/saml", method = RequestMethod.POST)
    public String loginReturn(@RequestParam("SAMLResponse")String samlResponseString, @RequestParam("RelayState") String relayState) {

        Response samlResponse = SAMLUtility.convertToSamlResponse(samlResponseString);
        System.out.println("RESPONSE TO: : " + samlResponse.getInResponseTo());

        String username = samlResponse.getAssertions().get(0).getSubject().getNameID().getValue();

        // TODO Implement SAML response validation

        // Authenticate the user
        Authentication auth =
                new UsernamePasswordAuthenticationToken(username, null, getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Get target url
        String targetUrl = SAMLUtility.getRelayStateByKey(relayState);

        // Redirect the user to the requested resource
        return "redirect:" + targetUrl;
    }

    @RequestMapping(value = "/saml", method = RequestMethod.GET)
    public String loginReturn2() {
        Authentication auth =
                new UsernamePasswordAuthenticationToken("user", null, getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        return "redirect:greeting";
    }

    public Collection<GrantedAuthority> getAuthorities() {
        //make everyone ROLE_USER
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        GrantedAuthority grantedAuthority = new GrantedAuthority() {
            //anonymous inner type
            public String getAuthority() {
                return "ROLE_USER";
            }
        };
        grantedAuthorities.add(grantedAuthority);
        return grantedAuthorities;
    }

}
