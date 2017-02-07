package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.sp.util.SAMLUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
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
import java.util.List;


/**
 * Created by Rajo on 19.11.2016..
 */

@Controller
public class LoginController {

    public static final String ASSERTION_CONSUMER_PATH = "/saml";

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response) {

        // TODO could be extracted to the method in the SAMLUtility class
        String serverAddress = SAMLUtility.getFullServerAddress(request);

        AuthnRequest sampleReq = SAMLUtility.createSamlAuthNRequest(serverAddress + request.getServletPath(),
                serverAddress + ASSERTION_CONSUMER_PATH,
                SAMLUtility.IDP_ADDRESS + SAMLUtility.IDP_AUTHNREQUEST_PROCESSING_PATH);
        String authNRequest = SAMLUtility.prepareAuthnRequestForSending(sampleReq);

        // Get requested URL
        SavedRequest savedRequest =
                new HttpSessionRequestCache().getRequest(request, response);

        String relayState = SAMLUtility.saveRelayState(savedRequest.getRedirectUrl());

        String redirectUrl = SAMLUtility.IDP_ADDRESS + "/Redirect?SAMLRequest=" + authNRequest + "&RelayState=" + relayState;
        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = ASSERTION_CONSUMER_PATH, method = RequestMethod.POST)
    public String loginReturn(@RequestParam("SAMLResponse")String samlResponseString, @RequestParam("RelayState") String relayState) {

        Response samlResponse = SAMLUtility.convertToSamlResponse(samlResponseString);
        System.out.println("RESPONSE TO: : " + samlResponse.getInResponseTo());

        String username = samlResponse.getAssertions().get(0).getSubject().getNameID().getValue();

        // TODO Implement SAML response validation

        List<String> roles = new ArrayList<>();
        // Extract authorities from attribute statement
        // TODO add this to SAML utility or Library
        for (Assertion assertion : samlResponse.getAssertions()) {
            for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
                if (attribute.getName().equals("role")) {
                    for (XMLObject attributeValue : attribute.getAttributeValues()) {
                        roles.add(((XSAny) attributeValue).getTextContent());
                    }
                }
            }
        }

        // Authenticate the user
        Authentication auth =
                new UsernamePasswordAuthenticationToken(username, null, setAuthorities(roles));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Get target url
        String targetUrl = SAMLUtility.getRelayStateByKey(relayState);

        // Redirect the user to the requested resource
        return "redirect:" + targetUrl;
    }

    public Collection<GrantedAuthority> setAuthorities(List<String> authorities) {
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
