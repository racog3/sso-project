package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.sp.service.SSOService;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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


    @Value("${sso.sp.path.assertionConsumer}")
    public String ASSERTION_CONSUMER_PATH;
    @Value("${sso.idp.address}")
    public String IDP_ADDRESS;
    @Value("${sso.idp.path.processing}")
    public String IDP_AUTHNREQUEST_PROCESSING_PATH;

    @Autowired
    public SSOService ssoService;

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request, HttpServletResponse response) {

        // TODO could be extracted to the method in the SAMLUtility class
        String serverAddress = ssoService.getFullServerAddress(request);

        AuthnRequest sampleReq = ssoService.createSamlAuthNRequest(serverAddress + request.getServletPath(),
                serverAddress + ASSERTION_CONSUMER_PATH,
                IDP_ADDRESS + IDP_AUTHNREQUEST_PROCESSING_PATH);
        String authNRequest = ssoService.prepareAuthnRequestForSending(sampleReq);

        // Get requested URL
        SavedRequest savedRequest =
                new HttpSessionRequestCache().getRequest(request, response);

        String relayState = ssoService.saveRelayState(savedRequest.getRedirectUrl());

        String redirectUrl = IDP_ADDRESS + "/Redirect?SAMLRequest=" + authNRequest + "&RelayState=" + relayState;
        return "redirect:" + redirectUrl;
    }

    @RequestMapping(value = "${sso.sp.path.assertionConsumer}", method = RequestMethod.POST)
    public String loginReturn(@RequestParam("SAMLResponse")String samlResponseString, @RequestParam("RelayState") String relayState) {

        Response samlResponse = ssoService.convertToSamlResponse(samlResponseString);
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
        String targetUrl = ssoService.getRelayStateByKey(relayState);

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
