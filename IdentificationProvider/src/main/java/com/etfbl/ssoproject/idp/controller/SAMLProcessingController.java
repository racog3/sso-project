package com.etfbl.ssoproject.idp.controller;

import com.etfbl.ssoproject.idp.client.SSOUtility;
import com.etfbl.ssoproject.idp.model.TargetAuthority;
import com.etfbl.ssoproject.idp.model.TargetAuthorityDao;
import com.etfbl.ssoproject.idp.model.TargetHost;
import com.etfbl.ssoproject.idp.model.TargetHostDao;
import com.etfbl.ssoproject.idp.util.SAMLUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@Controller
public class SAMLProcessingController {

    @Autowired
    TargetAuthorityDao targetAuthorityDao;

    @Autowired
    TargetHostDao targetHostDao;

    @RequestMapping(SSOUtility.AUTHNREQUEST_PROCESSING_PATH)
    public String processAuthNRequest(Model model, @RequestParam(SSOUtility.REQUEST_PARAM_NAME) String authNRequestRaw,
                                      @RequestParam(SSOUtility.RELAY_STATE_PARAM_NAME) String relayState, HttpServletRequest request) {
        AuthnRequest authnRequest = SAMLUtility.readAuthNRequest(authNRequestRaw);
        String requestIssuerURL = authnRequest.getIssuer().getValue();
        String issuerURL = SAMLUtility.getFullServerAddress(request) + SSOUtility.AUTHNREQUEST_PROCESSING_PATH;

        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = user.getUsername().toString();

        // extract to method or service class
        TargetHost targetHost = targetHostDao.findByUrl(requestIssuerURL);
        List<TargetAuthority> targetAuthorities = targetAuthorityDao.findByUsernameAndTargetHost(username, targetHost);
        List<String> roles = new ArrayList<>();
        for (TargetAuthority targetAuthority : targetAuthorities) {
            roles.add(targetAuthority.getRole());
        }

        Response samlResponse = SAMLUtility.createSamlResponse(authnRequest.getID(), issuerURL,
                authnRequest.getAssertionConsumerServiceURL(),
                requestIssuerURL, username, roles, StatusCode.SUCCESS_URI);
        String samlResponseString = SAMLUtility.prepareXmlObjectForSending(samlResponse);

        model.addAttribute("assertionConsumerServiceURL", authnRequest.getAssertionConsumerServiceURL());
        model.addAttribute("SAMLResponse", samlResponseString);
        model.addAttribute("RelayState", relayState);
        return "redirect";
    }
}
