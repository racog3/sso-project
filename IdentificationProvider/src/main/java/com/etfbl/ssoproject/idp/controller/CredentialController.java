package com.etfbl.ssoproject.idp.controller;

import com.etfbl.ssoproject.idp.model.TargetAuthority;
import com.etfbl.ssoproject.idp.model.TargetAuthorityDao;
import com.etfbl.ssoproject.idp.model.TargetHost;
import com.etfbl.ssoproject.idp.model.TargetHostDao;
import com.etfbl.ssoproject.idp.util.SAMLUtility;
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
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Rajo on 19.4.2016..
 */
@Controller
public class CredentialController {

    @Autowired
    private SAMLUtility samlUtility;

    @Autowired
    TargetAuthorityDao targetAuthorityDao;

    @Autowired
    TargetHostDao targetHostDao;

    @RequestMapping("/accessTest")
    @ResponseBody
    public String test(){
        return "IT WORKS!!";
    }

    @RequestMapping("/Redirect")
    public String processAuthNRequest(Model model, @RequestParam("SAMLRequest") String authNRequest, @RequestParam("RelayState") String relayState) {
        AuthnRequest authnRequest = samlUtility.readAuthNRequest(authNRequest);
        String issuerUrl = authnRequest.getIssuer().getValue();

        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = user.getUsername().toString();

        // extract to method or service class
        TargetHost targetHost = targetHostDao.findByUrl(issuerUrl);
        List<TargetAuthority> targetAuthorities = targetAuthorityDao.findByUsernameAndTargetHost(username, targetHost);
        List<String> roles = new ArrayList<>();
        for (TargetAuthority targetAuthority : targetAuthorities) {
            roles.add(targetAuthority.getRole());
        }

        Response samlResponse = SAMLUtility.createSamlResponse(issuerUrl, username , StatusCode.SUCCESS_URI, roles);
        String samlResponseString = SAMLUtility.prepareXmlObjectForSending(samlResponse);

        model.addAttribute("issuerUrl", issuerUrl);
        model.addAttribute("SAMLResponse", samlResponseString);
        model.addAttribute("RelayState", relayState);
        return "redirect";
    }
}
