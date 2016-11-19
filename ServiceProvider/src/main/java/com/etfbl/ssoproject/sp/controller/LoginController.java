package com.etfbl.ssoproject.sp.controller;

import com.etfbl.ssoproject.sp.util.SAMLUtility;
import org.opensaml.saml2.core.AuthnRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Created by Rajo on 19.11.2016..
 */

@Controller
@RequestMapping(value = "/login")
public class LoginController {

    @RequestMapping(method = RequestMethod.GET)
    public String login() {
        AuthnRequest sampleReq = SAMLUtility.createSamlAuthNRequest();
        String authNRequest = SAMLUtility.prepareAuthnRequestForSending(sampleReq);
        String redirectUrl = SAMLUtility.IDP_ADDRESS + "/Redirect?SAMLRequest=" + authNRequest;
        return "redirect:" + redirectUrl;
    }

}
