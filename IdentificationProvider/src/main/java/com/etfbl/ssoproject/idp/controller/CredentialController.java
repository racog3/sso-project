package com.etfbl.ssoproject.idp.controller;

import com.etfbl.ssoproject.idp.model.Credential;
import com.etfbl.ssoproject.idp.model.CredentialDao;
import com.etfbl.ssoproject.idp.util.SAMLUtility;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by Rajo on 19.4.2016..
 */
@Controller
public class CredentialController {

    @Autowired
    private CredentialDao credentialDao;

    @Autowired
    private SAMLUtility samlUtility;

    @RequestMapping("/get-by-username")
    @ResponseBody
    public String getByUsername(@RequestParam("username") String username) {
        Credential credential = null;
        try {
            credential = credentialDao.findByUsername(username);
        } catch(Exception e){
            e.printStackTrace();
        }

        return credential.getPassword();
    }

    @RequestMapping("/getIssuer")
    @ResponseBody
    public String getIssuer(){

        String authNRequestString = "fY9Ba8JAEIXv%2Fopl7oluNKJDdkUoQqC9tLYHb0u6NIHNbLozEX9%2B01rBXnqbB4%2Fve1PtLn1QZ5%2B4i2RA5wtQnpr43tGHgdfjIdvAzs4qdn0oBtyP0tKz%2Fxw9i6ofDMh0aFA18%2BhrYnEkBoqFXmdaZ3p71CtcFqjLvFyWJ1BvN1HxLZrUxHhFGxgTYXTcMZLrPaM0%2BLJ%2FesSpikOKEpsYwF6X4I8w3RP%2BBzhmn2RSg%2BUhD7FxoY0s1fweZ3%2Fj3z%2FtFw%3D%3D";
        AuthnRequest sampleReq = SAMLUtility.createSamlAuthNRequest();
        String authNrequest = SAMLUtility.prepareXmlObjectForSending(sampleReq);

        return samlUtility.readAuthNRequest(authNrequest).toString();
    }

    @RequestMapping("/Redirect")
    public String processAuthNRequest(Model model, @RequestParam("SAMLRequest") String authNRequest) {
        AuthnRequest authnRequest = samlUtility.readAuthNRequest(authNRequest);
        String issuerUrl = authnRequest.getIssuer().getValue();
        Response samlResponse = SAMLUtility.createSamlResponse(issuerUrl, StatusCode.SUCCESS_URI);
        String samlResponseString = SAMLUtility.prepareXmlObjectForSending(samlResponse);

        model.addAttribute("issuerUrl", issuerUrl);
        model.addAttribute("SAMLResponse", samlResponseString);
        return "redirect";
    }
}
