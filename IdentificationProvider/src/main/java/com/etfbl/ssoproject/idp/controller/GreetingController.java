package com.etfbl.ssoproject.idp.controller;

import com.etfbl.ssoproject.idp.util.SAMLUtility;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Created by Rajo on 19.4.2016..
 */
@Controller
public class GreetingController {

    @RequestMapping("/greeting")
    public String greeting(@RequestParam(value = "name", required = false, defaultValue = "World") String name, Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }

    @RequestMapping("/saml-req")
    public String samlReq(Model model) {
        String samlReq = SAMLUtility.prepareAuthnRequestForSending(SAMLUtility.createSamlAuthNRequest());

        model.addAttribute("name", samlReq);
        return "greeting";
    }
}
