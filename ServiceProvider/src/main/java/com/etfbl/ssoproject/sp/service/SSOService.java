package com.etfbl.ssoproject.sp.service;

import com.etfbl.ssoproject.idp.client.SSORequestBuilder;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.springframework.stereotype.Service;

@Service
public class SSOService {
    public Response convertToSamlResponse(String response) {
        return SSORequestBuilder.convertToSamlResponse(response);
    }

    public String prepareAuthnRequestForSending(AuthnRequest authnRequest) {
        return SSORequestBuilder.prepareAuthnRequestForSending(authnRequest);
    }

    public AuthnRequest createSamlAuthNRequest(String issuerURL, String assertionConsumerURL, String destinationURL) {
        return SSORequestBuilder.createSamlAuthNRequest(issuerURL, assertionConsumerURL, destinationURL);
    }

    public String getFullServerAddress(HttpServletRequest request) {
        return SSORequestBuilder.getFullServerAddress(request);
    }

    public String saveRelayState(String targetUrl) {
        return SSORequestBuilder.saveRelayState(targetUrl);
    }

    public String getRelayStateByKey(String key) {
        return SSORequestBuilder.getRelayStateByKey(key);
    }
}
