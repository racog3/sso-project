package com.etfbl.ssoproject.idp.controller;

import com.etfbl.ssoproject.idp.client.SSOUtility;
import com.etfbl.ssoproject.idp.model.*;
import com.etfbl.ssoproject.idp.util.SAMLUtility;
import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.collections.map.HashedMap;
import org.opensaml.saml2.core.*;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Controller
public class SAMLProcessingController {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(SAMLUtility.class);

    private static Map<String, Authentication> authMap = new HashedMap();

    @Autowired
    TargetAuthorityDao targetAuthorityDao;

    @Autowired
    TargetHostDao targetHostDao;

    @Autowired
    ServiceProviders serviceProviders;

    @RequestMapping(SSOUtility.AUTHNREQUEST_PROCESSING_PATH)
    public String processAuthNRequest(Model model, @RequestParam(SSOUtility.REQUEST_PARAM_NAME) String authNRequestRaw,
                                      @RequestParam(SSOUtility.RELAY_STATE_PARAM_NAME) String relayState, HttpServletRequest request) {
        // Convert raw SAML Authn request to object
        AuthnRequest authnRequest = SAMLUtility.readAuthNRequest(authNRequestRaw);

        String requestIssuerURL = authnRequest.getIssuer().getValue();
        String issuerURL = SAMLUtility.getFullServerAddress(request) + SSOUtility.AUTHNREQUEST_PROCESSING_PATH;

        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String username = user.getUsername().toString();

        // Find roles of authenticated user for requested target host
        TargetHost targetHost = targetHostDao.findByUrl(requestIssuerURL);
        List<TargetAuthority> targetAuthorities = targetAuthorityDao.findByUsernameAndTargetHost(username, targetHost);
        List<String> roles = new ArrayList<>();
        for (TargetAuthority targetAuthority : targetAuthorities) {
            roles.add(targetAuthority.getRole());
        }

        // Create SAML response including user roles
        Response samlResponse = SAMLUtility.createSamlResponse(issuerURL, authnRequest.getID(),
                authnRequest.getAssertionConsumerServiceURL(),
                requestIssuerURL, username, roles, StatusCode.SUCCESS_URI);
        // Prepare SAML response for sending
        String samlResponseString = SAMLUtility.prepareXmlObjectForSending(samlResponse);

        model.addAttribute("assertionConsumerServiceURL", authnRequest.getAssertionConsumerServiceURL());
        model.addAttribute("SAMLResponse", samlResponseString);
        model.addAttribute("RelayState", relayState);

        // Save to sessions and active service providers in a map for single logout
        authMap.put(samlResponse.getID(), SecurityContextHolder.getContext().getAuthentication());
        serviceProviders.addServiceProvider(samlResponse.getID(), targetHost);

        return "redirect";
    }

    @RequestMapping(SSOUtility.LOGOUTREQUEST_PROCESSING_PATH)
    public String processLogoutRequest(@RequestParam(SSOUtility.REQUEST_PARAM_NAME) String logoutRequestRaw, HttpServletRequest request, HttpServletResponse response) {
        // Convert raw SAML Logout request to object
        LogoutRequest logoutRequest = SAMLUtility.readLogoutRequest(logoutRequestRaw);

        String username = logoutRequest.getNameID().getValue();

        for (SessionIndex sessionIndex : logoutRequest.getSessionIndexes()) {
            Authentication auth = authMap.get(sessionIndex.getSessionIndex());
            if (auth != null && auth.getPrincipal() != null && username != null && auth.getName().toString().equals(username)) {
                try {
                    for (Map.Entry<String, TargetHost> sp : serviceProviders.getServiceProviders().entrySet()) {
                        try {
                            if (!sp.getValue().getUrl().equals(logoutRequest.getIssuer().getValue())) {
                                String issuerURL = SAMLUtility.getFullServerAddress(request) + SSOUtility.LOGOUTREQUEST_PROCESSING_PATH;
                                LogoutRequest spLogoutRequest = SAMLUtility.createLogoutRequest(issuerURL, username, Arrays.asList(sp.getKey()));

                                String spLogoutRequestEncoded = SSOUtility.prepareRequestForSending(spLogoutRequest);

                                try {
                                    sendLogoutRequestToSP(sp.getValue().getUrl(), spLogoutRequestEncoded);
                                } catch (IOException e) {
                                    System.out.println("Error sending request to logout from SP: " + sp.getValue());
                                    e.printStackTrace();
                                }
                            } else {
                                System.out.println("Skip sending logout request to SP which initiated the single logout!");
                            }
                        } catch (Exception e) {
                            logger.error("Error singing-out from SP:" + sp.getValue().getUrl());
                            e.printStackTrace();
                        }
                    }
                } catch (Exception e) {
                    logger.error("Error occurred during single logout.");
                    e.printStackTrace();
                } finally {
                    new CookieClearingLogoutHandler(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY).logout(request, response, auth);
                    new SecurityContextLogoutHandler().logout(request, response, auth);
                }

            }
        }

        return "redirect:/login?logout";
    }

    private void sendLogoutRequestToSP(String targetHost, String spLogoutRequestEncoded) throws IOException {

        String logoutAddress = targetHost + SSOUtility.LOGOUTREQUEST_PROCESSING_PATH;

        URL logoutUrl = new URL(logoutAddress + "?" + SSOUtility.REQUEST_PARAM_NAME + "=" + spLogoutRequestEncoded);

        HttpURLConnection con = (HttpURLConnection) logoutUrl.openConnection();

        con.setRequestMethod("GET");

        //add request header
        con.setRequestProperty("User-Agent", HttpHeaders.USER_AGENT);

        int responseCode = con.getResponseCode();
        logger.info("Sending 'GET' request for single logout to URL : " + logoutUrl);
        logger.info("Response Code : " + responseCode);

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
    }
}
