package com.etfbl.ssoproject.idp.client;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.collections.map.HashedMap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SSOUtility {
    public static final String AUTHNREQUEST_PROCESSING_PATH = "/Redirect";
    private static Map<String,String> relayStates = new HashedMap();
    private static Map<String,AuthnRequest> authnRequestMap = new HashedMap();

    public static String generateRedirectionURL(HttpServletRequest request, HttpServletResponse response, String assertionConsumerPath, String IDPAddress, String IDPAuthnProcessingPath) {
        String serverAddress = getFullServerAddress(request);

        AuthnRequest authnRequest = SAMLUtility.createSamlAuthNRequest(serverAddress + request.getServletPath(),
                serverAddress + assertionConsumerPath,
                IDPAddress + IDPAuthnProcessingPath);
        // save 'authnrequest' to the map so it can be used on response validation
        authnRequestMap.put(authnRequest.getID(), authnRequest);
        String authNRequest = prepareAuthnRequestForSending(authnRequest);

        // Get requested URL
        SavedRequest savedRequest =
                new HttpSessionRequestCache().getRequest(request, response);

        String relayState = saveRelayState(savedRequest.getRedirectUrl());

        String redirectUrl = IDPAddress + AUTHNREQUEST_PROCESSING_PATH + "?SAMLRequest=" + authNRequest + "&RelayState=" + relayState;

        return redirectUrl;
    }

    public static String getTargetURLByRelyState(String relayState) {
        return getRelayStateByKey(relayState);
    }

    public static String getAuthnUsername(Response samlResponse) {
        return SAMLUtility.getAssertionSubject(samlResponse);
    }

    public static List<String> getRoles(Response samlResponse) {
        return SAMLUtility.getAssertionAttributeValues("role", samlResponse);
    }

    private static String prepareAuthnRequestForSending(AuthnRequest authnRequest) {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);

        try {
            Element authDom = marshaller.marshall(authnRequest);

            StringWriter stringWriter = new StringWriter();
            XMLHelper.writeNode(authDom, stringWriter);

            // Raw AuthNRequest String
            String authNrequestMessage = stringWriter.toString();

            // Deflate XML
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(outputStream, deflater);

            deflaterOutputStream.write(authNrequestMessage.getBytes("UTF-8"));
            deflaterOutputStream.close();

            // Base64 encode deflated XML
            String encodedAuthNRequest = Base64.encodeBytes(outputStream.toByteArray(), Base64.DONT_BREAK_LINES);
            encodedAuthNRequest = URLEncoder.encode(encodedAuthNRequest, "UTF-8").trim();

            return encodedAuthNRequest;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String saveRelayState(String targetUrl) {
        UUID uuid = UUID.randomUUID();
        String key = uuid.toString();
        relayStates.put(key, targetUrl);
        return key;
    }

    private static String getRelayStateByKey(String key) {
        String targetUrl = relayStates.get(key);
        relayStates.remove(key);
        return targetUrl;
    }

    private static String getFullServerAddress(HttpServletRequest request) {
        String serverAddress = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();

        return serverAddress;
    }
}
