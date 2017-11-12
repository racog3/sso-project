package com.etfbl.ssoproject.idp.client;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.collections.map.HashedMap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import javax.servlet.http.HttpSession;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SSOUtility {
    public static final String AUTHNREQUEST_PROCESSING_PATH = "/redirect";
    public static final String LOGOUTREQUEST_PROCESSING_PATH = "/single-logout";
    public static final String REQUEST_PARAM_NAME = "SAMLRequest";
    public static final String RESPONSE_PARAM_NAME = "SAMLResponse";
    public static final String RELAY_STATE_PARAM_NAME = "RelayState";
    private static Map<String,String> relayStates = new HashedMap();
    private static Map<String,HttpSession> sessionMap = new HashedMap();

    public static String generateAuthNRedirectionURL(HttpServletRequest request, String requestedUrl, String assertionConsumerPath, String IDPAddress) {
        String serverAddress = getFullServerAddress(request);

        AuthnRequest authnRequest = SAMLUtility.createSamlAuthNRequest(serverAddress,
                serverAddress + assertionConsumerPath,
                IDPAddress + AUTHNREQUEST_PROCESSING_PATH);
        String authNRequest = prepareRequestForSending(authnRequest);

        String relayState = saveRelayState(requestedUrl);

        String redirectUrl = IDPAddress + AUTHNREQUEST_PROCESSING_PATH + "?" + REQUEST_PARAM_NAME + "=" + authNRequest + "&" + RELAY_STATE_PARAM_NAME + "=" + relayState;

        return redirectUrl;
    }

    public static String generateLogoutRedirectionURL(HttpServletRequest request, String username, String IDPAddress) {
        String serverAddress = getFullServerAddress(request);

        List<String> sessionIndexes = SSOUtility.getSessionIndexesBySession(request.getSession(), true);

        LogoutRequest logoutRequest = SAMLUtility.createLogoutRequest(serverAddress, username, sessionIndexes);
        String logoutRequestEncoded = prepareRequestForSending(logoutRequest);

        String redirectUrl = IDPAddress + LOGOUTREQUEST_PROCESSING_PATH + "?" + REQUEST_PARAM_NAME + "=" + logoutRequestEncoded;

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

    public static void addToSessionMap(String sessionIndex, HttpSession session) {
        sessionMap.put(sessionIndex, session);
    }

    public static List<String> getSessionIndexesBySession(HttpSession session, boolean removeFromMap) {
        List<String> sessionIndexes = new ArrayList<>();
        for (Map.Entry<String, HttpSession> entry : sessionMap.entrySet()) {
            if (entry.getValue().equals(session)) {
                sessionIndexes.add(entry.getKey());
                if (removeFromMap) {
                    sessionMap.remove(entry);
                }
            }
        }

        return sessionIndexes;
    }

    public static HttpSession getSessionBySessionIndex(String sessionIndex, boolean removeFromMap) {
        HttpSession session = sessionMap.get(sessionIndex);
        if (removeFromMap) {
            sessionMap.remove(sessionIndex);
        }
        return session;
    }

    public static String prepareRequestForSending(RequestAbstractType request) {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(request);

        try {
            Element authDom = marshaller.marshall(request);

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
