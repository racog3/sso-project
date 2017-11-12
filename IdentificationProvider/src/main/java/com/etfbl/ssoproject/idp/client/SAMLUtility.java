package com.etfbl.ssoproject.idp.client;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class SAMLUtility {
    public static final String NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String BINDINGS_HTTP_REDIRECT = "urn:oasis:names.tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public static final String STATUS_PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout\n";

    public static Response convertToSamlResponse(String response){
        return (Response) convertToXMLObject(response, true);
    }

    public static LogoutRequest convertToSamlLogoutRequest(String response){
        return (LogoutRequest) convertToXMLObject(response, false);
    }

    public static AuthnRequest createSamlAuthNRequest(String issuerURL, String assertionConsumerURL, String destinationURL) {

        try {
            DefaultBootstrap.bootstrap();
        } catch (Exception e ){
            e.printStackTrace();
        }

        // Create empty authNRequest
        AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();

        // Generate random UUID and append it to 'id' (since AuthnRequest can't start with number)
        String requestID = "id" + UUID.randomUUID().toString();

        // ID
        authnRequest.setID(requestID);

        // SAML Version - REQ
        authnRequest.setVersion(SAMLVersion.VERSION_20);

        // ProtocolBinding
        authnRequest.setProtocolBinding(BINDINGS_HTTP_REDIRECT);

        // AssertionConsumerServiceURL - URL on SP which will consume Assertion from Response
        authnRequest.setAssertionConsumerServiceURL(assertionConsumerURL);

        // Destination
        authnRequest.setDestination(destinationURL);

        //The time instant of issue in UTC - REQ
        authnRequest.setIssueInstant(DateTime.now());

        // Build Issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerURL);

        authnRequest.setIssuer(issuer);

        // NameID policy
        NameIDPolicyBuilder nameIDPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
        nameIDPolicy.setFormat(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS);
        nameIDPolicy.setAllowCreate(true);

        authnRequest.setNameIDPolicy(nameIDPolicy);

        // RequestedAuthnContext
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);

        // AuthnContextClassRef
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT);

        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        authnRequest.setRequestedAuthnContext(requestedAuthnContext);

        return authnRequest;
    }

    public static LogoutRequest createLogoutRequest(String issuerURL, String username, List<String> sessionIndexes) {
        try {
            DefaultBootstrap.bootstrap();
        } catch (Exception e ){
            e.printStackTrace();
        }

        // Create LogoutRequest
        LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();

        // Generate random UUID and append it to 'id'
        String requestID = "id" + UUID.randomUUID().toString();

        // ID
        logoutRequest.setID(requestID);

        // SAML Version - REQ
        logoutRequest.setVersion(SAMLVersion.VERSION_20);

        //The time instant of issue in UTC - REQ
        logoutRequest.setIssueInstant(DateTime.now());

        // Build Issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerURL);

        logoutRequest.setIssuer(issuer);

        // Build NameID
        NameIDBuilder nameIDBuilder = new NameIDBuilder();
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS);
        nameID.setValue(username);

        logoutRequest.setNameID(nameID);

        // Build SessionIndexes
        for (String sessionIdx : sessionIndexes) {
            SessionIndexBuilder sessionIndexBuilder = new SessionIndexBuilder();
            SessionIndex sessionIndex = sessionIndexBuilder.buildObject();
            sessionIndex.setSessionIndex(sessionIdx);

            logoutRequest.getSessionIndexes().add(sessionIndex);
        }

        return logoutRequest;
    }

    public static LogoutResponse createLogoutResponse(boolean fullSuccess) {
        LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
        LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();

        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();

        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();

        if (fullSuccess) {
            statusCode.setValue(STATUS_SUCCESS);
        } else {
            statusCode.setValue(STATUS_PARTIAL_LOGOUT);
        }

        status.setStatusCode(statusCode);
        logoutResponse.setStatus(status);

        return logoutResponse;
    }

    public static List<String> getAssertionAttributeValues(String attributeName, Response samlResponse) {
        List<String> values = new ArrayList<>();
        for (Assertion assertion : samlResponse.getAssertions()) {
            for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
                if (attribute.getName().equals(attributeName)) {
                    for (XMLObject attributeValue : attribute.getAttributeValues()) {
                        values.add(((XSAny) attributeValue).getTextContent());
                    }
                }
            }
        }

        return values;
    }

    public static String getAssertionSubject(Response samlResponse) {
        return samlResponse.getAssertions().get(0).getSubject().getNameID().getValue();
    }

    private static XMLObject convertToXMLObject(String raw, boolean urlDecode) {
        try {
            DefaultBootstrap.bootstrap();

            String decoded = raw;

            if (urlDecode) {
                decoded = URLDecoder.decode(raw, "UTF-8");
            }

            byte[] decodedSamlAsBytes = Base64.decode(decoded);

            byte[] inflated = inflate(decodedSamlAsBytes, true);

            // Get parser pool manager
            BasicParserPool ppMgr = new BasicParserPool();
            ppMgr.setNamespaceAware(true);

            // Parse metadata file
            InputStream in = new ByteArrayInputStream(inflated);
            Document document = ppMgr.parse(in);
            Element element = document.getDocumentElement();

            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

            XMLObject xmlObject = unmarshaller.unmarshall(element);

            return xmlObject;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static byte[] inflate(byte[] bytes, boolean nowrap) throws Exception {

        Inflater decompressor = null;
        InflaterInputStream decompressorStream = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            decompressor = new Inflater(nowrap);
            decompressorStream = new InflaterInputStream(new ByteArrayInputStream(bytes),
                    decompressor);
            byte[] buf = new byte[1024];
            int count;
            while ((count = decompressorStream.read(buf)) != -1) {
                out.write(buf, 0, count);
            }
            return out.toByteArray();
        } finally {
            if (decompressor != null) {
                decompressor.end();
            }
            try {
                if (decompressorStream != null) {
                    decompressorStream.close();
                }
            } catch (IOException ioe) {
             /*ignore*/
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ioe) {
             /*ignore*/
            }
        }
    }
}
