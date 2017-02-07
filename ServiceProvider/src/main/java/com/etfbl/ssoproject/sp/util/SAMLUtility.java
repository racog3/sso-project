package com.etfbl.ssoproject.sp.util;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
import org.apache.commons.collections.map.HashedMap;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * Created by Rajo on 19.4.2016..
 */
@Service
public class SAMLUtility {

    public static final String NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String BINDINGS_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    public static final String IDP_ADDRESS = "http://localhost:8080/sso";
    public static final String IDP_AUTHNREQUEST_PROCESSING_PATH = "/Redirect";

    private static Map<String,String> relayStates = new HashedMap();
    private static Map<String,AuthnRequest> authnRequestMap = new HashedMap();

    private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    public static Response convertToSamlResponse(String response){
        try {
            DefaultBootstrap.bootstrap();

            String decoded = URLDecoder.decode(response,"UTF-8");

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

            XMLObject requestXmlObject = unmarshaller.unmarshall(element);
            Response samlResponse = (Response) requestXmlObject;

            System.out.println("Issuer : " + samlResponse.getIssuer());
            System.out.println("ID : " + samlResponse.getID());

            return samlResponse;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /*
    Basic elements of AuthNRequest
    - ID
    - Version
    - IssueInstant
    - AssertionConsumerServiceIndex
    - AttributeConsumingServiceIndex
     */
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
        authnRequest.setProtocolBinding(BINDINGS_HTTP_POST);

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

        // save 'authnrequest' to the map so it can be used on response validation
        authnRequestMap.put(requestID, authnRequest);

        return authnRequest;
    }

    public static String prepareAuthnRequestForSending(AuthnRequest authnRequest) {
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

    public static String saveRelayState(String targetUrl) {
        UUID uuid = UUID.randomUUID();
        String key = uuid.toString();
        relayStates.put(key, targetUrl);
        return key;
    }

    public static String getRelayStateByKey(String key) {
        String targetUrl = relayStates.get(key);
        relayStates.remove(key);
        return targetUrl;
    }

    public static String getFullServerAddress(HttpServletRequest request) {
        String serverAddress = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();

        return serverAddress;
    }
}
