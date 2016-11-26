package com.etfbl.ssoproject.sp.util;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.metadata.Endpoint;
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

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.namespace.QName;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
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
    public static final String IDP_ADDRESS = "http://localhost:8081";

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
    public static AuthnRequest createSamlAuthNRequest() {

        try {
            DefaultBootstrap.bootstrap();
        } catch (Exception e ){
            e.printStackTrace();
        }

        // Create empty authNRequest
        AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authnRequest = authnRequestBuilder.buildObject();

        // ID
        authnRequest.setID("test1");

        // SAML Version - REQ
        authnRequest.setVersion(SAMLVersion.VERSION_20);

        //The time instant of issue in UTC - REQ
        authnRequest.setIssueInstant(DateTime.now());

        // Build issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("http://localhost:8080");

        authnRequest.setIssuer(issuer);

        // NameID policy
        NameIDPolicyBuilder nameIDPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
        nameIDPolicy.setFormat(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS);
        nameIDPolicy.setAllowCreate(true);

        authnRequest.setNameIDPolicy(nameIDPolicy);

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

    public void doAuthenticationRedirect(HttpServletResponse response, final HttpSession httpSession){
        AuthnRequest authnRequest = createSamlAuthNRequest();

        SAMLMessageContext<?, AuthnRequest, ?> context =  SAMLUtility.makeSamlMessageContext();

        //context.setPeerEntityEndpoint();
        context.setOutboundSAMLMessage(authnRequest);
    }

    public static <TI extends SAMLObject, TO extends SAMLObject, TN extends SAMLObject>
    SAMLMessageContext<TI, TO, TN> makeSamlMessageContext() {
        return new BasicSAMLMessageContext<TI, TO, TN>();
    }

    public Endpoint generateEndpoint(QName service, String location, String responseLocation) {

        SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(service);
        Endpoint samlEndpoint = endpointBuilder.buildObject();

        samlEndpoint.setLocation(location);

        // this does not have to be set
        if (StringUtils.isNotEmpty(responseLocation))
            samlEndpoint.setResponseLocation(responseLocation);

        return samlEndpoint;
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
