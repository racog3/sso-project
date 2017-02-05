package com.etfbl.ssoproject.idp.util;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.xacml.ctx.impl.AttributeValueTypeImplBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
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
import java.util.List;
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
    public static final String SUBJECT_CONFIMRATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    private XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    public AuthnRequest readAuthNRequest(String request){
        try {
            DefaultBootstrap.bootstrap();

            // not needed if received throught GET request as parameter
            // String decoded = URLDecoder.decode(request,"UTF-8");

            byte[] decodedSamlAsBytes = Base64.decode(request);

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
            AuthnRequest authnRequest = (AuthnRequest) requestXmlObject;

            System.out.println("Issuer : " + authnRequest.getIssuer().getValue());
            System.out.println("ID : " + authnRequest.getID());
            System.out.println("Name ID policy : " + authnRequest.getNameIDPolicy().getFormat());

            return authnRequest;
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
        authnRequest.setID("identifier_1");

        // SAML Version - REQ
        authnRequest.setVersion(SAMLVersion.VERSION_20);

        //The time instant of issue in UTC - REQ
        authnRequest.setIssueInstant(DateTime.now());

        // Build issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue("sp.localhost");

        authnRequest.setIssuer(issuer);

        // NameID policy
        NameIDPolicyBuilder nameIDPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
        nameIDPolicy.setFormat(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS);
        nameIDPolicy.setAllowCreate(true);

        authnRequest.setNameIDPolicy(nameIDPolicy);

        return authnRequest;
    }

    public static Response createSamlResponse(String requestIssuerUrl, String userEmailAddress,String statusCodeUri, List<String> roles) {
        XMLObjectBuilderFactory builderFactory = null;

        try {
            DefaultBootstrap.bootstrap();
            builderFactory = Configuration.getBuilderFactory();
        } catch (Exception e ){
            e.printStackTrace();
        }

        DateTime issueDate = DateTime.now();
        DateTime notOnOrAfterDate = issueDate.plusMinutes(5);
        String issuerUrl = "localhost:8081";

        // create empty response
        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();

        // set basic attributes
        response.setID("identifier_2");
        response.setVersion(SAMLVersion.VERSION_20);
        response.setInResponseTo("identifier_1");
        response.setIssueInstant(issueDate.plusSeconds(5));
        response.setDestination(requestIssuerUrl + "/saml");

        // Build issuer
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerUrl);

        response.setIssuer(issuer);

        // build status with status code
        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeUri);
        status.setStatusCode(statusCode);

        // build assertion
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID("identifier_3");
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssueInstant(issueDate.plusSeconds(5));

        Issuer issuer1 = issuerBuilder.buildObject();
        issuer1.setValue(issuerUrl);
        assertion.setIssuer(issuer1);

        // build subject
        SubjectBuilder subjectBuilder = new SubjectBuilder();
        Subject subject = subjectBuilder.buildObject();

        //build name id
        NameIDBuilder nameIDBuilder = new NameIDBuilder();
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS);
        nameID.setValue(userEmailAddress);

        subject.setNameID(nameID);

        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SUBJECT_CONFIMRATION_METHOD_BEARER);

        SubjectConfirmationDataBuilder subjectConfirmationDataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
        subjectConfirmationData.setInResponseTo("identifier_1");
        subjectConfirmationData.setRecipient(requestIssuerUrl + "/saml");
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfterDate);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        // build conditions
        ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueDate.minusMinutes(5));
        conditions.setNotOnOrAfter(notOnOrAfterDate);


        // build audience restriction
        AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        // audience builder
        AudienceBuilder audienceBuilder = new AudienceBuilder();
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(requestIssuerUrl);

        //attribute statement
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute roleAttribute = attributeBuilder.buildObject();
        roleAttribute.setName("role");

        for (String role : roles) {
            XSAnyBuilder sb2 = (XSAnyBuilder) builderFactory.getBuilder(XSAny.TYPE_NAME);
            XSAny roleValue = sb2.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
            roleValue.setTextContent(role);
            roleAttribute.getAttributeValues().add(roleValue);
        }

        attributeStatement.getAttributes().add(roleAttribute);

        audienceRestriction.getAudiences().add(audience);

        conditions.getAudienceRestrictions().add(audienceRestriction);

        AuthnStatementBuilder authnStatementBuilder = new AuthnStatementBuilder();
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(issueDate);
        authnStatement.setSessionIndex("identifier_3");

        assertion.setConditions(conditions);

        assertion.setSubject(subject);

        assertion.getAttributeStatements().add(attributeStatement);

        response.getAssertions().add(assertion);

        return response;
    }

    public static String prepareXmlObjectForSending(XMLObject xmlObject) {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

        Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);

        try {
            Element authDom = marshaller.marshall(xmlObject);

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
