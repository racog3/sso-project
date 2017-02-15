package com.etfbl.ssoproject.idp.util;

import org.apache.catalina.servlet4preview.http.HttpServletRequest;
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
    public static final String SUBJECT_CONFIMRATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    public AuthnRequest readAuthNRequest(String request){
        try {
            DefaultBootstrap.bootstrap();

            // not needed if received through GET request as parameter
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

    public static Response createSamlResponse(String issuerURL, String inResponseTo, String destinationURL, String requestIssuerUrl, String userEmailAddress, List<String> roles, String statusCodeURI) {

        try {
            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

            DefaultBootstrap.bootstrap();

            DateTime issueDate = DateTime.now();
            DateTime notOnOrAfterDate = issueDate.plusMinutes(5);

            // Generate random UUID and append it to 'id'
            String responseID = "id" + UUID.randomUUID().toString();

            //Response
            ResponseBuilder responseBuilder = new ResponseBuilder();
            Response response = responseBuilder.buildObject();

            response.setID(responseID);
            response.setVersion(SAMLVersion.VERSION_20);
            response.setInResponseTo(inResponseTo);
            response.setIssueInstant(issueDate.plusSeconds(5));
            response.setDestination(destinationURL);

                //Issuer
                Issuer issuer = createIssuer(issuerURL);

            response.setIssuer(issuer);

                //Status
                Status status = createStatus();

                    //StatusCode
                    StatusCode statusCode = createStatusCode(statusCodeURI);

                status.setStatusCode(statusCode);

            response.setStatus(status);

                //Assertion

                String assertionID = "id" + UUID.randomUUID().toString();

                Assertion assertion = createAssertion(assertionID, SAMLVersion.VERSION_20, issueDate.plusSeconds(5));

                    //Issuer
                    Issuer issuer1 = createIssuer(issuerURL);

                assertion.setIssuer(issuer1);

                    //Subject
                    Subject subject = createSubject();

                        //NameID
                        NameID subjectNameID = createNameID(NAME_ID_POLICY_FORMAT_EMAIL_ADDRESS, userEmailAddress);
                        subject.setNameID(subjectNameID);

                            //SubjectConfirmation
                            SubjectConfirmation subjectConfirmation = createSubjectConfirmation(SUBJECT_CONFIMRATION_METHOD_BEARER);

                                //SubjectConfirmationData
                                SubjectConfirmationData subjectConfirmationData = createSubjectConfirmationData(inResponseTo, destinationURL, notOnOrAfterDate);
                                subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

                            subject.getSubjectConfirmations().add(subjectConfirmation);

                assertion.setSubject(subject);

                    //Conditions
                    Conditions conditions = createConditions(issueDate.minusMinutes(5), notOnOrAfterDate);

                        //AudienceRestriction
                        AudienceRestriction audienceRestriction = createAudienceRestrictions();

                            //Audience
                            Audience audience = createAudience(requestIssuerUrl);

                        audienceRestriction.getAudiences().add(audience);

                    conditions.getAudienceRestrictions().add(audienceRestriction);

                assertion.setConditions(conditions);

                //AttributeStatement
                    AttributeStatement attributeStatement = createAttributeStatement();

                        //Attribute
                        Attribute roleAttribute = createAttribute("role");

                            //AttributeValues
                            for (String role : roles) {
                                roleAttribute.getAttributeValues().add(createAttributeValue(role, builderFactory));
                            }

                    attributeStatement.getAttributes().add(roleAttribute);

                assertion.getAttributeStatements().add(attributeStatement);

            response.getAssertions().add(assertion);

            return response;

        } catch (Exception e ){
            e.printStackTrace();
        }

        return null;
    }

    //Status
    public static Status createStatus() {
        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();

        return status;
    }

    //StatusCode
    public static StatusCode createStatusCode(String statusCodeURI) {
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeURI);

        return statusCode;
    }

    //Issuer
    public static Issuer createIssuer(String issuerUrl) {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerUrl);

        return issuer;
    }

    //Subject
    public static Subject createSubject() {
        SubjectBuilder subjectBuilder = new SubjectBuilder();
        Subject subject = subjectBuilder.buildObject();

        return subject;
    }

    public static SubjectConfirmation createSubjectConfirmation(String method) {
        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(method);

        return subjectConfirmation;
    }

    public static SubjectConfirmationData createSubjectConfirmationData(String inResponseTo, String recipient, DateTime notOnOrAfter) {
        SubjectConfirmationDataBuilder subjectConfirmationDataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmationData.setRecipient(recipient);
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

        return subjectConfirmationData;
    }

    //Conditions
    public static Conditions createConditions(DateTime notBefore, DateTime notOnOrAfter) {
        ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notOnOrAfter);

        return conditions;
    }

    //AudienceRestrictions
    public static AudienceRestriction createAudienceRestrictions() {
        // build audience restriction
        AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        return audienceRestriction;
    }

    public static Audience createAudience(String audienceURI) {
        // audience builder
        AudienceBuilder audienceBuilder = new AudienceBuilder();
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(audienceURI);

        return audience;
    }

    // AttributeStatement
    public static AttributeStatement createAttributeStatement() {
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        return attributeStatement;
    }

    // Attribute
    public static Attribute createAttribute(String name){
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(name);

        return attribute;
    }

    // AttributeValue
    public static XSAny createAttributeValue(String value, XMLObjectBuilderFactory builderFactory) {
        XSAnyBuilder sb2 = (XSAnyBuilder) builderFactory.getBuilder(XSAny.TYPE_NAME);
        XSAny anyValue = sb2.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
        anyValue.setTextContent(value);

        return anyValue;
    }

    //AuthnStatement
    public static AuthnStatement createAuthnStatement(DateTime authnInstant, String sessionIndex) {
        AuthnStatementBuilder authnStatementBuilder = new AuthnStatementBuilder();
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(authnInstant);
        authnStatement.setSessionIndex(sessionIndex);

        return authnStatement;
    }

    // Assertion
    public static Assertion createAssertion(String id, SAMLVersion samlVersion, DateTime issueInstant) {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(id);
        assertion.setVersion(samlVersion);
        assertion.setIssueInstant(issueInstant);

        return assertion;
    }

    //NameID
    public static NameID createNameID(String format, String value){
        NameIDBuilder nameIDBuilder = new NameIDBuilder();
        NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat(format);
        nameID.setValue(value);

        return nameID;
    }

    public static String getFullServerAddress(HttpServletRequest request) {
        String serverAddress = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();

        return serverAddress;
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
