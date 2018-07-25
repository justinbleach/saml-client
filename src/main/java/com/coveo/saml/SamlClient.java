package com.coveo.saml;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import com.sun.org.apache.xerces.internal.parsers.DOMParser;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class SamlClient {
  private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);
  private static boolean initializedOpenSaml = false;

  public enum SamlIdpBinding {
    POST, Redirect;
  }

  private String relyingPartyIdentifier;
  private String assertionConsumerServiceUrl;
  private String identityProviderUrl;
  private String responseIssuer;
  private List<X509Credential> credentials;
  private DateTime now; // used for testing only
  private SamlIdpBinding samlBinding;
  private List<SessionIndex> currentSessionIndex;

  /**
   * Returns the url where SAML requests should be posted.
   *
   * @return the url where SAML requests should be posted.
   */
  public String getIdentityProviderUrl() {
    return identityProviderUrl;
  }

  /**
   * Sets the date that will be considered as now. This is only useful for
   * testing.
   *
   * @param now the date to use for now.
   */
  public void setDateTimeNow(DateTime now) {
    this.now = now;
  }

  /**
   * Constructs an SAML client using explicit parameters.
   *
   * @param relyingPartyIdentifier      the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will
   *                                    post back the SAML response.
   * @param identityProviderUrl         the url where the SAML request will be
   *                                    submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificates                the list of base-64 encoded certificates
   *                                    to use to validate responses.
   * @param samlBinding                 what type of SAML binding should the
   *                                    client use.
   * @throws SamlException thrown if any error occur while loading the provider
   *                       information.
   */
  public SamlClient(String relyingPartyIdentifier, String assertionConsumerServiceUrl, String identityProviderUrl,
      String responseIssuer, List<X509Certificate> certificates, SamlIdpBinding samlBinding) throws SamlException {

    ensureOpenSamlIsInitialized();

    if (relyingPartyIdentifier == null) {
      throw new IllegalArgumentException("relyingPartyIdentifier");
    }
    if (identityProviderUrl == null) {
      throw new IllegalArgumentException("identityProviderUrl");
    }
    if (responseIssuer == null) {
      throw new IllegalArgumentException("responseIssuer");
    }
    if (certificates == null || certificates.isEmpty()) {
      throw new IllegalArgumentException("certificates");
    }

    this.relyingPartyIdentifier = relyingPartyIdentifier;
    this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    this.identityProviderUrl = identityProviderUrl;
    this.responseIssuer = responseIssuer;
    credentials = certificates.stream().map(SamlClient::getCredential).collect(Collectors.toList());
    this.samlBinding = samlBinding;
  }

  /**
   * Constructs an SAML client using explicit parameters.
   *
   * @param relyingPartyIdentifier      the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will
   *                                    post back the SAML response.
   * @param identityProviderUrl         the url where the SAML request will be
   *                                    submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificates                the list of base-64 encoded certificates
   *                                    to use to validate responses.
   * @throws SamlException thrown if any error occur while loading the provider
   *                       information.
   */
  public SamlClient(String relyingPartyIdentifier, String assertionConsumerServiceUrl, String identityProviderUrl,
      String responseIssuer, List<X509Certificate> certificates) throws SamlException {

    this(relyingPartyIdentifier, assertionConsumerServiceUrl, identityProviderUrl, responseIssuer, certificates,
        SamlIdpBinding.POST);
  }

  /**
   * Constructs an SAML client using explicit parameters.
   *
   * @param relyingPartyIdentifier      the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will
   *                                    post back the SAML response.
   * @param identityProviderUrl         the url where the SAML request will be
   *                                    submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificate                 the base-64 encoded certificate to use to
   *                                    validate responses.
   * @throws SamlException thrown if any error occur while loading the provider
   *                       information.
   */
  public SamlClient(String relyingPartyIdentifier, String assertionConsumerServiceUrl, String identityProviderUrl,
      String responseIssuer, X509Certificate certificate) throws SamlException {

    this(relyingPartyIdentifier, assertionConsumerServiceUrl, identityProviderUrl, responseIssuer,
        Collections.singletonList(certificate), SamlIdpBinding.POST);
  }

  /**
   * Builds an encoded SAML request.
   *
   * @return The base-64 encoded SAML request.
   * @throws SamlException thrown if an unexpected error occurs.
   */
  public String getSamlRequest() throws SamlException {
    AuthnRequest request = (AuthnRequest) buildSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    String currentRequestId = "z" + UUID.randomUUID().toString();
    request.setID(currentRequestId); // ADFS needs IDs to start with a letter

    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssueInstant(DateTime.now());
    request.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-" + this.samlBinding.toString());
    request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    request.setIssuer(issuer);

    NameIDPolicy nameIDPolicy = (NameIDPolicy) buildSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
    nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    request.setNameIDPolicy(nameIDPolicy);
    signRequest(request);

    StringWriter stringWriter = new StringWriter();
    try {
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
      Element dom = marshaller.marshall(request);
      XMLHelper.writeNode(dom, stringWriter);
    } catch (MarshallingException ex) {
      throw new SamlException("Error while marshalling SAML request to XML", ex);
    }

    logger.trace("Issuing SAML request: " + stringWriter.toString());

    try {
      return Base64.encodeBytes(stringWriter.toString().getBytes("UTF-8"));
    } catch (UnsupportedEncodingException ex) {
      throw new SamlException("Error while encoding SAML request", ex);
    }
  }

  private Signature setSignatureRaw(String signatureAlgorithm, X509Credential cred) throws SAMLException {
    Signature signature = (Signature) buildSamlObject(Signature.DEFAULT_ELEMENT_NAME);
    signature.setSigningCredential(cred);
    signature.setSignatureAlgorithm(signatureAlgorithm);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

    try {
      KeyInfo keyInfo = (KeyInfo) buildSamlObject(KeyInfo.DEFAULT_ELEMENT_NAME);
      X509Data data = (X509Data) buildSamlObject(X509Data.DEFAULT_ELEMENT_NAME);
      org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) buildSamlObject(
          org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
      String value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
      cert.setValue(value);
      data.getX509Certificates().add(cert);
      keyInfo.getX509Datas().add(data);
      signature.setKeyInfo(keyInfo);
      return signature;

    } catch (CertificateEncodingException e) {
      throw new SAMLException("Error getting certificate", e);
    }
  }

  private X509Certificate loadCertificate(String filename) throws SamlException {
    try {
      FileInputStream fis = new FileInputStream(filename);
      BufferedInputStream bis = new BufferedInputStream(fis);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      while (bis.available() > 0) {
        X509Certificate cert = (X509Certificate) cf.generateCertificate(bis);
        System.out.println(cert.toString());
        bis.close();
        return cert;
      }

      bis.close();
      throw new SamlException("empty public key");
    } catch (Exception e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  private PrivateKey loadPrivateKey(String filename) throws SamlException {
    try {
      RandomAccessFile raf = new RandomAccessFile(filename, "r");
      byte[] buf = new byte[(int) raf.length()];
      raf.readFully(buf);
      raf.close();
      PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePrivate(kspec);

    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }

  private X509Credential getSpCredential() throws SamlException {
    try {
      PrivateKey privKey = this.loadPrivateKey("signing-private.der");
      X509Certificate cert = this.loadCertificate("signing-public.pem");
      BasicX509Credential cred = new BasicX509Credential();
      cred.setEntityCertificate(cert);
      cred.setPrivateKey(privKey);

      return cred;
    } catch (Exception e) {
      logger.warn("Failed to get SP credentials, so can't sign request.  Please create a signing-private.der and signing-public.pem in this directory to sign requests.");
      return null;
    }
  }

  private void signRequest(SignableSAMLObject request) throws SamlException {

    try {
      X509Credential credential = getSpCredential();
      if (credential != null) {
        Signature signature = this.setSignatureRaw(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, credential);

        request.setSignature(signature);
  
        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);
  
        // Marshall and Sign
        MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
  
        marshaller.marshall(request);
  
        org.apache.xml.security.Init.init();
        Signer.signObjects(signatureList);  
      }
    } catch (Exception e) {
      e.printStackTrace();
      throw new SamlException("Failed to sign request", e);
    }
  }

  public class RequestValues {
    public String request;
    public String signature;
  }

  private String encode(String message) throws IOException {
    Deflater deflater = new Deflater(Deflater.DEFLATED, true);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
    deflaterOutputStream.write(message.getBytes());
    deflaterOutputStream.close();
    String samlRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
    return URLEncoder.encode(samlRequest, "UTF-8");
  }

  /**
   * Builds an encoded SAML request.
   *
   * @return The base-64 encoded SAML request.
   * @throws SamlException        thrown if an unexpected error occurs.
   * @throws SAMLException
   * @throws SignatureException
   * @throws MarshallingException
   */
  public RequestValues getSamlLogoutRequest(String nameId)
      throws SamlException, MarshallingException, SignatureException, SAMLException {
    LogoutRequest request = (LogoutRequest) buildSamlObject(LogoutRequest.DEFAULT_ELEMENT_NAME);
    request.setID("z" + UUID.randomUUID().toString()); // ADFS needs IDs to start with a letter

    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssueInstant(DateTime.now());

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    request.setIssuer(issuer);

    NameID nid = (NameID) buildSamlObject(NameID.DEFAULT_ELEMENT_NAME);
    nid.setValue(nameId);
    request.setNameID(nid);

    for (SessionIndex si : this.currentSessionIndex) {
      request.getSessionIndexes().add(si);
    }

    signRequest(request);

    StringWriter stringWriter = new StringWriter();
    try {
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
      Element dom = marshaller.marshall(request);
      XMLHelper.writeNode(dom, stringWriter);
    } catch (MarshallingException ex) {
      throw new SamlException("Error while marshalling SAML request to XML", ex);
    }

    logger.trace("Issuing SAML Logout request: " + stringWriter.toString());

    try {
      RequestValues ret = new RequestValues();
      ret.signature = null;
      Signature signature = request.getSignature();
      if (signature != null) {
        XMLSignature xmlSignature = ((SignatureImpl) signature)
          .getXMLSignature();
        ret.signature = URLEncoder.encode(Base64.encodeBytes(xmlSignature.getSignatureValue(), Base64.DONT_BREAK_LINES), "UTF-8");
      }
      ret.request = encode(stringWriter.toString());
      return ret;
    } catch (UnsupportedEncodingException ex) {
      throw new SamlException("Error while encoding SAML request", ex);
    } catch (IOException e) {
      e.printStackTrace();
      throw new SamlException("Error while compressing SAML request", e);
    } catch (XMLSignatureException e) {
      e.printStackTrace();
      throw new SamlException("error getting signature", e);
    }
  }

  /**
   * Decodes and validates an SAML response returned by an identity provider.
   *
   * @param encodedResponse the encoded response returned by the identity
   *                        provider.
   * @return An {@link SamlResponse} object containing information decoded from
   *         the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error
   *                       occurs.
   */
  public SamlResponse decodeAndValidateSamlResponse(String encodedResponse) throws SamlException {
    String decodedResponse;
    try {
      decodedResponse = new String(Base64.decode(encodedResponse), "UTF-8");
    } catch (UnsupportedEncodingException ex) {
      throw new SamlException("Cannot decode base64 encoded response", ex);
    }

    logger.trace("Validating SAML response: " + decodedResponse);

    Response response;
    try {
      DOMParser parser = createDOMParser();
      parser.parse(new InputSource(new StringReader(decodedResponse)));
      response = (Response) Configuration.getUnmarshallerFactory()
          .getUnmarshaller(parser.getDocument().getDocumentElement())
          .unmarshall(parser.getDocument().getDocumentElement());
    } catch (IOException | SAXException | UnmarshallingException ex) {
      throw new SamlException("Cannot decode xml encoded response", ex);
    }

    validateResponse(response);
    validateAssertion(response);
    validateSignature(response);

    Assertion assertion = response.getAssertions().get(0);
    List<AuthnStatement> ausl = assertion.getAuthnStatements();
    this.currentSessionIndex = new ArrayList<SessionIndex>();
    if (ausl != null) {
      for (AuthnStatement aus : ausl) {
        SessionIndex sindex = (SessionIndex) buildSamlObject(SessionIndex.DEFAULT_ELEMENT_NAME);
        sindex.setSessionIndex(aus.getSessionIndex());
        this.currentSessionIndex.add(sindex);
      }
    }
    return new SamlResponse(assertion);
  }

  /**
   * Redirects an {@link HttpServletResponse} to the configured identity provider.
   *
   * @param response   The {@link HttpServletResponse}.
   * @param relayState Optional relay state that will be passed along.
   * @throws IOException   thrown if an IO error occurs.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public void redirectToIdentityProvider(HttpServletResponse response, String relayState)
      throws IOException, SamlException {
    Map<String, String> values = new HashMap<>();
    values.put("SAMLRequest", getSamlRequest());
    if (relayState != null) {
      values.put("RelayState", relayState);
    }

    BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
  }

  /**
   * Processes a POST containing the SAML response.
   *
   * @param request the {@link HttpServletRequest}.
   * @return An {@link SamlResponse} object containing information decoded from
   *         the SAML response.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public SamlResponse processPostFromIdentityProvider(HttpServletRequest request) throws SamlException {
    String encodedResponse = request.getParameter("SAMLResponse");
    return decodeAndValidateSamlResponse(encodedResponse);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity
   * provider.
   * <p>
   * When using Okta as an identity provider, it is possible to pass null to
   * relyingPartyIdentifier and assertionConsumerServiceUrl; they will be inferred
   * from the metadata provider XML.
   *
   * @param relyingPartyIdentifier      the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will
   *                                    post back the SAML response.
   * @param metadata                    the XML metadata obtained from the
   *                                    identity provider.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata
   *                       information.
   */
  public static SamlClient fromMetadata(String relyingPartyIdentifier, String assertionConsumerServiceUrl,
      Reader metadata) throws SamlException {
    return fromMetadata(relyingPartyIdentifier, assertionConsumerServiceUrl, metadata, SamlIdpBinding.POST);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity
   * provider.
   * <p>
   * When using Okta as an identity provider, it is possible to pass null to
   * relyingPartyIdentifier and assertionConsumerServiceUrl; they will be inferred
   * from the metadata provider XML.
   *
   * @param relyingPartyIdentifier      the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will
   *                                    post back the SAML response.
   * @param metadata                    the XML metadata obtained from the
   *                                    identity provider.
   * @param samlBinding                 the HTTP method to use for binding to the
   *                                    IdP.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata
   *                       information.
   */
  public static SamlClient fromMetadata(String relyingPartyIdentifier, String assertionConsumerServiceUrl,
      Reader metadata, SamlIdpBinding samlBinding) throws SamlException {

    ensureOpenSamlIsInitialized();

    MetadataProvider metadataProvider = createMetadataProvider(metadata);
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataProvider);

    IDPSSODescriptor idpSsoDescriptor = getIDPSSODescriptor(entityDescriptor);
    SingleSignOnService idpBinding = getIdpBinding(idpSsoDescriptor, samlBinding);
    List<X509Certificate> x509Certificates = getCertificates(idpSsoDescriptor);
    boolean isOkta = entityDescriptor.getEntityID().contains(".okta.com");

    if (relyingPartyIdentifier == null) {
      // Okta's own toolkit uses the entity ID as a relying party identifier, so if we
      // detect that the IDP is Okta let's tolerate a null value for this parameter.
      if (isOkta) {
        relyingPartyIdentifier = entityDescriptor.getEntityID();
      } else {
        throw new IllegalArgumentException("relyingPartyIdentifier");
      }
    }

    if (assertionConsumerServiceUrl == null && isOkta) {
      // Again, Okta's own toolkit uses this value for the assertion consumer url,
      // which
      // kinda makes no sense since this is supposed to be a url pointing to a server
      // outside Okta, but it probably just straight ignores this and use the one from
      // it's own config anyway.
      assertionConsumerServiceUrl = idpBinding.getLocation();
    }

    String identityProviderUrl = idpBinding.getLocation();
    String responseIssuer = entityDescriptor.getEntityID();

    return new SamlClient(relyingPartyIdentifier, assertionConsumerServiceUrl, identityProviderUrl, responseIssuer,
        x509Certificates, samlBinding);
  }

  private void validateResponse(Response response) throws SamlException {
    try {
      new ResponseSchemaValidator().validate(response);
    } catch (ValidationException ex) {
      throw new SamlException("The response schema validation failed", ex);
    }

    if (!response.getIssuer().getValue().equals(responseIssuer)) {
      throw new SamlException("The response issuer didn't match the expected value");
    }

    String statusCode = response.getStatus().getStatusCode().getValue();

    if (!statusCode.equals("urn:oasis:names:tc:SAML:2.0:status:Success")) {
      throw new SamlException("Invalid status code: " + statusCode);
    }
  }

  private void validateAssertion(Response response) throws SamlException {
    if (response.getAssertions().size() != 1) {
      throw new SamlException("The response doesn't contain exactly 1 assertion");
    }

    Assertion assertion = response.getAssertions().get(0);
    if (!assertion.getIssuer().getValue().equals(responseIssuer)) {
      throw new SamlException("The assertion issuer didn't match the expected value");
    }

    if (assertion.getSubject().getNameID() == null) {
      throw new SamlException(
          "The NameID value is missing from the SAML response; this is likely an IDP configuration issue");
    }

    enforceConditions(assertion.getConditions());
  }

  private void enforceConditions(Conditions conditions) throws SamlException {
    DateTime now = this.now != null ? this.now : DateTime.now();

    if (now.isBefore(conditions.getNotBefore())) {
      throw new SamlException("The assertion cannot be used before " + conditions.getNotBefore().toString());
    }

    if (now.isAfter(conditions.getNotOnOrAfter())) {
      throw new SamlException("The assertion cannot be used after  " + conditions.getNotOnOrAfter().toString());
    }
  }

  private void validateSignature(Response response) throws SamlException {
    Signature responseSignature = response.getSignature();
    Signature assertionSignature = response.getAssertions().get(0).getSignature();

    if (responseSignature == null && assertionSignature == null) {
      throw new SamlException("No signature is present in either response or assertion");
    }

    if (responseSignature != null && !validate(responseSignature)) {
      throw new SamlException("The response signature is invalid");
    }

    if (assertionSignature != null && !validate(assertionSignature)) {
      throw new SamlException("The assertion signature is invalid");
    }
  }

  private boolean validate(Signature signature) {
    if (signature == null) {
      return false;
    }

    // It's fine if any of the credentials match the signature
    return credentials.stream().anyMatch(c -> {
      try {
        SignatureValidator signatureValidator = new SignatureValidator(c);
        signatureValidator.validate(signature);
        return true;
      } catch (ValidationException ex) {
        return false;
      }
    });
  }

  private synchronized static void ensureOpenSamlIsInitialized() throws SamlException {
    if (!initializedOpenSaml) {
      try {
        DefaultBootstrap.bootstrap();
        initializedOpenSaml = true;
      } catch (Throwable ex) {
        throw new SamlException("Error while initializing the Open SAML library", ex);
      }
    }
  }

  private static DOMParser createDOMParser() throws SamlException {
    DOMParser parser = new DOMParser() {
      {
        try {
          setFeature(INCLUDE_COMMENTS_FEATURE, false);
        } catch (Throwable ex) {
          throw new SamlException("Cannot disable comments parsing to mitigate https://www.kb.cert.org/vuls/id/475445",
              ex);
        }
      }
    };

    return parser;
  }

  private static MetadataProvider createMetadataProvider(Reader metadata) throws SamlException {
    try {
      DOMParser parser = createDOMParser();
      parser.parse(new InputSource(metadata));
      DOMMetadataProvider provider = new DOMMetadataProvider(parser.getDocument().getDocumentElement());
      provider.initialize();
      return provider;
    } catch (IOException | SAXException | MetadataProviderException ex) {
      throw new SamlException("Cannot load identity provider metadata", ex);
    }
  }

  private static EntityDescriptor getEntityDescriptor(MetadataProvider metadataProvider) throws SamlException {
    EntityDescriptor descriptor;

    try {
      descriptor = (EntityDescriptor) metadataProvider.getMetadata();
    } catch (MetadataProviderException ex) {
      throw new SamlException("Cannot retrieve the entity descriptor", ex);
    }

    if (descriptor == null) {
      throw new SamlException("Cannot retrieve the entity descriptor");
    }

    return descriptor;
  }

  private static IDPSSODescriptor getIDPSSODescriptor(EntityDescriptor entityDescriptor) throws SamlException {
    IDPSSODescriptor idpssoDescriptor = entityDescriptor.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
    if (idpssoDescriptor == null) {
      throw new SamlException("Cannot retrieve IDP SSO descriptor");
    }

    return idpssoDescriptor;
  }

  private static SingleSignOnService getIdpBinding(IDPSSODescriptor idpSsoDescriptor, SamlIdpBinding samlBinding)
      throws SamlException {
    return idpSsoDescriptor.getSingleSignOnServices().stream()
        .filter(x -> x.getBinding().equals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-" + samlBinding.toString()))
        .findAny().orElseThrow(() -> new SamlException("Cannot find HTTP-POST SSO binding in metadata"));
  }

  private static List<X509Certificate> getCertificates(IDPSSODescriptor idpSsoDescriptor) throws SamlException {

    List<X509Certificate> certificates;

    try {
      certificates = idpSsoDescriptor.getKeyDescriptors().stream().filter(x -> x.getUse() == UsageType.SIGNING)
          .flatMap(SamlClient::getDatasWithCertificates).map(SamlClient::getFirstCertificate)
          .collect(Collectors.toList());

    } catch (Exception e) {
      throw new SamlException("Exception in getCertificates", e);
    }

    return certificates;
  }

  private static Stream<X509Data> getDatasWithCertificates(KeyDescriptor descriptor) {
    return descriptor.getKeyInfo().getX509Datas().stream().filter(d -> d.getX509Certificates().size() > 0);
  }

  private static X509Certificate getFirstCertificate(X509Data data) {
    try {
      org.opensaml.xml.signature.X509Certificate cert = data.getX509Certificates().stream().findFirst().orElse(null);
      if (cert != null) {
        return KeyInfoHelper.getCertificate(cert);
      }
    } catch (CertificateException e) {
      logger.error("Exception in getFirstCertificate", e);
    }

    return null;
  }

  private static BasicX509Credential getCredential(X509Certificate certificate) {
    BasicX509Credential credential = new BasicX509Credential();
    credential.setEntityCertificate(certificate);
    credential.setPublicKey(certificate.getPublicKey());
    credential.setCRLs(Collections.emptyList());
    return credential;
  }

  private static XMLObject buildSamlObject(QName qname) {
    return Configuration.getBuilderFactory().getBuilder(qname).buildObject(qname);
  }
}
