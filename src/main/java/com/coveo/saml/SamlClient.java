package com.coveo.saml;

import org.apache.xerces.parsers.DOMParser;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

public class SamlClient {
  private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);

  private static final String HTTP_REQ_SAML_PARAM = "SAMLRequest";
  private static final String HTTP_RESP_SAML_PARAM = "SAMLResponse";

  private static boolean initializedOpenSaml = false;

  public enum SamlIdpBinding {
    POST,
    Redirect;
  }

  private String relyingPartyIdentifier;
  private String assertionConsumerServiceUrl;
  private String identityProviderUrl;
  private String responseIssuer;
  private List<Credential> credentials;
  private DateTime now; // used for testing only
  private long notBeforeSkew = 0L;
  private SamlIdpBinding samlBinding;
  private BasicX509Credential spCredential;

  /**
   * Returns the url where SAML requests should be posted.
   *
   * @return the url where SAML requests should be posted.
   */
  public String getIdentityProviderUrl() {
    return identityProviderUrl;
  }

  /**
   * Sets the date that will be considered as now. This is only useful for testing.
   *
   * @param now the date to use for now.
   */
  public void setDateTimeNow(DateTime now) {
    this.now = now;
  }

  /**
   * Sets by how much the current time can be before the assertion's notBefore.
   *
   * Used to mitigate clock differences between the identity provider and relying party.
   *
   * @param notBeforeSkew non-negative amount of skew (in milliseconds) to allow between the
   *                      current time and the assertion's notBefore date. Default: 0
   */
  public void setNotBeforeSkew(long notBeforeSkew) {
    if (notBeforeSkew < 0) {
      throw new IllegalArgumentException("Skew must be non-negative");
    }
    this.notBeforeSkew = notBeforeSkew;
  }

  /**
   * Constructs an SAML client using explicit parameters.
   *
   * @param relyingPartyIdentifier      the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param identityProviderUrl         the url where the SAML request will be submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificates                the list of base-64 encoded certificates to use to validate
   *                                    responses.
   * @param samlBinding                 what type of SAML binding should the client use.
   * @throws SamlException thrown if any error occur while loading the provider information.
   */
  public SamlClient(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      String identityProviderUrl,
      String responseIssuer,
      List<X509Certificate> certificates,
      SamlIdpBinding samlBinding)
      throws SamlException {

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
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param identityProviderUrl         the url where the SAML request will be submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificates                the list of base-64 encoded certificates to use to validate
   *                                    responses.
   * @throws SamlException thrown if any error occur while loading the provider information.
   */
  public SamlClient(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      String identityProviderUrl,
      String responseIssuer,
      List<X509Certificate> certificates)
      throws SamlException {

    this(
        relyingPartyIdentifier,
        assertionConsumerServiceUrl,
        identityProviderUrl,
        responseIssuer,
        certificates,
        SamlIdpBinding.POST);
  }

  /**
   * Constructs an SAML client using explicit parameters.
   *
   * @param relyingPartyIdentifier      the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param identityProviderUrl         the url where the SAML request will be submitted.
   * @param responseIssuer              the expected issuer ID for SAML responses.
   * @param certificate                 the base-64 encoded certificate to use to validate
   *                                    responses.
   * @throws SamlException thrown if any error occur while loading the provider information.
   */
  public SamlClient(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      String identityProviderUrl,
      String responseIssuer,
      X509Certificate certificate)
      throws SamlException {

    this(
        relyingPartyIdentifier,
        assertionConsumerServiceUrl,
        identityProviderUrl,
        responseIssuer,
        Collections.singletonList(certificate),
        SamlIdpBinding.POST);
  }

  /**
   * Builds an encoded SAML request.
   *
   * @return The base-64 encoded SAML request.
   * @throws SamlException thrown if an unexpected error occurs.
   */
  public String getSamlRequest() throws SamlException {
    AuthnRequest request = (AuthnRequest) buildSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    request.setID("z" + UUID.randomUUID().toString()); // ADFS needs IDs to start with a letter

    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssueInstant(DateTime.now());
    request.setProtocolBinding(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-" + this.samlBinding.toString());
    request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    request.setIssuer(issuer);

    NameIDPolicy nameIDPolicy = (NameIDPolicy) buildSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
    nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    request.setNameIDPolicy(nameIDPolicy);

    StringWriter stringWriter;
    try {
      stringWriter = marshallXmlObject(request);
    } catch (MarshallingException e) {
      throw new SamlException("Error while marshalling SAML request to XML", e);
    }

    logger.trace("Issuing SAML request: " + stringWriter.toString());

    return Base64.encodeBytes(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Decodes and validates an SAML response returned by an identity provider.
   *
   * @param encodedResponse the encoded response returned by the identity provider.
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public SamlResponse decodeAndValidateSamlResponse(String encodedResponse) throws SamlException {
    //Decode and parse the response
    Response response = (Response) parseResponse(encodedResponse);

    // Decode and add the assertion
    try {
      decodeEncryptedAssertion(response);
    } catch (DecryptionException e) {
      throw new SamlException("Cannot decrypt the assertion", e);
    }
    //Validate  the response (Assertion / Signature / Schema)
    ValidatorUtils.validate(response, responseIssuer, credentials, this.now, notBeforeSkew);

    Assertion assertion = response.getAssertions().get(0);
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
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public SamlResponse processPostFromIdentityProvider(HttpServletRequest request)
      throws SamlException {
    String encodedResponse = request.getParameter(HTTP_RESP_SAML_PARAM);
    return decodeAndValidateSamlResponse(encodedResponse);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity provider. <p> When
   * using Okta as an identity provider, it is possible to pass null to relyingPartyIdentifier and
   * assertionConsumerServiceUrl; they will be inferred from the metadata provider XML.
   *
   * @param relyingPartyIdentifier      the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param metadata                    the XML metadata obtained from the identity provider.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata information.
   */
  public static SamlClient fromMetadata(
      String relyingPartyIdentifier, String assertionConsumerServiceUrl, Reader metadata)
      throws SamlException {
    return fromMetadata(
        relyingPartyIdentifier, assertionConsumerServiceUrl, metadata, SamlIdpBinding.POST);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity provider. <p> When
   * using Okta as an identity provider, it is possible to pass null to relyingPartyIdentifier and
   * assertionConsumerServiceUrl; they will be inferred from the metadata provider XML.
   *
   * @param relyingPartyIdentifier      the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param metadata                    the XML metadata obtained from the identity provider.
   * @param samlBinding                 the HTTP method to use for binding to the IdP.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata information.
   */
  public static SamlClient fromMetadata(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      Reader metadata,
      SamlIdpBinding samlBinding)
      throws SamlException {
    return fromMetadata(
        relyingPartyIdentifier, assertionConsumerServiceUrl, metadata, samlBinding, null);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity provider. <p> When
   * using Okta as an identity provider, it is possible to pass null to relyingPartyIdentifier and
   * assertionConsumerServiceUrl; they will be inferred from the metadata provider XML.
   *
   * @param relyingPartyIdentifier      the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the
   *                                    SAML response.
   * @param metadata                    the XML metadata obtained from the identity provider.
   * @param samlBinding                 the HTTP method to use for binding to the IdP.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata information.
   */
  public static SamlClient fromMetadata(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      Reader metadata,
      SamlIdpBinding samlBinding,
      List<X509Certificate> certificates)
      throws SamlException {

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
      // Again, Okta's own toolkit uses this value for the assertion consumer url, which
      // kinda makes no sense since this is supposed to be a url pointing to a server
      // outside Okta, but it probably just straight ignores this and use the one from
      // it's own config anyway.
      assertionConsumerServiceUrl = idpBinding.getLocation();
    }

    if (certificates != null) {
      // Adding certificates given to this method
      // because some idp metadata file does not embedded signing certificate
      x509Certificates.addAll(certificates);
    }

    String identityProviderUrl = idpBinding.getLocation();
    String responseIssuer = entityDescriptor.getEntityID();

    return new SamlClient(
        relyingPartyIdentifier,
        assertionConsumerServiceUrl,
        identityProviderUrl,
        responseIssuer,
        x509Certificates,
        samlBinding);
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
    DOMParser parser =
        new DOMParser() {
          {
            try {
              setFeature(INCLUDE_COMMENTS_FEATURE, false);
            } catch (Throwable ex) {
              throw new SamlException(
                  "Cannot disable comments parsing to mitigate https://www.kb.cert.org/vuls/id/475445",
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
      DOMMetadataProvider provider =
          new DOMMetadataProvider(parser.getDocument().getDocumentElement());
      provider.initialize();
      return provider;
    } catch (IOException | SAXException | MetadataProviderException ex) {
      throw new SamlException("Cannot load identity provider metadata", ex);
    }
  }

  private static EntityDescriptor getEntityDescriptor(MetadataProvider metadataProvider)
      throws SamlException {
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

  private static IDPSSODescriptor getIDPSSODescriptor(EntityDescriptor entityDescriptor)
      throws SamlException {
    IDPSSODescriptor idpssoDescriptor =
        entityDescriptor.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
    if (idpssoDescriptor == null) {
      throw new SamlException("Cannot retrieve IDP SSO descriptor");
    }

    return idpssoDescriptor;
  }

  private static SingleSignOnService getIdpBinding(
      IDPSSODescriptor idpSsoDescriptor, SamlIdpBinding samlBinding) throws SamlException {
    return idpSsoDescriptor
        .getSingleSignOnServices()
        .stream()
        .filter(
            x
                -> x.getBinding()
                    .equals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-" + samlBinding.toString()))
        .findAny()
        .orElseThrow(() -> new SamlException("Cannot find HTTP-POST SSO binding in metadata"));
  }

  private static List<X509Certificate> getCertificates(IDPSSODescriptor idpSsoDescriptor)
      throws SamlException {

    List<X509Certificate> certificates;

    try {
      certificates =
          idpSsoDescriptor
              .getKeyDescriptors()
              .stream()
              .filter(x -> x.getUse() == UsageType.SIGNING)
              .flatMap(SamlClient::getDatasWithCertificates)
              .map(SamlClient::getFirstCertificate)
              .collect(Collectors.toList());

    } catch (Exception e) {
      throw new SamlException("Exception in getCertificates", e);
    }

    return certificates;
  }

  private static Stream<X509Data> getDatasWithCertificates(KeyDescriptor descriptor) {
    return descriptor
        .getKeyInfo()
        .getX509Datas()
        .stream()
        .filter(d -> d.getX509Certificates().size() > 0);
  }

  private static X509Certificate getFirstCertificate(X509Data data) {
    try {
      org.opensaml.xml.signature.X509Certificate cert =
          data.getX509Certificates().stream().findFirst().orElse(null);
      if (cert != null) {
        return KeyInfoHelper.getCertificate(cert);
      }
    } catch (CertificateException e) {
      logger.error("Exception in getFirstCertificate", e);
    }

    return null;
  }

  private static Credential getCredential(X509Certificate certificate) {
    BasicX509Credential credential = new BasicX509Credential();
    credential.setEntityCertificate(certificate);
    credential.setPublicKey(certificate.getPublicKey());
    credential.setCRLs(Collections.emptyList());
    return credential;
  }

  /**
   * Decodes and validates an SAML response returned by an identity provider.
   *
   * @param encodedResponse the encoded response returned by the identity provider.
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public SamlLogoutResponse decodeAndValidateSamlLogoutResponse(String encodedResponse)
      throws SamlException {
    LogoutResponse logoutResponse = (LogoutResponse) parseResponse(encodedResponse);

    ValidatorUtils.validate(logoutResponse, responseIssuer, credentials);

    return new SamlLogoutResponse(logoutResponse.getStatus());
  }

  /**
   * Decodes and validates an SAML logout request send by an identity provider.
   *
   * @param encodedRequest the encoded request send by the identity provider.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public void decodeAndValidateSamlLogoutRequest(String encodedRequest, String nameID)
      throws SamlException {
    LogoutRequest logoutRequest = (LogoutRequest) parseResponse(encodedRequest);

    ValidatorUtils.validate(logoutRequest, responseIssuer, credentials, nameID);
  }
  /**
   * Set service provider keys.
   *
   * @param publicKey  the public key
   * @param privateKey the private key
   * @throws SamlException the saml exception
   */
  public void setSPKeys(String publicKey, String privateKey) throws SamlException {
    if (publicKey == null || privateKey == null) {
      return;
    }
    PrivateKey pk = loadPrivateKey(privateKey);
    X509Certificate cert = this.loadCertificate(publicKey);
    spCredential = new BasicX509Credential();
    spCredential.setEntityCertificate(cert);
    spCredential.setPrivateKey(pk);
  }

  /**
   * Gets attributes from the IDP Response
   *
   * @param response the response
   * @return the attributes
   */
  public static Map<String, String> getAttributes(SamlResponse response) {
    HashMap<String, String> map = new HashMap<>();
    if (response == null) {
      return map;
    }
    List<AttributeStatement> attributeStatements = response.getAssertion().getAttributeStatements();
    if (attributeStatements == null) {
      return map;
    }

    for (AttributeStatement statement : attributeStatements) {
      for (Attribute attribute : statement.getAttributes()) {
        XMLObject xmlObject = attribute.getAttributeValues().get(0);
        if (xmlObject instanceof XSStringImpl) {
          map.put(attribute.getName(), ((XSStringImpl) xmlObject).getValue());
        } else {
          map.put(attribute.getName(), ((XSAnyImpl) xmlObject).getTextContent());
        }
      }
    }
    return map;
  }
  /**
   * Gets the encoded logout request.
   *
   * @param nameId the name id
   * @return the logout request
   * @throws SamlException the saml exception
   */
  public String getLogoutRequest(String nameId) throws SamlException {
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
    //Add the signature
    signSAMLObject(request);

    //Convert the xml object to string
    StringWriter stringWriter;
    try {
      stringWriter = marshallXmlObject(request);
    } catch (MarshallingException e) {
      throw new SamlException("Error while marshalling SAML request to XML", e);
    }

    logger.trace("Issuing SAML Logout request: " + stringWriter.toString());

    return Base64.encodeBytes(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
  }
  /**
   * Gets saml logout response.
   *
   * @param status  the status code @See StatusCode.java
   * @return saml logout response
   * @throws SamlException the saml exception
   */
  public String getSamlLogoutResponse(final String status) throws SamlException {
    return getSamlLogoutResponse(status, null);
  }
  /**
   * Gets saml logout response.
   *
   * @param status  the status code @See StatusCode.java
   * @param statMsg the status message
   * @return saml logout response
   * @throws SamlException the saml exception
   */
  public String getSamlLogoutResponse(final String status, final String statMsg)
      throws SamlException {
    LogoutResponse response = (LogoutResponse) buildSamlObject(LogoutResponse.DEFAULT_ELEMENT_NAME);
    response.setID("z" + UUID.randomUUID().toString()); // ADFS needs IDs to start with a letter

    response.setVersion(SAMLVersion.VERSION_20);
    response.setIssueInstant(DateTime.now());

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    response.setIssuer(issuer);

    //Status
    Status stat = (Status) buildSamlObject(Status.DEFAULT_ELEMENT_NAME);
    StatusCode statCode = new StatusCodeBuilder().buildObject();
    statCode.setValue(status);
    stat.setStatusCode(statCode);
    if (statMsg != null) {
      StatusMessage statMessage = new StatusMessageBuilder().buildObject();
      statMessage.setMessage(statMsg);
      stat.setStatusMessage(statMessage);
    }
    response.setStatus(stat);
    //Add a signature into the response
    signSAMLObject(response);

    StringWriter stringWriter;
    try {
      stringWriter = marshallXmlObject(response);
    } catch (MarshallingException ex) {
      throw new SamlException("Error while marshalling SAML request to XML", ex);
    }

    logger.trace("Issuing SAML Logout request: " + stringWriter.toString());

    return Base64.encodeBytes(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
  }
  /**
   * Processes a POST containing the SAML logout request.
   *
   * @param request the {@link HttpServletRequest}.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public void processLogoutRequestPostFromIdentityProvider(
      HttpServletRequest request, String nameID) throws SamlException {
    String encodedResponse = request.getParameter(HTTP_REQ_SAML_PARAM);
    decodeAndValidateSamlLogoutRequest(encodedResponse, nameID);
  }
  /**
   * Processes a POST containing the SAML response.
   *
   * @param request the {@link HttpServletRequest}.
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public SamlLogoutResponse processPostLogoutResponseFromIdentityProvider(
      HttpServletRequest request) throws SamlException {
    String encodedResponse = request.getParameter(HTTP_RESP_SAML_PARAM);
    return decodeAndValidateSamlLogoutResponse(encodedResponse);
  }
  /**
   * Redirects an {@link HttpServletResponse} to the configured identity provider.
   *
   * @param response   The {@link HttpServletResponse}.
   * @param relayState Optional relay state that will be passed along.
   * @throws IOException   thrown if an IO error occurs.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public void redirectToIdentityProvider(
      HttpServletResponse response, String relayState, String nameId)
      throws IOException, SamlException {
    Map<String, String> values = new HashMap<>();
    values.put("SAMLRequest", getLogoutRequest(nameId));
    if (relayState != null) {
      values.put("RelayState", relayState);
    }

    BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
  }
  /**
   * Redirect to identity provider logout.
   *
   * @param response   the response
   * @param statusCode the status code
   * @param statMsg    the stat msg
   * @throws IOException   the io exception
   * @throws SamlException the saml exception
   */
  public void redirectToIdentityProviderLogout(
      HttpServletResponse response, String statusCode, String statMsg)
      throws IOException, SamlException {
    Map<String, String> values = new HashMap<>();
    values.put(HTTP_RESP_SAML_PARAM, getSamlLogoutResponse(statusCode, statMsg));
    BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
  }

  private static XMLObject buildSamlObject(QName qname) {
    return Configuration.getBuilderFactory().getBuilder(qname).buildObject(qname);
  }

  private PrivateKey createPrivateKey(byte[] file)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(file);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(kspec);
  }

  private X509Certificate createCertificate(FileInputStream fis) throws SamlException {
    try {
      BufferedInputStream bis = new BufferedInputStream(fis);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      if (bis.available() > 0) {
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
  /**
   * Decode the encrypted assertion.
   *
   * @param response the response
   * @throws DecryptionException the decryption exception
   */
  private void decodeEncryptedAssertion(Response response) throws DecryptionException {
    if (response.getEncryptedAssertions().size() == 0) {
      return;
    }
    for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
      // Create a decrypter.
      Decrypter decrypter =
          new Decrypter(
              null,
              new StaticKeyInfoCredentialResolver(spCredential),
              new InlineEncryptedKeyResolver());
      // Decrypt the assertion.
      Assertion decryptedAssertion = decrypter.decrypt(encryptedAssertion);
      // Add the assertion
      response.getAssertions().add(decryptedAssertion);
    }
  }

  private X509Certificate loadCertificate(String filename) throws SamlException {
    try {
      FileInputStream fis = new FileInputStream(filename);
      return createCertificate(fis);
    } catch (FileNotFoundException e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  private PrivateKey loadPrivateKey(String filename) throws SamlException {
    try {
      RandomAccessFile raf = new RandomAccessFile(filename, "r");
      byte[] buf = new byte[(int) raf.length()];
      raf.readFully(buf);
      raf.close();
      return createPrivateKey(buf);
    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }

  private StringWriter marshallXmlObject(XMLObject object) throws MarshallingException {
    StringWriter stringWriter = new StringWriter();
    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(object);
    Element dom = marshaller.marshall(object);
    XMLHelper.writeNode(dom, stringWriter);

    return stringWriter;
  }

  private SAMLObject parseResponse(String encodedResponse) throws SamlException {
    String decodedResponse;
    decodedResponse = new String(Base64.decode(encodedResponse), StandardCharsets.UTF_8);
    logger.trace("Validating SAML response: " + decodedResponse);
    try {
      DOMParser parser = createDOMParser();
      parser.parse(new InputSource(new StringReader(decodedResponse)));
      return (SAMLObject)
          Configuration.getUnmarshallerFactory()
              .getUnmarshaller(parser.getDocument().getDocumentElement())
              .unmarshall(parser.getDocument().getDocumentElement());
    } catch (IOException | SAXException | UnmarshallingException ex) {
      throw new SamlException("Cannot decode xml encoded response", ex);
    }
  }

  private Signature setSignatureRaw(String signatureAlgorithm, X509Credential cred)
      throws SAMLException {
    Signature signature = (Signature) buildSamlObject(Signature.DEFAULT_ELEMENT_NAME);
    signature.setSigningCredential(cred);
    signature.setSignatureAlgorithm(signatureAlgorithm);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

    try {
      KeyInfo keyInfo = (KeyInfo) buildSamlObject(KeyInfo.DEFAULT_ELEMENT_NAME);
      X509Data data = (X509Data) buildSamlObject(X509Data.DEFAULT_ELEMENT_NAME);
      org.opensaml.xml.signature.X509Certificate cert =
          (org.opensaml.xml.signature.X509Certificate)
              buildSamlObject(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
      String value =
          org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
      cert.setValue(value);
      data.getX509Certificates().add(cert);
      keyInfo.getX509Datas().add(data);
      signature.setKeyInfo(keyInfo);
      return signature;

    } catch (CertificateEncodingException e) {
      throw new SAMLException("Error getting certificate", e);
    }
  }

  private void signSAMLObject(SignableSAMLObject samlObject) throws SamlException {

    try {

      if (spCredential != null) {
        Signature signature =
            this.setSignatureRaw(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, spCredential);

        samlObject.setSignature(signature);

        List<Signature> signatureList = new ArrayList<>();
        signatureList.add(signature);

        // Marshall and Sign
        MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(samlObject);

        marshaller.marshall(samlObject);

        org.apache.xml.security.Init.init();
        Signer.signObjects(signatureList);
      }
    } catch (Exception e) {
      e.printStackTrace();
      throw new SamlException("Failed to sign request", e);
    }
  }
}
