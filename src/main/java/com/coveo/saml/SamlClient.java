package com.coveo.saml;

import com.sun.org.apache.xerces.internal.parsers.DOMParser;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
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
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Util;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class SamlClient {
  private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);
  private static boolean initializedOpenSaml = false;

  private String relyingPartyIdentifier;
  private String assertionConsumerServiceUrl;
  private String identityProviderUrl;
  private String responseIssuer;
  private Credential credential;

  /**
   * Constructs an SAML client using explicit parameters.
   * @param relyingPartyIdentifier the identifier of the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the SAML response.
   * @param identityProviderUrl the url where the SAML request will be submitted.
   * @param responseIssuer the expected issuer ID for SAML responses.
   * @param certificate the base-64 encoded certificate to use to validate responses.
   * @throws SamlException thrown if any error occur while loading the provider information.
   */
  public SamlClient(
      String relyingPartyIdentifier,
      String assertionConsumerServiceUrl,
      String identityProviderUrl,
      String responseIssuer,
      X509Certificate certificate)
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
    if (certificate == null) {
      throw new IllegalArgumentException("certificate");
    }

    this.relyingPartyIdentifier = relyingPartyIdentifier;
    this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    this.identityProviderUrl = identityProviderUrl;
    this.responseIssuer = responseIssuer;
    credential = getCredential(certificate);
  }

  /**
   * Returns the url where SAML requests should be posted.
   * @return the url where SAML requests should be posted.
   */
  public String getIdentityProviderUrl() {
    return identityProviderUrl;
  }

  /**
   * Builds an encoded SAML request.
   * @return The base-64 encoded SAML request.
   * @throws SamlException thrown if an unexpected error occurs.
   */
  public String getSamlRequest() throws SamlException {
    AuthnRequest request = (AuthnRequest) buildSamlObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    request.setID("z" + UUID.randomUUID().toString()); // ADFS needs IDs to start with a letter

    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssueInstant(DateTime.now());
    request.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    request.setIssuer(issuer);

    NameIDPolicy nameIDPolicy = (NameIDPolicy) buildSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
    nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    request.setNameIDPolicy(nameIDPolicy);

    RequestedAuthnContext requestedAuthnContext =
        (RequestedAuthnContext) buildSamlObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
    request.setRequestedAuthnContext(requestedAuthnContext);

    AuthnContextClassRef authnContextClassRef =
        (AuthnContextClassRef) buildSamlObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    authnContextClassRef.setAuthnContextClassRef(
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

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

  /**
   * Decodes and validates an SAML response returned by an identity provider.
   * @param encodedResponse the encoded response returned by the identity provider.
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
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
      DOMParser parser = new DOMParser();
      parser.parse(new InputSource(new StringReader(decodedResponse)));
      response =
          (Response)
              Configuration.getUnmarshallerFactory()
                  .getUnmarshaller(parser.getDocument().getDocumentElement())
                  .unmarshall(parser.getDocument().getDocumentElement());
    } catch (IOException | SAXException | UnmarshallingException ex) {
      throw new SamlException("Cannot decode xml encoded response", ex);
    }

    validateResponse(response);
    validateAssertion(response);
    validateSignature(response);

    Assertion assertion = response.getAssertions().get(0);
    return new SamlResponse(assertion);
  }

  /**
   * Redirects an {@link HttpServletResponse} to the configured identity provider.
   * @param response The {@link HttpServletResponse}.
   * @param relayState Optional relay state that will be passed along.
   * @throws IOException thrown if an IO error occurs.
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
   * @param request the {@link HttpServletRequest}.
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public SamlResponse processPostFromIdentityProvider(HttpServletRequest request)
      throws SamlException {
    String encodedResponse = request.getParameter("SAMLResponse");
    return decodeAndValidateSamlResponse(encodedResponse);
  }

  /**
   * Constructs an SAML client using XML metadata obtained from the identity provider.
   * <p>
   * When using Okta as an identity provider, it is possible to pass null to relyingPartyIdentifier and assertionConsumerServiceUrl; they will be inferred from the metadata provider XML.
   * @param relyingPartyIdentifier the identifier for the relying party.
   * @param assertionConsumerServiceUrl the url where the identity provider will post back the SAML response.
   * @param metadata the XML metadata obtained from the identity provider.
   * @return The created {@link SamlClient}.
   * @throws SamlException thrown if any error occur while loading the metadata information.
   */
  public static SamlClient fromMetadata(
      String relyingPartyIdentifier, String assertionConsumerServiceUrl, Reader metadata)
      throws SamlException {

    ensureOpenSamlIsInitialized();

    MetadataProvider metadataProvider = createMetadataProvider(metadata);
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataProvider);

    IDPSSODescriptor idpSsoDescriptor = getIDPSSODescriptor(entityDescriptor);
    SingleSignOnService postBinding = getPostBinding(idpSsoDescriptor);
    X509Certificate x509Certificate = getCertificate(idpSsoDescriptor);
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
      assertionConsumerServiceUrl = postBinding.getLocation();
    }

    String identityProviderUrl = postBinding.getLocation();
    String responseIssuer = entityDescriptor.getEntityID();

    return new SamlClient(
        relyingPartyIdentifier,
        assertionConsumerServiceUrl,
        identityProviderUrl,
        responseIssuer,
        x509Certificate);
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
    DateTime now = DateTime.now();

    if (now.isBefore(conditions.getNotBefore())) {
      throw new SamlException(
          "The assertion cannot be used before " + conditions.getNotBefore().toString());
    }

    if (now.isAfter(conditions.getNotOnOrAfter())) {
      throw new SamlException(
          "The assertion cannot be after before " + conditions.getNotOnOrAfter().toString());
    }
  }

  private void validateSignature(Response response) throws SamlException {
    // I must admit this is not yet 100% clear to me, but it seems that it's OK if either
    // the assertion is signed (since we take the stuff from it) OR if the response itself
    // is signed, since it contains the assertion. I've seen boths possibilities coming out
    // from ADFS and Okta.
    if (!validateResponseSignature(response) && !validateAssertionSignature(response)) {
      throw new SamlException("No signature is present in either response or assertion");
    }
  }

  private boolean validateResponseSignature(Response response) throws SamlException {
    Signature signature = response.getSignature();
    if (signature == null) {
      return false;
    }

    try {
      SignatureValidator signatureValidator = new SignatureValidator(credential);
      signatureValidator.validate(signature);
      return true;
    } catch (ValidationException ex) {
      throw new SamlException("Invalid response signature", ex);
    }
  }

  private boolean validateAssertionSignature(Response response) throws SamlException {
    Assertion assertion = response.getAssertions().get(0);

    Signature signature = assertion.getSignature();
    if (signature == null) {
      return false;
    }

    try {
      SignatureValidator signatureValidator = new SignatureValidator(credential);
      signatureValidator.validate(signature);
      return true;
    } catch (ValidationException ex) {
      throw new SamlException("Invalid assertion signature", ex);
    }
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

  private static MetadataProvider createMetadataProvider(Reader metadata) throws SamlException {
    try {
      DOMParser parser = new DOMParser();
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

  private static SingleSignOnService getPostBinding(IDPSSODescriptor idpSsoDescriptor)
      throws SamlException {
    return idpSsoDescriptor
        .getSingleSignOnServices()
        .stream()
        .filter(x -> x.getBinding().equals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"))
        .findAny()
        .orElseThrow(() -> new SamlException("Cannot find HTTP-POST SSO binding in metadata"));
  }

  private static X509Certificate getCertificate(IDPSSODescriptor idpSsoDescriptor)
      throws SamlException {
    KeyDescriptor keyDescriptor =
        idpSsoDescriptor
            .getKeyDescriptors()
            .stream()
            .filter(x -> x.getUse() == UsageType.SIGNING)
            .findAny()
            .orElseThrow(() -> new SamlException("Cannot find signing certificate"));

    X509Data data =
        keyDescriptor
            .getKeyInfo()
            .getX509Datas()
            .stream()
            .findFirst()
            .orElseThrow(() -> new SamlException("Cannot find X509 data"));

    org.opensaml.xml.signature.X509Certificate certificate =
        data.getX509Certificates()
            .stream()
            .findFirst()
            .orElseThrow(() -> new SamlException("Cannot find X509 certificate"));

    try {
      return KeyInfoHelper.getCertificate(certificate);
    } catch (CertificateException ex) {
      throw new SamlException("Cannot load signing certificate", ex);
    }
  }

  private static X509Certificate getCertificate(String certificate) throws SamlException {
    try {
      Collection<X509Certificate> certificates =
          X509Util.decodeCertificate(Base64.decode(certificate));
      return certificates
          .stream()
          .findFirst()
          .orElseThrow(() -> new SamlException("Cannot load certificate"));
    } catch (CertificateException ex) {
      throw new SamlException("Cannot load certificate", ex);
    }
  }

  private static Credential getCredential(X509Certificate certificate) throws SamlException {
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
