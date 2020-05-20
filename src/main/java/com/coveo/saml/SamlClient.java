package com.coveo.saml;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
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
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.impl.XSAnyImpl;
import org.opensaml.core.xml.schema.impl.XSStringImpl;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

public class SamlClient {
  private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);

  private static final String HTTP_REQ_SAML_PARAM = "SAMLRequest";
  private static final String HTTP_RESP_SAML_PARAM = "SAMLResponse";

  private static boolean initializedOpenSaml = false;
  private BasicParserPool domParser;

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
    this.domParser = createDOMParser();
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
   * Decodes and validates an SAML response returned by an identity provider.
   *
   * @param encodedResponse the encoded response returned by the identity provider.
   * @param method The HTTP method used by the request
   *
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public SamlResponse decodeAndValidateSamlResponse(String encodedResponse, String method)
      throws SamlException {
    //Decode and parse the response
    Response response = (Response) parseResponse(encodedResponse, method);

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

    if (samlBinding == SamlClient.SamlIdpBinding.Redirect) {
      response.sendRedirect(getRedirectURL(relayState));
      return;
    }

    Map<String, String> values = new HashMap<>();
    values.put("SAMLRequest", getSamlRequest());
    if (relayState != null) {
      values.put("RelayState", relayState);
    }

    BrowserUtils.postUsingBrowser(identityProviderUrl, response, values);
  }

  public String getRedirectURL(String relayState) throws IOException, SamlException {
    //From https://medium.com/@sagarag/reloading-saml-saml-basics-b8999995c73e
    //- RelayState is supported but should be limited to 80 bytes and it should be appended to the URL with “RelayState=value” format.
    //- The SAML request is first compressed using DEFLATE compression mechanism and then encoded using Base64 finally it again need to be URL encoded.
    //- For the request signing, it should use DSAWithSHA or RSAWithSHA algorithms.
    //- HTTP Cache should not be used with this binding.
    //- SAML processors should not use HTTP error codes instead SAML error coded need to be used.
    //
    //Following are the URL parameter names supported in this binding.
    //- SAMLRequest — SAML request message
    //- RelayState — RelayState value
    //nb. these are additional to POST...
    //- SAMLEncoding — indicate the SAML encoding mechanism
    //- SigAlg — Signature algorithm identifier
    //- Signature — Base64 encoded signature value
    //
    //Example: https://localhost:9443/samlsso?SAMLRequest=nZPBjpskDyneY4s...&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=VoTUhZQVI1y...
    //
    //From: https://www.oasis-open.org/committees/download.php/35387/sstc-saml-bindings-errata-2.0-wd-05-diff.pdf
    //1. Any signature on the SAML protocol message, including the <ds:Signature> XML element itself,MUST be removed.
    //   Note that if the content of the message includes another signature, such as asigned SAML assertion, this embedded signature is not removed.
    //   However, the length of such amessage after encoding essentially precludes using this mechanism.
    //   Thus SAML protocolmessages that contain signed content SHOULD NOT be encoded using this mechanism.
    //2. The DEFLATE compression mechanism, as specified in [RFC1951] is then applied to the entireremaining XML content of the original SAML protocol message.
    //3. The compressed data is subsequently base64-encoded according to the rules specified in  IETFRFC 2045 [RFC2045].
    //   Linefeeds or other whitespace MUST be removed from the result.
    //4. The base-64 encoded data is then URL-encoded, and added to the URL as a query stringparameter which MUST be named SAMLRequest (if the message is a SAML request) or
    //   SAMLResponse (if the message is a SAML response).
    //5. If RelayState data is to accompany the SAML protocol message, it MUST be URL-encoded and placed in an additional query string parameter named RelayState.
    //6. If the original SAML protocol message was signed using an XML digital signature, a new signaturecovering the encoded data as specified above MUST be attached using the rules stated below.
    //
    //SAMLRequest=value&RelayState=value&SigAlg=value "Finally, note that if there is no RelayState value, the entire parameter should be omitted from thesignature computation (and not included as an empty parameter name)."
    //
    StringBuilder sb = new StringBuilder();
    sb.append("SAMLRequest=").append(URLEncoder.encode(getSamlRequest(SamlClient.SamlIdpBinding.Redirect), "UTF-8"));

    if (relayState != null)
      sb.append("&RelayState=").append(URLEncoder.encode(relayState, "UTF-8"));

    sb.append("&SigAlg=").append( "http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1" );

    byte[] bytesToSign = sb.toString().getBytes("UTF-8");
    try {
      java.security.Signature sig = java.security.Signature.getInstance("SHA1withRSA");
      sig.initSign(spCredential.getPrivateKey());
      sig.update(bytesToSign);
      byte[] signature = sig.sign();
      sb.append("&Signature=")
          .append(URLEncoder.encode(Base64.encodeBase64String(signature), "UTF-8"));
    } catch (NoSuchAlgorithmException | InvalidKeyException | java.security.SignatureException e) {
      throw new SamlException("Unsupported algorithm. " + e);
    }

    sb.append("&SAMLEncoding=")
        .append(
            URLEncoder.encode(
                "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE", "UTF-8")); //optional

    return identityProviderUrl + "?" + sb.toString();
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
    return decodeAndValidateSamlResponse(encodedResponse, request.getMethod());
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
   * @param certificates                list of certificates.
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

    DOMMetadataResolver metadataResolver = createMetadataResolver(skipBom(metadata));
    EntityDescriptor entityDescriptor = getEntityDescriptor(metadataResolver);

    IDPSSODescriptor idpSsoDescriptor = getIDPSSODescriptor(entityDescriptor);
    SingleSignOnService idpBinding = null;
    if (idpSsoDescriptor.getSingleSignOnServices() != null
        && !idpSsoDescriptor.getSingleSignOnServices().isEmpty()) {
      idpBinding = getIdpBinding(idpSsoDescriptor, samlBinding);
    }

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

    if (idpBinding != null && assertionConsumerServiceUrl == null && isOkta) {
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

    String identityProviderUrl;
    if (idpBinding != null) {
      identityProviderUrl = idpBinding.getLocation();
    } else {
      identityProviderUrl = assertionConsumerServiceUrl;
    }
    String responseIssuer = entityDescriptor.getEntityID();

    return new SamlClient(
        relyingPartyIdentifier,
        assertionConsumerServiceUrl,
        identityProviderUrl,
        responseIssuer,
        x509Certificates,
        samlBinding);
  }

  /**
   * Wrap a {@link java.io.Reader Reader} to skip a BOM if it is present.
   * OpenSaml won't accept a metadata file if it starts with a BOM.
   * @param metadata The metadata with optional BOM
   * @return A {@link Reader} which will never return a BOM
   */
  private static InputStream skipBom(Reader metadata) throws SamlException {
    try {
      InputStream metadataInputStream;
      metadataInputStream =
          IOUtils.toInputStream(IOUtils.toString(metadata), StandardCharsets.UTF_8);

      return new BOMInputStream(metadataInputStream, false);
    } catch (IOException e) {
      throw new SamlException("Couldn't read metadata", e);
    }
  }

  /**
   * Decode Base64, then decode if needed
   * @param encodedResponse a Base64 String with optionally deflated xml
   * @param method The HTTP method used by the request
   * @return A Reader with decoded and inflated xml
   */
  private static Reader decodeAndInflate(String encodedResponse, String method) {
    ByteArrayInputStream afterB64Decode =
        new ByteArrayInputStream(Base64.decodeBase64(encodedResponse));

    if ("GET".equals(method)) {
      // If the request was a GET request, the value will have been deflated
      InputStream afterInflate = new InflaterInputStream(afterB64Decode, new Inflater(true));
      return new InputStreamReader(afterInflate, StandardCharsets.UTF_8);
    } else {
      return new InputStreamReader(afterB64Decode, StandardCharsets.UTF_8);
    }
  }

  private synchronized static void ensureOpenSamlIsInitialized() throws SamlException {
    if (!initializedOpenSaml) {
      try {
        InitializationService.initialize();
        initializedOpenSaml = true;
      } catch (Throwable ex) {
        throw new SamlException("Error while initializing the Open SAML library", ex);
      }
    }
  }

  private static BasicParserPool createDOMParser() throws SamlException {
    BasicParserPool basicParserPool = new BasicParserPool();
    try {
      basicParserPool.initialize();
    } catch (ComponentInitializationException e) {
      throw new SamlException("Failed to create an XML parser");
    }

    return basicParserPool;
  }

  private static DOMMetadataResolver createMetadataResolver(InputStream metadata)
      throws SamlException {
    try {
      BasicParserPool parser = createDOMParser();
      Document metadataDocument = parser.parse(metadata);
      DOMMetadataResolver resolver = new DOMMetadataResolver(metadataDocument.getDocumentElement());
      resolver.setId(
          "componentId"); // The resolver needs an ID for the initialization to go through.
      resolver.initialize();
      return resolver;
    } catch (ComponentInitializationException | XMLParserException ex) {
      throw new SamlException("Cannot load identity provider metadata", ex);
    }
  }

  private static EntityDescriptor getEntityDescriptor(DOMMetadataResolver metadata)
      throws SamlException {
    List<EntityDescriptor> entityDescriptors = new ArrayList<>();
    metadata.forEach(entityDescriptors::add);
    if (entityDescriptors.size() != 1) {
      throw new SamlException("Bad entity descriptor count: " + entityDescriptors.size());
    }
    return entityDescriptors.get(0);
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
      org.opensaml.xmlsec.signature.X509Certificate cert =
          data.getX509Certificates().stream().findFirst().orElse(null);
      if (cert != null) {
        return KeyInfoSupport.getCertificate(cert);
      }
    } catch (CertificateException e) {
      logger.error("Exception in getFirstCertificate", e);
    }

    return null;
  }

  private static Credential getCredential(X509Certificate certificate) {
    BasicX509Credential credential = new BasicX509Credential(certificate);
    credential.setCRLs(Collections.emptyList());
    return credential;
  }

  /**
   * Decodes and validates an SAML response returned by an identity provider.
   *
   * @param encodedResponse the encoded response returned by the identity provider.
   * @param method The HTTP method used by the request
   * @return An {@link SamlResponse} object containing information decoded from the SAML response.
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public SamlLogoutResponse decodeAndValidateSamlLogoutResponse(
      String encodedResponse, String method) throws SamlException {
    LogoutResponse logoutResponse = (LogoutResponse) parseResponse(encodedResponse, method);

    ValidatorUtils.validate(logoutResponse, responseIssuer, credentials);

    return new SamlLogoutResponse(logoutResponse.getStatus());
  }

  /**
   * Decodes and validates an SAML logout request send by an identity provider.
   *
   * @param encodedRequest the encoded request send by the identity provider.
   * @param nameID The user to logout
   * @param method The HTTP method used by the request
   * @throws SamlException if the signature is invalid, or if any other error occurs.
   */
  public void decodeAndValidateSamlLogoutRequest(
      String encodedRequest, String nameID, String method) throws SamlException {
    LogoutRequest logoutRequest = (LogoutRequest) parseResponse(encodedRequest, method);

    ValidatorUtils.validate(logoutRequest, responseIssuer, credentials, nameID);
  }
  /**
   * Set service provider keys.
   *
   * @param publicKey  the public key
   * @param privateKey the private key
   * @throws SamlException if publicKey and privateKey don't form a valid credential
   */
  public void setSPKeys(String publicKey, String privateKey) throws SamlException {
    if (publicKey == null || privateKey == null) {
      throw new SamlException("No credentials provided");
    }
    PrivateKey pk = loadPrivateKey(privateKey);
    X509Certificate cert = loadCertificate(publicKey);
    spCredential = new BasicX509Credential(cert, pk);
  }

  /**
   * Set service provider keys.
   *
   * @param certificate the certificate
   * @param privateKey the private key
   * @throws SamlException if publicKey and privateKey don't form a valid credential
   */
  public void setSPKeys(X509Certificate certificate, PrivateKey privateKey) throws SamlException {
    if (certificate == null || privateKey == null) {
      throw new SamlException("No credentials provided");
    }
    spCredential = new BasicX509Credential(certificate, privateKey);
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

  /** Create a minimal SAML request
   *
   * @param defaultElementName The SomeClass.DEFAULT_ELEMENT_NAME we'll be casting this object into
   * */
  private RequestAbstractType getBasicSamlRequest(QName defaultElementName) {
    RequestAbstractType request = (RequestAbstractType) buildSamlObject(defaultElementName);
    request.setID("z" + UUID.randomUUID().toString()); // ADFS needs IDs to start with a letter

    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssueInstant(DateTime.now());

    Issuer issuer = (Issuer) buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(relyingPartyIdentifier);
    request.setIssuer(issuer);

    return request;
  }

  /** Convert a SAML request to a base64-encoded String
   *
   * @param request The request to encode
   * @param binding Whether we are doing a POST or Redirect
   * @throws SamlException if marshalling the request fails
   * */
  private String marshallAndEncodeSamlObject(RequestAbstractType request, SamlIdpBinding binding)
      throws SamlException {
    StringWriter stringWriter;
    try {
      stringWriter = marshallXmlObject(request);
    } catch (MarshallingException e) {
      throw new SamlException("Error while marshalling SAML request to XML", e);
    }

    String requestStr = stringWriter.toString();
    logger.trace("Issuing SAML request: " + requestStr);

    byte[] requestBytes;
    if (binding == SamlClient.SamlIdpBinding.Redirect) {
      try {
        //For a Redirect we compress (deflate) the bytes before we Base64 them
        InputStream input = new ByteArrayInputStream(requestStr.getBytes("UTF-8"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Deflater def = new Deflater(1, true);
        DeflaterOutputStream compresser = new DeflaterOutputStream(output, def);
        int len;
        byte[] oneKay = new byte[1024];
        while ((len = input.read(oneKay)) != -1) {
          compresser.write(oneKay, 0, len);
        }
        compresser.flush();
        compresser.finish();
        requestBytes = output.toByteArray();
      } catch (IOException e) {
        throw new SamlException("Failed to deflate request for redirect.", e);
      }
    } else {
      //For a POST we just Base64 the bytes
      requestBytes = requestStr.getBytes(StandardCharsets.UTF_8);
    }
    return Base64.encodeBase64String(requestBytes);
  }

  /**
   * Builds an encoded SAML request for the POST binding.
   *
   * @return The base-64 encoded SAML request.
   * @throws SamlException thrown if an unexpected error occurs.
   */
  public String getSamlRequest() throws SamlException {
    return getSamlRequest(SamlClient.SamlIdpBinding.POST);
  }

  /**
   * Builds an encoded SAML request.
   *
   * @return The base-64 encoded SAML request.
   * @throws SamlException thrown if an unexpected error occurs.
   */
  public String getSamlRequest(SamlIdpBinding binding) throws SamlException {
    AuthnRequest request = (AuthnRequest) getBasicSamlRequest(AuthnRequest.DEFAULT_ELEMENT_NAME);

    request.setProtocolBinding(
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-" + this.samlBinding.toString());
    request.setDestination(identityProviderUrl);
    request.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);

    NameIDPolicy nameIDPolicy = (NameIDPolicy) buildSamlObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
    nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    request.setNameIDPolicy(nameIDPolicy);

    if (binding != SamlClient.SamlIdpBinding.Redirect) 
        signSAMLObject(request);

    return marshallAndEncodeSamlObject(request, binding);
  }

  /**
   * Gets the encoded logout request.
   * 
   * Assumes use of POST.
   *
   * @param nameId the name id
   * @return the logout request
   * @throws SamlException the saml exception
   */
  public String getLogoutRequest(String nameId) throws SamlException {
    LogoutRequest request = (LogoutRequest) getBasicSamlRequest(LogoutRequest.DEFAULT_ELEMENT_NAME);

    NameID nid = (NameID) buildSamlObject(NameID.DEFAULT_ELEMENT_NAME);
    nid.setValue(nameId);
    request.setNameID(nid);

    signSAMLObject(request);

    return marshallAndEncodeSamlObject(request, SamlClient.SamlIdpBinding.POST);
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

    return Base64.encodeBase64String(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
  }
  /**
   * Processes a POST containing the SAML logout request.
   *
   * @param request the {@link HttpServletRequest}.
   * @param nameID the user to log out.
   * @throws SamlException thrown is an unexpected error occurs.
   */
  public void processLogoutRequestPostFromIdentityProvider(
      HttpServletRequest request, String nameID) throws SamlException {
    String encodedResponse = request.getParameter(HTTP_REQ_SAML_PARAM);
    decodeAndValidateSamlLogoutRequest(encodedResponse, nameID, request.getMethod());
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
    return decodeAndValidateSamlLogoutResponse(encodedResponse, request.getMethod());
  }
  /**
   * Redirects an {@link HttpServletResponse} to the configured identity provider.
   *
   * @param response   The {@link HttpServletResponse}.
   * @param relayState Optional relay state that will be passed along.
   * @param nameId the user to log out.
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
    return XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilder(qname)
        .buildObject(qname);
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

      decrypter.setRootInNewDocument(true);

      // Decrypt the assertion.
      Assertion decryptedAssertion = decrypter.decrypt(encryptedAssertion);
      // Add the assertion
      response.getAssertions().add(decryptedAssertion);
    }
  }

  /**
   * Load an X.509 certificate
   * @param filename The path of the certificate
   * */
  private X509Certificate loadCertificate(String filename) throws SamlException {
    try (FileInputStream fis = new FileInputStream(filename);
        BufferedInputStream bis = new BufferedInputStream(fis)) {

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      return (X509Certificate) cf.generateCertificate(bis);

    } catch (FileNotFoundException e) {
      throw new SamlException("Public key file doesn't exist", e);
    } catch (Exception e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  /**
   * Load an X.509 certificate
   * @param bis An input stream providing the bytes of the key.
   * */
  private X509Certificate loadCertificate(InputStream bis) throws SamlException {
    try {

      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      return (X509Certificate) cf.generateCertificate(bis);

    } catch (Exception e) {
      throw new SamlException("Couldn't load public key", e);
    }
  }

  /**
   * Load a PKCS8 key
   * @param filename The path of the key
   * */
  private PrivateKey loadPrivateKey(String filename) throws SamlException {
    try (RandomAccessFile raf = new RandomAccessFile(filename, "r")) {
      byte[] buf = new byte[(int) raf.length()];
      raf.readFully(buf);
      PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
      KeyFactory kf = KeyFactory.getInstance("RSA");

      return kf.generatePrivate(kspec);

    } catch (FileNotFoundException e) {
      throw new SamlException("Private key file doesn't exist", e);
    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }

  /**
   * Load a PKCS8 key
   * @param bis An input stream providing the bytes of the key.
   * */
  private PrivateKey loadPrivateKey(InputStream bis) throws SamlException {
    try //(RandomAccessFile raf = new RandomAccessFile(filename, "r"))
    {

      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      int totalBytes = 0;
      byte[] onekay = new byte[1024];
      int bytesRead = 0;
      while (true) {
        bytesRead = bis.read(onekay);

        if (bytesRead == -1) break;

        if (bytesRead > 0) baos.write(onekay, 0, bytesRead);
      }
      bis.close();
      baos.flush();
      baos.close();

      PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(baos.toByteArray());
      KeyFactory kf = KeyFactory.getInstance("RSA");

      return kf.generatePrivate(kspec);

    } catch (Exception e) {
      throw new SamlException("Couldn't load private key", e);
    }
  }

  private StringWriter marshallXmlObject(XMLObject object) throws MarshallingException {
    StringWriter stringWriter = new StringWriter();
    Marshaller marshaller =
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
    Element dom = marshaller.marshall(object);
    XMLHelper.writeNode(dom, stringWriter);

    return stringWriter;
  }

  private SAMLObject parseResponse(String encodedResponse, String method) throws SamlException {
    logger.trace("Validating SAML response " + encodedResponse);
    try {
      Document responseDocument = domParser.parse(decodeAndInflate(encodedResponse, method));
      return (SAMLObject)
          XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
              .getUnmarshaller(responseDocument.getDocumentElement())
              .unmarshall(responseDocument.getDocumentElement());
    } catch (UnmarshallingException | XMLParserException ex) {
      throw new SamlException("Cannot decode xml encoded response", ex);
    }
  }

  /** Sign a SamlObject with default settings.
   * Note that this method is a no-op if spCredential is unset.
   * @param samlObject The object to sign
   *
   * @throws SamlException if {@link SignatureSupport#signObject(SignableXMLObject, SignatureSigningParameters) signObject} fails
   * */
  private void signSAMLObject(SignableSAMLObject samlObject) throws SamlException {
    if (spCredential != null) {
      try {
        // Describe how we're going to sign the request
        SignatureBuilder signer = new SignatureBuilder();
        Signature signature = signer.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setKeyInfo(
            new X509KeyInfoGeneratorFactory().newInstance().generate(spCredential));
        signature.setSigningCredential(spCredential);
        samlObject.setSignature(signature);

        // Actually sign the request
        SignatureSigningParameters signingParameters = new SignatureSigningParameters();
        signingParameters.setSigningCredential(spCredential);
        signingParameters.setSignatureCanonicalizationAlgorithm(
            SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signingParameters.setKeyInfoGenerator(new X509KeyInfoGeneratorFactory().newInstance());
        SignatureSupport.signObject(samlObject, signingParameters);
      } catch (SecurityException | MarshallingException | SignatureException e) {
        throw new SamlException("Failed to sign request", e);
      }
    }
  }

  /**
   * Get the response issuer. 
   * 
   * @return 
   */
  public String getResponseIssuer() {
    return responseIssuer;
  }
}
