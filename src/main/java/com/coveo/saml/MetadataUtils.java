package com.coveo.saml;

import java.io.StringWriter;
import java.security.cert.X509Certificate;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;


public class MetadataUtils {

	private static final Logger logger = LoggerFactory.getLogger(SamlClient.class);

	public static String generateSpMetadata(String entityId, String assertionConsumerServiceURL, String logoutServiceURL) {
		return generateSpMetadata(entityId, assertionConsumerServiceURL, logoutServiceURL, null);
	}

	public static String generateSpMetadata(String entityId, String assertionConsumerServiceURL, String singleLogoutServiceURL, X509Certificate certificate) {
		try {
			InitializationService.initialize();

			EntityDescriptor spEntityDescriptor = createSAMLObject(EntityDescriptor.class);
			if (spEntityDescriptor == null) {
				return null;
			}
			spEntityDescriptor.setEntityID(entityId);
			SPSSODescriptor spSSODescriptor = createSAMLObject(SPSSODescriptor.class);
			if (spSSODescriptor == null) {
				return null;
			}

			spSSODescriptor.setWantAssertionsSigned(false);
			spSSODescriptor.setAuthnRequestsSigned(false);

			if (certificate != null) {

				spSSODescriptor.setWantAssertionsSigned(true);
				spSSODescriptor.setAuthnRequestsSigned(true);

				X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
				keyInfoGeneratorFactory.setEmitEntityCertificate(true);
				KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

				KeyDescriptor encKeyDescriptor = createSAMLObject(KeyDescriptor.class);
				if (encKeyDescriptor == null) {
					return null;
				}

				encKeyDescriptor.setUse(UsageType.ENCRYPTION);

				Credential credential = new BasicX509Credential(certificate);

				try {
					encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
				}
				catch (Exception e) {
					logger.error("Error while creating credentials", e);
				}
				spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);

				KeyDescriptor signKeyDescriptor = createSAMLObject(KeyDescriptor.class);
				if (signKeyDescriptor == null) {
					return null;
				}

				signKeyDescriptor.setUse(UsageType.SIGNING); // Set usage

				try {
					signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(credential));
				}
				catch (SecurityException e) {
					logger.error("Error while creating credentials", e);
				}
				spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);
			}

			SingleLogoutService singleLogoutService = createSAMLObject(SingleLogoutService.class);
			if (singleLogoutService == null) {
				return null;
			}
			singleLogoutService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			singleLogoutService.setLocation(singleLogoutServiceURL);
			spSSODescriptor.getSingleLogoutServices().add(singleLogoutService);

			NameIDFormat nameIDFormat = createSAMLObject(NameIDFormat.class);
			if (nameIDFormat == null) {
				return null;
			}

			nameIDFormat.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
			spSSODescriptor.getNameIDFormats().add(nameIDFormat);

			AssertionConsumerService assertionConsumerService = createSAMLObject(AssertionConsumerService.class);
			if (assertionConsumerService == null) {
				return null;
			}
			assertionConsumerService.setIndex(1);
			assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);

			assertionConsumerService.setLocation(assertionConsumerServiceURL);
			spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);

			spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

			spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);

			DocumentBuilder builder;
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

			builder = factory.newDocumentBuilder();
			Document document = builder.newDocument();
			Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(spEntityDescriptor);
			out.marshall(spEntityDescriptor, document);

			TransformerFactory transformerfactory = TransformerFactory.newInstance();
			transformerfactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			Transformer transformer = transformerfactory.newTransformer();
			StringWriter stringWriter = new StringWriter();
			StreamResult streamResult = new StreamResult(stringWriter);
			DOMSource source = new DOMSource(document);
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
			transformer.transform(source, streamResult);
			stringWriter.close();

			return stringWriter.toString();
		}
		catch (Exception e) {
			logger.error("Error while generation SP metadata", e);
			return null;
		}

	}

	public static <T> T createSAMLObject(final Class<T> clazz) {
		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		QName defaultElementName = null;
		try {
			defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
		}
		catch (Exception e) {
			logger.error("Error while creating SAML object", e);
			return null;
		}
		T object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);

		return object;
	}
}
