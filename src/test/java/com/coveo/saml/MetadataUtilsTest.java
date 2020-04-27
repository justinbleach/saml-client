package com.coveo.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.junit.Test;


public class MetadataUtilsTest {

	@Test
	public void generateSpMetadata_AllNull() {
		String metadata = MetadataUtils.generateSpMetadata(null, null, null);
		assertEquals(
		    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"/>        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" index=\"1\"/>    </md:SPSSODescriptor></md:EntityDescriptor>",
		    metadata.replace("\r\n", "").replace("\n", ""));
	}

	@Test
	public void generateSpMetadata_AllFields() {
		String metadata = MetadataUtils.generateSpMetadata("testSp", "http://localhost:8080/consume", "http://localhost:8080/logout");
		assertEquals(
		    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"testSp\">    <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/logout\"/>        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/consume\" index=\"1\"/>    </md:SPSSODescriptor></md:EntityDescriptor>",
		    metadata.replace("\r\n", "").replace("\n", ""));
	}

	@Test
	public void generateSpMetadata_AllFieldsAndCertificat() {
		Certificate cert = null;
		try {
			InputStream keyStoreInputStream = this.getClass().getResourceAsStream("/com/coveo/saml/test.p12");

			KeyStore keystore = KeyStore.getInstance("PKCS12");
			keystore.load(keyStoreInputStream, "test".toCharArray());
			cert = keystore.getCertificate("tester");
		}
		catch (Exception e) {
			fail();
		}

		String metadata = MetadataUtils.generateSpMetadata("testSp", "http://localhost:8080/consume", "http://localhost:8080/logout", (X509Certificate) cert);
		assertEquals(
		    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"testSp\">    <md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">        <md:KeyDescriptor use=\"encryption\">            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">                <ds:X509Data>                    <ds:X509Certificate>MIIDCTCCAfGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJERTEMMAoGA1UECBMDTlJXMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQ0wCwYDVQQDEwR0ZXN0MB4XDTIwMDQyNzEzNDcwMFoXDTIxMDQyNzEzNDcwMFowSDELMAkGA1UEBhMCREUxDDAKBgNVBAgTA05SVzENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhZvjhIbJYV+ufRs/wF2W3710XzK8Cdg19pXZw9rOP5OE54ixAh6Hbbe0AHLTAt+T1Ljepqshwyo3an85q1JyuSLkPJBGks7WQKT6x0389V8c2nwbxOU2FkuIrOAG1y2rCmh+zjbndSBRLVMLPRwm7He+zeLH2yDl8tlPT3rVOzPX6/SEvhnG2yz2qsz1tNeski+9gK8+Anzzu+Ze2uf/q2y7tEFgrNOdkxEHtta4kqjglbacWougyNKFbRzILsDLJP7S0csssunXdIuYNmdsQ857Emjh1Yth4ZHaks8Np4TBRfjX+91PSQ5CTlw4zDijk/vNPgQ39cnY6SiucMEnkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAIGnBuviT6kDVK/b2mhCKKROp3bEqIaO3Ccl55H1ZKQNaY/xw4FUxaMGTdUuVo3Kbh5AT5iyEd+U+hd0skG4HbQ0nPkeEg15w07fh04mgTccC/IPAyrT++w9yiHOrXB0R6sXlwLOebXK6/6GQdt6pNDPc1GJaDhYhmI0IoXGO2iVFRlefqCSmGSRRbW4hU5SIdPrmCX/oOfnGBVN3Vo3wQtq9MAUTYnzpdVKBWaAbwzJdWXkF5GbHue5lxOnKmZB7ctd7VZk+L+dtmCozABk+NjdF0nGnjc3zIHD3EE+NCIas9jYPr0Ib8SReNsVL46zF3w1BvxQfkpMLIQThXyoZ/w==</ds:X509Certificate>                </ds:X509Data>            </ds:KeyInfo>        </md:KeyDescriptor>        <md:KeyDescriptor use=\"signing\">            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">                <ds:X509Data>                    <ds:X509Certificate>MIIDCTCCAfGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJERTEMMAoGA1UECBMDTlJXMQ0wCwYDVQQKEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQ0wCwYDVQQDEwR0ZXN0MB4XDTIwMDQyNzEzNDcwMFoXDTIxMDQyNzEzNDcwMFowSDELMAkGA1UEBhMCREUxDDAKBgNVBAgTA05SVzENMAsGA1UEChMEdGVzdDENMAsGA1UECxMEdGVzdDENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhZvjhIbJYV+ufRs/wF2W3710XzK8Cdg19pXZw9rOP5OE54ixAh6Hbbe0AHLTAt+T1Ljepqshwyo3an85q1JyuSLkPJBGks7WQKT6x0389V8c2nwbxOU2FkuIrOAG1y2rCmh+zjbndSBRLVMLPRwm7He+zeLH2yDl8tlPT3rVOzPX6/SEvhnG2yz2qsz1tNeski+9gK8+Anzzu+Ze2uf/q2y7tEFgrNOdkxEHtta4kqjglbacWougyNKFbRzILsDLJP7S0csssunXdIuYNmdsQ857Emjh1Yth4ZHaks8Np4TBRfjX+91PSQ5CTlw4zDijk/vNPgQ39cnY6SiucMEnkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAIGnBuviT6kDVK/b2mhCKKROp3bEqIaO3Ccl55H1ZKQNaY/xw4FUxaMGTdUuVo3Kbh5AT5iyEd+U+hd0skG4HbQ0nPkeEg15w07fh04mgTccC/IPAyrT++w9yiHOrXB0R6sXlwLOebXK6/6GQdt6pNDPc1GJaDhYhmI0IoXGO2iVFRlefqCSmGSRRbW4hU5SIdPrmCX/oOfnGBVN3Vo3wQtq9MAUTYnzpdVKBWaAbwzJdWXkF5GbHue5lxOnKmZB7ctd7VZk+L+dtmCozABk+NjdF0nGnjc3zIHD3EE+NCIas9jYPr0Ib8SReNsVL46zF3w1BvxQfkpMLIQThXyoZ/w==</ds:X509Certificate>                </ds:X509Data>            </ds:KeyInfo>        </md:KeyDescriptor>        <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/logout\"/>        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>        <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/consume\" index=\"1\"/>    </md:SPSSODescriptor></md:EntityDescriptor>",
		    metadata.replace("\r\n", "").replace("\n", ""));
	}

}
