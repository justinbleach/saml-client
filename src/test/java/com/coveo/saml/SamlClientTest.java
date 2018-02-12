package com.coveo.saml;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import org.opensaml.xml.util.Base64;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SamlClientTest {
  private static String AN_ENCODED_RESPONSE =
      "PHNhbWxwOlJlc3BvbnNlIElEPSJfMTEzMjlhZjQtYTdkMC00MDkwLTg3N2QtYTJkNWNlYWRlZWU0IiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxNi0wMy0yMVQxNjo1MDo0Ny4zOTlaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My9yZXN0L3NlYXJjaC9sb2dpbi9hZGZzIiBDb25zZW50PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y29uc2VudDp1bnNwZWNpZmllZCIgSW5SZXNwb25zZVRvPSJ6ZjE3MDkyNGItZjVlYy00Y2I1LWE5YWUtMmFiMmNmZDcxNGQzIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vYWRmczAxLmRldi5jb3Zlby5jb20vYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIgLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfYTg4MGU1M2QtMTVhMC00ZDNiLTk5NDEtZWExMWY4MTBhODhkIiBJc3N1ZUluc3RhbnQ9IjIwMTYtMDMtMjFUMTY6NTA6NDcuMzk5WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PElzc3Vlcj5odHRwOi8vYWRmczAxLmRldi5jb3Zlby5jb20vYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiAvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2IiAvPjxkczpSZWZlcmVuY2UgVVJJPSIjX2E4ODBlNTNkLTE1YTAtNGQzYi05OTQxLWVhMTFmODEwYTg4ZCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIiAvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiIC8+PGRzOkRpZ2VzdFZhbHVlPlRlbzBFdk5kU1BLUVZsV0R4bVJ1RlBPU3pFS0ROYU5TMzllejIybGJDdVU9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPnFXOW1wK2tPNTdvK2k3cUJ5RXhsQmZUYnlnTHVENjU2N3RibWlodXFOQ3lxNnZQbFp4WW9XQkIybHpYR2VmaDh6cTRYOStHcWtxMXhSVElDemNNUmhjYTZPaVF2eWd3NWQzZ2NtLzh3bG9remFZQmJDeHdzTUFpNUMwMk4xb3hqTXZsU2xOdkUzN0piMXI5cDdyOGZNeEJreVBwUFFDa3RRYnFLUXk3TTBvWmhQaVpjMVRpMXZ3c0xvbWJVc3hCVzl0RzJ5WTlKVU9QK2dKak82SStUV2IrS0lzWTBGS21pN1hXK3dmSDNpaTI0RTFUVkh5LzYvandtUzlhVjJrZ2RjVXNvN3FYZVpQZ2JsTy9JM2VaQzBHQUp1bFErcEtjS2V2ZEd2c2JWM25HQmY0M3BZcnVzRTM1ZXo1WTRBdFNiNjRUaE1mT1I1c3lER0lpTkEzL29IZz09PC9kczpTaWduYXR1cmVWYWx1ZT48S2V5SW5mbyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJQzVqQ0NBYzZnQXdJQkFnSVFjd0Y4ektkZ2hMRkRKWUtNdW5heGpqQU5CZ2txaGtpRzl3MEJBUXNGQURBdU1Td3dLZ1lEVlFRREV5TkJSRVpUSUZOcFoyNXBibWNnTFNCaFpHWnpNREV1WkdWMkxtTnZkbVZ2TG1OdmJUQWdGdzB4TkRBME1UUXhOVEF6TkRaYUdBOHlNVEUwTURNeU1URTFNRE0wTmxvd0xqRXNNQ29HQTFVRUF4TWpRVVJHVXlCVGFXZHVhVzVuSUMwZ1lXUm1jekF4TG1SbGRpNWpiM1psYnk1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDenJidEhBMklMcnpUTmsrU2ZEd1dVaG42Rk1uVDFFZUFianNYaDVwd3NCZmUwOGhobDJXTWZIWktGZlNVNk1wRk0xVDdlNERjSDNINldibmY2WTNUeG82aVI2ZWpRaExxWVdPQlNTSFM0T0hXeE1hY3o2MUViOFc1MXhwOW9DZnpocmFJSnJJeFhKcXJFVzhZVkZObmtrUTg0UUxYZVpPT3RWUnE0UTJ5azNOUE56RUF6aVlUazRoK01WQlJ5SUwvaFFjcTcrRGVhTE0weDRUZnY4c1VHVU9QQThjMEVybXNFVURrS3pxM242dENCZG05SEFielVWcU5FenBQcEs0T0ovR01zdHFyeXF0dStPYzJ4ZERMMVZZTVhZU1ZzbHJIRFc1b2ZWTGlML3kyQS9BMXpBNmRHbExOZm1WV1JwOGJIS0ZpVlJabTFrKzlmYzNicHdnSVJBZ01CQUFFd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFGSWN1M09FQ1JEY1paT3BWaUNFRy9vRWU2UDJaWUZBSlJOUVNiS3cvUWhQOWlJVDJwbGJod3p0S0ZzckFoSTZmOXI4a2VDNnhmVitnMzdRWHJyL2dWVTR5SGIyUFQ4YjllYStuWStWM2FNeCt5RlF3K1djd3A0U1k3cTRMTnc0RVA4aHR6ejEzZnRiTTh0SUN1bytneGpLQ2FjZkhVZmFIOUZqUWRTUExrejNWZGZiSTVrbUdFc1RCVzEvQzBNR2cwc2o1MnkwM1BFYWxQQ09oRmNla01nU1hPdmh2enN0WkhFaENBaEtlbkdaME9iQ0I5RHZhUHFzN3ZiUlBtTUdFVjJwbUU0MHVqRlRORHBzNUVTaCs5MFk5Slh1U2lUVEpLTnB2K1ZhRmIyQnAyOWZuWXR3SGVXQXBWeXppdENsQlZqbFN5Z3l0dGliTjl0d2xMOXFNVnc9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L0tleUluZm8+PC9kczpTaWduYXR1cmU+PFN1YmplY3Q+PE5hbWVJRD5tbGFwb3J0ZUBjb3Zlby5jb208L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89InpmMTcwOTI0Yi1mNWVjLTRjYjUtYTlhZS0yYWIyY2ZkNzE0ZDMiIE5vdE9uT3JBZnRlcj0iMjAxNi0wMy0yMVQxNjo1NTo0Ny4zOTlaIiBSZWNpcGllbnQ9Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMvcmVzdC9zZWFyY2gvbG9naW4vYWRmcyIgLz48L1N1YmplY3RDb25maXJtYXRpb24+PC9TdWJqZWN0PjxDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0wMy0yMVQxNjo1MDo0Ny4zODNaIiBOb3RPbk9yQWZ0ZXI9IjIwMTYtMDMtMjFUMTc6NTA6NDcuMzgzWiI+PEF1ZGllbmNlUmVzdHJpY3Rpb24+PEF1ZGllbmNlPmh0dHBzOi8vbG9jYWxob3N0Ojg0NDM8L0F1ZGllbmNlPjwvQXVkaWVuY2VSZXN0cmljdGlvbj48L0NvbmRpdGlvbnM+PEF0dHJpYnV0ZVN0YXRlbWVudD48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL3VwbiI+PEF0dHJpYnV0ZVZhbHVlPm1sYXBvcnRlQGNvdmVvLmNvbTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAxNi0wMy0yMVQwOTo0NjoxNy4yMzFaIiBTZXNzaW9uSW5kZXg9Il9hODgwZTUzZC0xNWEwLTRkM2ItOTk0MS1lYTExZjgxMGE4OGQiPjxBdXRobkNvbnRleHQ+PEF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9BdXRobkNvbnRleHRDbGFzc1JlZj48L0F1dGhuQ29udGV4dD48L0F1dGhuU3RhdGVtZW50PjwvQXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+";

  private static Reader getXml(String name) throws IOException {
    return new InputStreamReader(SamlClientTest.class.getResourceAsStream(name), "UTF-8");
  }

  @Test
  public void metadataXMLFromADFSCanBeLoaded() throws Throwable {
    SamlClient.fromMetadata(
        "myidentifier", "http://some/url", getXml("adfs.xml"), SamlClient.SamlIdpBinding.POST);
  }

  @Test
  public void metadataXMLFromOktaCanBeLoaded() throws Throwable {
    SamlClient.fromMetadata(
        "myidentifier", "http://some/url", getXml("okta.xml"), SamlClient.SamlIdpBinding.POST);
  }

  @Test
  public void relyingPartyIdentifierAndAssertionConsumerServiceUrlCanBeOmittedForOkta()
      throws Throwable {
    SamlClient.fromMetadata(null, null, getXml("okta.xml"), SamlClient.SamlIdpBinding.POST);
  }

  @Test
  public void getSamlRequestReturnsAnEncodedRequest() throws Throwable {
    SamlClient client =
        SamlClient.fromMetadata(
            "myidentifier", "http://some/url", getXml("adfs.xml"), SamlClient.SamlIdpBinding.POST);
    String decoded = new String(Base64.decode(client.getSamlRequest()), "UTF-8");
    assertTrue(decoded.contains(">myidentifier<"));
  }

  @Test
  public void decodeAndValidateSamlResponseCanDecodeAnSamlResponse() throws Throwable {
    SamlClient client =
        SamlClient.fromMetadata(
            "myidentifier", "http://some/url", getXml("adfs.xml"), SamlClient.SamlIdpBinding.POST);
    client.setDateTimeNow(new DateTime(2016, 3, 21, 17, 0, DateTimeZone.UTC));
    SamlResponse response = client.decodeAndValidateSamlResponse(AN_ENCODED_RESPONSE);
    assertEquals("mlaporte@coveo.com", response.getNameID());
  }

  @Test(expected = SamlException.class)
  public void decodeAndValidateSamlResponseRejectsATamperedResponse() throws Throwable {
    String decoded = new String(Base64.decode(AN_ENCODED_RESPONSE), "UTF-8");
    String tampered = decoded.replace("mlaporte", "evilperson");
    SamlClient client =
        SamlClient.fromMetadata(
            "myidentifier", "http://some/url", getXml("adfs.xml"), SamlClient.SamlIdpBinding.POST);
    client.decodeAndValidateSamlResponse(Base64.encodeBytes(tampered.getBytes("UTF-8")));
  }

  @Test
  public void decodeAndValidateSamlResponseWorksWithCertsInDifferentOrder() throws Throwable {
    SamlClient client =
        SamlClient.fromMetadata(
            "myidentifier", "http://some/url", getXml("adfs2.xml"), SamlClient.SamlIdpBinding.POST);
    client.setDateTimeNow(new DateTime(2016, 3, 21, 17, 0, DateTimeZone.UTC));
    SamlResponse response = client.decodeAndValidateSamlResponse(AN_ENCODED_RESPONSE);
    assertEquals("mlaporte@coveo.com", response.getNameID());
  }

  @Test
  public void decodeAndValidateSamlResponseWithHttpRedirect() throws Throwable {
    SamlClient client =
        SamlClient.fromMetadata(
            "myidentifier",
            "http://some/url",
            getXml("adfs.xml"),
            SamlClient.SamlIdpBinding.Redirect);
    String decoded = new String(Base64.decode(client.getSamlRequest()), "UTF-8");
    assertTrue(decoded.contains(">myidentifier<"));
  }
}
