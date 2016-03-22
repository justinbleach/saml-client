# Dead Simple SAML 2.0 Client

This library implements a very simple SAML 2.0 client that allows retrieving an authenticated identity from a compliant identity provider, using the HTTP POST binding.

It is based on the OpenSAML library, and only provides the necessary glue code to make it work in a basic scenario. This is by no means a complete implementation supporting all the nitty gritty SAML details, but it does perform the basic task of generating requests and validating responses. It's useful if you need to authenticate with SAML but don't want to bring in an uber large framework such as Spring Security.

In order to work, the library must be provided with the xml metadata information that can be obtained from the identity provider. It is also possible to initialize it by directly providing the required values.

As of now, I've tested the library with ADFS and Okta as identity providers.

# Maven

Add this dependency to your `pom.xml` to reference the library:

```xml
    <dependency>
      <groupId>com.coveo</groupId>
      <artifactId>saml-client</artifactId>
      <version>1.0.0</version>
    </dependency>
```

# Usage

## SAML authentication process overview

An SAML authentication exchange involves sending an SAML request to the Identity Provider (ADFS, Okta, etc...) and then receiving a signed SAML response. Both the request and the response will be transferred through POST HTTP requests made from the browser (other means of exchanging the data exist, but aren't supported by this library).

This library provide an easy way to generate the SAML request and then supports decoding and validating the answer returned from the Identity Provider. It also provide an helper method to generate the necessary HTML and JavaScript code to properly POST the SAML request.

## Creating an instance of `SamlClient`

```java
    SamlClient client = SamlClient.fromMetadata("MyRelyingPartyIdentifier", "http://some/url/that/processes/assertions", "<your.IDP.metadata.xml>");
```

## Generating a SAML request

```java
    String encodedRequest = client.getSamlRequest();
    String idpUrl = client.getIdentityProviderUrl();
    // redirect to the identity provider, passing the encoded request with the SAMLRequest form parameter.
```

## Processing an SAML response

```java
    String encodedResponse = servletRequest.getParameter("SAMLResponse");
    SamlResponse response = client.decodeAndValidateSamlResponse(encodedResponse);
    String authenticatedUser = response.getNameID();
```

## Using the helpers for servlet requests and responses

```java
    // To initiate the authentication exchange
    client.redirectToIdentityProvider(servletResponse, null);
    ...
    // To process the POST containing the SAML response
    SamlResponse response = client.processPostFromIdentityProvider(servletRequest);
```

# Identity Provider Configuration

## ADFS

To configure ADFS to work with this library, you should go to the MMC snap-in for ADFS and add a Relying Party Trust with the following properties:

* In the Identifiers tab, add a Relying Party Identifier that will match the one you'll provide when initializing `SamlClient`.
* In the Endpoints tab, add the url that will process SAML responses to the list, using `POST` for the Binding value.

Then, to obtain the metadata provider XML, load this url in your browser: https://myserver.domain.com/FederationMetadata/2007-06/FederationMetadata.xml

## Okta

To configure Okta to work with this library, create an SAML 2.0 application with the following settings:

* The *Single sign on URL* should be the URL that processes SAML responses (e.g. assertions).
* The *Audience URI* should be a value that matches the one you'll specify when initializing `SamlClient`.
