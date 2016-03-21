# Dead Simple SAML 2.0 Client

This library implements a very simple SAML 2.0 client that allows retrieving an authenticated identity from a compliant identity provider, using the HTTP POST binding.

It is based on the OpenSAML library, and only provides the necessary glue code to make it work in a basic scenario. This is by no means a complete implementation supporting all the nitty gritty SAML details, but it does perform the basic task of generating requests and validating responses. I've tested it with ADFS and Okta identity providers.

# Usage

In order to work, the library must be provided with the xml metadata information that can be obtained from the identity provider. It is also possible to initialize it by directly providing the required values.
