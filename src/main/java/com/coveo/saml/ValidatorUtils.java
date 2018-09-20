package com.coveo.saml;

import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.validator.LogoutRequestSchemaValidator;
import org.opensaml.saml2.core.validator.LogoutResponseSchemaValidator;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;

import java.util.List;

/**
 * The type Validator utils.
 */
class ValidatorUtils {

  /**
   * Validate response.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @throws SamlException the saml exception
   */
  private static void validateResponse(LogoutResponse response, String responseIssuer)
      throws SamlException {
    try {
      new LogoutResponseSchemaValidator().validate(response);
    } catch (ValidationException ex) {
      throw new SamlException("The response schema validation failed", ex);
    }
    validateIssuer(response, responseIssuer);
  }

  /**
   * Validate status.
   *
   * @param response the response
   * @throws SamlException the saml exception
   */
  private static void validateStatus(StatusResponseType response) throws SamlException {

    String statusCode = response.getStatus().getStatusCode().getValue();

    if (!StatusCode.SUCCESS_URI.equals(statusCode)) {
      throw new SamlException("Invalid status code: " + statusCode);
    }
  }

  /**
   * Validate issuer.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @throws SamlException the saml exception
   */
  private static void validateIssuer(StatusResponseType response, String responseIssuer)
      throws SamlException {
    if (!response.getIssuer().getValue().equals(responseIssuer)) {
      throw new SamlException("The response issuer didn't match the expected value");
    }
  }
  /**
   * Validate issuer.
   *
   * @param request       the response
   * @param requestIssuer the request issuer
   * @throws SamlException the saml exception
   */
  private static void validateIssuer(RequestAbstractType request, String requestIssuer)
      throws SamlException {
    if (!request.getIssuer().getValue().equals(requestIssuer)) {
      throw new SamlException("The request issuer didn't match the expected value");
    }
  }
  /**
   * Validate assertion.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @param now            the current date time (for unit test only)
   * @param notBeforeSkew  the notBeforeSkew
   * @throws SamlException the saml exception
   */
  private static void validateAssertion(
      Response response, String responseIssuer, DateTime now, long notBeforeSkew)
      throws SamlException {
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

    enforceConditions(assertion.getConditions(), now, notBeforeSkew);
  }

  /**
   * Enforce conditions.
   *
   * @param conditions the conditions
   * @param _now            the current date time (for unit test only)
   * @param notBeforeSkew  the notBeforeSkew
   * @throws SamlException the saml exception
   */
  private static void enforceConditions(Conditions conditions, DateTime _now, long notBeforeSkew)
      throws SamlException {
    DateTime now = _now != null ? _now : DateTime.now();

    DateTime notBefore = conditions.getNotBefore();
    DateTime skewedNotBefore = notBefore.minus(notBeforeSkew);
    if (now.isBefore(skewedNotBefore)) {
      throw new SamlException("The assertion cannot be used before " + notBefore.toString());
    }

    DateTime notOnOrAfter = conditions.getNotOnOrAfter();
    if (now.isAfter(notOnOrAfter)) {
      throw new SamlException("The assertion cannot be used after  " + notOnOrAfter.toString());
    }
  }

  /**
   * Validate signature.
   *
   * @param response    the response
   * @param credentials the credentials
   * @throws SamlException the saml exception
   */
  private static void validateSignature(SignableSAMLObject response, List<Credential> credentials)
      throws SamlException {
    if (response.getSignature() != null && !validate(response.getSignature(), credentials)) {
      throw new SamlException("The response signature is invalid");
    }
  }

  /**
   * Validate assertion signature.
   *
   * @param response    the response
   * @param credentials the credentials
   * @throws SamlException the saml exception
   */
  private static void validateAssertionSignature(Response response, List<Credential> credentials)
      throws SamlException {
    Signature assertionSignature = response.getAssertions().get(0).getSignature();

    if (response.getSignature() == null && assertionSignature == null) {
      throw new SamlException("No signature is present in either response or assertion");
    }

    if (assertionSignature != null && !validate(assertionSignature, credentials)) {
      throw new SamlException("The assertion signature is invalid");
    }
  }

  /**
   * Validate boolean.
   *
   * @param signature   the signature
   * @param credentials the credentials
   * @return the boolean
   */
  private static boolean validate(Signature signature, List<Credential> credentials) {
    if (signature == null) {
      return false;
    }

    // It's fine if any of the credentials match the signature
    return credentials
        .stream()
        .anyMatch(
            c -> {
              try {
                SignatureValidator signatureValidator = new SignatureValidator(c);
                signatureValidator.validate(signature);
                return true;
              } catch (ValidationException ex) {
                return false;
              }
            });
  }

  /**
   * Validate.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @param credentials    the credentials
   * @param now            the current date time (for unit test only)
   * @param notBeforeSkew  the notBeforeSkew
   * @throws SamlException the saml exception
   */
  public static void validate(
      Response response,
      String responseIssuer,
      List<Credential> credentials,
      DateTime now,
      long notBeforeSkew)
      throws SamlException {
    validateResponse(response, responseIssuer);
    validateAssertion(response, responseIssuer, now, notBeforeSkew);
    validateSignature(response, credentials);
    validateAssertionSignature(response, credentials);
  }
  /**
   * Validate.
   *
   * @param logoutRequest       the response
   * @param responseIssuer the response issuer
   * @param credentials    the credentials
   * @throws SamlException the saml exception
   */
  public static void validate(
      LogoutRequest logoutRequest,
      String responseIssuer,
      List<Credential> credentials,
      String nameID)
      throws SamlException {
    validateLogoutRequest(logoutRequest, responseIssuer, nameID);
    validateSignature(logoutRequest, credentials);
  }
  /**
   * Validate.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @param credentials    the credentials
   * @throws SamlException the saml exception
   */
  public static void validate(
      LogoutResponse response, String responseIssuer, List<Credential> credentials)
      throws SamlException {
    validateResponse(response, responseIssuer);
    validateSignature(response, credentials);
  }

  /**
   * Validate response.
   *
   * @param response       the response
   * @param responseIssuer the response issuer
   * @throws SamlException the saml exception
   */
  private static void validateResponse(Response response, String responseIssuer)
      throws SamlException {
    try {
      new ResponseSchemaValidator().validate(response);
    } catch (ValidationException ex) {
      throw new SamlException("The response schema validation failed", ex);
    }
    validateIssuer(response, responseIssuer);
    validateStatus(response);
  }
  /**
   * Validate response.
   *
   * @param request       the request
   * @param requestIssuer the response issuer
   * @throws SamlException the saml exception
   */
  private static void validateLogoutRequest(
      LogoutRequest request, String requestIssuer, String nameID) throws SamlException {
    try {
      new LogoutRequestSchemaValidator().validate(request);
    } catch (ValidationException ex) {
      throw new SamlException("The request schema validation failed", ex);
    }
    validateIssuer(request, requestIssuer);
    validateNameId(request, nameID);
  }

  /**
   * Validate the logout request name id.
   *
   * @param request the request
   * @param nameID  the name id
   * @throws SamlException the saml exception
   */
  private static void validateNameId(LogoutRequest request, String nameID) throws SamlException {
    if (nameID == null || !nameID.equals(request.getNameID().getValue())) {
      throw new SamlException("The nameID of the logout request is incorrect");
    }
  }
}
