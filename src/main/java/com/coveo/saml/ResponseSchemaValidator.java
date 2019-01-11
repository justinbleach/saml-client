package com.coveo.saml;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Response;

import java.util.Objects;

import javax.xml.bind.ValidationException;

public class ResponseSchemaValidator {
  public void validate(Response response) throws ValidationException {
    validateStatus(response);
    validateID(response);
    validateVersion(response);
    validateIssueInstant(response);
  }

  private void validateStatus(Response response) throws ValidationException {
    if (response.getStatus() == null) {
      throw new ValidationException("Status is required");
    }
  }

  private void validateID(Response response) throws ValidationException {
    if (StringUtils.isEmpty(response.getID())) {
      throw new ValidationException("ID attribute must not be empty");
    }
  }

  private void validateVersion(Response response) throws ValidationException {
    if (response.getVersion() == null) {
      throw new ValidationException("Version attribute must not be null");
    }
    if (!Objects.equals(response.getVersion().toString(), SAMLVersion.VERSION_20.toString())) {
      throw new ValidationException("Wrong SAML Version");
    }
  }

  private void validateIssueInstant(Response response) throws ValidationException {
    if (response.getIssueInstant() == null) {
      throw new ValidationException("IssueInstant attribute must not be null");
    }
  }
}
