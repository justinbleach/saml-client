package com.coveo.saml;

public class SamlException extends Exception {
  private static final long serialVersionUID = 1L;

public SamlException(String message) {
    super(message);
  }

  public SamlException(String message, Throwable cause) {
    super(message, cause);
  }
}
