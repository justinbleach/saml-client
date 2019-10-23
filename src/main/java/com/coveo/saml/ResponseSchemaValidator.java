/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.coveo.saml;

import java.util.Objects;

import javax.xml.bind.ValidationException;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.StatusResponseType;

public class ResponseSchemaValidator {
  public void validate(StatusResponseType response) throws ValidationException {
    validateStatus(response);
    validateID(response);
    validateVersion(response);
    validateIssueInstant(response);
  }

  private void validateStatus(StatusResponseType response) throws ValidationException {
    if (response.getStatus() == null) {
      throw new ValidationException("Status is required");
    }
  }

  private void validateID(StatusResponseType response) throws ValidationException {
    if (StringUtils.isEmpty(response.getID())) {
      throw new ValidationException("ID attribute must not be empty");
    }
  }

  private void validateVersion(StatusResponseType response) throws ValidationException {
    if (response.getVersion() == null) {
      throw new ValidationException("Version attribute must not be null");
    }
    if (!Objects.equals(response.getVersion().toString(), SAMLVersion.VERSION_20.toString())) {
      throw new ValidationException("Wrong SAML Version");
    }
  }

  private void validateIssueInstant(StatusResponseType response) throws ValidationException {
    if (response.getIssueInstant() == null) {
      throw new ValidationException("IssueInstant attribute must not be null");
    }
  }
}
