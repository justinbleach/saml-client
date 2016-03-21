/*
 * Copyright 2001-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.coveo.saml;

import org.opensaml.saml2.core.Assertion;

public class SamlResponse {
  private Assertion assertion;

  public SamlResponse(Assertion assertion) {
    this.assertion = assertion;
  }

  /**
   * Retrieves the {@link Assertion} for the SAML response.
   * @return The assertion for the SAML response.
   */
  public Assertion getAssertion() {
    return assertion;
  }

  /**
   * Retrieves the Name ID from the SAML response. This is normally the name of the authenticated user.
   * @return The Name ID from the SAML response.
   */
  public String getNameID() {
    return assertion.getSubject().getNameID().getValue();
  }
}
