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

import org.apache.commons.lang.StringEscapeUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.Map;

public class BrowserUtils {
  /**
   * Renders an HTTP response that will cause the browser to POST the specified values to an url.
   * @param url the url where to perform the POST.
   * @param response the {@link HttpServletResponse}.
   * @param values the values to include in the POST.
   * @throws IOException thrown if an IO error occurs.
   */
  public static void postUsingBrowser(
      String url, HttpServletResponse response, Map<String, String> values) throws IOException {

    response.setContentType("text/html");
    Writer writer = response.getWriter();
    writer.write(
        "<html><head></head><body><form id='TheForm' action='"
            + StringEscapeUtils.escapeHtml(url)
            + "' method='POST'>");

    for (String key : values.keySet()) {
      String encodedKey = StringEscapeUtils.escapeHtml(key);
      String encodedValue = StringEscapeUtils.escapeHtml(values.get(key));
      writer.write(
          "<input type='hidden' id='"
              + encodedKey
              + "' name='"
              + encodedKey
              + "' value='"
              + encodedValue
              + "'/>");
    }

    writer.write(
        "</form><script type='text/javascript'>document.getElementById('TheForm').submit();</script></body></html>");
    writer.flush();
  }
}
