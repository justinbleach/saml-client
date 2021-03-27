package com.coveo.saml;

import org.apache.commons.text.StringEscapeUtils;

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
    @SuppressWarnings("resource")
    Writer writer = response.getWriter();
    writer.write(
        "<html><head></head><body><form id='TheForm' action='"
            + StringEscapeUtils.escapeHtml4(url)
            + "' method='POST'>");

    for (String key : values.keySet()) {
      String encodedKey = StringEscapeUtils.escapeHtml4(key);
      String encodedValue = StringEscapeUtils.escapeHtml4(values.get(key));
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

    response.setHeader("Cache-Control", "no-cache, no-store");
    response.setHeader("Pragma", "no-cache");
  }
}
