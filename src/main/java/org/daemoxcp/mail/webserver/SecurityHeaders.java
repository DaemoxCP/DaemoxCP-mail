package org.daemoxcp.mail.webserver;

/**
 * The panel's Content-Security-Policy, in a single place: the server sends it with every response
 * (SSLMailServer.addSecurityHeaders) and the browser tests use it, serving the generated pages
 * with the same header.
 *
 * <p>Without 'unsafe-inline' and without 'unsafe-eval' (finding 178). Before, script-src and style-src had
 * 'unsafe-inline', because the pages carried 458 onclick="..." handlers, some thirty inline scripts and
 * styles and 208 style attributes: a string injected into a page could run code.
 * Now scripts and styles are files (PageAssets), the handlers are data-on-* and the styles
 * data-style (panel-actions.js), and the policy can say just 'self'.
 *
 * <ul>
 *   <li>img-src keeps data: because Bootstrap draws some form icons (the arrow of a
 *   select, the closing X) with SVG in data: URIs inside its CSS; it no longer keeps https:, which
 *   allowed images from any site (everything must come from the panel);</li>
 *   <li>object-src 'none', base-uri 'self' and form-action 'self' shut out plugins, an injected &lt;base&gt;
 *   that would move relative addresses, and a form that would submit elsewhere;</li>
 *   <li>frame-ancestors 'none': nobody can put the panel in a frame.</li>
 * </ul>
 */
public final class SecurityHeaders {

    private SecurityHeaders() {}

    /**
     * Built with String.join and not written as a constant: the compiler copies a constant
     * into every class that uses it, and then the server and the tests could send and check
     * two different policies without noticing (and a fault planted here would not show).
     */
    public static final String CONTENT_SECURITY_POLICY = String.join("; ", java.util.List.of(
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'"));
}
