package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;

/**
 * A HEAD request seen by the filters and the handler as a GET (getRequestMethod says GET too): the
 * permission, the redirect to login, the 405 of the handlers that want GET are those of the GET. The handler
 * writes its response as always, and here the length becomes the Content-Length header and the body
 * is discarded. Before, a HEAD on a protected page gave 401 instead of the redirect, and on an API 405.
 *
 * <p>Every handler calls sendResponseHeaders(code, length) and then writes the body. With a HEAD the
 * Java HTTP server (sun.net.httpserver.ExchangeImpl) logs "being invoked with a content length
 * for a HEAD request" and then refuses the write ("stream closed"), which the handler logged as a
 * severe error: measured on the production server on 2026-11-07 with a single `curl -I` on the login page.
 * RFC 9110 9.3.2: the response to a HEAD has the same headers as the one to the GET, without a body; the
 * Java server sends the Content-Length written among the headers when it is passed -1.
 */
final class HeadExchange extends HttpExchange {

    private final HttpExchange real;
    private boolean closed;

    HeadExchange(HttpExchange real) {
        this.real = real;
    }

    /** The real request underneath, if this is a wrapped HEAD; otherwise the one given. */
    static HttpExchange unwrap(HttpExchange e) {
        return e instanceof HeadExchange h ? h.real : e;
    }

    /** The body goes nowhere; closing it closes the real response. */
    private final OutputStream discard = new OutputStream() {
        @Override public void write(int b) { }
        @Override public void write(byte[] b, int off, int len) { }
        @Override public void close() throws IOException {
            if (closed) return;
            closed = true;
            real.getResponseBody().close();
        }
    };

    @Override
    public void sendResponseHeaders(int rCode, long responseLength) throws IOException {
        if (responseLength > 0) real.getResponseHeaders().set("Content-Length", String.valueOf(responseLength));
        real.sendResponseHeaders(rCode, -1);
    }

    @Override public OutputStream getResponseBody() { return discard; }

    @Override public Headers getRequestHeaders() { return real.getRequestHeaders(); }

    @Override public Headers getResponseHeaders() { return real.getResponseHeaders(); }

    @Override public URI getRequestURI() { return real.getRequestURI(); }

    /** GET: for everyone that follows, a HEAD is a GET (RFC 9110 9.3.2). */
    @Override public String getRequestMethod() { return "GET"; }

    @Override public HttpContext getHttpContext() { return real.getHttpContext(); }

    @Override public void close() { real.close(); }

    @Override public InputStream getRequestBody() { return real.getRequestBody(); }

    @Override public InetSocketAddress getRemoteAddress() { return real.getRemoteAddress(); }

    @Override public int getResponseCode() { return real.getResponseCode(); }

    @Override public InetSocketAddress getLocalAddress() { return real.getLocalAddress(); }

    @Override public String getProtocol() { return real.getProtocol(); }

    @Override public Object getAttribute(String name) { return real.getAttribute(name); }

    @Override public void setAttribute(String name, Object value) { real.setAttribute(name, value); }

    @Override public void setStreams(InputStream i, OutputStream o) { real.setStreams(i, null); }

    @Override public HttpPrincipal getPrincipal() { return real.getPrincipal(); }
}
