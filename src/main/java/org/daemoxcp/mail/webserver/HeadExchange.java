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
 * Una richiesta HEAD vista dai filtri e dal gestore come una GET (anche getRequestMethod dice GET): il
 * permesso, il rimando all'accesso, il 405 dei gestori che vogliono GET sono quelli della GET. Il gestore
 * scrive la sua risposta come sempre, e qui la lunghezza diventa l'intestazione Content-Length e il corpo
 * si scarta. Prima una HEAD su una pagina protetta dava 401 invece del rimando, e su un'API 405.
 *
 * <p>Ogni gestore chiama sendResponseHeaders(codice, lunghezza) e poi scrive il corpo. Con una HEAD il
 * server HTTP di Java (sun.net.httpserver.ExchangeImpl) registra «being invoked with a content length
 * for a HEAD request» e poi rifiuta la scrittura («stream closed»), che il gestore registrava come
 * errore grave: misurato sul server vero il 07/11/2026 con una sola `curl -I` sulla pagina di accesso.
 * RFC 9110 9.3.2: la risposta a una HEAD ha le stesse intestazioni di quella alla GET, senza corpo; il
 * server di Java manda la Content-Length scritta fra le intestazioni quando gli si passa -1.
 */
final class HeadExchange extends HttpExchange {

    private final HttpExchange real;
    private boolean closed;

    HeadExchange(HttpExchange real) {
        this.real = real;
    }

    /** La richiesta vera sotto, se questa e' una HEAD avvolta; se no quella data. */
    static HttpExchange unwrap(HttpExchange e) {
        return e instanceof HeadExchange h ? h.real : e;
    }

    /** Il corpo non va da nessuna parte; chiuderlo chiude la risposta vera. */
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

    /** GET: per tutti quelli che seguono, una HEAD e' una GET (RFC 9110 9.3.2). */
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
