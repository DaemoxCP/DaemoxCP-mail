package org.mail_panel.webserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Una richiesta arrivata dalla parte web sul socket della root (RootChannel), vista dai gestori di
 * SSLMailServer come una richiesta HTTP qualunque: cosi' la parte root usa gli stessi gestori di oggi,
 * senza riscriverli.
 *
 * <p>Le intestazioni sono solo quelle che RootChannel lascia passare, piu' Content-Length del corpo.
 * L'indirizzo remoto e' l'IP del client che ha visto la web. La risposta parte sul socket quando il
 * gestore chiama sendResponseHeaders; se il gestore finisce senza averla mandata, finish() manda un 500.
 */
public final class ForwardedExchange extends HttpExchange {

    /** Le intestazioni di risposta che non si rimandano: le scrive il server HTTP della parte web. */
    static final Set<String> HOP_BY_HOP = Set.of("content-length", "transfer-encoding", "connection", "date", "keep-alive");

    private final RootChannel.Request request;
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();
    private final URI uri;
    private final InetSocketAddress remote;
    private final OutputStream socket;
    private final Map<String, Object> attributes = new HashMap<>();
    private InputStream requestBody;
    private OutputStream filter;
    private int responseCode = -1;
    /** La lunghezza detta in sendResponseHeaders: -1 nessun corpo, 0 qualunque, n esattamente n byte. */
    private long declared;
    private long written;
    private boolean bodyClosed;

    ForwardedExchange(RootChannel.Request request, OutputStream socket) throws IOException {
        this.request = request;
        this.socket = socket;
        request.headers().forEach(requestHeaders::set);
        requestHeaders.set("Content-Length", String.valueOf(request.body().length));
        this.uri = URI.create(request.path() + (request.query() == null ? "" : "?" + request.query()));
        // L'IP e' gia' controllato (InputValidator.isValidIp): un indirizzo letterale non chiede al DNS.
        this.remote = new InetSocketAddress(InetAddress.getByName(request.clientIp()), 0);
        this.requestBody = new ByteArrayInputStream(request.body());
    }

    public RootChannel.Request request() { return request; }

    @Override public Headers getRequestHeaders() { return requestHeaders; }

    @Override public Headers getResponseHeaders() { return responseHeaders; }

    @Override public URI getRequestURI() { return uri; }

    @Override public String getRequestMethod() { return request.method(); }

    /** Nessun context: la rotta l'ha gia' scelta la web, e la root l'ha controllata (SSLMailServer.serveForwarded). */
    @Override public HttpContext getHttpContext() { return null; }

    @Override public InputStream getRequestBody() { return requestBody; }

    @Override
    public OutputStream getResponseBody() {
        return filter != null ? filter : body;
    }

    /** Il corpo della risposta: va sul socket solo dopo sendResponseHeaders, e mai oltre la lunghezza detta. */
    private final OutputStream body = new OutputStream() {
        @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (responseCode < 0) throw new IOException("response headers not sent yet");
            if (bodyClosed) throw new IOException("response body closed");
            if (declared == -1) {
                if (len > 0) throw new IOException("this response has no body");
                return;
            }
            if (declared > 0 && written + len > declared) throw new IOException("more bytes than the declared length");
            written += len;
            socket.write(b, off, len);
        }

        @Override public void flush() throws IOException { if (responseCode >= 0) socket.flush(); }

        @Override
        public void close() throws IOException {
            if (bodyClosed) return;
            bodyClosed = true;
            if (responseCode >= 0) socket.flush();
        }
    };

    @Override
    public void sendResponseHeaders(int rCode, long responseLength) throws IOException {
        if (responseCode >= 0) throw new IOException("headers already sent");
        List<String[]> out = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : responseHeaders.entrySet()) {
            if (HOP_BY_HOP.contains(e.getKey().toLowerCase(Locale.ROOT))) continue;
            for (String v : e.getValue()) out.add(new String[]{e.getKey(), v});
        }
        // Come HttpServer: per HEAD e per 204/304 niente corpo, qualunque lunghezza dica il gestore.
        long length = "HEAD".equals(request.method()) || rCode == 204 || rCode == 304 ? -1 : responseLength;
        RootChannel.writeResponseHead(socket, rCode, length, out);
        responseCode = rCode;
        declared = length;
    }

    @Override public InetSocketAddress getRemoteAddress() { return remote; }

    @Override public int getResponseCode() { return responseCode; }

    @Override public InetSocketAddress getLocalAddress() { return new InetSocketAddress(InetAddress.getLoopbackAddress(), 0); }

    @Override public String getProtocol() { return "HTTP/1.1"; }

    @Override public Object getAttribute(String name) { return attributes.get(name); }

    @Override public void setAttribute(String name, Object value) {
        if (value == null) attributes.remove(name); else attributes.put(name, value);
    }

    @Override
    public void setStreams(InputStream i, OutputStream o) {
        if (i != null) requestBody = i;
        if (o != null) filter = o;
    }

    @Override public HttpPrincipal getPrincipal() { return null; }

    @Override
    public void close() {
        try {
            getResponseBody().close();
        } catch (IOException ignored) {
            // la web ha chiuso la connessione: niente da fare
        }
    }

    /** A fine gestore: se la risposta non e' partita, un 500; poi tutto quello che c'e' va sul socket. */
    void finish() {
        try {
            if (responseCode < 0) {
                byte[] json = ("{\"success\":false,\"error\":" + org.json.JSONObject.quote(
                        org.mail_panel.i18n.I18n.tr("server.internalError")) + "}").getBytes(StandardCharsets.UTF_8);
                responseHeaders.set("Content-Type", "application/json");
                sendResponseHeaders(500, json.length);
                body.write(json, 0, json.length);
            }
            body.close();
        } catch (IOException ignored) {
            // la web ha chiuso la connessione
        }
    }
}
