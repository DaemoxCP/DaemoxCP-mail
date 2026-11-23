package org.daemoxcp.mail.webserver;

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
 * A request that arrived from the web part on the root socket (RootChannel), seen by the
 * SSLMailServer handlers as any HTTP request: that way the root part uses the same handlers as today,
 * without rewriting them.
 *
 * <p>The headers are only those that RootChannel lets through, plus the Content-Length of the body.
 * The remote address is the IP of the client that the web part saw. The response goes out on the socket
 * when the handler calls sendResponseHeaders; if the handler finishes without having sent it, finish()
 * sends a 500.
 */
public final class ForwardedExchange extends HttpExchange {

    /** The response headers that are not sent back: the HTTP server of the web part writes them. */
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
    /** The length given in sendResponseHeaders: -1 no body, 0 any, n exactly n bytes. */
    private long declared;
    private long written;
    private boolean bodyClosed;

    ForwardedExchange(RootChannel.Request request, OutputStream socket) throws IOException {
        this.request = request;
        this.socket = socket;
        request.headers().forEach(requestHeaders::set);
        requestHeaders.set("Content-Length", String.valueOf(request.body().length));
        this.uri = URI.create(request.path() + (request.query() == null ? "" : "?" + request.query()));
        // The IP has already been checked (InputValidator.isValidIp): a literal address does not query DNS.
        this.remote = new InetSocketAddress(InetAddress.getByName(request.clientIp()), 0);
        this.requestBody = new ByteArrayInputStream(request.body());
    }

    public RootChannel.Request request() { return request; }

    @Override public Headers getRequestHeaders() { return requestHeaders; }

    @Override public Headers getResponseHeaders() { return responseHeaders; }

    @Override public URI getRequestURI() { return uri; }

    @Override public String getRequestMethod() { return request.method(); }

    /** No context: the web part already chose the route, and root checked it (SSLMailServer.serveForwarded). */
    @Override public HttpContext getHttpContext() { return null; }

    @Override public InputStream getRequestBody() { return requestBody; }

    @Override
    public OutputStream getResponseBody() {
        return filter != null ? filter : body;
    }

    /** The response body: it goes on the socket only after sendResponseHeaders, and never beyond the declared length. */
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
        // Like HttpServer: for HEAD and for 204/304 no body, whatever length the handler declares.
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
            // the web part closed the connection: nothing to do
        }
    }

    /** At the end of the handler: if the response did not go out, a 500; then everything left goes on the socket. */
    void finish() {
        try {
            if (responseCode < 0) {
                byte[] json = ("{\"success\":false,\"error\":" + org.json.JSONObject.quote(
                        org.daemoxcp.mail.i18n.I18n.tr("server.internalError")) + "}").getBytes(StandardCharsets.UTF_8);
                responseHeaders.set("Content-Type", "application/json");
                sendResponseHeaders(500, json.length);
                body.write(json, 0, json.length);
            }
            body.close();
        } catch (IOException ignored) {
            // the web part closed the connection
        }
    }
}
