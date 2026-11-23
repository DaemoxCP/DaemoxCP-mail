package org.daemoxcp.mail.webserver;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * The channel between the two parts of the separated panel: a unix socket
 * of the root part, {@code /var/run/daemoxcp-mail/root.sock}, on which the web part (user daemoxcp_mail)
 * passes it the APIs of whoever has logged in, after its own filters (Host, language, permission, CSRF).
 *
 * <p>One request per connection. The web part writes {@code "MPR1"}, the length of the header (int),
 * the header in JSON (UTF-8), the length of the body (long) and the body. The root part answers
 * {@code "MPS1"}, the length (int) and the header in JSON (status, body length with the same
 * meaning as in {@code sendResponseHeaders}, headers), then the body until the connection closes.
 *
 * <p>In the header: the route the web part chose, the raw method, path and query, the headers
 * in the {@link #HEADERS} list and no other, the client IP for the log, the language, and who has
 * logged in: the id of the administrator and that of their session. <strong>Never the cookies nor the
 * session token</strong> that the browser sends. Administrator, permissions and recent confirmation are
 * reread by the root part from the database (WebSessions.forwarded), without trusting what the web part
 * tells it.
 *
 * <p>Without an administrator (id 0 and 0) only the routes in {@link #BEFORE_SIGN_IN} pass: the login, which
 * the root part decides, and the session key, which the web part asks for
 * at startup.
 *
 * <p>The socket is in a 0750 root:daemoxcp_mail folder and the socket is 0660 root:daemoxcp_mail; in addition
 * the root part only accepts connections whose process belongs to the web part's user (SO_PEERCRED, which
 * Java 25 on FreeBSD returns: measured on the VM on 2026-11-07).
 */
public final class RootChannel implements Closeable {

    private static final Logger LOGGER = Logger.getLogger(RootChannel.class.getName());

    static final byte[] REQUEST_MAGIC = "MPR1".getBytes(StandardCharsets.US_ASCII);
    static final byte[] RESPONSE_MAGIC = "MPS1".getBytes(StandardCharsets.US_ASCII);
    /** The header of a request or of a response: generous for a few short headers. */
    static final int MAX_HEAD = 64 * 1024;
    /** The body of a request: the same limit as SSLMailServer.readRequestBodyWithLimit. */
    static final long MAX_BODY = 10L * 1024 * 1024;
    /** How long the web part may take to send the whole request, once connected. */
    static final long READ_SECONDS = 60;

    /**
     * The only request headers that pass to the root part, with the names as Headers writes them. The
     * rest (Cookie, X-CSRF-Token, Authorization, the proxy headers) never passes: the filters that
     * use them have already been applied by the web part, and the client IP arrives in a field of its own.
     * Host passes: the web part has already compared it with the panel's names (HostCheck), and the root
     * part uses it for the passkey rpId.
     */
    static final List<String> HEADERS = List.of("Content-type", "Accept-language", "User-agent", "Accept", "Host");

    /**
     * The routes the web part passes without an administrator (id 0 and 0): the login, the session key, and the
     * three webmail ones (password change, copy into the vault, automatic emptying), which the web part has
     * already checked (loopback and key).
     */
    public static final java.util.Set<String> BEFORE_SIGN_IN = java.util.Set.of("/api/login", "/op/session-key",
            org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH,
            org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH);

    static final List<String> METHODS = List.of("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH");

    /** A route as SSLMailServer.context registers it: an absolute path, without "..". */
    private static final Pattern ROUTE = Pattern.compile("/[A-Za-z0-9/_.-]{0,200}");
    /** The raw path of the request: in addition, the characters of a %XX encoding and the tilde. */
    private static final Pattern PATH = Pattern.compile("/[A-Za-z0-9/_.~%-]{0,1000}");
    /** The raw query: printable ASCII without spaces (spaces arrive encoded). */
    private static final Pattern QUERY = Pattern.compile("[\\x21-\\x7E]{0,8192}");
    /** The value of a header: printable ASCII, no line breaks. */
    private static final Pattern HEADER_VALUE = Pattern.compile("[\\x20-\\x7E]{0,1024}");
    private static final Pattern LANG = Pattern.compile("[a-z]{2}");

    /** A forwarded request, whose shape has already been checked. */
    public record Request(String route, String method, String path, String query, Map<String, String> headers,
                          String clientIp, String lang, long adminId, long sessionId, byte[] body) {
        public Request {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
            body = body == null ? new byte[0] : body;
        }
    }

    /** The header of a response: status, length as in sendResponseHeaders, headers. */
    public record ResponseHead(int status, long length, List<String[]> headers) {}

    /** Who serves the requests on the root part's side: SSLMailServer in ROOT_PART mode. */
    public interface Dispatcher {
        void serve(Request request, ForwardedExchange exchange) throws IOException;
    }

    // ===================== The format =====================

    static void writeRequest(OutputStream out, Request r) throws IOException {
        JSONObject h = new JSONObject()
                .put("route", r.route()).put("method", r.method()).put("path", r.path())
                .put("client_ip", r.clientIp()).put("lang", r.lang())
                .put("admin_id", r.adminId()).put("session_id", r.sessionId());
        if (r.query() != null) h.put("query", r.query());
        JSONObject hs = new JSONObject();
        r.headers().forEach(hs::put);
        h.put("headers", hs);
        byte[] head = h.toString().getBytes(StandardCharsets.UTF_8);
        if (head.length > MAX_HEAD) throw new IOException("request head too large");
        DataOutputStream d = new DataOutputStream(out);
        d.write(REQUEST_MAGIC);
        d.writeInt(head.length);
        d.write(head);
        d.writeLong(r.body().length);
        d.write(r.body());
        d.flush();
    }

    /**
     * Reads and checks a request. A field with the wrong shape rejects all of it (IllegalArgumentException):
     * nothing is cleaned up. Headers not on the list, instead, are simply discarded.
     */
    static Request readRequest(InputStream in) throws IOException {
        DataInputStream d = new DataInputStream(in);
        byte[] magic = d.readNBytes(REQUEST_MAGIC.length);
        if (!Arrays.equals(magic, REQUEST_MAGIC)) throw new IllegalArgumentException("not a panel request");
        int headLength = d.readInt();
        if (headLength <= 0 || headLength > MAX_HEAD) throw new IllegalArgumentException("bad head length " + headLength);
        byte[] head = d.readNBytes(headLength);
        if (head.length != headLength) throw new EOFException("truncated head");
        long bodyLength = d.readLong();
        if (bodyLength < 0 || bodyLength > MAX_BODY) throw new IllegalArgumentException("bad body length " + bodyLength);
        byte[] body = d.readNBytes((int) bodyLength);
        if (body.length != bodyLength) throw new EOFException("truncated body");

        JSONObject h = new JSONObject(new String(head, StandardCharsets.UTF_8));
        String route = h.optString("route", "");
        String method = h.optString("method", "");
        String path = h.optString("path", "");
        String query = h.has("query") ? h.optString("query", null) : null;
        String clientIp = h.optString("client_ip", "");
        String lang = h.optString("lang", "");
        long adminId = h.optLong("admin_id", 0);
        long sessionId = h.optLong("session_id", 0);
        if (!ROUTE.matcher(route).matches() || route.contains("..")) throw new IllegalArgumentException("bad route");
        if (!METHODS.contains(method)) throw new IllegalArgumentException("bad method");
        if (!PATH.matcher(path).matches() || path.contains("..") || path.toLowerCase(Locale.ROOT).contains("%2e"))
            throw new IllegalArgumentException("bad path");
        if (query != null && !QUERY.matcher(query).matches()) throw new IllegalArgumentException("bad query");
        if (!org.daemoxcp.mail.security.InputValidator.isValidIp(clientIp)) throw new IllegalArgumentException("bad client ip");
        if (!LANG.matcher(lang).matches()) throw new IllegalArgumentException("bad language");
        boolean before = adminId == 0 && sessionId == 0 && BEFORE_SIGN_IN.contains(route);
        if (!before && (adminId <= 0 || sessionId <= 0)) throw new IllegalArgumentException("no administrator");
        Map<String, String> headers = new LinkedHashMap<>();
        JSONObject hs = h.optJSONObject("headers");
        if (hs != null) {
            for (String allowed : HEADERS) {
                for (String k : hs.keySet()) {
                    if (!k.equalsIgnoreCase(allowed)) continue;
                    String v = hs.optString(k, "");
                    if (!HEADER_VALUE.matcher(v).matches()) throw new IllegalArgumentException("bad header " + allowed);
                    headers.put(allowed, v);
                }
            }
        }
        return new Request(route, method, path, query, headers, clientIp, lang, adminId, sessionId, body);
    }

    static void writeResponseHead(OutputStream out, int status, long length, List<String[]> headers) throws IOException {
        JSONArray hs = new JSONArray();
        for (String[] kv : headers) hs.put(new JSONArray().put(kv[0]).put(kv[1]));
        byte[] head = new JSONObject().put("status", status).put("length", length).put("headers", hs)
                .toString().getBytes(StandardCharsets.UTF_8);
        if (head.length > MAX_HEAD) throw new IOException("response head too large");
        DataOutputStream d = new DataOutputStream(out);
        d.write(RESPONSE_MAGIC);
        d.writeInt(head.length);
        d.write(head);
        d.flush();
    }

    static ResponseHead readResponseHead(InputStream in) throws IOException {
        DataInputStream d = new DataInputStream(in);
        byte[] magic = d.readNBytes(RESPONSE_MAGIC.length);
        if (!Arrays.equals(magic, RESPONSE_MAGIC)) throw new IOException("not a panel response");
        int headLength = d.readInt();
        if (headLength <= 0 || headLength > MAX_HEAD) throw new IOException("bad response head length " + headLength);
        byte[] head = d.readNBytes(headLength);
        if (head.length != headLength) throw new EOFException("truncated response head");
        JSONObject h = new JSONObject(new String(head, StandardCharsets.UTF_8));
        int status = h.getInt("status");
        if (status < 100 || status > 599) throw new IOException("bad status " + status);
        long length = h.getLong("length");
        if (length < -1) throw new IOException("bad length " + length);
        List<String[]> headers = new ArrayList<>();
        JSONArray hs = h.optJSONArray("headers");
        if (hs != null) {
            for (int i = 0; i < hs.length(); i++) {
                JSONArray kv = hs.getJSONArray(i);
                headers.add(new String[]{kv.getString(0), kv.getString(1)});
            }
        }
        return new ResponseHead(status, length, headers);
    }

    // ===================== The root part: the socket =====================

    private final ServerSocketChannel channel;
    private final Path socket;
    private final String peerUser;
    private final Dispatcher dispatcher;
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "root-channel-timer");
        t.setDaemon(true);
        return t;
    });
    private volatile boolean closed;

    private RootChannel(ServerSocketChannel channel, Path socket, String peerUser, Dispatcher dispatcher) {
        this.channel = channel;
        this.socket = socket;
        this.peerUser = peerUser;
        this.dispatcher = dispatcher;
    }

    /**
     * Opens the socket and starts accepting. The folder is prepared by the caller (PanelSeparation): here a
     * socket left over from a previous start is removed and, as soon as the new one is created, it is set to 0660
     * with the given group.
     *
     * @param peerUser the user of the only process that can talk to the root part; null for the tests
     */
    public static RootChannel open(Path socket, String group, String peerUser, Dispatcher dispatcher) throws IOException {
        if (Files.isSymbolicLink(socket)) throw new IOException(socket + " is a symbolic link");
        Files.deleteIfExists(socket);
        ServerSocketChannel ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            ch.bind(UnixDomainSocketAddress.of(socket));
            // Right after creation the socket has the umask permissions (0755 measured): only root writes to it, so
            // until the chmod nobody else connects.
            Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-rw----"));
            if (group != null) {
                Files.getFileAttributeView(socket, PosixFileAttributeView.class)
                        .setGroup(socket.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(group));
            }
        } catch (IOException | RuntimeException e) {
            ch.close();
            throw e;
        }
        RootChannel rc = new RootChannel(ch, socket, peerUser, dispatcher);
        Thread t = new Thread(rc::acceptLoop, "root-channel");
        t.setDaemon(true);
        t.start();
        return rc;
    }

    private void acceptLoop() {
        while (!closed) {
            try {
                SocketChannel c = channel.accept();
                Thread.ofVirtual().name("root-channel-request").start(() -> serve(c));
            } catch (ClosedChannelException e) {
                return;
            } catch (IOException e) {
                if (!closed) LOGGER.log(Level.WARNING, "Root channel: accept failed", e);
            }
        }
    }

    private void serve(SocketChannel c) {
        try (c) {
            if (peerUser != null) {
                String who;
                try {
                    who = c.getOption(jdk.net.ExtendedSocketOptions.SO_PEERCRED).user().getName();
                } catch (IOException | UnsupportedOperationException e) {
                    who = "?";
                }
                if (!peerUser.equals(who)) {
                    LOGGER.warning("Root channel: connection from user " + who + " refused (only " + peerUser + ")");
                    return;
                }
            }
            InputStream in = Channels.newInputStream(c);
            OutputStream out = Channels.newOutputStream(c);
            Request request;
            // Whoever connects and then stays silent does not hold a thread forever: after READ_SECONDS it is closed.
            ScheduledFuture<?> deadline = timer.schedule(() -> { try { c.close(); } catch (IOException ignored) { } },
                    READ_SECONDS, TimeUnit.SECONDS);
            try {
                request = readRequest(in);
            } catch (IllegalArgumentException | org.json.JSONException e) {
                deadline.cancel(false);
                LOGGER.warning("Root channel: request refused: " + e.getMessage());
                refuse(out, 400, "{\"success\":false,\"error\":\"bad forwarded request\"}");
                return;
            } finally {
                deadline.cancel(false);
            }
            ForwardedExchange exchange = new ForwardedExchange(request, out);
            try {
                dispatcher.serve(request, exchange);
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "Root channel: " + request.method() + " " + request.path() + " failed", t);
            }
            exchange.finish();
        } catch (IOException e) {
            if (!closed) LOGGER.log(Level.FINE, "Root channel: connection ended", e);
        }
    }

    private static void refuse(OutputStream out, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        writeResponseHead(out, status, body.length, List.<String[]>of(new String[]{"Content-Type", "application/json"}));
        out.write(body);
        out.flush();
    }

    public Path socket() { return socket; }

    @Override
    public void close() {
        closed = true;
        try { channel.close(); } catch (IOException ignored) { }
        timer.shutdownNow();
        try { Files.deleteIfExists(socket); } catch (IOException ignored) { }
    }

    // ===================== The web part: a forward =====================

    /**
     * Sends a request to the root part and reads the header of the response; the body remains to be read in
     * {@code connection}. Throws IOException if the root part does not answer.
     */
    static Exchange send(Path socket, Request request) throws IOException {
        SocketChannel c = SocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            c.connect(UnixDomainSocketAddress.of(socket));
            OutputStream out = Channels.newOutputStream(c);
            writeRequest(out, request);
            InputStream in = new java.io.BufferedInputStream(Channels.newInputStream(c));
            return new Exchange(c, readResponseHead(in), in);
        } catch (IOException | RuntimeException e) {
            c.close();
            throw e;
        }
    }

    /** An incoming response from the root part: the header already read, the body to be copied. */
    record Exchange(SocketChannel connection, ResponseHead head, InputStream body) implements Closeable {
        @Override public void close() throws IOException { connection.close(); }
    }

    /** Reads the body of a browser request up to MAX_BODY: null if it is longer. */
    static byte[] readBody(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > MAX_BODY) return null;
            b.write(buf, 0, n);
        }
        return b.toByteArray();
    }
}
