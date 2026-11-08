package org.mail_panel.webserver;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The channel between the two parts of the separated panel, without
 * a database:
 *
 *  1. the format: a request goes and comes back the same; headers outside the list (Cookie,
 *     X-CSRF-Token, Authorization, the proxies' ones) never pass, Host does; a field out of shape refuses
 *     the whole request (route or path with "..", an encoded dot, an unknown method, a client address that
 *     is not an IP, a language that is not two letters, no administrator or session except on the sign-in
 *     and the session key, a body over the limit);
 *  2. the socket: a request reaches the dispatcher and its answer comes back, with status, headers and
 *     body; the socket is 0660; a connection from a user other than the allowed one gets nothing;
 *  3. the in-memory exchange: the declared length is enforced, a response without body stays without,
 *     HEAD has no body, a handler that answers nothing gives a 500, the client IP is the remote address.
 *
 * Usage (on the VM):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RootChannelTest
 */
public class RootChannelTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static RootChannel.Request request(String route, String method, String path, String query, Map<String, String> headers,
                                       String ip, String lang, long admin, long session, byte[] body) {
        return new RootChannel.Request(route, method, path, query, headers, ip, lang, admin, session, body);
    }

    static RootChannel.Request good() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-type", "application/json");
        h.put("User-agent", "Mozilla/5.0 test");
        return request("/api/domains", "POST", "/api/domains", "a=1&b=%20x", h, "203.0.113.7", "it", 4, 17,
                "{\"action\":\"list\"}".getBytes(StandardCharsets.UTF_8));
    }

    static byte[] encode(RootChannel.Request r) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        RootChannel.writeRequest(b, r);
        return b.toByteArray();
    }

    /** A request whose head is written by hand: what a web part that lies could send. */
    static byte[] raw(String headJson, byte[] body) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(b);
        d.write(RootChannel.REQUEST_MAGIC);
        byte[] head = headJson.getBytes(StandardCharsets.UTF_8);
        d.writeInt(head.length);
        d.write(head);
        d.writeLong(body.length);
        d.write(body);
        return b.toByteArray();
    }

    static boolean refused(byte[] bytes) {
        try {
            RootChannel.readRequest(new ByteArrayInputStream(bytes));
            return false;
        } catch (IllegalArgumentException | org.json.JSONException e) {
            return true;
        } catch (IOException e) {
            return true;
        }
    }

    static String head(String route, String method, String path, String ip, String lang, long admin, long session) {
        return new org.json.JSONObject().put("route", route).put("method", method).put("path", path).put("client_ip", ip)
                .put("lang", lang).put("admin_id", admin).put("session_id", session).put("headers", new org.json.JSONObject()).toString();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The format ==");
        RootChannel.Request in = good();
        RootChannel.Request out = RootChannel.readRequest(new ByteArrayInputStream(encode(in)));
        check("a request comes back the same", out.route().equals(in.route()) && out.method().equals(in.method())
                && out.path().equals(in.path()) && out.query().equals(in.query()) && out.clientIp().equals(in.clientIp())
                && out.lang().equals("it") && out.adminId() == 4 && out.sessionId() == 17
                && new String(out.body(), StandardCharsets.UTF_8).equals("{\"action\":\"list\"}")
                && "application/json".equals(out.headers().get("Content-type")));

        org.json.JSONObject liar = new org.json.JSONObject(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 4, 17));
        liar.put("headers", new org.json.JSONObject().put("Cookie", "__Host-MailPanel=abc").put("X-CSRF-Token", "t")
                .put("Authorization", "Bearer x").put("Host", "evil.example").put("CF-Connecting-IP", "1.2.3.4")
                .put("User-Agent", "UA"));
        liar.put("token", "the-session-token");
        RootChannel.Request filtered = RootChannel.readRequest(new ByteArrayInputStream(raw(liar.toString(), new byte[0])));
        check("headers outside the list never pass, Host does (checked by the web part, the passkeys' rpId) ("
                + filtered.headers().keySet() + ")", filtered.headers().keySet().equals(java.util.Set.of("User-agent", "Host")));

        check("a route with .. is refused", refused(raw(head("/api/../index", "GET", "/api/../index", "203.0.113.7", "en", 4, 17), new byte[0])));
        check("a path with .. is refused", refused(raw(head("/api/domains", "GET", "/api/domains/../../x", "203.0.113.7", "en", 4, 17), new byte[0])));
        check("an encoded dot is refused", refused(raw(head("/api/domains", "GET", "/api/domains/%2E%2e/x", "203.0.113.7", "en", 4, 17), new byte[0])));
        check("an unknown method is refused", refused(raw(head("/api/domains", "TRACE", "/api/domains", "203.0.113.7", "en", 4, 17), new byte[0])));
        check("a client address that is not an IP is refused", refused(raw(head("/api/domains", "GET", "/api/domains", "evil.example", "en", 4, 17), new byte[0])));
        check("a language that is not two letters is refused", refused(raw(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "../../etc", 4, 17), new byte[0])));
        check("no administrator is refused", refused(raw(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 0, 17), new byte[0])));
        check("no session is refused", refused(raw(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 4, 0), new byte[0])));
        check("neither, on a signed-in route: refused", refused(raw(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 0, 0), new byte[0])));
        check("neither, on the sign-in and the session key: accepted (they are before any session)",
                !refused(raw(head("/api/login", "POST", "/api/login", "203.0.113.7", "en", 0, 0), new byte[0]))
                && !refused(raw(head("/op/session-key", "POST", "/op/session-key", "203.0.113.7", "en", 0, 0), new byte[0])));
        check("  but only with both at zero", refused(raw(head("/api/login", "POST", "/api/login", "203.0.113.7", "en", 0, 17), new byte[0])));
        org.json.JSONObject crlf = new org.json.JSONObject(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 4, 17));
        crlf.put("headers", new org.json.JSONObject().put("User-Agent", "a\r\nSet-Cookie: x=1"));
        check("a header value with a line break is refused", refused(raw(crlf.toString(), new byte[0])));
        org.json.JSONObject q = new org.json.JSONObject(head("/api/domains", "GET", "/api/domains", "203.0.113.7", "en", 4, 17));
        q.put("query", "a=1 HTTP/1.1\r\nX: y");
        check("a query with spaces or line breaks is refused", refused(raw(q.toString(), new byte[0])));
        ByteArrayOutputStream big = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(big);
        byte[] h = head("/api/domains", "POST", "/api/domains", "203.0.113.7", "en", 4, 17).getBytes(StandardCharsets.UTF_8);
        d.write(RootChannel.REQUEST_MAGIC);
        d.writeInt(h.length);
        d.write(h);
        d.writeLong(RootChannel.MAX_BODY + 1);
        check("a body over the limit is refused before reading it", refused(big.toByteArray()));
        check("something that is not a panel request is refused", refused("GET / HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));

        System.out.println("\n== 2. The socket ==");
        Path dir = Files.createTempDirectory("root-channel");
        Path sock = dir.resolve("root.sock");
        AtomicReference<RootChannel.Request> seen = new AtomicReference<>();
        AtomicReference<String> seenCookie = new AtomicReference<>("unset");
        RootChannel.Dispatcher echo = (r, ex) -> {
            seen.set(r);
            seenCookie.set(ex.getRequestHeaders().getFirst("Cookie"));
            byte[] b = ("{\"path\":\"" + ex.getRequestURI().getPath() + "\",\"ip\":\"" + ex.getRemoteAddress().getAddress().getHostAddress()
                    + "\",\"body\":" + new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8) + "}").getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.getResponseHeaders().add("X-Test", "yes");
            ex.sendResponseHeaders(201, b.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(b); }
        };
        String me = System.getProperty("user.name");
        try (RootChannel channel = RootChannel.open(sock, null, me, echo)) {
            check("the socket is 0660 (" + PosixFilePermissions.toString(Files.getPosixFilePermissions(sock)) + ")",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(sock)).equals("rw-rw----"));
            try (RootChannel.Exchange ex = RootChannel.send(sock, good())) {
                String body = new String(ex.body().readAllBytes(), StandardCharsets.UTF_8);
                check("the answer comes back: status " + ex.head().status() + ", body " + body, ex.head().status() == 201
                        && body.equals("{\"path\":\"/api/domains\",\"ip\":\"203.0.113.7\",\"body\":{\"action\":\"list\"}}"));
                check("with its headers", ex.head().headers().stream().anyMatch(kv -> kv[0].equalsIgnoreCase("X-Test") && kv[1].equals("yes"))
                        && ex.head().length() == body.getBytes(StandardCharsets.UTF_8).length);
                check("the dispatcher saw no Cookie header", seenCookie.get() == null);
            }
        }
        check("closing removes the socket", !Files.exists(sock));

        try (RootChannel channel = RootChannel.open(sock, null, "nobody-but-me-" + me, echo)) {
            seen.set(null);
            boolean nothing;
            try (RootChannel.Exchange ex = RootChannel.send(sock, good())) {
                nothing = false;
            } catch (IOException e) {
                nothing = true;
            }
            check("a connection from another user gets nothing, and reaches no dispatcher", nothing && seen.get() == null);
        }

        RootChannel.Dispatcher silent = (r, ex) -> { };
        try (RootChannel channel = RootChannel.open(sock, null, me, silent);
             RootChannel.Exchange ex = RootChannel.send(sock, good())) {
            check("a handler that answers nothing gives a 500 (" + ex.head().status() + ")", ex.head().status() == 500);
        }
        RootChannel.Dispatcher thrower = (r, ex) -> { throw new IllegalStateException("boom"); };
        try (RootChannel channel = RootChannel.open(sock, null, me, thrower);
             RootChannel.Exchange ex = RootChannel.send(sock, good())) {
            check("a handler that throws gives a 500 (" + ex.head().status() + ")", ex.head().status() == 500);
        }
        try (RootChannel channel = RootChannel.open(sock, null, me, echo)) {
            java.nio.channels.SocketChannel c = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX);
            c.connect(java.net.UnixDomainSocketAddress.of(sock));
            java.nio.channels.Channels.newOutputStream(c).write(raw(head("/api/x/../y", "GET", "/api/x", "203.0.113.7", "en", 4, 17), new byte[0]));
            RootChannel.ResponseHead r = RootChannel.readResponseHead(java.nio.channels.Channels.newInputStream(c));
            c.close();
            check("a request out of shape gets a 400 (" + r.status() + ")", r.status() == 400);
        }

        System.out.println("\n== 3. The in-memory exchange ==");
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        ForwardedExchange fx = new ForwardedExchange(good(), wire);
        boolean before;
        try { fx.getResponseBody().write(1); before = false; } catch (IOException e) { before = true; }
        check("no body before the headers", before);
        fx.sendResponseHeaders(200, 3);
        boolean over;
        try (OutputStream os = fx.getResponseBody()) { os.write(new byte[]{1, 2, 3, 4}); over = false; } catch (IOException e) { over = true; }
        check("no more bytes than the declared length", over);
        boolean twice;
        try { fx.sendResponseHeaders(200, 1); twice = false; } catch (IOException e) { twice = true; }
        check("the headers go once", twice);
        check("the client IP is the remote address", fx.getRemoteAddress().getAddress().getHostAddress().equals("203.0.113.7"));
        check("Content-Length is the body's", "17".equals(fx.getRequestHeaders().getFirst("Content-Length")));

        ByteArrayOutputStream wire2 = new ByteArrayOutputStream();
        RootChannel.Request head = request("/api/domains", "HEAD", "/api/domains", null, Map.of(), "203.0.113.7", "en", 4, 17, null);
        ForwardedExchange hx = new ForwardedExchange(head, wire2);
        hx.sendResponseHeaders(200, 10);
        RootChannel.ResponseHead hh = RootChannel.readResponseHead(new ByteArrayInputStream(wire2.toByteArray()));
        check("HEAD: no body, whatever the handler says (" + hh.length() + ")", hh.length() == -1);

        ByteArrayOutputStream wire3 = new ByteArrayOutputStream();
        ForwardedExchange nx = new ForwardedExchange(good(), wire3);
        nx.getResponseHeaders().set("Set-Cookie", "x=1");
        nx.getResponseHeaders().set("Content-Length", "99");
        nx.sendResponseHeaders(204, -1);
        RootChannel.ResponseHead nh = RootChannel.readResponseHead(new ByteArrayInputStream(wire3.toByteArray()));
        check("hop-by-hop headers are not sent back", nh.headers().stream().noneMatch(kv -> kv[0].equalsIgnoreCase("Content-Length")));
        List<String[]> hs = nh.headers();
        check("a Set-Cookie of the root still travels (the web part drops it)", hs.stream().anyMatch(kv -> kv[0].equalsIgnoreCase("Set-Cookie")));

        Files.deleteIfExists(dir);
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
