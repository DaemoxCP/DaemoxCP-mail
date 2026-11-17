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
 * Il canale fra le due parti del pannello separato: un socket unix
 * della parte root, {@code /var/run/daemoxcp-mail/root.sock}, su cui la parte web (utente mailpanel) le
 * passa le API di chi ha fatto l'accesso, dopo i suoi filtri (Host, lingua, permesso, CSRF).
 *
 * <p>Una richiesta per connessione. La web scrive {@code "MPR1"}, la lunghezza dell'intestazione (int),
 * l'intestazione in JSON (UTF-8), la lunghezza del corpo (long) e il corpo. La root risponde
 * {@code "MPS1"}, la lunghezza (int) e l'intestazione in JSON (stato, lunghezza del corpo con lo stesso
 * significato di {@code sendResponseHeaders}, intestazioni), poi il corpo fino alla chiusura.
 *
 * <p>Nell'intestazione: la rotta che la web ha scelto, metodo, percorso e query grezzi, le intestazioni
 * dell'elenco {@link #HEADERS} e nessun'altra, l'IP del client per il registro, la lingua, e chi ha
 * fatto l'accesso: l'id dell'amministratore e quello della sua sessione. <strong>Mai i cookie ne' il
 * token della sessione</strong> che manda il browser. Amministratore, permessi e conferma recente la root
 * li rilegge dal database (WebSessions.forwarded), senza fidarsi di quello che le dice la web.
 *
 * <p>Senza amministratore (id 0 e 0) passano solo le rotte di {@link #BEFORE_SIGN_IN}: l'accesso, che
 * decide la root, e la chiave delle sessioni, che la web chiede
 * all'avvio.
 *
 * <p>Il socket sta in una cartella 0750 root:mailpanel e il socket e' 0660 root:mailpanel; in piu' la
 * root accetta solo connessioni il cui processo e' dell'utente della web (SO_PEERCRED, che Java 25 su
 * FreeBSD restituisce: misurato sulla VM il 07/11/2026).
 */
public final class RootChannel implements Closeable {

    private static final Logger LOGGER = Logger.getLogger(RootChannel.class.getName());

    static final byte[] REQUEST_MAGIC = "MPR1".getBytes(StandardCharsets.US_ASCII);
    static final byte[] RESPONSE_MAGIC = "MPS1".getBytes(StandardCharsets.US_ASCII);
    /** L'intestazione di una richiesta o di una risposta: abbondante per poche intestazioni corte. */
    static final int MAX_HEAD = 64 * 1024;
    /** Il corpo di una richiesta: lo stesso limite di SSLMailServer.readRequestBodyWithLimit. */
    static final long MAX_BODY = 10L * 1024 * 1024;
    /** Quanto puo' metterci la web a mandare la richiesta intera, una volta collegata. */
    static final long READ_SECONDS = 60;

    /**
     * Le sole intestazioni della richiesta che passano alla root, coi nomi come li scrive Headers. Il
     * resto (Cookie, X-CSRF-Token, Authorization, le intestazioni dei proxy) non passa mai: i filtri che
     * le usano li ha gia' fatti la web, e l'IP del client arriva in un campo suo. Host passa: la web lo ha
     * gia' confrontato coi nomi del pannello (HostCheck), e la root lo usa per l'rpId delle passkey.
     */
    static final List<String> HEADERS = List.of("Content-type", "Accept-language", "User-agent", "Accept", "Host");

    /**
     * Le rotte che la web passa senza un amministratore (id 0 e 0): l'accesso, la chiave delle sessioni, e le due
     * della webmail (cambio password e copia nel vault), che la web ha gia' controllato (loopback e chiave).
     */
    public static final java.util.Set<String> BEFORE_SIGN_IN = java.util.Set.of("/api/login", "/op/session-key",
            org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH);

    static final List<String> METHODS = List.of("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH");

    /** Una rotta come la registra SSLMailServer.context: un percorso assoluto, senza "..". */
    private static final Pattern ROUTE = Pattern.compile("/[A-Za-z0-9/_.-]{0,200}");
    /** Il percorso grezzo della richiesta: in piu' i caratteri di una codifica %XX e la tilde. */
    private static final Pattern PATH = Pattern.compile("/[A-Za-z0-9/_.~%-]{0,1000}");
    /** La query grezza: ASCII stampabile senza spazi (gli spazi arrivano codificati). */
    private static final Pattern QUERY = Pattern.compile("[\\x21-\\x7E]{0,8192}");
    /** Il valore di un'intestazione: ASCII stampabile, niente a capo. */
    private static final Pattern HEADER_VALUE = Pattern.compile("[\\x20-\\x7E]{0,1024}");
    private static final Pattern LANG = Pattern.compile("[a-z]{2}");

    /** Una richiesta inoltrata, gia' controllata nella forma. */
    public record Request(String route, String method, String path, String query, Map<String, String> headers,
                          String clientIp, String lang, long adminId, long sessionId, byte[] body) {
        public Request {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
            body = body == null ? new byte[0] : body;
        }
    }

    /** L'intestazione di una risposta: stato, lunghezza come in sendResponseHeaders, intestazioni. */
    public record ResponseHead(int status, long length, List<String[]> headers) {}

    /** Chi serve le richieste dalla parte root: SSLMailServer in modo ROOT_PART. */
    public interface Dispatcher {
        void serve(Request request, ForwardedExchange exchange) throws IOException;
    }

    // ===================== Il formato =====================

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
     * Legge e controlla una richiesta. Un campo fuori forma la rifiuta tutta (IllegalArgumentException):
     * non si ripulisce niente. Le intestazioni fuori elenco invece si scartano e basta.
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

    // ===================== La parte root: il socket =====================

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
     * Apre il socket e comincia ad accettare. La cartella la prepara chi chiama (PanelSeparation): qui si
     * toglie un socket rimasto da un avvio di prima e, appena creato, lo si porta a 0660 col gruppo dato.
     *
     * @param peerUser l'utente del solo processo che puo' parlare con la root; null per le prove
     */
    public static RootChannel open(Path socket, String group, String peerUser, Dispatcher dispatcher) throws IOException {
        if (Files.isSymbolicLink(socket)) throw new IOException(socket + " is a symbolic link");
        Files.deleteIfExists(socket);
        ServerSocketChannel ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        try {
            ch.bind(UnixDomainSocketAddress.of(socket));
            // Appena creato il socket ha i permessi dell'umask (0755 misurato): solo root ci scrive, quindi
            // fino al chmod nessun altro si collega.
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
            // Chi si collega e poi tace non tiene un thread per sempre: dopo READ_SECONDS si chiude.
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

    // ===================== La parte web: un inoltro =====================

    /**
     * Manda una richiesta alla root e ne legge l'intestazione della risposta; il corpo resta da leggere in
     * {@code connection}. Lancia IOException se la root non risponde.
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

    /** Una risposta della root in arrivo: l'intestazione letta, il corpo da copiare. */
    record Exchange(SocketChannel connection, ResponseHead head, InputStream body) implements Closeable {
        @Override public void close() throws IOException { connection.close(); }
    }

    /** Legge il corpo di una richiesta del browser fino a MAX_BODY: null se e' piu' lungo. */
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
