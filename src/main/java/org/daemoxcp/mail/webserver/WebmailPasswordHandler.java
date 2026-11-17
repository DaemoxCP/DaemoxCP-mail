package org.daemoxcp.mail.webserver;

import com.sun.net.httpserver.HttpExchange;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.PanelSecrets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Le due rotte che usa solo la webmail (Roundcube, sullo stesso server), mai un browser:
 *
 *  - POST /api/internal/mailbox-password (user, curpass, newpass): il cambio password dalla
 *    webmail. Il plugin password di Roundcube (driver httpapi, vedi WebmailPasswordConfig) la
 *    manda qui invece di scrivere da se' nel database: il pannello controlla la password attuale
 *    e scrive insieme l'hash bcrypt e la copia cifrata, cosi' la password si puo' sempre rivedere.
 *  - POST /api/internal/mailbox-vault (user, pass): dopo un accesso alla webmail con la password
 *    della casella, il plugin daemoxcp_mail_sso la manda qui. Se il pannello non ne ha la copia (casella
 *    di prima del vault) o la copia e' vecchia, e la password corrisponde all'hash, la copia si scrive.
 *
 * Chi chiama deve arrivare da 127.0.0.1 (o ::1) direttamente, senza intestazioni di un proxy
 * davanti, e mandare la chiave della webmail (X-DaemoxCP-Key, nel file dei segreti del pannello).
 * Altrimenti la risposta e' 404, come per una rotta che non c'e'. Nessuna password nei log.
 *
 * <p>Col pannello separato le serve la root: la web controlla chi chiama
 * ({@link #callerRefused}) e passa la richiesta; la root rifa' tutto il resto, password attuale con bcrypt e
 * limite dei tentativi compresi, senza il controllo del chiamante, che non vede.
 */
final class WebmailPasswordHandler {

    private static final Logger LOGGER = Logger.getLogger(WebmailPasswordHandler.class.getName());
    private static final int MAX_BODY = 8 * 1024;
    private static final int MAX_CURRENT_PASSWORD = 256;
    /** Tentativi per casella in WINDOW_MS: password attuale sbagliata, o controlli bcrypt per la copia. */
    static int maxAttempts = 5;
    static long windowMs = 15 * 60 * 1000L;

    private final SSLMailServer server;
    private final Map<String, Deque<Long>> attempts = new ConcurrentHashMap<>();

    WebmailPasswordHandler(SSLMailServer server) { this.server = server; }

    // ===================== Rotte =====================

    void handlePasswordChange(HttpExchange ex) throws IOException {
        handlePasswordChange(ex, true);
    }

    /** checkCaller false: la parte root, con la richiesta che la web ha gia' controllato (callerRefused). */
    void handlePasswordChange(HttpExchange ex, boolean checkCaller) throws IOException {
        Map<String, String> form = authorizedForm(ex, checkCaller);
        if (form == null) return;
        String user = form.getOrDefault("user", "").trim().toLowerCase(java.util.Locale.ROOT);
        String current = form.getOrDefault("curpass", "");
        String next = form.getOrDefault("newpass", "");
        String ip = remoteIp(ex);
        if (!SecurityUtils.isValidEmail(user) || current.isEmpty() || current.length() > MAX_CURRENT_PASSWORD) {
            reply(ex, 400, "invalid");
            return;
        }
        if (!SecurityUtils.isValidMailboxPassword(next)) {
            reply(ex, 400, "invalid new password");
            return;
        }
        if (limited(user)) {
            reply(ex, 429, "too many attempts");
            return;
        }
        try {
            MailDatabase.Mailbox box = Main.mailDatabase.getMailboxByEmail(user);
            if (box == null || !Main.mailDatabase.mailboxPasswordMatches(box.id, current)) {
                count(user);
                server.logAudit("WEBMAIL_PASSWORD_CHANGE_REFUSED", ip, "email=" + user);
                reply(ex, 403, "error");
                return;
            }
            if (!Main.mailDatabase.updateMailboxPassword(box.id, next)) {
                reply(ex, 500, "error");
                return;
            }
            server.logAudit("WEBMAIL_PASSWORD_CHANGED", ip, "mailbox_id=" + box.id + " email=" + user);
            reply(ex, 200, "ok");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Webmail password change failed for " + user, e);
            reply(ex, 500, "error");
        }
    }

    void handleVaultCopy(HttpExchange ex) throws IOException {
        handleVaultCopy(ex, true);
    }

    /** checkCaller false: la parte root, con la richiesta che la web ha gia' controllato (callerRefused). */
    void handleVaultCopy(HttpExchange ex, boolean checkCaller) throws IOException {
        Map<String, String> form = authorizedForm(ex, checkCaller);
        if (form == null) return;
        String user = form.getOrDefault("user", "").trim().toLowerCase(java.util.Locale.ROOT);
        String pass = form.getOrDefault("pass", "");
        if (!SecurityUtils.isValidEmail(user) || pass.isEmpty() || pass.length() > MAX_CURRENT_PASSWORD) {
            reply(ex, 400, "invalid");
            return;
        }
        try {
            MailDatabase.Mailbox box = Main.mailDatabase.getMailboxByEmail(user);
            if (box == null) {
                reply(ex, 200, "ok");
                return;
            }
            // La copia c'e' ed e' questa password: niente da fare, e nessun bcrypt a ogni accesso
            if (copyIs(box.id, pass)) {
                reply(ex, 200, "ok");
                return;
            }
            if (limited(user)) {
                reply(ex, 429, "too many attempts");
                return;
            }
            count(user);
            if (Main.mailDatabase.fillMissingVaultCopy(box.id, pass)) {
                server.logAudit("MAILBOX_PASSWORD_COPY_STORED", remoteIp(ex), "mailbox_id=" + box.id + " email=" + user + " source=webmail_login");
            }
            reply(ex, 200, "ok");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Storing the webmail password copy failed for " + user, e);
            reply(ex, 500, "error");
        }
    }

    // ===================== Controlli =====================

    /** La copia nel vault decifra esattamente in questa password. */
    private static boolean copyIs(int mailboxId, String pass) throws java.sql.SQLException {
        String enc = Main.mailDatabase.getMailboxPasswordEncrypted(mailboxId);
        if (enc == null || enc.isEmpty()) return false;
        try {
            String plain = org.daemoxcp.mail.security.PasswordVault.getInstance().decrypt(enc);
            return plain != null && MessageDigest.isEqual(plain.getBytes(StandardCharsets.UTF_8), pass.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Il modulo della richiesta se chi chiama e' la webmail: POST, da loopback senza proxy, con la
     * chiave giusta. Altrimenti risponde lui (404 o 405) e torna null.
     */
    private Map<String, String> authorizedForm(HttpExchange ex, boolean checkCaller) throws IOException {
        if (checkCaller ? callerRefused(ex) : methodRefused(ex)) return null;
        String body = readBody(ex);
        if (body == null) {
            reply(ex, 413, "too large");
            return null;
        }
        Map<String, String> form = parseForm(body);
        if (form == null) {
            reply(ex, 400, "invalid");
            return null;
        }
        return form;
    }

    /**
     * Chi chiama non e' la webmail sulla stessa macchina, o non manda un POST: risposto (404 o 405) e vero. La
     * parte web lo chiede prima di passare la richiesta alla root.
     */
    static boolean callerRefused(HttpExchange ex) throws IOException {
        if (!fromLocalWebmail(ex)) {
            drain(ex);
            reply(ex, 404, "not found");
            return true;
        }
        return methodRefused(ex);
    }

    private static boolean methodRefused(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            drain(ex);
            reply(ex, 405, "method not allowed");
            return true;
        }
        return false;
    }

    /** Quanto puo' essere grande il corpo (la parte web non passa alla root niente di piu'). */
    static int maxBody() {
        return MAX_BODY;
    }

    static boolean fromLocalWebmail(HttpExchange ex) {
        InetAddress addr = ex.getRemoteAddress() == null ? null : ex.getRemoteAddress().getAddress();
        if (addr == null || !addr.isLoopbackAddress()) return false;
        // Passata da nginx (o da Cloudflare) non e' la webmail che chiama direttamente
        var h = ex.getRequestHeaders();
        if (h.containsKey("X-Forwarded-For") || h.containsKey("X-Real-IP") || h.containsKey("CF-Connecting-IP")
                || h.containsKey("Forwarded")) return false;
        // L'intestazione di adesso, o una di prima (sezione "webmailKeyHeaders"): Roundcube la manda come dice il suo
        // config.inc.php, che il pannello riscrive all'avvio, ma una richiesta puo' arrivare in mezzo.
        String given = h.getFirst(org.daemoxcp.mail.integration.WebmailPasswordConfig.KEY_HEADER);
        for (String old : org.daemoxcp.mail.system.LegacyNames.oldNamesOf("webmailKeyHeaders",
                org.daemoxcp.mail.integration.WebmailPasswordConfig.KEY_HEADER))
            if (given == null) given = h.getFirst(old);
        if (given == null || given.isEmpty() || given.length() > 128) return false;
        String expected = PanelSecrets.webmailKey();
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), given.getBytes(StandardCharsets.US_ASCII));
    }

    private boolean limited(String user) {
        long now = System.currentTimeMillis();
        Deque<Long> q = attempts.get(user);
        if (q == null) return false;
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) q.pollFirst();
            return q.size() >= maxAttempts;
        }
    }

    private void count(String user) {
        if (attempts.size() > 10_000) attempts.clear();     // un tetto alla memoria; si riparte da zero
        Deque<Long> q = attempts.computeIfAbsent(user, k -> new ArrayDeque<>());
        synchronized (q) { q.addLast(System.currentTimeMillis()); }
    }

    void resetLimits() { attempts.clear(); }

    // ===================== Utilita' =====================

    private static String remoteIp(HttpExchange ex) {
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }

    /** application/x-www-form-urlencoded; null se non si decodifica o un campo e' ripetuto. */
    static Map<String, String> parseForm(String body) {
        Map<String, String> out = new HashMap<>();
        if (body.isEmpty()) return out;
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            try {
                String k = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                String v = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                if (out.put(k, v) != null) return null;
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return out;
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[2048];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (out.size() + n > MAX_BODY) return null;
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /** Il corpo non si legge: si chiude e basta (chi non e' la webmail non fa leggere niente al server). */
    private static void drain(HttpExchange ex) {
        try {
            ex.getRequestBody().close();
        } catch (IOException ignored) {
            // niente
        }
    }

    private static void reply(HttpExchange ex, int status, String text) throws IOException {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }
}
