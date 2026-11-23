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
 * The two routes used only by the webmail (Roundcube, on the same server), never by a browser:
 *
 *  - POST /api/internal/mailbox-password (user, curpass, newpass): the password change from the
 *    webmail. Roundcube's password plugin (httpapi driver, see WebmailPasswordConfig) sends it
 *    here instead of writing to the database itself: the panel checks the current password and
 *    writes the bcrypt hash and the encrypted copy together, so the password can always be viewed again.
 *  - POST /api/internal/mailbox-cleanup (user, action get|set, junk, trash): the automatic emptying of Junk
 *    and Trash of one's own mailbox, from the webmail settings (the daemoxcp_mail_cleanup plugin). The user
 *    is the one of the Roundcube session: the key says the webmail is calling, which already has Dovecot's
 *    master user and therefore every mailbox; from here it gets nothing more. Only the days of the list
 *    (MailDatabase.CLEANUP_DAYS, 0 = never), and only for an active mailbox. The change goes into the audit log.
 *  - POST /api/internal/mailbox-vault (user, pass): after a login to the webmail with the mailbox's
 *    password, the daemoxcp_mail_sso plugin sends it here. If the panel has no copy of it (a mailbox
 *    from before the vault) or the copy is old, and the password matches the hash, the copy is written.
 *
 * The caller must come from 127.0.0.1 (or ::1) directly, without the headers of a proxy
 * in front, and send the webmail key (X-DaemoxCP-Key, in the panel's secrets file).
 * Otherwise the response is 404, as for a route that does not exist. No passwords in the logs.
 *
 * <p>With the separated panel the root serves them: the web part checks the
 * caller ({@link #callerRefused}) and passes the request on; the root redoes all the rest, current password
 * with bcrypt and attempt limit included, without the caller check, which it cannot see.
 */
final class WebmailPasswordHandler {

    private static final Logger LOGGER = Logger.getLogger(WebmailPasswordHandler.class.getName());
    private static final int MAX_BODY = 8 * 1024;
    private static final int MAX_CURRENT_PASSWORD = 256;
    /** Attempts per mailbox in WINDOW_MS: wrong current password, or bcrypt checks for the copy. */
    static int maxAttempts = 5;
    static long windowMs = 15 * 60 * 1000L;

    private final SSLMailServer server;
    private final Map<String, Deque<Long>> attempts = new ConcurrentHashMap<>();

    WebmailPasswordHandler(SSLMailServer server) { this.server = server; }

    // ===================== Routes =====================

    void handlePasswordChange(HttpExchange ex) throws IOException {
        handlePasswordChange(ex, true);
    }

    /** checkCaller false: the root part, with the request that the web part has already checked (callerRefused). */
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

    void handleCleanup(HttpExchange ex) throws IOException {
        handleCleanup(ex, true);
    }

    /**
     * checkCaller false: the root part, with the request that the web part has already checked (callerRefused).
     * Answers "junk=N trash=N" (the current days, also after a change), 404 "not found" if the mailbox does not
     * exist or is not active, 400 "invalid" for a user or days that are not acceptable.
     */
    void handleCleanup(HttpExchange ex, boolean checkCaller) throws IOException {
        Map<String, String> form = authorizedForm(ex, checkCaller);
        if (form == null) return;
        String user = form.getOrDefault("user", "").trim().toLowerCase(java.util.Locale.ROOT);
        String action = form.getOrDefault("action", "get");
        if (!SecurityUtils.isValidEmail(user) || !(action.equals("get") || action.equals("set"))) {
            reply(ex, 400, "invalid");
            return;
        }
        try {
            MailDatabase.Mailbox box = Main.mailDatabase.getMailboxByEmail(user);
            if (box == null || !box.active) {
                reply(ex, 404, "not found");
                return;
            }
            if (action.equals("set")) {
                int junk = days(form.get("junk")), trash = days(form.get("trash"));
                if (!MailDatabase.cleanupDaysAllowed(junk) || !MailDatabase.cleanupDaysAllowed(trash)) {
                    reply(ex, 400, "invalid");
                    return;
                }
                if (junk != box.junkExpungeDays || trash != box.trashExpungeDays) {
                    if (!Main.mailDatabase.setMailboxCleanup(user, junk, trash)) {
                        reply(ex, 500, "error");
                        return;
                    }
                    server.logAudit("WEBMAIL_CLEANUP_CHANGED", remoteIp(ex), "mailbox_id=" + box.id + " email=" + user
                            + " junk_days=" + box.junkExpungeDays + "->" + junk + " trash_days=" + box.trashExpungeDays + "->" + trash);
                }
                reply(ex, 200, "junk=" + junk + " trash=" + trash);
                return;
            }
            reply(ex, 200, "junk=" + box.junkExpungeDays + " trash=" + box.trashExpungeDays);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Webmail automatic emptying failed for " + user, e);
            reply(ex, 500, "error");
        }
    }

    /** The days of a form field: digits only, at most three; -1 otherwise (and the list check rejects it). */
    static int days(String value) {
        return value != null && value.matches("[0-9]{1,3}") ? Integer.parseInt(value) : -1;
    }

    /** checkCaller false: the root part, with the request that the web part has already checked (callerRefused). */
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
            // The copy exists and is this password: nothing to do, and no bcrypt on every login
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

    // ===================== Checks =====================

    /** The copy in the vault decrypts to exactly this password. */
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
     * The request's form if the caller is the webmail: POST, from loopback without a proxy, with the
     * right key. Otherwise it answers itself (404 or 405) and returns null.
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
     * The caller is not the webmail on the same machine, or does not send a POST: answered (404 or 405) and
     * true. The web part asks this before passing the request to the root.
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

    /** How large the body can be (the web part passes nothing larger to the root). */
    static int maxBody() {
        return MAX_BODY;
    }

    static boolean fromLocalWebmail(HttpExchange ex) {
        InetAddress addr = ex.getRemoteAddress() == null ? null : ex.getRemoteAddress().getAddress();
        if (addr == null || !addr.isLoopbackAddress()) return false;
        // Passed through nginx (or Cloudflare), it is not the webmail calling directly
        var h = ex.getRequestHeaders();
        if (h.containsKey("X-Forwarded-For") || h.containsKey("X-Real-IP") || h.containsKey("CF-Connecting-IP")
                || h.containsKey("Forwarded")) return false;
        // The current header, or an earlier one (section "webmailKeyHeaders"): Roundcube sends it as its
        // config.inc.php says, which the panel rewrites at startup, but a request can arrive in between.
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
        if (attempts.size() > 10_000) attempts.clear();     // a cap on memory; start again from zero
        Deque<Long> q = attempts.computeIfAbsent(user, k -> new ArrayDeque<>());
        synchronized (q) { q.addLast(System.currentTimeMillis()); }
    }

    void resetLimits() { attempts.clear(); }

    // ===================== Utilita' =====================

    private static String remoteIp(HttpExchange ex) {
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }

    /** application/x-www-form-urlencoded; null if it does not decode or a field is repeated. */
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

    /** The body is not read: it is just closed (whoever is not the webmail gets the server to read nothing). */
    private static void drain(HttpExchange ex) {
        try {
            ex.getRequestBody().close();
        } catch (IOException ignored) {
            // nothing
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
