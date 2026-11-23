package org.daemoxcp.mail.security;

import org.daemoxcp.mail.i18n.I18n;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;
import java.util.logging.Logger;

/**
 * The one-time codes: login via email, login from the server console, confirmation of
 * a sensitive operation, change of the login email.
 *
 *  - the code exists only in the message (or on the console): the database holds the HMAC fingerprint;
 *  - it is valid for 10 minutes (15 from the console and for the email change), five attempts, once;
 *  - asking for a code for an address that belongs to nobody gives the same answer, in the
 *    same time: sending starts from a separate queue and whoever answers does not wait for sendmail;
 *  - limits against spam: per IP address, per subnet and per recipient. Over the limit
 *    the answer stays the same, the message simply does not go out;
 *  - never the code nor the email address in the logs.
 *
 * The message goes out from this server's Postfix (the same sendmail as the periodic report):
 * the panel sits on the mail server and does not need SMTP credentials.
 */
public final class LoginCodes {

    private LoginCodes() {}

    private static final Logger LOGGER = Logger.getLogger(LoginCodes.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();

    static final long EMAIL_TTL_S = 600;
    static final long CONSOLE_TTL_S = 900;
    static final long STEP_UP_TTL_S = 600;
    static final long EMAIL_CHANGE_TTL_S = 900;
    public static final int MAX_ATTEMPTS = 5;

    static LongSupplier clock = System::currentTimeMillis;

    /**
     * Who sends the emails; the tests replace it with a lambda that receives recipient,
     * subject and text. The real panel receives the whole message (text and HTML) from the second
     * method, which for a lambda falls back on the first.
     */
    public interface Mailer {
        void send(String to, String subject, String body) throws Exception;

        default void send(String to, org.daemoxcp.mail.system.PanelMail.Message message) throws Exception {
            send(to, message.subject(), message.text());
        }
    }

    public static Mailer mailer = new Mailer() {
        @Override
        public void send(String to, String subject, String body) throws Exception {
            send(to, new org.daemoxcp.mail.system.PanelMail.Message(subject, body,
                    "<pre>" + org.daemoxcp.mail.system.PanelMail.esc(body) + "</pre>", I18n.current()));
        }

        @Override
        public void send(String to, org.daemoxcp.mail.system.PanelMail.Message message) {
            if (!org.daemoxcp.mail.system.PeriodicReport.sendPanelMessage(to, message))
                throw new IllegalStateException("Postfix did not accept the message");
        }
    };

    private static final ExecutorService QUEUE = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "login-code-mail");
        t.setDaemon(true);
        return t;
    });

    /** In tests the sending happens immediately, so that it can be checked. */
    public static boolean synchronousMail = false;

    /**
     * Queued, in the language of whoever asked, with the time and the address of the request: the
     * message is composed in the queue's thread, because reading the server name may mean
     * asking Postfix, and whoever answers the request must not wait for it.
     */
    static void queue(String to, org.daemoxcp.mail.system.CodeMail.Kind kind, String code, long minutes, String ip) {
        String lang = I18n.current();
        java.time.ZonedDateTime when = java.time.ZonedDateTime.now();
        Runnable job = () -> {
            try {
                mailer.send(to, org.daemoxcp.mail.system.CodeMail.message(kind, lang,
                        org.daemoxcp.mail.system.PanelMail.serverName(), code, minutes, ip, when));
            } catch (Exception e) {
                // Neither the address nor the message: the code is inside. The details are in the mail log.
                LOGGER.warning("Login code email not delivered");
            }
        };
        if (synchronousMail) job.run(); else QUEUE.submit(job);
    }

    // ===================== Limits =====================

    private static final Map<String, Deque<Long>> HITS = new HashMap<>();

    /** True (and counts the request) if in the window there have been fewer than max. */
    static synchronized boolean allow(String key, int max, long windowMs) {
        long now = clock.getAsLong();
        Deque<Long> d = HITS.computeIfAbsent(key, k -> new ArrayDeque<>());
        while (!d.isEmpty() && now - d.peekFirst() >= windowMs) d.pollFirst();
        if (d.size() >= max) return false;
        d.addLast(now);
        if (HITS.size() > 20000) HITS.entrySet().removeIf(e -> e.getValue().isEmpty() || now - e.getValue().peekLast() > DAY);
        return true;
    }

    public static synchronized void resetLimits() { HITS.clear(); }

    /** The subnet of an address: /24 for IPv4, /64 for IPv6. */
    static String subnet(String ip) {
        try {
            if (!InputValidator.isValidIp(ip)) return "?:" + ip;
            byte[] a = InetAddress.getByName(ip).getAddress();
            int keep = a.length == 4 ? 3 : 8;
            StringBuilder b = new StringBuilder(a.length == 4 ? "v4:" : "v6:");
            for (int i = 0; i < keep; i++) b.append(a[i] & 0xff).append('.');
            return b.toString();
        } catch (Exception e) {
            return "?:" + ip;
        }
    }

    private static final long MIN = 60_000L, HOUR = 3_600_000L, DAY = 86_400_000L;

    // ===================== Codes =====================

    static String digits(int n) {
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++) b.append(RANDOM.nextInt(10));
        return b.toString();
    }

    private static Instant in(long seconds) { return AuthStore.now().plusSeconds(seconds); }

    /** Only digits and the right length (spaces and dashes removed): everything else does not reach the comparison. */
    static String clean(String code, int length) {
        if (code == null || code.length() > 20) return null;
        String c = code.replace(" ", "").replace("-", "");
        return c.matches("[0-9]{" + length + "}") ? c : null;
    }

    /** An acceptable email address: printable ASCII only, at most 254 characters. */
    public static boolean validEmail(String email) {
        return email != null && email.length() <= 254 && org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(email);
    }

    /** Checks the administrator's latest valid code: counts the attempt, and if it is correct consumes it. */
    private static boolean check(AuthStore.CodeFlow flow, String purpose, long adminId, String code) {
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(flow, adminId);
        if (rows.isEmpty()) return false;
        AuthStore.CodeRow row = rows.get(0);
        if (row.attempts() >= MAX_ATTEMPTS) return false;
        AuthStore.codeAttempt(flow, row.id());
        return DataCrypto.sameHash(row.codeHash(), DataCrypto.codeHash(purpose, adminId, code))
                && AuthStore.consumeCode(flow, row.id(), MAX_ATTEMPTS);
    }

    // ----- login via email -----

    /** Sends a code if the address belongs to an administrator and the limits allow it. Never says which of the two. */
    public static void requestEmailLogin(String email, String ip) {
        if (!validEmail(email)) return;
        String index = DataCrypto.emailIndex(email);
        boolean ok = allow("email-req-ip:" + ip, 5, 15 * MIN)
                & allow("email-req-net:" + subnet(ip), 20, HOUR)
                & allow("email-req-to:" + index, 3, 15 * MIN)
                & allow("email-req-to-day:" + index, 10, DAY);
        if (!ok) {
            LOGGER.info("Login code request over the limit from " + ip);
            return;
        }
        Optional<AuthStore.Admin> admin = AuthStore.adminByEmail(email);
        if (admin.isEmpty()) return;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.EMAIL_LOGIN, admin.get().id(),
                DataCrypto.codeHash("email_login", admin.get().id(), code), in(EMAIL_TTL_S), null, null)) return;
        queue(admin.get().email(), org.daemoxcp.mail.system.CodeMail.Kind.LOGIN, code, EMAIL_TTL_S / 60, ip);
    }

    /** The administrator, if the code is correct, valid and not used yet. */
    public static Optional<AuthStore.Admin> verifyEmailLogin(String email, String code, String ip) {
        String c = clean(code, 6);
        if (!allow("email-verify-ip:" + ip, 10, 15 * MIN) || c == null || !validEmail(email)) return Optional.empty();
        Optional<AuthStore.Admin> admin = AuthStore.adminByEmail(email);
        if (admin.isEmpty()) {
            // The same work as a real comparison, so as not to answer sooner.
            DataCrypto.sameHash(DataCrypto.codeHash("email_login", 0, c), DataCrypto.codeHash("email_login", 0, "000000"));
            return Optional.empty();
        }
        return check(AuthStore.CodeFlow.EMAIL_LOGIN, "email_login", admin.get().id(), c) ? admin : Optional.empty();
    }

    // ----- login from the server console -----

    /** An eight-digit code to log in without email or passkey: whoever has access to the server generates it. */
    public static String issueConsoleCode(AuthStore.Admin admin) {
        String code = digits(8);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.CONSOLE_LOGIN, admin.id(),
                DataCrypto.codeHash("console_login", admin.id(), code), in(CONSOLE_TTL_S), null, null))
            throw new IllegalStateException("Console code not saved");
        return code;
    }

    public static Optional<AuthStore.Admin> verifyConsoleCode(String code, String ip) {
        String c = clean(code, 8);
        if (!allow("console-verify-ip:" + ip, 10, 15 * MIN) || c == null) return Optional.empty();
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(AuthStore.CodeFlow.CONSOLE_LOGIN, -1);
        for (AuthStore.CodeRow row : rows) {
            if (row.attempts() >= MAX_ATTEMPTS) continue;
            if (DataCrypto.sameHash(row.codeHash(), DataCrypto.codeHash("console_login", row.adminId(), c))) {
                AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
                return AuthStore.consumeCode(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id(), MAX_ATTEMPTS)
                        ? AuthStore.adminById(row.adminId()) : Optional.empty();
            }
        }
        // A wrong code consumes an attempt of every valid code: you cannot try all the numbers.
        for (AuthStore.CodeRow row : rows) AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
        return Optional.empty();
    }

    /**
     * The confirmation of a sensitive operation with a console code (--access-code): whoever reads it has the root
     * shell, which is worth more than any confirmation. Only the codes of the logged-in administrator: another's does
     * not pass and is not consumed. Same per-address limit and same attempts as logging in with that code.
     */
    public static boolean verifyConsoleStepUp(AuthStore.Admin admin, String code, String ip) {
        String c = clean(code, 8);
        if (!allow("console-verify-ip:" + ip, 10, 15 * MIN) || c == null) return false;
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(AuthStore.CodeFlow.CONSOLE_LOGIN, admin.id());
        for (AuthStore.CodeRow row : rows) {
            if (row.attempts() >= MAX_ATTEMPTS) continue;
            if (DataCrypto.sameHash(row.codeHash(), DataCrypto.codeHash("console_login", row.adminId(), c))) {
                AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
                return AuthStore.consumeCode(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id(), MAX_ATTEMPTS);
            }
        }
        for (AuthStore.CodeRow row : rows) AuthStore.codeAttempt(AuthStore.CodeFlow.CONSOLE_LOGIN, row.id());
        return false;
    }

    // ----- confirmation of a sensitive operation (for those without a passkey) -----

    /** Sends a code to the email of the logged-in administrator. False if they have no email or are over the limit. */
    public static boolean requestStepUp(AuthStore.Admin admin, String ip) {
        if (!admin.hasEmail()) return false;
        if (!(allow("stepup:" + admin.id(), 3, 15 * MIN) & allow("stepup-ip:" + ip, 5, 15 * MIN))) return false;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.STEP_UP, admin.id(),
                DataCrypto.codeHash("step_up", admin.id(), code), in(STEP_UP_TTL_S), null, null)) return false;
        queue(admin.email(), org.daemoxcp.mail.system.CodeMail.Kind.STEP_UP, code, STEP_UP_TTL_S / 60, ip);
        return true;
    }

    public static boolean verifyStepUp(AuthStore.Admin admin, String code) {
        String c = clean(code, 6);
        return c != null && check(AuthStore.CodeFlow.STEP_UP, "step_up", admin.id(), c);
    }

    // ----- email change -----

    public enum ChangeResult { SENT, INVALID, TAKEN, LIMIT }

    /** Sends a code to the new address: the email changes only when that code comes back. */
    public static ChangeResult requestEmailChange(AuthStore.Admin admin, String newEmail, String ip) {
        if (!validEmail(newEmail)) return ChangeResult.INVALID;
        Optional<AuthStore.Admin> owner = AuthStore.adminByEmail(newEmail);
        if (owner.isPresent() && owner.get().id() != admin.id()) return ChangeResult.TAKEN;
        if (!(allow("email-change:" + admin.id(), 3, 15 * MIN) & allow("email-change-ip:" + ip, 5, 15 * MIN)))
            return ChangeResult.LIMIT;
        String code = digits(6);
        if (!AuthStore.saveCode(AuthStore.CodeFlow.EMAIL_CHANGE, admin.id(),
                DataCrypto.codeHash("email_change", admin.id(), code), in(EMAIL_CHANGE_TTL_S),
                DataCrypto.encrypt(newEmail.trim()), DataCrypto.emailIndex(newEmail)))
            return ChangeResult.LIMIT;
        queue(newEmail.trim(), org.daemoxcp.mail.system.CodeMail.Kind.EMAIL_CHANGE, code, EMAIL_CHANGE_TTL_S / 60, ip);
        return ChangeResult.SENT;
    }

    /** True if the code is correct and the address is still free: from that moment the login email is the new one. */
    public static boolean confirmEmailChange(AuthStore.Admin admin, String code) {
        String c = clean(code, 6);
        if (c == null) return false;
        List<AuthStore.CodeRow> rows = AuthStore.activeCodes(AuthStore.CodeFlow.EMAIL_CHANGE, admin.id());
        if (rows.isEmpty()) return false;
        AuthStore.CodeRow row = rows.get(0);
        if (!check(AuthStore.CodeFlow.EMAIL_CHANGE, "email_change", admin.id(), c)) return false;
        return AuthStore.setEmail(admin.id(), DataCrypto.decrypt(row.targetEnc())) == AuthStore.CreateResult.CREATED;
    }
}
