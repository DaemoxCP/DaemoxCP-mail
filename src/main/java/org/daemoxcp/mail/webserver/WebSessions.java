package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.database.SqlCatalog;

import org.daemoxcp.mail.security.AuthStore;
import org.daemoxcp.mail.security.DataCrypto;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The panel's sessions, in the database (table panel_sessions), tied to the jar's run.
 *
 *  - the token is only in the __Host-DaemoxCPMail cookie: the database holds its fingerprint, an HMAC
 *    with the key of THIS run (finding 184). The key is 32 random bytes, born with the
 *    process and kept only in its memory: never on disk, never in the database. Once the jar restarts, the
 *    key is a different one and no earlier token finds its row any more, not even with a copy of the
 *    database or of the cookie; and whoever reads the database cannot even test a token;
 *  - when the web server starts, the rows of the previous run are removed (beginRun), so the list
 *    of sessions does not show sessions that are no longer valid;
 *  - the cookie is a browser-session cookie (no Max-Age: once the browser is closed, it is gone) and
 *    SameSite=Strict: a link or a form from another site reaches the panel without a session;
 *  - a session expires after 30 minutes without requests and in any case after 12 hours;
 *  - it is valid only with the same browser (fingerprint of the User-Agent); the IP is not compared,
 *    because behind Cloudflare it changes, but it is kept encrypted for the list of sessions;
 *  - the CSRF token is not stored: it is the HMAC of the session token with the key of this run.
 *    Before login the same scheme applies with a separate cookie (__Host-DaemoxCPMailPre), which ties
 *    the login page's token to that browser without creating anything on the server: that one too
 *    is valid only until the restart;
 *  - it can be revoked: on logout, from the list of sessions, and by removing the administrator (ON DELETE
 *    CASCADE). Before, every visit to the login page created a session in memory, and the
 *    sessions lived in a shared list without synchronization.
 */
public final class WebSessions {

    private static final Logger LOGGER = Logger.getLogger(WebSessions.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();

    public static final String COOKIE = "__Host-DaemoxCPMail";
    public static final String PRE_COOKIE = "__Host-DaemoxCPMailPre";
    public static final long IDLE_SECONDS = 30 * 60;
    public static final long ABSOLUTE_SECONDS = 12 * 3600;
    /** The last activity is rewritten at most once a minute, not on every request. */
    private static final long TOUCH_SECONDS = 60;
    /**
     * The key of this run of the jar: the token fingerprints, the CSRF tokens and the pre-login
     * tokens depend on it. Only in memory: at restart a new one is born (finding 184).
     */
    private static final byte[] RUN_KEY = new byte[32];
    static {
        RANDOM.nextBytes(RUN_KEY);
    }
    private static volatile boolean runKeyAdopted = false;

    /**
     * With the separated panel the key is the root part's, which creates the sessions: the web part asks
     * the root for it at startup (the socket's closed session-key operation) to
     * recognize the sessions and the CSRF tokens. A copy, never on disk.
     */
    public static byte[] runKeyForWebPart() {
        return RUN_KEY.clone();
    }

    /** The web part adopts the root's key, only once, before serving. */
    public static synchronized void adoptRunKey(byte[] key) {
        if (key == null || key.length != RUN_KEY.length) throw new IllegalArgumentException("session key of the wrong size");
        if (runKeyAdopted) throw new IllegalStateException("session key already adopted");
        System.arraycopy(key, 0, RUN_KEY, 0, RUN_KEY.length);
        java.util.Arrays.fill(key, (byte) 0);
        runKeyAdopted = true;
    }
    /** A token: 32 random bytes in base64url, without "=". Anything else does not reach the database. */
    private static final java.util.regex.Pattern TOKEN = java.util.regex.Pattern.compile("[A-Za-z0-9_-]{43}");

    /** A valid session, with its administrator. */
    public record Current(long id, String token, AuthStore.Admin admin, LocalDateTime reauthAt) {
        /** True if the administrator confirmed their identity (passkey or code) within the given seconds. */
        public boolean reauthenticatedWithin(long seconds) {
            return reauthAt != null && reauthAt.isAfter(AuthStore.utc(Instant.now().minusSeconds(seconds)));
        }
    }

    /** One row of an administrator's list of sessions. */
    public record Listed(long id, String ip, String userAgent, LocalDateTime createdAt, LocalDateTime lastSeenAt) {}

    public static boolean wellFormed(String token) {
        return token != null && TOKEN.matcher(token).matches();
    }

    static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** The HMAC-SHA256 of a value with the key of this run, for a declared purpose. */
    private static byte[] runMac(String purpose, String value) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(RUN_KEY, "HmacSHA256"));
            return mac.doFinal((purpose + ":" + value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    /**
     * The fingerprint of a token in the database: 64 hexadecimal characters, like the token_hash column.
     * Public for the tests, which look up the row of a session.
     */
    public static String tokenHash(String token) {
        return java.util.HexFormat.of().formatHex(runMac("session", token));
    }

    private static String uaHash(String userAgent) {
        return DataCrypto.sha256Hex("ua:" + clip(userAgent));
    }

    private static String clip(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.trim();
        return ua.length() > 512 ? ua.substring(0, 512) : ua;
    }

    private static LocalDateTime utc(Instant i) { return LocalDateTime.ofInstant(i, ZoneOffset.UTC); }

    /** A new session for an administrator who has just logged in; returns the token for the cookie. */
    public String create(long adminId, String userAgent, String ip) {
        String token = newToken();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_CREATE)) {
            p.setString(1, tokenHash(token));
            p.setLong(2, adminId);
            p.setString(3, uaHash(userAgent));
            p.setString(4, DataCrypto.encrypt(clip(userAgent)));
            p.setString(5, ip == null ? null : DataCrypto.encrypt(ip));
            p.setObject(6, utc(now));
            p.setObject(7, utc(now));
            p.setObject(8, utc(now.plusSeconds(ABSOLUTE_SECONDS)));
            p.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Session not created", e);
        }
        AuthStore.loggedIn(adminId);
        return token;
    }

    /**
     * The session's Set-Cookie header: HTTPS only, not readable by scripts, never sent
     * from another site (Strict), and without Max-Age: it is a browser-session cookie, which the browser
     * forgets when it closes. The 12 hours and the 30 minutes are checked by the server anyway.
     */
    public static String cookieHeader(String token) {
        return COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    public static String clearCookieHeader() {
        return COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
    }

    /**
     * True if the last check of this thread could not read the database: then "no
     * session" does not mean that the session is over (finding 185). During a restart MySQL
     * stops before the panel, and the panel removed everyone's cookie as if the session had
     * expired; the same for a MySQL restart during a package update.
     */
    private static final ThreadLocal<Boolean> LAST_CHECK_FAILED = ThreadLocal.withInitial(() -> false);

    public static boolean lastCheckFailed() {
        return LAST_CHECK_FAILED.get();
    }

    /**
     * The token's session, if it exists, has not expired, is from the same browser and its administrator is active.
     *
     * <p>In the web part, with its own MySQL user, the procedures receive from here the fingerprint of this token
     * (CatalogGuard.useSession): the database checks the session again on every call. If the session is not
     * there, the fingerprint is forgotten at once.
     */
    public Optional<Current> check(String token, String userAgent) {
        Optional<Current> found = lookUp(token, userAgent);
        if (found.isEmpty()) org.daemoxcp.mail.database.CatalogGuard.forgetSession();
        return found;
    }

    private Optional<Current> lookUp(String token, String userAgent) {
        LAST_CHECK_FAILED.set(false);
        if (!wellFormed(token)) return Optional.empty();
        Instant now = Instant.now();
        String hash = tokenHash(token);
        org.daemoxcp.mail.database.CatalogGuard.useSession(hash);
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_CHECK)) {
            p.setString(1, hash);
            p.setObject(2, utc(now));
            p.setObject(3, utc(now.minusSeconds(IDLE_SECONDS)));
            try (ResultSet r = p.executeQuery()) {
                if (!r.next()) return Optional.empty();
                if (!DataCrypto.sameHash(r.getString(3), uaHash(userAgent))) return Optional.empty();
                long id = r.getLong(1);
                Optional<AuthStore.Admin> admin = AuthStore.adminById(r.getLong(2));
                if (admin.isEmpty()) return Optional.empty();
                LocalDateTime lastSeen = r.getObject(4, LocalDateTime.class);
                if (lastSeen.isBefore(utc(now.minusSeconds(TOUCH_SECONDS)))) touch(id, now);
                return Optional.of(new Current(id, token, admin.get(), r.getObject(5, LocalDateTime.class)));
            }
        } catch (SQLException e) {
            LAST_CHECK_FAILED.set(true);
            LOGGER.log(Level.WARNING, "Session check failed", e);
            return Optional.empty();
        }
    }

    /**
     * The root part of the separated panel: the session of a request that the web part passes to it, by id.
     * It must still exist (not expired, not revoked), belong to the administrator the web part names, and
     * that administrator must be active. The role and the recent confirmation are the database's. The token
     * is absent (null): the root never receives it, and the last activity is updated by the web part, which
     * has just checked the cookie.
     */
    public Optional<Current> forwarded(long sessionId, long adminId) {
        LAST_CHECK_FAILED.set(false);
        if (sessionId <= 0 || adminId <= 0) return Optional.empty();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_FORWARDED)) {
            p.setLong(1, sessionId);
            p.setObject(2, utc(now));
            p.setObject(3, utc(now.minusSeconds(IDLE_SECONDS)));
            try (ResultSet r = p.executeQuery()) {
                if (!r.next() || r.getLong(1) != adminId) return Optional.empty();
                Optional<AuthStore.Admin> admin = AuthStore.adminById(adminId);
                if (admin.isEmpty()) return Optional.empty();
                return Optional.of(new Current(sessionId, null, admin.get(), r.getObject(2, LocalDateTime.class)));
            }
        } catch (SQLException e) {
            LAST_CHECK_FAILED.set(true);
            LOGGER.log(Level.WARNING, "Forwarded session check failed", e);
            return Optional.empty();
        }
    }

    private void touch(long id, Instant now) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_TOUCH)) {
            p.setObject(1, utc(now));
            p.setLong(2, id);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session activity not recorded", e);
        }
    }

    /** Records that this session's administrator has just confirmed their identity. */
    public void markReauthenticated(long sessionId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_MARK_REAUTHENTICATED)) {
            p.setObject(1, utc(Instant.now()));
            p.setLong(2, sessionId);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Re-authentication not recorded", e);
        }
    }

    // ===================== CSRF =====================

    /** A session's CSRF token: it depends on the session token and on a key that exists only on the server. */
    public static String csrfToken(String sessionToken) {
        return wellFormed(sessionToken) ? Base64.getUrlEncoder().withoutPadding().encodeToString(runMac("csrf", sessionToken)) : null;
    }

    public static boolean validCsrf(String sessionToken, String presented) {
        String expected = csrfToken(sessionToken);
        return expected != null && presented != null && DataCrypto.sameHash(expected, presented);
    }

    /** The value of the pre-login cookie: a new one if it is missing or not well-formed. */
    public static String preLoginCookieValue(String current) {
        return wellFormed(current) ? current : newToken();
    }

    public static String preCookieHeader(String value) {
        return PRE_COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    public static String preLoginCsrf(String preCookie) {
        return wellFormed(preCookie) ? Base64.getUrlEncoder().withoutPadding().encodeToString(runMac("pre", preCookie)) : null;
    }

    public static boolean validPreLoginCsrf(String preCookie, String presented) {
        String expected = preLoginCsrf(preCookie);
        return expected != null && presented != null && DataCrypto.sameHash(expected, presented);
    }

    // ===================== Revocation and list =====================

    /**
     * The start of a run of the web server (SSLMailServer.start, after taking the port): the
     * sessions of the previous run are already invalid (the key is a different one) and here they
     * are also removed from the database, so they do not show in the list. Returns how many there
     * were, -1 if the database does not answer: in that case dead rows remain, which the cleanup of
     * expired sessions removes.
     */
    public int beginRun() {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_BEGIN_RUN)) {
            return p.executeUpdate();
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "Sessions of the previous start not removed", e);
            return -1;
        }
    }

    public void revoke(String token) {
        if (!wellFormed(token)) return;
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_REVOKE)) {
            p.setString(1, tokenHash(token));
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session not revoked", e);
        }
    }

    /** Removes one of the administrator's sessions (from the list). False if it is not theirs or not there. */
    public boolean revokeById(long id, long adminId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_REVOKE_BY_ID)) {
            p.setLong(1, id);
            p.setLong(2, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session not revoked", e);
            return false;
        }
    }

    /** Removes all of the administrator's sessions except the one to keep (-1: all of them). */
    public int revokeOthers(long adminId, long keepId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_REVOKE_OTHERS)) {
            p.setLong(1, adminId);
            p.setLong(2, keepId);
            return p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Sessions not revoked", e);
            return 0;
        }
    }

    /** The administrator's sessions that are still valid, most recent first. */
    public List<Listed> list(long adminId) {
        List<Listed> out = new ArrayList<>();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_LIST)) {
            p.setLong(1, adminId);
            p.setObject(2, utc(now));
            p.setObject(3, utc(now.minusSeconds(IDLE_SECONDS)));
            try (ResultSet r = p.executeQuery()) {
                while (r.next()) out.add(new Listed(r.getLong(1), DataCrypto.decryptOrEmpty(r.getString(2)),
                        DataCrypto.decryptOrEmpty(r.getString(3)), r.getObject(4, LocalDateTime.class), r.getObject(5, LocalDateTime.class)));
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Sessions unreadable", e);
        }
        return out;
    }

    /** How many valid sessions there are in total (for the tests and diagnostics). */
    public int count() {
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(SqlCatalog.SESSION_COUNT)) {
            p.setObject(1, utc(now));
            p.setObject(2, utc(now.minusSeconds(IDLE_SECONDS)));
            try (ResultSet r = p.executeQuery()) {
                return r.next() ? r.getInt(1) : 0;
            }
        } catch (SQLException e) {
            return 0;
        }
    }
}
