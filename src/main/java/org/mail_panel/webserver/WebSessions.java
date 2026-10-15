package org.mail_panel.webserver;

import org.mail_panel.security.AuthStore;
import org.mail_panel.security.DataCrypto;

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
 * Le sessioni del pannello, nel database (tabella panel_sessions), non in memoria.
 *
 *  - il token sta solo nel cookie __Host-MailPanel: nel database c'e' la sua fingerprint SHA-256,
 *    quindi chi legge il database non puo' usarlo;
 *  - una sessione scade dopo 30 minuti senza richieste e comunque dopo 12 ore;
 *  - vale solo con lo stesso browser (fingerprint dello User-Agent); l'IP non si confronta, perche'
 *    dietro Cloudflare cambia, ma si conserva cifrato per l'elenco delle sessioni;
 *  - il token CSRF non si salva: e' l'HMAC del token di sessione con la chiave delle sessioni.
 *    Prima di entrare vale lo stesso schema con un cookie a parte (__Host-MailPanelPre), che lega
 *    il token della pagina di accesso a quel browser senza creare niente sul server;
 *  - si revoca: all'uscita, dall'elenco delle sessioni, e togliendo l'amministratore (ON DELETE
 *    CASCADE). Prima ogni visita alla pagina di accesso creava una sessione in memoria, e le
 *    sessioni stavano in una lista condivisa senza sincronizzazione.
 */
public final class WebSessions {

    private static final Logger LOGGER = Logger.getLogger(WebSessions.class.getName());
    private static final SecureRandom RANDOM = new SecureRandom();

    public static final String COOKIE = "__Host-MailPanel";
    public static final String PRE_COOKIE = "__Host-MailPanelPre";
    public static final long IDLE_SECONDS = 30 * 60;
    public static final long ABSOLUTE_SECONDS = 12 * 3600;
    /** L'ultima attivita' si riscrive al massimo una volta al minuto, non a ogni richiesta. */
    private static final long TOUCH_SECONDS = 60;
    /** Un token: 32 byte casuali in base64url, senza "=". Tutto il resto non arriva al database. */
    private static final java.util.regex.Pattern TOKEN = java.util.regex.Pattern.compile("[A-Za-z0-9_-]{43}");

    /** Una sessione valida, con il suo amministratore. */
    public record Current(long id, String token, AuthStore.Admin admin, LocalDateTime reauthAt) {
        /** Vero se l'amministratore ha confermato di essere lui (passkey o codice) negli ultimi secondi dati. */
        public boolean reauthenticatedWithin(long seconds) {
            return reauthAt != null && reauthAt.isAfter(AuthStore.utc(Instant.now().minusSeconds(seconds)));
        }
    }

    /** Una riga dell'elenco delle sessioni di un amministratore. */
    public record Listed(long id, String ip, String userAgent, LocalDateTime createdAt, LocalDateTime lastSeenAt) {}

    public static boolean wellFormed(String token) {
        return token != null && TOKEN.matcher(token).matches();
    }

    static String newToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String uaHash(String userAgent) {
        return DataCrypto.sha256Hex("ua:" + clip(userAgent));
    }

    private static String clip(String userAgent) {
        String ua = userAgent == null ? "" : userAgent.trim();
        return ua.length() > 512 ? ua.substring(0, 512) : ua;
    }

    private static LocalDateTime utc(Instant i) { return LocalDateTime.ofInstant(i, ZoneOffset.UTC); }

    /** Una sessione nuova per un amministratore appena entrato; restituisce il token per il cookie. */
    public String create(long adminId, String userAgent, String ip) {
        String token = newToken();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(
                "INSERT INTO panel_sessions (token_hash, admin_id, ua_hash, ua_enc, ip_enc, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
            p.setString(1, DataCrypto.sha256Hex(token));
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

    /** L'intestazione Set-Cookie della sessione: solo HTTPS, non leggibile dagli script. */
    public static String cookieHeader(String token) {
        return COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + ABSOLUTE_SECONDS;
    }

    public static String clearCookieHeader() {
        return COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
    }

    /** La sessione del token, se esiste, non e' scaduta, e' dello stesso browser e l'amministratore e' attivo. */
    public Optional<Current> check(String token, String userAgent) {
        if (!wellFormed(token)) return Optional.empty();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(
                "SELECT id, admin_id, ua_hash, last_seen_at, reauth_at FROM panel_sessions "
              + "WHERE token_hash = ? AND expires_at > ? AND last_seen_at > ?")) {
            p.setString(1, DataCrypto.sha256Hex(token));
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
            LOGGER.log(Level.WARNING, "Session check failed", e);
            return Optional.empty();
        }
    }

    private void touch(long id, Instant now) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement("UPDATE panel_sessions SET last_seen_at = ? WHERE id = ?")) {
            p.setObject(1, utc(now));
            p.setLong(2, id);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session activity not recorded", e);
        }
    }

    /** Annota che l'amministratore di questa sessione ha appena confermato di essere lui. */
    public void markReauthenticated(long sessionId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement("UPDATE panel_sessions SET reauth_at = ? WHERE id = ?")) {
            p.setObject(1, utc(Instant.now()));
            p.setLong(2, sessionId);
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Re-authentication not recorded", e);
        }
    }

    // ===================== CSRF =====================

    /** Il token CSRF di una sessione: dipende dal token di sessione e da una chiave che sta solo sul server. */
    public static String csrfToken(String sessionToken) {
        return wellFormed(sessionToken) ? DataCrypto.sessionMac("csrf", sessionToken) : null;
    }

    public static boolean validCsrf(String sessionToken, String presented) {
        String expected = csrfToken(sessionToken);
        return expected != null && presented != null && DataCrypto.sameHash(expected, presented);
    }

    /** Il valore del cookie da prima del login: uno nuovo se manca o non ha la forma giusta. */
    public static String preLoginCookieValue(String current) {
        return wellFormed(current) ? current : newToken();
    }

    public static String preCookieHeader(String value) {
        return PRE_COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Lax";
    }

    public static String preLoginCsrf(String preCookie) {
        return wellFormed(preCookie) ? DataCrypto.sessionMac("pre", preCookie) : null;
    }

    public static boolean validPreLoginCsrf(String preCookie, String presented) {
        String expected = preLoginCsrf(preCookie);
        return expected != null && presented != null && DataCrypto.sameHash(expected, presented);
    }

    // ===================== Revoca ed elenco =====================

    public void revoke(String token) {
        if (!wellFormed(token)) return;
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement("DELETE FROM panel_sessions WHERE token_hash = ?")) {
            p.setString(1, DataCrypto.sha256Hex(token));
            p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session not revoked", e);
        }
    }

    /** Toglie una sessione dell'amministratore (dall'elenco). Falso se non e' sua o non c'e'. */
    public boolean revokeById(long id, long adminId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement("DELETE FROM panel_sessions WHERE id = ? AND admin_id = ?")) {
            p.setLong(1, id);
            p.setLong(2, adminId);
            return p.executeUpdate() == 1;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Session not revoked", e);
            return false;
        }
    }

    /** Toglie tutte le sessioni dell'amministratore tranne quella da tenere (-1: tutte). */
    public int revokeOthers(long adminId, long keepId) {
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement("DELETE FROM panel_sessions WHERE admin_id = ? AND id <> ?")) {
            p.setLong(1, adminId);
            p.setLong(2, keepId);
            return p.executeUpdate();
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Sessions not revoked", e);
            return 0;
        }
    }

    /** Le sessioni ancora valide dell'amministratore, la piu' recente prima. */
    public List<Listed> list(long adminId) {
        List<Listed> out = new ArrayList<>();
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(
                "SELECT id, ip_enc, ua_enc, created_at, last_seen_at FROM panel_sessions "
              + "WHERE admin_id = ? AND expires_at > ? AND last_seen_at > ? ORDER BY last_seen_at DESC")) {
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

    /** Quante sessioni valide ci sono in tutto (per i test e la diagnostica). */
    public int count() {
        Instant now = Instant.now();
        try (PreparedStatement p = AuthStore.connection.get().prepareStatement(
                "SELECT COUNT(*) FROM panel_sessions WHERE expires_at > ? AND last_seen_at > ?")) {
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
