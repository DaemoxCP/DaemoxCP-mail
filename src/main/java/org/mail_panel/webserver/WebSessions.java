package org.mail_panel.webserver;

import org.mail_panel.database.SqlCatalog;

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
 * Le sessioni del pannello, nel database (tabella panel_sessions), legate all'avvio del jar.
 *
 *  - il token sta solo nel cookie __Host-MailPanel: nel database c'e' la sua impronta, un HMAC
 *    con la chiave di QUESTO avvio (reperto 184). La chiave e' di 32 byte casuali, nasce col
 *    processo e sta solo nella sua memoria: mai su disco, mai nel database. Riavviato il jar, la
 *    chiave e' un'altra e nessun token di prima trova piu' la sua riga, nemmeno con una copia del
 *    database o del cookie; e chi legge il database non puo' nemmeno provare un token;
 *  - all'avvio del server web le righe dell'avvio di prima si tolgono (beginRun), cosi' l'elenco
 *    delle sessioni non mostra sessioni che non valgono piu';
 *  - il cookie e' di sessione del browser (senza Max-Age: chiuso il browser, sparisce) e
 *    SameSite=Strict: un link o un modulo da un altro sito arriva al pannello senza sessione;
 *  - una sessione scade dopo 30 minuti senza richieste e comunque dopo 12 ore;
 *  - vale solo con lo stesso browser (impronta dello User-Agent); l'IP non si confronta, perche'
 *    dietro Cloudflare cambia, ma si conserva cifrato per l'elenco delle sessioni;
 *  - il token CSRF non si salva: e' l'HMAC del token di sessione con la chiave di questo avvio.
 *    Prima di entrare vale lo stesso schema con un cookie a parte (__Host-MailPanelPre), che lega
 *    il token della pagina di accesso a quel browser senza creare niente sul server: anche quello
 *    vale solo fino al riavvio;
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
    /**
     * La chiave di questo avvio del jar: le impronte dei token, i token CSRF e quelli di prima
     * dell'accesso dipendono da lei. Solo in memoria: al riavvio ne nasce un'altra (reperto 184).
     */
    private static final byte[] RUN_KEY = new byte[32];
    static {
        RANDOM.nextBytes(RUN_KEY);
    }
    private static volatile boolean runKeyAdopted = false;

    /**
     * Col pannello separato la chiave e' quella della parte root, che crea le sessioni: la web la chiede alla root all'avvio (l'operazione chiusa session-key del socket) per
     * riconoscere le sessioni e i token CSRF. Una copia, mai su disco.
     */
    public static byte[] runKeyForWebPart() {
        return RUN_KEY.clone();
    }

    /** La parte web adotta la chiave della root, una volta sola, prima di servire. */
    public static synchronized void adoptRunKey(byte[] key) {
        if (key == null || key.length != RUN_KEY.length) throw new IllegalArgumentException("session key of the wrong size");
        if (runKeyAdopted) throw new IllegalStateException("session key already adopted");
        System.arraycopy(key, 0, RUN_KEY, 0, RUN_KEY.length);
        java.util.Arrays.fill(key, (byte) 0);
        runKeyAdopted = true;
    }
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

    /** L'HMAC-SHA256 di un valore con la chiave di questo avvio, per uno scopo dichiarato. */
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
     * L'impronta di un token nel database: 64 caratteri esadecimali, come la colonna token_hash.
     * Pubblica per le prove, che cercano la riga di una sessione.
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

    /** Una sessione nuova per un amministratore appena entrato; restituisce il token per il cookie. */
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
     * L'intestazione Set-Cookie della sessione: solo HTTPS, non leggibile dagli script, mai mandata
     * da un altro sito (Strict), e senza Max-Age: e' un cookie di sessione del browser, che lo
     * dimentica quando si chiude. Le 12 ore e i 30 minuti li controlla comunque il server.
     */
    public static String cookieHeader(String token) {
        return COOKIE + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    public static String clearCookieHeader() {
        return COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
    }

    /**
     * Vero se l'ultimo check di questo thread non ha potuto leggere il database: allora "nessuna
     * sessione" non vuol dire che la sessione e' finita (reperto 185). Durante un riavvio MySQL si
     * ferma prima del pannello, e il pannello toglieva il cookie a tutti come se la sessione fosse
     * scaduta; lo stesso per un riavvio di MySQL durante un aggiornamento dei pacchetti.
     */
    private static final ThreadLocal<Boolean> LAST_CHECK_FAILED = ThreadLocal.withInitial(() -> false);

    public static boolean lastCheckFailed() {
        return LAST_CHECK_FAILED.get();
    }

    /**
     * La sessione del token, se esiste, non e' scaduta, e' dello stesso browser e l'amministratore e' attivo.
     *
     * <p>Nella parte web, con il suo utente MySQL, le procedure ricevono da qui l'impronta di questo token
     * (CatalogGuard.useSession): il database ricontrolla la sessione a ogni chiamata. Se la sessione non c'e',
     * l'impronta si dimentica subito.
     */
    public Optional<Current> check(String token, String userAgent) {
        Optional<Current> found = lookUp(token, userAgent);
        if (found.isEmpty()) org.mail_panel.database.CatalogGuard.forgetSession();
        return found;
    }

    private Optional<Current> lookUp(String token, String userAgent) {
        LAST_CHECK_FAILED.set(false);
        if (!wellFormed(token)) return Optional.empty();
        Instant now = Instant.now();
        String hash = tokenHash(token);
        org.mail_panel.database.CatalogGuard.useSession(hash);
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
     * La parte root del pannello separato: la sessione di una richiesta che le passa la web, per id. Deve
     * esserci ancora (non scaduta, non revocata), essere dell'amministratore che dice la web, e lui deve
     * essere attivo. Il ruolo e la conferma recente sono quelli del database. Il token non c'e' (null): la
     * root non lo riceve mai, e l'ultima attivita' la aggiorna la web, che ha appena controllato il cookie.
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

    /** Annota che l'amministratore di questa sessione ha appena confermato di essere lui. */
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

    /** Il token CSRF di una sessione: dipende dal token di sessione e da una chiave che sta solo sul server. */
    public static String csrfToken(String sessionToken) {
        return wellFormed(sessionToken) ? Base64.getUrlEncoder().withoutPadding().encodeToString(runMac("csrf", sessionToken)) : null;
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
        return PRE_COOKIE + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=Strict";
    }

    public static String preLoginCsrf(String preCookie) {
        return wellFormed(preCookie) ? Base64.getUrlEncoder().withoutPadding().encodeToString(runMac("pre", preCookie)) : null;
    }

    public static boolean validPreLoginCsrf(String preCookie, String presented) {
        String expected = preLoginCsrf(preCookie);
        return expected != null && presented != null && DataCrypto.sameHash(expected, presented);
    }

    // ===================== Revoca ed elenco =====================

    /**
     * L'inizio di un avvio del server web (SSLMailServer.start, dopo aver preso la porta): le
     * sessioni dell'avvio di prima non valgono gia' piu' (la chiave e' un'altra) e qui si tolgono
     * anche dal database, cosi' non compaiono nell'elenco. Restituisce quante erano, -1 se il
     * database non risponde: in quel caso restano righe morte, che la pulizia delle scadute toglie.
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

    /** Toglie una sessione dell'amministratore (dall'elenco). Falso se non e' sua o non c'e'. */
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

    /** Toglie tutte le sessioni dell'amministratore tranne quella da tenere (-1: tutte). */
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

    /** Le sessioni ancora valide dell'amministratore, la piu' recente prima. */
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

    /** Quante sessioni valide ci sono in tutto (per i test e la diagnostica). */
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
