package org.daemoxcp.mail.webserver;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.security.InputValidator;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * L'elenco chiuso di quello che la parte root accetta dalla parte web, prima di qualunque gestore:
 * <ul>
 *   <li>per ogni rotta che resta alla root, i metodi che il suo gestore usa ({@link #METHODS}); una rotta che
 *       non e' qui la root la rifiuta;</li>
 *   <li>la forma di ogni valore della query e del corpo JSON: chiavi di lettere, cifre e trattino basso, niente
 *       caratteri di controllo (salvo a capo e tabulazione), lunghezze e profondita' massime;</li>
 *   <li>per i parametri che i gestori mettono in un comando, in un percorso o in un file di configurazione
 *       della root, la loro forma stretta ({@link #STRICT}): nomi di host, IP e reti, jail, porte, selettori
 *       DKIM, pacchetti, servizi, paesi, registri, certificati e chiavi PEM. Un nome di host che comincia con
 *       un trattino, per esempio, diventerebbe un'opzione del comando a cui lo si passa (dig -f legge un file).</li>
 * </ul>
 * I gestori controllano gia' molti di questi valori dove li usano; qui si controllano tutti, una volta, per
 * chiunque scriva sul socket. Le azioni non sono in elenco: un'azione che il gestore non conosce la rifiuta il
 * gestore stesso, senza toccare niente.
 */
final class RootGate {

    private RootGate() {}

    static final Set<String> GET = Set.of("GET");
    static final Set<String> POST = Set.of("POST");
    static final Set<String> GET_POST = Set.of("GET", "POST");

    /** Le rotte della root e i metodi dei loro gestori (letti dal codice dei gestori). /api/login senza sessione. */
    static final Map<String, Set<String>> METHODS = Map.ofEntries(
            Map.entry("/api/status", GET_POST), Map.entry("/api/stats", GET_POST), Map.entry("/api/versions", GET),
            Map.entry("/api/aliases", Set.of("GET", "POST", "PUT", "DELETE")), Map.entry("/api/webmail/open", GET_POST),
            Map.entry("/api/autoresponder", GET_POST), Map.entry("/api/sieve", GET_POST), Map.entry("/api/forwarding", GET_POST),
            Map.entry("/api/queue", GET_POST), Map.entry("/api/ratelimits", GET_POST), Map.entry("/api/dns", GET_POST),
            Map.entry("/api/dkim", GET_POST), Map.entry("/api/ssl", GET_POST), Map.entry("/api/cloudflare", GET_POST),
            Map.entry("/api/autodns", POST), Map.entry("/api/autoconfig", POST), Map.entry("/api/fail2ban", GET_POST),
            Map.entry("/api/fail2ban_health", GET_POST), Map.entry("/api/clamav_health", GET_POST),
            Map.entry("/api/unbound_health", GET_POST), Map.entry("/api/firewall", GET_POST), Map.entry("/api/rspamd", GET_POST),
            Map.entry("/api/updates", GET_POST), Map.entry("/api/logs", GET_POST), Map.entry("/api/system_paths", GET),
            Map.entry("/api/panel_info", GET), Map.entry("/api/mailbox-quota", GET), Map.entry("/api/service", POST), Map.entry("/api/timezone-diag", GET_POST),
            Map.entry("/api/postfix-aliases-health", GET_POST), Map.entry("/api/sso", GET_POST), Map.entry("/api/admins", GET_POST),
            Map.entry("/api/report", POST), Map.entry("/api/hostname", GET_POST), Map.entry("/api/roundcube-domain", GET_POST),
            // L'accesso e la scheda Account: amministratori, passkey, codici e sessioni li decide la root (0.8.2, A).
            Map.entry("/api/login", POST), Map.entry("/api/account", GET_POST),
            // POP3 acceso o spento (Impostazioni).
            Map.entry("/api/pop3", GET_POST),
            Map.entry("/api/ip-family", GET_POST),
            // Gli indirizzi IPv4 e IPv6 del server e la loro guida (ServerAddresses): ifconfig, route, rc.conf, solo da root.
            Map.entry("/api/server-addresses", GET_POST),
            // Le chiavi SSH di root (Impostazioni).
            Map.entry("/api/ssh-keys", GET_POST),
            // «Mostra password»: la copia dal vault la legge solo la root (0.8, punto 3).
            Map.entry("/api/mailbox-password", POST),
            // Il profilo Apple da scaricare: lo firma la root, con la chiave del certificato della posta (23/11/2026).
            Map.entry("/apple-profile", GET),
            // La webmail: cambio password e copia nel vault, senza sessione (la web ha controllato chi chiama).
            Map.entry(org.daemoxcp.mail.integration.WebmailPasswordConfig.PATH, POST),
            Map.entry(org.daemoxcp.mail.integration.WebmailPasswordConfig.VAULT_PATH, POST),
            Map.entry(org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH, POST));

    static final int MAX_STRING = 64 * 1024;
    static final int MAX_DEPTH = 4;
    static final int MAX_ITEMS = 2000;
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_]{1,64}");
    private static final Pattern CONTROL = Pattern.compile("[\\p{Cc}&&[^\\n\\r\\t]]");
    private static final Pattern SERVICE = Pattern.compile("[a-z0-9_-]{1,40}");
    private static final Pattern COUNTRY = Pattern.compile("[A-Za-z]{2}");
    private static final Pattern LOG_ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    /** Come UpdateManager.isValidName: il primo carattere lettera o cifra, o il nome diventerebbe un'opzione di pkg. */
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");
    /**
     * Le impronte che il pannello stesso calcola e la pagina gli rimanda: lo stato del ramo dei pacchetti (16 cifre
     * esadecimali, PkgBranch) e quello di un indirizzo prima di trasformarlo in casella (64, AddressTransform). Lo
     * stesso nome, «fingerprint», lo usa l'impronta di una chiave SSH (SHA256:...): con quella forma sola il cambio di
     * ramo e «Trasforma in casella» venivano rifiutati con «la richiesta non ha la forma che il pannello si aspetta»
     * (reperto 204, sul server vero il 09/11/2026). Solo cifre esadecimali minuscole: niente spazi, niente trattini.
     */
    private static final Pattern PANEL_FINGERPRINT = Pattern.compile("[0-9a-f]{16}|[0-9a-f]{64}");
    private static final Pattern PEM_LINE = Pattern.compile("[A-Za-z0-9+/=]{0,128}");
    private static final Pattern PEM_MARKER = Pattern.compile(
            "-----(BEGIN|END) (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----");

    static boolean hostname(String s) { return s.isEmpty() || InputValidator.isValidHostname(s); }

    static boolean ipOrNet(String s) {
        if (s.isEmpty()) return true;
        int slash = s.indexOf('/');
        if (slash < 0) return InputValidator.isValidIp(s);
        String prefix = s.substring(slash + 1);
        return InputValidator.isValidIp(s.substring(0, slash)) && prefix.matches("[0-9]{1,3}") && Integer.parseInt(prefix) <= 128;
    }

    static boolean port(String s) {
        if (s.isEmpty()) return true;
        if (!s.matches("[0-9]{1,5}")) return false;
        int p = Integer.parseInt(s);
        return p >= 1 && p <= 65535;
    }

    /**
     * Blocchi PEM di certificati o chiavi private: dentro un blocco solo righe base64, e il blocco si chiude.
     * Fuori dai blocchi si accetta il testo che lasciano gli esportatori (openssl pkcs12 scrive «Bag
     * Attributes»): OpenSSL lo salta, e i caratteri di controllo li ha gia' esclusi il controllo generale.
     */
    static boolean pem(String s) {
        if (s.isEmpty()) return true;
        boolean inside = false, any = false;
        for (String line : s.split("\\r?\\n")) {
            String l = line.trim();
            java.util.regex.Matcher m = PEM_MARKER.matcher(l);
            if (m.matches()) {
                boolean begin = m.group(1).equals("BEGIN");
                if (begin == inside) return false;
                inside = begin;
                any |= begin;
            } else if (inside && !PEM_LINE.matcher(l).matches()) {
                return false;
            }
        }
        return any && !inside;
    }

    /** I parametri con una forma stretta, per nome, in qualunque rotta della root. */
    static final Map<String, Predicate<String>> STRICT = Map.ofEntries(
            Map.entry("domain", RootGate::hostname), Map.entry("new_domain", RootGate::hostname),
            Map.entry("hostname", RootGate::hostname), Map.entry("mail_hostname", RootGate::hostname),
            Map.entry("ip", RootGate::ipOrNet), Map.entry("cidr", RootGate::ipOrNet),
            Map.entry("jail", s -> s.isEmpty() || InputValidator.isValidJailName(s)),
            Map.entry("selector", s -> s.isEmpty() || InputValidator.isValidDkimSelector(s)),
            Map.entry("port", RootGate::port),
            Map.entry("package", s -> s.isEmpty() || PACKAGE.matcher(s).matches()),
            Map.entry("service", s -> s.isEmpty() || SERVICE.matcher(s).matches()),
            Map.entry("country", s -> s.isEmpty() || COUNTRY.matcher(s).matches()),
            Map.entry("log", s -> s.isEmpty() || LOG_ID.matcher(s).matches()),
            Map.entry("log_id", s -> s.isEmpty() || LOG_ID.matcher(s).matches()),
            Map.entry("fingerprint", s -> s.isEmpty() || org.daemoxcp.mail.system.RootSshKeys.FINGERPRINT.matcher(s).matches()
                    || PANEL_FINGERPRINT.matcher(s).matches()),
            Map.entry("certificate", RootGate::pem), Map.entry("private_key", RootGate::pem),
            Map.entry("ssl_cert", RootGate::pem), Map.entry("ssl_key", RootGate::pem), Map.entry("ssl_chain", RootGate::pem));

    /**
     * Null se la richiesta puo' passare; altrimenti il motivo, da scrivere nel registro (mai il valore).
     */
    static String check(RootChannel.Request r) {
        Set<String> methods = METHODS.get(r.route());
        if (methods == null) return "route " + r.route() + " is not in the root's list";
        if (!methods.contains(r.method())) return "method " + r.method() + " not used by " + r.route();
        if (r.query() != null && !r.query().isEmpty()) {
            for (String pair : r.query().split("&")) {
                int eq = pair.indexOf('=');
                String k, v;
                try {
                    k = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                    v = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                } catch (IllegalArgumentException e) {
                    return "query not well encoded";
                }
                String why = value(k, v);
                if (why != null) return "query " + why;
            }
        }
        if (r.body().length > 0) {
            String text = new String(r.body(), StandardCharsets.UTF_8);
            String t = text.trim();
            if (t.isEmpty()) return null;
            // Le pagine mandano JSON; un corpo che non lo e' (un modulo) si guarda solo nella forma.
            if (!t.startsWith("{")) return CONTROL.matcher(text).find() || text.length() > RootChannel.MAX_BODY ? "body with control characters" : null;
            try {
                String why = object(new JSONObject(t), 0);
                if (why != null) return "body " + why;
            } catch (org.json.JSONException e) {
                return "body is not valid JSON";
            }
        }
        return null;
    }

    private static String object(JSONObject o, int depth) {
        if (depth > MAX_DEPTH) return "too deep";
        if (o.length() > MAX_ITEMS) return "too many fields";
        for (String k : o.keySet()) {
            Object v = o.opt(k);
            String why = any(k, v, depth);
            if (why != null) return why;
        }
        return null;
    }

    private static String any(String key, Object v, int depth) {
        if (v instanceof JSONObject jo) {
            if (!KEY.matcher(key).matches()) return "a field name that is not one";
            return object(jo, depth + 1);
        }
        if (v instanceof JSONArray ja) {
            if (!KEY.matcher(key).matches()) return "a field name that is not one";
            if (ja.length() > MAX_ITEMS) return "field " + key + " has too many items";
            for (int i = 0; i < ja.length(); i++) {
                String why = any(key, ja.opt(i), depth + 1);
                if (why != null) return why;
            }
            return null;
        }
        if (v == null || v == JSONObject.NULL || v instanceof Boolean || v instanceof Number)
            return KEY.matcher(key).matches() ? null : "a field name that is not one";
        return value(key, String.valueOf(v));
    }

    /** Un valore con la sua chiave: la forma generale, poi quella stretta se la chiave ne ha una. */
    static String value(String key, String v) {
        if (!KEY.matcher(key).matches()) return "a field name that is not one";
        if (v.length() > MAX_STRING) return "field " + key + " too long";
        if (CONTROL.matcher(v).find()) return "field " + key + " has control characters";
        Predicate<String> strict = STRICT.get(key);
        if (strict != null && !strict.test(v.trim())) return "field " + key + " does not have its shape";
        return null;
    }
}
