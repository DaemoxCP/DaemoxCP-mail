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
 * The closed list of what the root part accepts from the web part, before any
 * handler:
 * <ul>
 *   <li>for every route that stays with the root part, the methods its handler uses ({@link #METHODS}); a route
 *       that is not here is rejected by the root part;</li>
 *   <li>the shape of every value of the query and of the JSON body: keys made of letters, digits and underscore,
 *       no control characters (except newline and tab), maximum lengths and depths;</li>
 *   <li>for the parameters that the handlers put into a command, a path or a configuration file of the root
 *       part, their strict shape ({@link #STRICT}): host names, IPs and networks, jails, ports, DKIM selectors,
 *       packages, services, countries, logs, certificates and PEM keys. A host name that starts with a hyphen,
 *       for example, would become an option of the command it is passed to (dig -f reads a file).</li>
 * </ul>
 * The handlers already check many of these values where they use them; here they are all checked, once, for
 * whoever writes on the socket. Actions are not on the list: an action the handler does not know is rejected
 * by the handler itself, without touching anything.
 */
final class RootGate {

    private RootGate() {}

    static final Set<String> GET = Set.of("GET");
    static final Set<String> POST = Set.of("POST");
    static final Set<String> GET_POST = Set.of("GET", "POST");

    /**
     * The root part's routes and the methods of their handlers (read from the handlers' code). /api/login
     * without a session.
     */
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
            // Login and the Account tab: administrators, passkeys, codes and sessions are decided by the root part
            // (0.8.2, A).
            Map.entry("/api/login", POST), Map.entry("/api/account", GET_POST),
            // POP3 on or off ("Settings").
            Map.entry("/api/pop3", GET_POST),
            Map.entry("/api/ip-family", GET_POST),
            // The server's IPv4 and IPv6 addresses and their guide (ServerAddresses): ifconfig, route, rc.conf,
            // root only.
            Map.entry("/api/server-addresses", GET_POST),
            // Root's SSH keys (Settings).
            Map.entry("/api/ssh-keys", GET_POST),
            // "Show password": the copy from the vault is read only by the root part (0.8, point 3).
            Map.entry("/api/mailbox-password", POST),
            // The Apple profile to download: the root part signs it with the mail certificate's key (2026-11-23).
            Map.entry("/apple-profile", GET),
            // The webmail: password change and vault copy, without a session (the web part has checked the caller).
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
    /** Like UpdateManager.isValidName: the first character a letter or digit, or the name would become a pkg option. */
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");
    /**
     * The fingerprints that the panel itself computes and the page sends back to it: the state of the package branch
     * (16 hex digits, PkgBranch) and that of an address before turning it into a mailbox (64, AddressTransform). The
     * same name, "fingerprint", is used by the fingerprint of an SSH key (SHA256:...): with that shape alone the
     * branch change and "Turn into a mailbox" were refused with "the request does not have the shape the panel
     * expects" (finding 204, on the production server on 2026-11-09). Only lowercase hex digits: no spaces, no
     * hyphens.
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
     * PEM blocks of certificates or private keys: inside a block only base64 lines, and the block is closed.
     * Outside the blocks the text that exporters leave is accepted (openssl pkcs12 writes "Bag
     * Attributes"): OpenSSL skips it, and control characters have already been excluded by the general check.
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

    /** The parameters with a strict shape, by name, in any route of the root part. */
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
     * Null if the request can pass; otherwise the reason, to be written to the log (never the value).
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
            // The pages send JSON; a body that is not JSON (a form) is checked only for its shape.
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

    /** A value with its key: the general shape, then the strict one if the key has one. */
    static String value(String key, String v) {
        if (!KEY.matcher(key).matches()) return "a field name that is not one";
        if (v.length() > MAX_STRING) return "field " + key + " too long";
        if (CONTROL.matcher(v).find()) return "field " + key + " has control characters";
        Predicate<String> strict = STRICT.get(key);
        if (strict != null && !strict.test(v.trim())) return "field " + key + " does not have its shape";
        return null;
    }
}
