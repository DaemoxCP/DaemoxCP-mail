package org.mail_panel.security;

import java.util.regex.Pattern;

/**
 * Validatori centralizzati per input utente che finiscono in:
 *  - shell commands (Fail2banManager, AcmeManager, scripts)
 *  - file paths (Paths.get con hostname concatenato)
 *  - SQL identifier (DROP TABLE table_name)
 *
 * Tutti i metodi sono difensivi: ritornano true SOLO se l'input rispetta
 * un pattern conservativo che è certo non possa contenere caratteri pericolosi
 * per shell, path o SQL identifier (`;`, `|`, `&`, backtick, `$`, `..`, ` `, etc.).
 *
 * Se un input legittimo viene rifiutato, allarga il pattern in modo conservativo,
 * NON rimuovere la validazione.
 */
public final class InputValidator {
    private InputValidator() {}

    // Hostname: lettere, numeri, dot, hyphen. RFC 1035 + tolleranza per IDN già normalizzati.
    // Massimo 253 char totali (limite DNS). Niente caratteri speciali shell.
    private static final Pattern HOSTNAME = Pattern.compile(
        "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
        Pattern.CASE_INSENSITIVE
    );

    // Domain: simile a hostname ma deve avere almeno 1 dot (TLD richiesto).
    private static final Pattern DOMAIN = Pattern.compile(
        "^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
        Pattern.CASE_INSENSITIVE
    );

    // IPv4 stretto.
    private static final Pattern IPV4 = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    // IPv6 — pattern semplificato ma sicuro (solo cifre hex, : e ::).
    private static final Pattern IPV6 = Pattern.compile(
        "^[0-9a-fA-F:]+$"
    );

    // Jail name (Fail2ban): solo lettere, numeri, underscore, dash. Max 64 char.
    private static final Pattern JAIL_NAME = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    // Email: pattern conservativo, non RFC-completo ma sicuro per shell e path.
    private static final Pattern EMAIL = Pattern.compile(
        "^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    // Identificatore SQL (table/column): solo lettere, numeri, underscore.
    private static final Pattern SQL_IDENT = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$");

    // Selector DKIM: lettere, numeri, dash, underscore. Max 63.
    private static final Pattern DKIM_SELECTOR = Pattern.compile("^[a-zA-Z0-9_-]{1,63}$");

    public static boolean isValidHostname(String s) {
        return s != null && !s.isEmpty() && HOSTNAME.matcher(s).matches() && !s.contains("..");
    }

    public static boolean isValidDomain(String s) {
        return s != null && !s.isEmpty() && DOMAIN.matcher(s).matches() && !s.contains("..");
    }

    public static boolean isValidIp(String s) {
        if (s == null || s.isEmpty()) return false;
        return IPV4.matcher(s).matches() || IPV6.matcher(s).matches();
    }

    public static boolean isValidJailName(String s) {
        return s != null && JAIL_NAME.matcher(s).matches();
    }

    public static boolean isValidEmail(String s) {
        return s != null && s.length() <= 254 && EMAIL.matcher(s).matches();
    }

    public static boolean isValidSqlIdentifier(String s) {
        return s != null && SQL_IDENT.matcher(s).matches();
    }

    public static boolean isValidDkimSelector(String s) {
        return s != null && DKIM_SELECTOR.matcher(s).matches();
    }

    /**
     * Sanitizza per shell: lascia passare SOLO se è un hostname/dominio valido,
     * altrimenti lancia IllegalArgumentException.
     * Da usare come gate prima di mettere una stringa in un comando shell.
     */
    public static String requireHostname(String s) {
        if (!isValidHostname(s)) throw new IllegalArgumentException("Invalid hostname: " + s);
        return s;
    }

    public static String requireIp(String s) {
        if (!isValidIp(s)) throw new IllegalArgumentException("Invalid IP: " + s);
        return s;
    }

    public static String requireJailName(String s) {
        if (!isValidJailName(s)) throw new IllegalArgumentException("Invalid jail name: " + s);
        return s;
    }

    public static String requireSqlIdentifier(String s) {
        if (!isValidSqlIdentifier(s)) throw new IllegalArgumentException("Invalid SQL identifier: " + s);
        return s;
    }
}
