package org.daemoxcp.mail.security;

import java.util.regex.Pattern;

/**
 * Centralized validators for user input that ends up in:
 *  - shell commands (Fail2banManager, AcmeManager, scripts)
 *  - file paths (Paths.get with a concatenated hostname)
 *  - SQL identifiers (DROP TABLE table_name)
 *
 * All methods are defensive: they return true ONLY if the input follows
 * a conservative pattern that certainly cannot contain characters dangerous
 * for shell, path or SQL identifier (`;`, `|`, `&`, backtick, `$`, `..`, ` `, etc.).
 *
 * If a legitimate input is rejected, widen the pattern conservatively,
 * do NOT remove the validation.
 */
public final class InputValidator {
    private InputValidator() {}

    // Hostname: letters, digits, dot, hyphen. RFC 1035 + tolerance for already normalized IDNs.
    // At most 253 chars in total (DNS limit). No shell special characters.
    private static final Pattern HOSTNAME = Pattern.compile(
        "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
        Pattern.CASE_INSENSITIVE
    );

    // Domain: similar to hostname but must have at least 1 dot (TLD required).
    private static final Pattern DOMAIN = Pattern.compile(
        "^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
        Pattern.CASE_INSENSITIVE
    );

    // Strict IPv4.
    private static final Pattern IPV4 = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    // IPv6 -- simplified but safe pattern (only hex digits, : and ::).
    private static final Pattern IPV6 = Pattern.compile(
        "^[0-9a-fA-F:]+$"
    );

    // Jail name (Fail2ban): only letters, digits, underscore, dash. Max 64 chars.
    private static final Pattern JAIL_NAME = Pattern.compile("^[a-zA-Z0-9_-]{1,64}$");

    // Email: conservative pattern, not RFC-complete but safe for shell and path.
    private static final Pattern EMAIL = Pattern.compile(
        "^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    );

    // SQL identifier (table/column): only letters, digits, underscore.
    private static final Pattern SQL_IDENT = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]{0,63}$");

    // DKIM selector: letters, digits, dash, underscore. Max 63.
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
     * Sanitizes for shell: lets it through ONLY if it is a valid hostname/domain,
     * otherwise throws IllegalArgumentException.
     * To be used as a gate before putting a string in a shell command.
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
