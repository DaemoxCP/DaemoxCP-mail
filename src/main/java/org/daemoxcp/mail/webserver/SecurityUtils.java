package org.daemoxcp.mail.webserver;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Security utilities for input validation, sanitization and CSRF protection.
 */
public class SecurityUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    // Username: letters, numbers, underscore, hyphen (3-50 chars)
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,50}$");

    // Password: letters without accents, digits and the symbols below, from 4 to 128 characters.
    //
    // It is the single source of the rule: isValidPassword uses it, and so do the generator (PasswordVault, for the
    // symbols of "All characters") and the mailbox page, which warns while one types or
    // pastes. Before, the generator had symbols of its own, and produced passwords that did not pass here.
    /** The symbols allowed in a mailbox password, besides letters (without accents) and digits. */
    public static final String PASSWORD_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.?";
    /** The same rule as a character class, valid both in Java and in JavaScript. */
    public static final String PASSWORD_CHARACTERS = characterClass(PASSWORD_SYMBOLS);
    public static final int PASSWORD_MIN = 4, PASSWORD_MAX = 128;
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^" + PASSWORD_CHARACTERS + "{" + PASSWORD_MIN + "," + PASSWORD_MAX + "}$");

    // MAILBOX passwords: the same characters, but at least 12 (since 2026-10-01; before, 4, like
    // the admin's). isValidPassword stays as it was because the admin login uses it too:
    // raising it would have locked out whoever has a shorter password. Existing mailboxes are not
    // touched: the rule applies when a password is created or changed.
    public static final int MAILBOX_PASSWORD_MIN = 12;
    private static final Pattern MAILBOX_PASSWORD_PATTERN =
            Pattern.compile("^" + PASSWORD_CHARACTERS + "{" + MAILBOX_PASSWORD_MIN + "," + PASSWORD_MAX + "}$");

    /** A mailbox password: 12..128 characters among letters without accents, digits and PASSWORD_SYMBOLS. */
    public static boolean isValidMailboxPassword(String password) {
        return password != null && MAILBOX_PASSWORD_PATTERN.matcher(password).matches();
    }

    /** The reason for the rejection, for whoever creates or edits a mailbox. */
    public static String passwordRule() {
        return org.daemoxcp.mail.i18n.I18n.tr("server.mailbox.passwordRule", java.util.Map.of("min", MAILBOX_PASSWORD_MIN, "max", PASSWORD_MAX,
                "symbols", String.join(" ", PASSWORD_SYMBOLS.split(""))));
    }

    /** [a-zA-Z0-9 + symbols], escaping only the characters that need it inside a class: \ [ ] ^ - */
    private static String characterClass(String symbols) {
        StringBuilder sb = new StringBuilder("[a-zA-Z0-9");
        for (char c : symbols.toCharArray()) {
            if ("\\[]^-".indexOf(c) >= 0) sb.append('\\');
            sb.append(c);
        }
        return sb.append(']').toString();
    }

    // Domain: valid domain name format
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}[a-zA-Z0-9]$");

    // Email pattern
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");

    // Generic alphanumeric
    private static final Pattern ALPHANUMERIC_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$");

    /**
     * Generates a cryptographically secure CSRF token.
     */
    public static String generateCsrfToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Validates CSRF token using constant-time comparison.
     */
    public static boolean validateCsrfToken(String expected, String actual) {
        // SECURITY: explicitly rejects empty tokens: otherwise two empty
        // strings would pass the check (length matches, result = 0).
        if (expected == null || actual == null) return false;
        if (expected.isEmpty() || actual.isEmpty()) return false;
        if (expected.length() < 16) return false; // a real CSRF token is > 16 chars
        if (expected.length() != actual.length()) return false;
        int result = 0;
        for (int i = 0; i < expected.length(); i++) {
            result |= expected.charAt(i) ^ actual.charAt(i);
        }
        return result == 0;
    }

    public static boolean isValidUsername(String username) {
        if (username == null) return false;
        return USERNAME_PATTERN.matcher(username).matches();
    }

    public static boolean isValidPassword(String password) {
        if (password == null) return false;
        return PASSWORD_PATTERN.matcher(password).matches();
    }

    public static boolean isValidDomain(String domain) {
        if (domain == null) return false;
        return DOMAIN_PATTERN.matcher(domain).matches();
    }

    public static boolean isValidEmail(String email) {
        if (email == null) return false;
        return EMAIL_PATTERN.matcher(email).matches();
    }

    public static boolean isAlphanumeric(String input) {
        if (input == null) return false;
        return ALPHANUMERIC_PATTERN.matcher(input).matches();
    }

    /**
     * Escapes HTML special characters to prevent XSS attacks.
     */
    public static String escapeHtml(String input) {
        if (input == null) return null;
        StringBuilder escaped = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '<': escaped.append("&lt;"); break;
                case '>': escaped.append("&gt;"); break;
                case '&': escaped.append("&amp;"); break;
                case '"': escaped.append("&quot;"); break;
                case '\'': escaped.append("&#x27;"); break;
                case '/': escaped.append("&#x2F;"); break;
                default: escaped.append(c);
            }
        }
        return escaped.toString();
    }

    /**
     * Escapes special characters for JSON string values.
     */
    public static String escapeJson(String input) {
        if (input == null) return null;
        StringBuilder escaped = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '"': escaped.append("\\\""); break;
                case '\\': escaped.append("\\\\"); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (c < ' ') escaped.append(String.format("\\u%04x", (int) c));
                    else escaped.append(c);
            }
        }
        return escaped.toString();
    }

    public static String sanitizeInput(String input) {
        if (input == null) return null;
        StringBuilder sanitized = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c <= 126) sanitized.append(c);
        }
        return sanitized.toString();
    }
}
