package org.mail_panel.webserver;

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

    // Password: letters, numbers, and safe special chars (4-128 chars)
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^[a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{}|;:,.?]{4,128}$");

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
        if (expected == null || actual == null) return false;
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
