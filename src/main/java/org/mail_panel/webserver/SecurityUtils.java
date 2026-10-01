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

    // Password: lettere senza accenti, cifre e i simboli qui sotto, da 4 a 128 caratteri.
    //
    // E' l'unica fonte della regola: la usano isValidPassword, il generatore (PasswordVault, per i
    // simboli di "Tutti i caratteri") e la pagina delle caselle, che avvisa mentre si scrive o si
    // incolla. Prima il generatore aveva simboli suoi, e produceva password che qui non passavano.
    /** I simboli ammessi in una password di casella, oltre a lettere (senza accenti) e cifre. */
    public static final String PASSWORD_SIMBOLI = "!@#$%^&*()_+-=[]{}|;:,.?";
    /** La stessa regola come classe di caratteri, valida sia in Java sia in JavaScript. */
    public static final String PASSWORD_CARATTERI = classeDiCaratteri(PASSWORD_SIMBOLI);
    public static final int PASSWORD_MIN = 4, PASSWORD_MAX = 128;
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^" + PASSWORD_CARATTERI + "{" + PASSWORD_MIN + "," + PASSWORD_MAX + "}$");

    // Le password delle CASELLE: stessi caratteri, ma almeno 12 (dal 01/10/2026; prima 4, come
    // quelle dell'admin). isValidPassword resta com'era perche' la usa anche il login dell'admin:
    // alzarla avrebbe chiuso fuori chi ha una password piu' corta. Le caselle esistenti non sono
    // toccate: la regola vale quando una password si crea o si cambia.
    public static final int PASSWORD_CASELLA_MIN = 12;
    private static final Pattern PASSWORD_CASELLA_PATTERN =
            Pattern.compile("^" + PASSWORD_CARATTERI + "{" + PASSWORD_CASELLA_MIN + "," + PASSWORD_MAX + "}$");

    /** Una password di casella: 12..128 caratteri tra lettere senza accenti, cifre e PASSWORD_SIMBOLI. */
    public static boolean isValidMailboxPassword(String password) {
        return password != null && PASSWORD_CASELLA_PATTERN.matcher(password).matches();
    }

    /** Il perche' del rifiuto, per chi crea o modifica una casella. */
    public static final String PASSWORD_CASELLA_REGOLA = "servono da " + PASSWORD_CASELLA_MIN + " a " + PASSWORD_MAX
            + " caratteri tra lettere senza accenti, cifre e " + String.join(" ", PASSWORD_SIMBOLI.split(""));

    /** [a-zA-Z0-9 + simboli], con i soli caratteri che dentro una classe vanno protetti: \ [ ] ^ - */
    private static String classeDiCaratteri(String simboli) {
        StringBuilder sb = new StringBuilder("[a-zA-Z0-9");
        for (char c : simboli.toCharArray()) {
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
        // SECURITY: rifiuta esplicitamente i token vuoti — altrimenti due stringhe
        // vuote passerebbero il check (length matches, result = 0).
        if (expected == null || actual == null) return false;
        if (expected.isEmpty() || actual.isEmpty()) return false;
        if (expected.length() < 16) return false; // un CSRF reale è > 16 char
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
