package org.daemoxcp.mail.security;

import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * The names the root part reads from MySQL before putting them into a command, a path or a configuration
 * file.
 *
 * <p>With the separated panel MySQL is also written by the web part, which has the panel's MySQL user. What
 * the root part reads from it is therefore no longer its own data: whoever broke into the web part could write a domain
 * like {@code x; command} and wait for root to put it into a shell script (ConfigRegeneratorScript
 * did that), or a mailbox like {@code ..} and make it write a file outside its folder
 * (SieveGenerator did that). The panel checks these names when it receives them from a page, but the root part
 * must not rely on whoever wrote them: it checks them again here, at the point where it uses them, and a name that does not
 * pass is not used.
 *
 * <p>The forms are strict on purpose: letters, digits and a few signs, never a slash, never a character that the
 * shell or a configuration file reads in a special way.
 */
public final class SafeNames {

    private SafeNames() {}

    /** A domain: labels of letters, digits and hyphens, separated by dots (RFC 1035 and RFC 5890 for xn--). */
    private static final Pattern DOMAIN = Pattern.compile(
            "(?=.{3,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
    /**
     * The part before the @ of a mailbox: the characters SecurityUtils accepts for an address, without a
     * leading dot and without two dots in a row, so it is never {@code .} or {@code ..} in a path.
     */
    private static final Pattern LOCAL_PART = Pattern.compile("[A-Za-z0-9_%+-](?:[A-Za-z0-9._%+-]{0,63})");
    /** A DKIM selector like those the panel generates (mail, r20261107, r20261107-2). */
    private static final Pattern SELECTOR = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})");

    public static boolean domain(String s) {
        return s != null && DOMAIN.matcher(s).matches();
    }

    public static boolean localPart(String s) {
        return s != null && LOCAL_PART.matcher(s).matches() && !s.contains("..") && !s.endsWith(".");
    }

    /** A complete address: a valid local part, a single @, a valid domain. */
    public static boolean address(String s) {
        if (s == null) return false;
        int at = s.indexOf('@');
        return at > 0 && at == s.lastIndexOf('@') && localPart(s.substring(0, at)) && domain(s.substring(at + 1));
    }

    public static boolean selector(String s) {
        return s != null && SELECTOR.matcher(s).matches();
    }

    /**
     * A path inside a folder: the pieces are appended to the base and the result, normalised, must
     * stay under the base. A piece with a slash, {@code ..} or empty does not even get this far.
     *
     * @throws IllegalArgumentException if the path would leave the base
     */
    public static Path under(Path base, String... parts) {
        Path b = base.normalize();
        Path p = b;
        for (String part : parts) {
            if (part == null || part.isEmpty() || part.contains("/") || part.equals(".") || part.equals(".."))
                throw new IllegalArgumentException("invalid path piece");
            p = p.resolve(part);
        }
        p = p.normalize();
        if (!p.startsWith(b) || p.equals(b)) throw new IllegalArgumentException("path outside " + b);
        return p;
    }
}
