package org.daemoxcp.mail.util;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PasskeyService;

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The text of an exception that can reach a page (finding 231, r19: only generic messages to the user, never the
 * name of a table, column, path or version).
 *
 * <p>The routes put into the response the {@code e.getMessage()} of any exception: a duplicate in MySQL told the
 * page "Duplicate entry 'x' for key 'mailboxes.email'", a missing file its path, a malformed JSON the name of the
 * key. Here a single place decides what gets through:
 * <ul>
 *   <li>the text of ShownException, already translated: it is the one the panel throws with a text written for
 *       whoever uses the page (AddressTransform, the updates). For PasskeyException, the text of the key it carries.
 *       Until 2026-11-19 the message of every IllegalArgumentException and IllegalStateException got through: many
 *       had an English text written in the code, or the toString() of a wrapped exception (class, path), and so
 *       they reached the Italian pages too (complete i18n);</li>
 *   <li>a MySQL duplicate (error 1062, even inside another exception): "already exists", without the key;</li>
 *   <li>any other: a line in the panel log with the whole exception, and the generic text for the page.</li>
 * </ul>
 */
public final class ErrorText {

    private static final Logger LOGGER = Logger.getLogger(ErrorText.class.getName());

    /** The MySQL error for a value already present in a UNIQUE column. */
    static final int MYSQL_DUPLICATE = 1062;

    private ErrorText() {}

    /**
     * The text the panel wrote for the page, null if the exception carries none. PasskeyException carries the
     * key of the text, not the text: it gets translated.
     */
    static String shown(Throwable e) {
        if (e == null || e.getMessage() == null || e.getMessage().isBlank()) return null;
        if (e instanceof PasskeyService.PasskeyException) return I18n.tr(e.getMessage());
        return e instanceof TranslatedError ? e.getMessage() : null;
    }

    /** True if among the causes there is a MySQL duplicate. */
    static boolean duplicate(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SQLException s && s.getErrorCode() == MYSQL_DUPLICATE) return true;
            if (t.getCause() == t) break;
        }
        return false;
    }

    /**
     * The error field of a response: the message if it is the panel's, "already exists" for a duplicate, otherwise
     * a line in the log and "Request failed: the details are in the panel log".
     *
     * @param caller the method that responds, to find the line in the log again
     */
    public static String forPage(String caller, Throwable e) {
        String text = shown(e);
        if (text != null) return text;
        if (duplicate(e)) return I18n.tr("server.alreadyExists");
        log(caller, e);
        return I18n.tr("server.requestFailed");
    }

    /**
     * The piece to put in the {error} slot of a text that frames it ("Conversion failed: {error}"): the
     * message if it is the panel's, otherwise a line in the log and "the details are in the panel log".
     */
    public static String detail(String caller, Throwable e) {
        String text = shown(e);
        if (text != null) return text;
        if (duplicate(e)) return I18n.tr("server.alreadyExists");
        log(caller, e);
        return I18n.tr("server.detailsInLog");
    }

    private static void log(String caller, Throwable e) {
        LOGGER.log(Level.WARNING, "[" + caller + "] request failed: " + (e == null ? "no exception" : e.getClass().getName()), e);
    }
}
