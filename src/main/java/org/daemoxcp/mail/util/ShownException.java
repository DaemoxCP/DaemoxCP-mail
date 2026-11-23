package org.daemoxcp.mail.util;

import org.daemoxcp.mail.i18n.I18n;

import java.util.Map;

/**
 * An error written for whoever uses the page, already in their language: the only one, with PasskeyException,
 * whose text ErrorText lets through to a page. Any other exception, even an IllegalArgumentException or
 * IllegalStateException with a hand-written text, ends up in the panel log, and the page gets the translated
 * generic text: that way no English text written in the code, nor the toString() of a wrapped exception (paths,
 * classes), reaches whoever uses the panel (complete i18n, 2026-11-19).
 *
 * <p>It is built with the key of the text: of("server.x.y") or of("server.x.y", Map.of("name", ...)). The text is
 * translated right away, in the language of the current request (I18n.current), as whoever threw it with
 * I18n.tr used to do.
 */
public class ShownException extends IllegalStateException implements TranslatedError {

    /** A wrong argument, told to the page already translated: like ShownException, but an IllegalArgumentException. */
    public static final class Argument extends IllegalArgumentException implements TranslatedError {
        private Argument(String text) {
            super(text);
        }

        public static Argument of(String key) {
            return new Argument(I18n.tr(key));
        }

        public static Argument of(String key, Map<String, ?> params) {
            return new Argument(I18n.tr(key, params));
        }
    }

    private final String key;

    private ShownException(String key, String text) {
        super(text);
        this.key = key;
    }

    /** The text of the key, in the language of the current request. */
    public static ShownException of(String key) {
        return new ShownException(key, I18n.tr(key));
    }

    /** The text of the key with its {values}, in the language of the current request. */
    public static ShownException of(String key, Map<String, ?> params) {
        return new ShownException(key, I18n.tr(key, params));
    }

    /**
     * A text already translated elsewhere with I18n.tr (a field of a state built earlier, in the same language). Only
     * for that: a text written in the code is thrown with of(key).
     */
    public static ShownException translated(String text) {
        return new ShownException(null, text);
    }

    /** The key of the text, for the tests and for whoever must recognise the error; null for translated(). */
    public String key() {
        return key;
    }
}
