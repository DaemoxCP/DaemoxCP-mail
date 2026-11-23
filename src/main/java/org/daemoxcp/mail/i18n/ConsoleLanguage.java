package org.daemoxcp.mail.i18n;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The console language (the on-screen menu and the command-line commands, Main). The console runs as root and does
 * not know who is in front of the terminal: with several administrators the first one's language alone is not
 * enough (2026-11-19). It is chosen in this order:
 * <ol>
 *   <li>--lang xx, if the panel has that language;</li>
 *   <li>the terminal's language (LC_ALL, then LC_MESSAGES, then LANG, as in POSIX: it_IT.UTF-8 is Italian; C, POSIX
 *       and C.UTF-8 are not a language): everyone sets it once in their own profile;</li>
 *   <li>for a command that concerns an administrator (--access-code followed by a name), the language that
 *       administrator chose in the panel: the code is for them;</li>
 *   <li>the panel's language: that of the first active administrator who has chosen one;</li>
 *   <li>English.</li>
 * </ol>
 * Pure functions: Main reads the environment and the database and calls them.
 */
public final class ConsoleLanguage {

    private ConsoleLanguage() {}

    /**
     * The language of --lang in the arguments, or null; a value the panel does not have is reported to wrong and
     * does not count.
     */
    public static String fromFlag(String[] args, Collection<String> languages, Consumer<String> wrong) {
        String asked = null;
        for (int i = 0; i < args.length; i++) {
            if (!"--lang".equals(args[i])) continue;
            String v = i + 1 < args.length ? args[i + 1].trim().toLowerCase(Locale.ROOT) : "";
            if (languages.contains(v)) asked = v;
            else wrong.accept(v);
        }
        return asked;
    }

    /**
     * The terminal's language, or null. As in POSIX, the first non-empty variable among LC_ALL, LC_MESSAGES and LANG
     * counts, and only that one: LC_ALL=C with LANG=it_IT.UTF-8 is the C language, that is, none. What counts in the
     * variable is the language before _ . @ (it_IT.UTF-8, it.UTF-8, it@euro), if the panel has it.
     */
    public static String fromTerminal(Map<String, String> env, Collection<String> languages) {
        for (String name : List.of("LC_ALL", "LC_MESSAGES", "LANG")) {
            String v = env.get(name);
            if (v == null || v.isBlank()) continue;
            String lang = v.trim().split("[_.@]", 2)[0].toLowerCase(Locale.ROOT);
            return languages.contains(lang) ? lang : null;
        }
        return null;
    }

    /** The language to use: the first one present in the order described above, English if none. */
    public static String choose(String flag, String terminal, String commandAdmin, String panel) {
        for (String lang : new String[] {flag, terminal, commandAdmin, panel}) if (lang != null && !lang.isBlank()) return lang;
        return "en";
    }

    /** The arguments without --lang and its value: this way --access-code --lang en does not take "--lang" for a name. */
    public static String[] withoutFlag(String[] args) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--lang".equals(args[i])) { i++; continue; }
            out.add(args[i]);
        }
        return out.toArray(new String[0]);
    }
}
