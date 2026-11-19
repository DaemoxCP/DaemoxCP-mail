package org.daemoxcp.mail.i18n;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The console's language (ConsoleLanguage): with several administrators the console cannot know who is at the
 * terminal, so it takes, in this order, --lang, the terminal's language, the language of the administrator a command is
 * for (--access-code name), the panel's language, English.
 *
 *  1. --lang: a language the panel has; a wrong value is reported and does not count.
 *  2. The terminal: the first non-empty of LC_ALL, LC_MESSAGES, LANG (POSIX), and only that one; it_IT.UTF-8, it.UTF-8
 *     and it@euro are Italian; C, POSIX and C.UTF-8 (the FreeBSD default, on the VM and on the real server) are no
 *     language; a language the panel does not have is none.
 *  3. The order of the five sources.
 *  4. --lang and its value leave the arguments, so a command reading its arguments by position does not take «--lang»
 *     for a name.
 *
 * Usage (from the project root):
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.i18n.ConsoleLanguageTest
 */
public class ConsoleLanguageTest {

    static int failed = 0;
    static final List<String> LANGS = List.of("it", "en");

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Map<String, String> env(String... pairs) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) m.put(pairs[i], pairs[i + 1]);
        return m;
    }

    static String terminal(String... pairs) {
        return ConsoleLanguage.fromTerminal(env(pairs), LANGS);
    }

    public static void main(String[] a) {
        System.out.println("== 1. --lang ==");
        List<String> wrong = new ArrayList<>();
        check("--lang it: Italian", "it".equals(ConsoleLanguage.fromFlag(new String[] {"--lang", "it", "--access-code"}, LANGS, wrong::add)));
        check("--lang EN, after the command: English", "en".equals(ConsoleLanguage.fromFlag(new String[] {"--access-code", "--lang", "EN"}, LANGS, wrong::add)));
        check("  nothing reported", wrong.isEmpty());
        check("--lang de (not a panel language): none, and reported", ConsoleLanguage.fromFlag(new String[] {"--lang", "de"}, LANGS, wrong::add) == null
                && wrong.equals(List.of("de")));
        check("--lang without a value: none, and reported", ConsoleLanguage.fromFlag(new String[] {"--lang"}, LANGS, wrong::add) == null && wrong.size() == 2);
        check("no --lang: none", ConsoleLanguage.fromFlag(new String[] {"--access-code", "mario"}, LANGS, wrong::add) == null);

        System.out.println("\n== 2. The terminal ==");
        check("LANG=it_IT.UTF-8: Italian", "it".equals(terminal("LANG", "it_IT.UTF-8")));
        check("LANG=en_US.UTF-8: English", "en".equals(terminal("LANG", "en_US.UTF-8")));
        check("LANG=it.UTF-8 and LANG=it@euro: Italian", "it".equals(terminal("LANG", "it.UTF-8")) && "it".equals(terminal("LANG", "it@euro")));
        check("LANG=C.UTF-8 (FreeBSD's default), C, POSIX: no language", terminal("LANG", "C.UTF-8") == null
                && terminal("LANG", "C") == null && terminal("LANG", "POSIX") == null);
        check("LANG=de_DE.UTF-8 (not a panel language): none", terminal("LANG", "de_DE.UTF-8") == null);
        check("nothing set, or only blanks: none", terminal() == null && terminal("LANG", "  ", "LC_ALL", "") == null);
        check("LC_MESSAGES=en_GB over LANG=it_IT: English", "en".equals(terminal("LANG", "it_IT.UTF-8", "LC_MESSAGES", "en_GB.UTF-8")));
        check("LC_ALL=it_IT over LC_MESSAGES=en_GB: Italian", "it".equals(terminal("LC_ALL", "it_IT.UTF-8", "LC_MESSAGES", "en_GB.UTF-8")));
        check("LC_ALL=C with LANG=it_IT: the C locale, so none (POSIX: only the first one counts)",
                terminal("LC_ALL", "C", "LANG", "it_IT.UTF-8") == null);
        check("an empty LC_ALL does not count: LANG=it_IT is Italian", "it".equals(terminal("LC_ALL", "", "LANG", "it_IT.UTF-8")));

        System.out.println("\n== 3. The order ==");
        check("--lang first", "en".equals(ConsoleLanguage.choose("en", "it", "it", "it")));
        check("then the terminal", "en".equals(ConsoleLanguage.choose(null, "en", "it", "it")));
        check("then the administrator the command is for", "en".equals(ConsoleLanguage.choose(null, null, "en", "it")));
        check("then the panel's language", "it".equals(ConsoleLanguage.choose(null, null, null, "it")));
        check("then English", "en".equals(ConsoleLanguage.choose(null, null, null, null)) && "en".equals(ConsoleLanguage.choose("", " ", null, "")));

        System.out.println("\n== 4. --lang leaves the arguments ==");
        check("--access-code --lang en mario: --access-code mario",
                Arrays.equals(ConsoleLanguage.withoutFlag(new String[] {"--access-code", "--lang", "en", "mario"}), new String[] {"--access-code", "mario"}));
        check("--lang it first: the command stays", Arrays.equals(ConsoleLanguage.withoutFlag(new String[] {"--lang", "it", "--ip-family", "both"}),
                new String[] {"--ip-family", "both"}));
        check("--lang at the end without a value: gone", Arrays.equals(ConsoleLanguage.withoutFlag(new String[] {"--addresses", "show", "--lang"}),
                new String[] {"--addresses", "show"}));
        check("no --lang: the same", Arrays.equals(ConsoleLanguage.withoutFlag(new String[] {"--create-admin", "a", "b@c.d"}),
                new String[] {"--create-admin", "a", "b@c.d"}));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
