package org.daemoxcp.mail.i18n;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * La lingua della console (il menu a schermo e i comandi da riga di comando, Main). La console gira da root e non sa chi
 * c'e' davanti al terminale: con piu' amministratori la sola lingua del primo non basta (19/11/2026). Si sceglie, in
 * quest'ordine:
 * <ol>
 *   <li>--lang xx, se il pannello ha quella lingua;</li>
 *   <li>la lingua del terminale (LC_ALL, poi LC_MESSAGES, poi LANG, come POSIX: it_IT.UTF-8 e' l'italiano; C, POSIX e
 *       C.UTF-8 non sono una lingua): ognuno la mette una volta nel suo profilo;</li>
 *   <li>per un comando che riguarda un amministratore (--access-code nome), la lingua che quell'amministratore ha
 *       scelto nel pannello: il codice e' per lui;</li>
 *   <li>la lingua del pannello: quella del primo amministratore attivo che ne ha scelta una;</li>
 *   <li>l'inglese.</li>
 * </ol>
 * Funzioni pure: Main legge l'ambiente e il database e le chiama.
 */
public final class ConsoleLanguage {

    private ConsoleLanguage() {}

    /** La lingua di --lang negli argomenti, o null; un valore che il pannello non ha si dice a wrong e non vale. */
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
     * La lingua del terminale, o null. Come POSIX vale la prima variabile non vuota fra LC_ALL, LC_MESSAGES e LANG, e
     * solo quella: LC_ALL=C con LANG=it_IT.UTF-8 e' la lingua C, cioe' nessuna. Della variabile conta la lingua prima
     * di _ . @ (it_IT.UTF-8, it.UTF-8, it@euro), se il pannello la ha.
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

    /** La lingua da usare: la prima che c'e' nell'ordine detto sopra, l'inglese se nessuna. */
    public static String choose(String flag, String terminal, String commandAdmin, String panel) {
        for (String lang : new String[] {flag, terminal, commandAdmin, panel}) if (lang != null && !lang.isBlank()) return lang;
        return "en";
    }

    /** Gli argomenti senza --lang e il suo valore: cosi' --access-code --lang en non prende «--lang» per un nome. */
    public static String[] withoutFlag(String[] args) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--lang".equals(args[i])) { i++; continue; }
            out.add(args[i]);
        }
        return out.toArray(new String[0]);
    }
}
