package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lo svuotamento d'emergenza della Junk e/o del Cestino, dalla console del server (--empty-folders): per tutte le
 * caselle o per alcune, subito. Lo svuotamento di tutti i giorni e' un'altra cosa: automatico, casella per casella,
 * spento finche' non lo si chiede, dal pannello o dalla webmail (junk_expunge_days, trash_expunge_days).
 *
 * <p>Prima si contano i messaggi di ogni cartella (doveadm mailbox status), si mostrano, e si chiede di scrivere quel
 * numero: solo da un terminale, mai a occhi chiusi. Poi doveadm expunge ... all, cartella per cartella; quello che e'
 * stato tolto va nel registro di controllo del pannello (quante caselle, quante cartelle, quanti messaggi: niente
 * contenuto). Una cartella che non c'e' conta zero e si salta.
 */
public final class EmergencyEmpty {

    private EmergencyEmpty() {}

    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** Le cartelle per la parola della riga di comando; null se la parola non va. Pura. */
    public static List<String> folders(String which) {
        if (which == null) return null;
        return switch (which) {
            case "junk" -> List.of(SpecialFolders.JUNK);
            case "trash" -> List.of(SpamLearning.TRASH);
            case "both" -> List.of(SpecialFolders.JUNK, SpamLearning.TRASH);
            default -> null;
        };
    }

    /** Il numero di messaggi dall'uscita di «doveadm -f flow mailbox status messages»: «messages=12». -1 se non c'e'. Pura. */
    static int messages(String flow) {
        Matcher m = Pattern.compile("(?:^|\\s)messages=(\\d+)").matcher(flow == null ? "" : flow);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** Quanti messaggi ha la cartella della casella: 0 se non c'e'. */
    @FunctionalInterface
    public interface Counter { int count(String mailbox, String folder); }

    /** Svuota la cartella della casella: vero se doveadm ha risposto bene. */
    @FunctionalInterface
    public interface Expunger { boolean expunge(String mailbox, String folder); }

    /** Il conto: per casella, per cartella, i messaggi; solo le cartelle che ne hanno. Puro rispetto a Counter. */
    public static Map<String, Map<String, Integer>> plan(List<String> mailboxes, List<String> folders, Counter counter) {
        Map<String, Map<String, Integer>> plan = new LinkedHashMap<>();
        for (String mb : mailboxes) {
            for (String f : folders) {
                int n = counter.count(mb, f);
                if (n > 0) plan.computeIfAbsent(mb, k -> new LinkedHashMap<>()).put(f, n);
            }
        }
        return plan;
    }

    public static int total(Map<String, Map<String, Integer>> plan) {
        int t = 0;
        for (Map<String, Integer> m : plan.values()) for (int n : m.values()) t += n;
        return t;
    }

    /** Il risultato: quante cartelle svuotate, quali no. */
    public record Result(int emptied, List<String> failed) {}

    /** Svuota quello che il conto dice. Puro rispetto a Expunger. */
    public static Result run(Map<String, Map<String, Integer>> plan, Expunger expunger) {
        int emptied = 0;
        List<String> failed = new ArrayList<>();
        for (Map.Entry<String, Map<String, Integer>> e : plan.entrySet())
            for (String f : e.getValue().keySet()) {
                if (expunger.expunge(e.getKey(), f)) emptied++;
                else failed.add(e.getKey() + " " + f);
            }
        return new Result(emptied, failed);
    }

    /** I messaggi di una cartella, da Dovecot. */
    public static int countWithDovecot(String mailbox, String folder) {
        Shell.Result r = Shell.run(Duration.ofSeconds(60), DOVEADM, "-f", "flow", "mailbox", "status", "-u", mailbox, "messages", folder);
        return r.success() ? Math.max(0, messages(r.output())) : 0;
    }

    /** doveadm expunge -u casella mailbox cartella all. */
    public static boolean expungeWithDovecot(String mailbox, String folder) {
        return Shell.run(Duration.ofSeconds(600), DOVEADM, "expunge", "-u", mailbox, "mailbox", folder, "all").success();
    }
}
