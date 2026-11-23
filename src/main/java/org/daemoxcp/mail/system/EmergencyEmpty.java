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
 * The emergency emptying of Junk and/or Trash, from the server console (--empty-folders): for all mailboxes or
 * for some, right away. The everyday emptying is something else: automatic, mailbox by mailbox, off until
 * requested, from the panel or from the webmail (junk_expunge_days, trash_expunge_days).
 *
 * <p>First the messages of each folder are counted (doveadm mailbox status), shown, and you are asked to type
 * that number: only from a terminal, never blindly. Then doveadm expunge ... all, folder by folder; what was
 * removed goes into the panel's audit log (how many mailboxes, how many folders, how many messages: no
 * content). A folder that does not exist counts as zero and is skipped.
 */
public final class EmergencyEmpty {

    private EmergencyEmpty() {}

    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** The folders for the command-line word; null if the word is not valid. Pure. */
    public static List<String> folders(String which) {
        if (which == null) return null;
        return switch (which) {
            case "junk" -> List.of(SpecialFolders.JUNK);
            case "trash" -> List.of(SpamLearning.TRASH);
            case "both" -> List.of(SpecialFolders.JUNK, SpamLearning.TRASH);
            default -> null;
        };
    }

    /**
     * The number of messages from the output of "doveadm -f flow mailbox status messages": "messages=12". -1 if
     * missing. Pure.
     */
    static int messages(String flow) {
        Matcher m = Pattern.compile("(?:^|\\s)messages=(\\d+)").matcher(flow == null ? "" : flow);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** How many messages the mailbox's folder has: 0 if it does not exist. */
    @FunctionalInterface
    public interface Counter { int count(String mailbox, String folder); }

    /** Empties the mailbox's folder: true if doveadm answered successfully. */
    @FunctionalInterface
    public interface Expunger { boolean expunge(String mailbox, String folder); }

    /**
     * The count: per mailbox, per folder, the messages; only the folders that have some. Pure with respect to
     * Counter.
     */
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

    /** The result: how many folders emptied, which ones not. */
    public record Result(int emptied, List<String> failed) {}

    /** Empties what the count says. Pure with respect to Expunger. */
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

    /** The messages of a folder, from Dovecot. */
    public static int countWithDovecot(String mailbox, String folder) {
        Shell.Result r = Shell.run(Duration.ofSeconds(60), DOVEADM, "-f", "flow", "mailbox", "status", "-u", mailbox, "messages", folder);
        return r.success() ? Math.max(0, messages(r.output())) : 0;
    }

    /** doveadm expunge -u user mailbox folder all. */
    public static boolean expungeWithDovecot(String mailbox, String folder) {
        return Shell.run(Duration.ofSeconds(600), DOVEADM, "expunge", "-u", mailbox, "mailbox", folder, "all").success();
    }
}
