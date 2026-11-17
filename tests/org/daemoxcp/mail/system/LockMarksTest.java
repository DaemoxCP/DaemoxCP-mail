package org.daemoxcp.mail.system;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.daemoxcp.mail.util.Shell;

/**
 * The "locked by the panel" mark must be on every package the panel keeps locked, and only on
 * those.
 *
 * Before, only the package locked at start was annotated. Measured on the FreeBSD 15.1 VM on
 * 24/10/2026: reinstalling a package (so also upgrading it) deletes its annotations — nginx
 * annotated, nginx 1.30.6,3 reinstalled from the cache, annotation gone — and no relocking wrote
 * them again. Of 39 protected packages the annotation was on one.
 *
 * Checks 1-3 are pure. Check 4 works on real pkg, if there is one, and puts the marks back exactly
 * as it found them, whatever the outcome.
 */
public class LockMarksTest {

    private static int failures = 0;

    public static void main(String[] args) {

        // --- 1. Who carries the mark, from an output of pkg query -a '%n %At' ---
        String output = String.join("\n",
                "alsa-lib FreeBSD_version",
                "nginx cpe",
                "nginx repository",
                "redis " + UpdateManager.MARK_KEY,
                "redis cpe",
                "postfix-mysql " + UpdateManager.MARK_KEY,
                "pkg: warning: something on stderr",
                "rm;-rf " + UpdateManager.MARK_KEY,
                "dovecot mail_panel_lock",
                "");
        Set<String> marked = UpdateManager.markedIn(output);
        check("from pkg's output: redis and postfix-mysql", marked.equals(Set.of("redis", "postfix-mysql")));
        check("  a stderr line is not a package", !marked.contains("pkg:"));
        check("  a name that does not pass the filter does not get in", marked.stream().noneMatch(n -> n.contains(";")));
        check("empty output: no mark", UpdateManager.markedIn("").isEmpty());
        // The key of before the product name (DaemoxCP Mail, 17/11/2026): it is not today's mark, it is removed.
        check("the key of before is not today's mark", !marked.contains("dovecot"));
        check("  and it goes away: one command, for that package and that key",
                UpdateManager.oldKeyCommands(output).equals(java.util.List.of("pkg annotate -y -D dovecot mail_panel_lock")));

        // --- 1-bis. The mark's text, from pkg query -a '%n %At %Av' ---
        // On the servers installed before the value is the Italian one: there is no need to
        // recognise it, it is enough that it is not today's. The panel rewrites it, only on the
        // packages still locked.
        String withValues = String.join("\n",
                "nginx repository FreeBSD",
                "redis " + UpdateManager.MARK_KEY + " " + UpdateManager.MARK_VALUE,
                "postfix-mysql " + UpdateManager.MARK_KEY + " an old text: see the note",
                "dovecot " + UpdateManager.MARK_KEY,
                "lmdb " + UpdateManager.MARK_KEY + " an old text",
                "");
        check("with the values the same marks are read",
             UpdateManager.markedIn(withValues).equals(Set.of("redis", "postfix-mysql", "dovecot", "lmdb")));
        check("  and those with the old text (or without text): postfix-mysql, dovecot, lmdb",
             UpdateManager.staleMarksIn(withValues).equals(Set.of("postfix-mysql", "dovecot", "lmdb")));
        List<String> rw = UpdateManager.lockMarkCommands(Set.of("redis", "postfix-mysql", "dovecot"),
                UpdateManager.markedIn(withValues), UpdateManager.staleMarksIn(withValues));
        check("postfix-mysql and dovecot, locked, are rewritten; lmdb, no longer locked, is removed (" + rw + ")",
             rw.size() == 3 && rw.contains(UpdateManager.rewriteMarkCommand("postfix-mysql"))
                     && rw.contains(UpdateManager.rewriteMarkCommand("dovecot")) && rw.contains(UpdateManager.removeMarkCommand("lmdb")));
        check("the value is in English and points to the note and to the unlock command",
             UpdateManager.MARK_VALUE.startsWith("locked by DaemoxCP Mail: see ")
                     && UpdateManager.MARK_VALUE.contains(UpdateManager.LOCK_NOTE) && UpdateManager.MARK_VALUE.contains(UpdateManager.UNLOCK_ALL_COMMAND));
        check("the rewriting command uses -M with the same value as the one that sets it",
             ("pkg annotate -y -M nginx " + UpdateManager.MARK_KEY + " '" + UpdateManager.MARK_VALUE + "'").equals(UpdateManager.rewriteMarkCommand("nginx"))
                     && UpdateManager.markCommand("nginx").endsWith(" '" + UpdateManager.MARK_VALUE + "'")
                     && UpdateManager.rewriteMarkCommand("x; rm -rf /") == null);

        // --- 2. The commands to bring the marks where they are needed ---
        List<String> c = UpdateManager.lockMarkCommands(
                Set.of("nginx", "redis", "dovecot"), Set.of("redis", "lmdb"));
        check("three commands: two to set, one to remove (" + c.size() + ")", c.size() == 3);
        check("  it puts the mark on dovecot", c.stream().anyMatch(x -> x.contains(" -A dovecot ")));
        check("  and on nginx", c.stream().anyMatch(x -> x.contains(" -A nginx ")));
        check("  it does not touch redis, which has it", c.stream().noneMatch(x -> x.contains(" redis ")));
        check("  it removes lmdb's, which is no longer locked",
             c.contains(UpdateManager.removeMarkCommand("lmdb")));
        check("  and the removing command names the key and the package",
             "pkg annotate -y -D lmdb daemoxcp_mail_lock".equals(UpdateManager.removeMarkCommand("lmdb")));
        check("everything even: no command",
             UpdateManager.lockMarkCommands(Set.of("nginx"), Set.of("nginx")).isEmpty());
        check("a name that does not pass the filter produces no command",
             UpdateManager.lockMarkCommands(Set.of("ngi nx; rm -rf /"), Set.of()).isEmpty()
             && UpdateManager.removeMarkCommand("x; rm -rf /") == null);

        // --- 3. The measured machine: 39 locked, the mark on one ---
        Set<String> thirtyNine = new TreeSet<>();
        for (int i = 0; i < 38; i++) thirtyNine.add("package" + i);
        thirtyNine.add("redis");
        check("39 locked and a single mark: 38 to set, nothing to remove",
             UpdateManager.lockMarkCommands(thirtyNine, Set.of("redis")).size() == 38);

        // --- 4. On real pkg ---
        if (!Shell.runShell(Duration.ofSeconds(10), "command -v pkg").success()) {
            System.out.println("  --   real pkg: pkg is not on this machine, skipped");
        } else {
            onRealPkg();
            // --- 5. No locked package (reperto 173): it unlocks everything, only on a clone ---
            if ("yes".equals(System.getProperty("e2e.vm"))) withNothingLocked();
            else System.out.println("  --   no locked package: it needs -De2e.vm=yes (it unlocks everything, on a clone)");
        }

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void onRealPkg() {
        Set<String> markedBefore = markedNow();
        Set<String> locked = panelLocked();
        if (locked.isEmpty()) {
            System.out.println("  --   real pkg: no package of the stack locked, skipped");
            return;
        }
        String one = locked.iterator().next();
        String free = firstUnlocked();
        try {
            UpdateManager.syncLockMarks();
            check("real pkg: after the sync the mark is on all and only the "
                 + locked.size() + " bloccati", markedNow().equals(locked));

            // The mark lost by an upgrade, and one left on an unlocked package
            sh("pkg annotate -y -D " + one + " " + UpdateManager.MARK_KEY);
            if (free != null) sh(UpdateManager.markCommand(free));
            int[] done = UpdateManager.syncLockMarks();
            check("  the mark removed from " + one + " comes back", markedNow().contains(one));
            if (free != null) {
                check("  the one put on " + free + ", which is not locked, goes away",
                     !markedNow().contains(free));
                check("  and the sync counts it: 1 set, 1 removed (" + done[0] + ", " + done[1] + ")",
                     done[0] == 1 && done[1] == 1);
            }
            check("  and a second time there is nothing to do",
                 java.util.Arrays.equals(UpdateManager.syncLockMarks(), new int[]{0, 0, 0}));

            // The mark with the old text, as a server installed before leaves it.
            sh("pkg annotate -y -M " + one + " " + UpdateManager.MARK_KEY + " 'an old text'");
            int[] again = UpdateManager.syncLockMarks();
            check("  " + one + "'s mark with the old text is rewritten (" + again[2] + "), and says today's",
                 again[2] == 1 && sh("pkg annotate -S " + one + " " + UpdateManager.MARK_KEY).contains(UpdateManager.MARK_VALUE));
        } finally {
            // As I found them, mark by mark.
            Set<String> now = markedNow();
            for (String n : now) if (!markedBefore.contains(n)) sh("pkg annotate -y -D " + n + " " + UpdateManager.MARK_KEY);
            for (String n : markedBefore) if (!now.contains(n)) sh(UpdateManager.markCommand(n));
        }
        check("  and the test leaves the marks as it found them", markedNow().equals(markedBefore));
    }

    /**
     * Without any locked package "pkg lock -l" exits with 1, and the sync took it for an error and
     * removed nothing. Everything is unlocked, a mark is put on any package, and the sync must
     * remove it. Then locks and marks as before.
     */
    private static void withNothingLocked() {
        Set<String> lockedBefore = new TreeSet<>(List.of(sh("pkg query -e '%k = 1' '%n'").split("\n")));
        lockedBefore.removeIf(String::isBlank);
        Set<String> markedBefore = markedNow();
        String any = sh("pkg query -a '%n' | head -1").trim();
        try {
            sh("pkg unlock -a -y");
            check("nothing locked: pkg lock -l exits with 1 (the trap)",
                 !Shell.runShell(Duration.ofSeconds(30), "pkg lock -l").success());
            sh(UpdateManager.markCommand(any));
            int[] done = UpdateManager.syncLockMarks();
            check("  the mark on " + any + ", which is not locked, goes away (" + done[1] + " removed)",
                 !markedNow().contains(any) && done[1] >= 1);
            check("  and no mark stays on an unlocked package", markedNow().isEmpty());
        } finally {
            for (String n : lockedBefore) sh("pkg lock -y " + n);
            Set<String> now = markedNow();
            for (String n : now) if (!markedBefore.contains(n)) sh("pkg annotate -y -D " + n + " " + UpdateManager.MARK_KEY);
            for (String n : markedBefore) if (!now.contains(n)) sh(UpdateManager.markCommand(n));
        }
        Set<String> lockedAfter = new TreeSet<>(List.of(sh("pkg query -e '%k = 1' '%n'").split("\n")));
        lockedAfter.removeIf(String::isBlank);
        check("  and the test puts locks and marks back as it found them",
             lockedAfter.equals(lockedBefore) && markedNow().equals(markedBefore));
    }

    private static Set<String> markedNow() {
        return UpdateManager.markedIn(sh("pkg query -a '%n %At'"));
    }

    /** The same rule as the note: the mail stack, locked now. */
    private static Set<String> panelLocked() {
        Set<String> r = new TreeSet<>();
        for (String line : sh("sed -n '/^[a-z]/p' " + UpdateManager.LOCK_NOTE + " 2>/dev/null").split("\n")) {
            if (!line.isBlank()) r.add(line.trim());
        }
        // The note is the one of the last start: only what is really locked now is kept.
        r.retainAll(UpdateManager.lockedNames(sh("pkg lock -l")));
        return r;
    }

    private static String firstUnlocked() {
        String r = sh("pkg query -a '%k %n' | awk '$1 == 0 {print $2; exit}'").trim();
        return r.isEmpty() ? null : r;
    }

    private static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(60), cmd).outputTrim();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
