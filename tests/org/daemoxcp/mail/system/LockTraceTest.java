package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

/**
 * The trace of the locks on the machine: why those packages are locked, and how they are freed if
 * the panel is no longer there.
 *
 * The lock does not expire and nobody removes it at shutdown: it is the rule, and it is right as
 * long as the panel is there. If the panel is uninstalled, or simply does not start again, those
 * packages stay locked forever — and a locked package does not even get the security fixes.
 *
 * Measured on the FreeBSD 15.1 VM on 23/10/2026, with 40 packages locked by the panel:
 * `pkg upgrade` names the locked ones in a passing line, does NOT put them in the summary and ends
 * with exit ZERO. From the system one could not tell who had locked them, nor why, nor how to free
 * them: `pkg lock -l` lists the names and nothing else.
 *
 * Here it is tested that the explanation is there, that it says the things that are needed, and
 * that it does not fall behind the real state.
 *
 * The note is written in the panel's source language (Italian), with its texts in the language
 * files (server.lockNote.*): the English note is checked with English words, the Italian one
 * against it.json by key, so no Italian text is written here.
 */
public class LockTraceTest {

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) throws Exception {

        // ===== 1. The note's text says everything that is needed =====
        List<String> three = List.of("dovecot", "nginx", "postfix-mysql");
        String when = "2026-10-23T01:00:00Z";
        String note = UpdateManager.lockNoteText(three, when, "en");
        // The paragraphs are wrapped into "# " lines: joined back, a sentence reads whole.
        String flat = flat(note);
        check("the note lists the locked packages",
             note.contains("dovecot") && note.contains("nginx") && note.contains("postfix-mysql"));
        check("it says when it was written, in UTC", note.contains(when) && note.contains("UTC"));
        check("it says the exact command that frees them", note.contains(UpdateManager.UNLOCK_ALL_COMMAND));
        check("it says a locked package does not get the security fixes", flat.contains("security fixes"));
        check("it says pkg upgrade skips them exiting with code 0", flat.contains("exiting with code 0"));
        check("it points to the panel to update them", flat.contains("from the panel, Updates page"));
        check("it says how to free a single one", note.contains("pkg unlock -y"));
        check("and where the real state is read", note.contains("pkg lock -l"));
        check("it warns not to edit it by hand", flat.contains("Do NOT edit by hand"));

        // A note without packages must not look like an empty list by mistake.
        check("with no locked package it says so",
             UpdateManager.lockNoteText(List.of(), when, "en").contains("(no locked package)"));

        // The file on the machine is in the panel's source language, whoever triggered the writing.
        String italian = UpdateManager.lockNoteText(three, when);
        I18n.setCurrent("en");
        boolean sameInsideAnEnglishRequest = UpdateManager.lockNoteText(three, when).equals(italian);
        I18n.clearCurrent();
        check("the note on the machine is in the source language, even inside an English request",
             italian.equals(UpdateManager.lockNoteText(three, when, I18n.SOURCE_LANGUAGE)) && sameInsideAnEnglishRequest
             && !italian.equals(note));
        boolean allTexts = true;
        for (String k : List.of("title", "why", "how", "warning", "single", "state"))
            allTexts &= flat(italian).contains(I18n.t(I18n.SOURCE_LANGUAGE, "server.lockNote." + k).replaceAll("\\s+", " "));
        check("  with every text of it.json, by key", allTexts && flat(UpdateManager.lockNoteText(List.of(), when))
             .contains(I18n.t(I18n.SOURCE_LANGUAGE, "server.lockNote.none")));

        // Outside the comments only the package names: that is what a reader of the list takes.
        boolean format = true;
        for (String lang : I18n.LANGUAGES)
            for (String line : UpdateManager.lockNoteText(three, when, lang).split("\n", -1))
                format &= (line.isEmpty() || line.startsWith("#") || three.contains(line)) && line.length() <= 84;
        check("in both languages: comment lines of at most 84 columns, and the package names", format);

        // ===== 2. The writing: atomic, and it does not fall behind =====
        Path d = Files.createTempDirectory("lock-note-test");
        Path f = d.resolve("locked-packages.txt");
        Path original = UpdateManager.lockNotePath;
        UpdateManager.lockNotePath = f;
        try {
            if (!hasPkg()) {
                skip("writing the note: pkg is not on this machine");
            } else {
                UpdateManager.writeLockNote();
                // How many packages OF THE STACK are locked: it is the count packagesStatus makes,
                // that is exactly what the note must list.
                JSONObject state = UpdateManager.packagesStatus();
                int lockedCount = state.optInt("lockedCount");
                java.util.List<String> reallyLocked = new java.util.ArrayList<>();
                org.json.JSONArray lines = state.getJSONArray("packages");
                for (int i = 0; i < lines.length(); i++)
                    if (lines.getJSONObject(i).optBoolean("locked"))
                        reallyLocked.add(lines.getJSONObject(i).getString("name"));
                if (lockedCount == 0) {
                    check("without locked packages the note does not exist", !Files.exists(f));
                    skip("the note's content: on this machine there is no lock");
                } else {
                    check("the note is written", Files.exists(f));
                    String written = Files.exists(f) ? Files.readString(f) : "";
                    final String text = written;
                    check("and it contains the really locked packages ("
                         + reallyLocked.size() + ")", reallyLocked.stream().allMatch(text::contains));
                    check("and the command to free them", written.contains(UpdateManager.UNLOCK_ALL_COMMAND));
                    check("no temporary file left behind",
                         !Files.exists(f.resolveSibling(f.getFileName() + ".tmp")));
                }
            }
        } finally {
            UpdateManager.lockNotePath = original;
            try { Files.deleteIfExists(f); Files.deleteIfExists(d); } catch (Exception ignored) { }
        }

        // ===== 3. The warning where the panel is taken out of the way =====
        if (!hasPkg()) {
            skip("the warning about the locks that stay: pkg is not on this machine");
            skip("the warning in the removal of the automatic start: pkg is not there");
        } else {
            String warning = UpdateManager.locksStayWarning();
            int howMany = UpdateManager.packagesStatus().optInt("lockedCount");
            if (howMany == 0) {
                check("without locks nothing is warned about", warning.isEmpty());
                skip("the warning's content: on this machine there is no lock");
            } else {
                check("the warning is there when there are locks", !warning.isEmpty());
                check("  it says how many there are", warning.contains(String.valueOf(howMany)));
                check("  it says the command that frees them", warning.contains(UpdateManager.UNLOCK_ALL_COMMAND));
                check("  and where the why is written", warning.contains(UpdateManager.LOCK_NOTE));

                // The removal of the automatic start repeats it: it is the moment when the question
                // "and the locks?" comes up by itself. Read only (execute = false).
                JSONObject rc = UpdateManager.removePanelRcScript(false);
                check("the removal of the automatic start warns about the locks",
                     rc.optString("note").contains(UpdateManager.UNLOCK_ALL_COMMAND)
                     || rc.optString("locksStay").contains(UpdateManager.UNLOCK_ALL_COMMAND));
                check("  and it executed nothing", !rc.optBoolean("executed", false));
            }
        }

        // ===== 4. The mark in pkg's database =====
        // A command line is tested by running it: the value contains spaces, a path and a dash, and
        // in this project a quote inside a text has already gone through a here-document intact to
        // break further on.
        check("a non-conforming name produces no command",
             UpdateManager.markCommand("ngi nx; rm -rf /") == null);
        String cmd = UpdateManager.markCommand("nginx");
        check("the command names the key and the package",
             cmd != null && cmd.contains(UpdateManager.MARK_KEY) && cmd.contains(" nginx "));
        check("  and points to the note and to the unlock command",
             cmd != null && cmd.contains(UpdateManager.LOCK_NOTE) && cmd.contains(UpdateManager.UNLOCK_ALL_COMMAND));

        if (!hasPkg()) {
            skip("the annotation on real pkg: pkg is not on this machine");
        } else {
            String target = firstInstalled();
            if (target == null) {
                skip("the annotation on real pkg: no package installed");
            } else {
                boolean executed = org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        UpdateManager.markCommand(target)).success();
                String readBack = org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + target).output();
                // It is put back as it was, whatever the outcome.
                org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg annotate -y -D " + target + " " + UpdateManager.MARK_KEY);
                check("the annotation command is run by pkg on " + target, executed);
                check("  and pkg info -A shows it", readBack.contains(UpdateManager.MARK_KEY));
                check("  with the pointer to the note", readBack.contains(UpdateManager.LOCK_NOTE));
                String after = org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + target).output();
                check("  and it can be removed, so the test leaves no trace",
                     !after.contains(UpdateManager.MARK_KEY));
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " CHECKS SKIPPED (they say so above)");
        System.out.println(failures == 0 ? "ALL OK" : failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** Any installed package, to try the annotation on. */
    private static String firstInstalled() {
        for (String n : PackagePlan.installed().keySet()) return n;
        return null;
    }

    /** The note with its "# " lines joined back, spaces collapsed: a wrapped sentence reads whole. */
    private static String flat(String note) {
        return note.replaceAll("\\n#[ ]*", " ").replaceAll("\\s+", " ");
    }

    private static boolean hasPkg() {
        return org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    private static void skip(String name) {
        System.out.println("  --   SKIPPED: " + name);
        skipped++;
    }
}
