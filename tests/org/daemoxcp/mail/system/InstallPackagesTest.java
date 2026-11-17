package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.util.Shell;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The full installation really installs the packages it asks for, and stops if pkg removes one.
 *
 * The defect, measured on 24/10/2026 on FreeBSD 15.1 with an installation from scratch with the jar of
 * main (reperto 52):
 *
 *   pkg install -y dovecot-mysql dovecot-pigeonhole
 *   - dovecot-2.3.21.1_3 conflicts with dovecot-mysql-2.3.21.1_3 on /usr/local/bin/doveadm
 *   Cannot solve problem using SAT solver, trying another plan
 *   New packages to be INSTALLED: dovecot, dovecot-pigeonhole          (exit code 0)
 *   [SUCCESS] Complete Mail Server Installation completed successfully!
 *
 * and then, at the first mailbox: "auth: Fatal: Support not compiled in for passdb driver 'sql'".
 * No IMAP login, and 587 closed ("no SASL authentication mechanisms").
 *
 * Three parts, because they are three different things and each can go wrong alone:
 *
 *  A. the script's text: it asks for Dovecot with MySQL and the Pigeonhole BUILT for it, and every
 *     package goes through the function that checks;
 *  B. the function behaves as it says: the real lines of the script are run against a fake pkg that
 *     does the measured thing (it removes a requested package and exits with 0), and the script must
 *     stop THERE, not reach the end. The fake pkg is the only way to test the "pkg lies" branch
 *     without waiting for the solver to do it again;
 *  C. the REAL solver, on the real catalog: for every line of the script pkg is asked for the plan
 *     as on a freshly installed machine (empty package database, in a copy) and with the packages
 *     already downloaded, because pkg sees the conflicts on files only after downloading them
 *     (reperto 14). Every requested package must be in the final plan. It downloads ~180 MB into a
 *     temporary folder: it is switched on with -De2e.vm=yes, as root, on FreeBSD; it installs
 *     nothing and does not touch pkg's real database.
 *
 * Plus a part D on the updater's labels, because the installation now puts dovecot-mysql and
 * dovecot-pigeonhole-mysql instead of the packages without flavour.
 *
 * Since reperto 215 the Dovecot line is "install_packages $DOVECOT_PACKAGES": the script itself picks
 * 2.4 (dovecot24-mysql) where the catalog offers it, else 2.3 (DovecotConfig.packagesShell). Part 0
 * reads the two choices from the script; A and B then run on the script as it runs with each of them,
 * C on the one this machine's catalog would pick.
 *
 * Usage, on the VM:
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.InstallPackagesTest
 *   java -De2e.vm=yes -cp "tests:freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.InstallPackagesTest
 */
public class InstallPackagesTest {

    static int failures = 0, skipped = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK       " : "  FAILED   ") + what);
        if (!ok) failures++;
    }

    static final String DOVECOT_LINE = "install_packages $DOVECOT_PACKAGES";

    public static void main(String[] args) throws Exception {
        String script = new FullMailServerScript().getScriptContent();
        List<String> choices = dovecotChoices(script);
        dovecotChoice(script, choices);
        String with24 = choices.size() == 2 ? asRun(script, choices.get(0)) : script;
        String with23 = choices.size() == 2 ? asRun(script, choices.get(1)) : script;
        List<List<String>> lines = installLines(with23);

        scriptText(with23, lines);
        functionBehaviour(with23, "dovecot-mysql", "Dovecot 2.3");
        functionBehaviour(with24, "dovecot24-mysql", "Dovecot 2.4");
        if ("yes".equals(System.getProperty("e2e.vm"))) {
            if (onFreeBsdAsRoot()) {
                // The same question the script asks: the plan of the Dovecot this machine would install.
                boolean offered24 = !sh("pkg rquery %v dovecot24-mysql 2>/dev/null", 60).trim().isEmpty();
                System.out.println("\n  the catalog " + (offered24 ? "offers" : "does not offer") + " dovecot24-mysql: part C with Dovecot "
                        + (offered24 ? "2.4" : "2.3"));
                realSolver(installLines(offered24 ? with24 : with23));
            }
            else { skipped++; System.out.println("\n  SKIPPED  part C: it needs FreeBSD and root"); }
        } else {
            skipped++;
            System.out.println("\n  SKIPPED  part C: it downloads ~180 MB, it is switched on with -De2e.vm=yes (FreeBSD, root)");
        }
        updaterLabels();

        System.out.println(failures == 0 ? "\nALL OK" + (skipped > 0 ? " (" + skipped + " parts skipped, said above)" : "")
                                         : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    // ------------------------------------------------------------------ 0

    /** The values the script can give DOVECOT_PACKAGES, in the order they are written. */
    static List<String> dovecotChoices(String script) {
        List<String> out = new ArrayList<>();
        for (String l : script.split("\n")) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("^\\s*DOVECOT_PACKAGES=\"([^\"]*)\"\\s*$").matcher(l);
            if (m.matches()) out.add(m.group(1));
        }
        return out;
    }

    /** The script as it runs with DOVECOT_PACKAGES set to that value: the Dovecot line with the names written out. */
    static String asRun(String script, String value) {
        return script.replace("\n" + DOVECOT_LINE + "\n", "\ninstall_packages " + value + "\n");
    }

    static void dovecotChoice(String script, List<String> choices) {
        System.out.println("\n== 0. The Dovecot the script picks ==");
        System.out.println("  choices: " + choices);
        check("two choices, 2.4 where the catalog offers it, else 2.3",
                choices.equals(List.of("dovecot24-mysql dovecot24-pigeonhole-mysql", "dovecot-mysql dovecot-pigeonhole-mysql")));
        check("  each one the MySQL flavor and the Pigeonhole built for it, in one variable (one line, one check)",
                choices.stream().allMatch(c -> c.matches("(dovecot|dovecot24)-mysql \\1-pigeonhole-mysql")));
        int lines = script.split("\n" + java.util.regex.Pattern.quote(DOVECOT_LINE) + "\n", -1).length - 1;
        check("Dovecot is installed by exactly one line, " + DOVECOT_LINE + " (found " + lines + ")", lines == 1);
        int lastChoice = script.lastIndexOf("DOVECOT_PACKAGES=\"");
        check("  after the choice is made", lastChoice >= 0 && script.indexOf("\n" + DOVECOT_LINE + "\n") > lastChoice);
    }

    // ------------------------------------------------------------------ A

    static void scriptText(String script, List<List<String>> lines) {
        System.out.println("\n== A. The script's text ==");
        Set<String> asked = new LinkedHashSet<>();
        for (List<String> l : lines) asked.addAll(l);
        System.out.println("  installation lines found: " + lines.size() + ", packages requested: " + asked.size());

        check("it asks for dovecot-mysql (the mailbox authentication is in MySQL)", asked.contains("dovecot-mysql"));
        check("it asks for dovecot-pigeonhole-mysql, the Sieve built for dovecot-mysql",
                asked.contains("dovecot-pigeonhole-mysql"));
        check("it does not ask for dovecot-pigeonhole, which depends on \"dovecot\" without MySQL", !asked.contains("dovecot-pigeonhole"));
        check("it does not ask for \"dovecot\" without flavour", !asked.contains("dovecot"));
        check("dovecot-mysql and its Pigeonhole are on the SAME line (a single plan, a single check)",
                lines.stream().anyMatch(l -> l.contains("dovecot-mysql") && l.contains("dovecot-pigeonhole-mysql")));

        int def = script.indexOf("\ninstall_packages() {");
        int firstUse = script.indexOf("\ninstall_packages ");
        check("the install_packages function is defined", def >= 0);
        check("and it is defined before its first use", def >= 0 && firstUse > def);
        check("the function checks every package with pkg info -e",
                functionText(script).contains("pkg info -e \"$pkg_wanted\""));

        // No "pkg install" outside the function: a bare one is a package that can be missing without
        // anybody noticing.
        List<String> bare = new ArrayList<>();
        String fn = functionText(script);
        String outside = fn.isEmpty() ? script : script.replace(fn, "");
        for (String l : outside.split("\n")) {
            String t = l.trim();
            if (t.startsWith("#")) continue;
            if (t.matches(".*\\bpkg\\s+install\\b.*")) bare.add(t);
        }
        check("no \"pkg install\" outside install_packages" + (bare.isEmpty() ? "" : ": " + bare), bare.isEmpty());

        List<String> swallowed = new ArrayList<>();
        for (String l : script.split("\n")) {
            String t = l.trim();
            if (t.startsWith("install_packages ") && (t.contains("|| true") || t.contains("2>/dev/null"))) swallowed.add(t);
        }
        check("no installation line hides its outcome (|| true, 2>/dev/null)"
                + (swallowed.isEmpty() ? "" : ": " + swallowed), swallowed.isEmpty());
    }

    // ------------------------------------------------------------------ B

    /** The script's real lines against a fake pkg that removes a package and exits with 0. */
    static void functionBehaviour(String script, String dovecotName, String label) throws Exception {
        System.out.println("\n== B. The function, with a pkg that silently removes a package (" + label + ") ==");
        Path dir = Files.createTempDirectory("install-packages-test");
        try {
            Files.createDirectories(dir.resolve("bin"));
            // The fake pkg. "install -y A B C": it records as installed all but those in FAKE_DROP,
            // writes the solver's line if it removes one, and exits with FAKE_RC (0 if not given): it
            // is exactly what the real pkg did. "info -e X": 0 only if X was recorded.
            Path fakePkg = dir.resolve("bin/pkg");
            Files.writeString(fakePkg, """
                    #!/bin/sh
                    case "$1" in
                      install)
                        shift; [ "$1" = "-y" ] && shift
                        echo "$*" >> "$FAKE_DIR/asked"
                        for p in "$@"; do
                          case " $FAKE_DROP " in
                            *" $p "*) echo "Cannot solve problem using SAT solver, trying another plan" ;;
                            *) echo "$p" >> "$FAKE_DIR/installed" ;;
                          esac
                        done
                        exit "${FAKE_RC:-0}" ;;
                      info)
                        [ "$2" = "-e" ] || exit 2
                        grep -qxF -- "$3" "$FAKE_DIR/installed" 2>/dev/null ;;
                      *) exit 0 ;;
                    esac
                    """, StandardCharsets.UTF_8);
            fakePkg.toFile().setExecutable(true);

            // The bench: the function as it is in the script, then the installation lines as they
            // are in the script and in the same order, then a mark that says "I reached the end".
            // The lines are taken both in the new form (install_packages) and in the old one (pkg
            // install -y), so the same bench measures the old script too. The "pkg install" INSIDE
            // the function is not a line of the script: it looks outside.
            StringBuilder bench = new StringBuilder("RED=''\nNC=''\n");
            String fn = functionText(script);
            bench.append(fn).append('\n');
            for (String l : (fn.isEmpty() ? script : script.replace(fn, "")).split("\n")) {
                String t = l.trim();
                if (t.startsWith("install_packages ") || t.startsWith("pkg install -y ")) bench.append(t).append('\n');
            }
            bench.append("echo REACHED-THE-END\n");
            Files.writeString(dir.resolve("bench.sh"), bench.toString(), StandardCharsets.UTF_8);

            List<List<String>> lines = installLines(script);
            Run all = run(dir, "", "0");
            check("with an honest pkg: it reaches the end", all.out.contains("REACHED-THE-END"));
            check("with an honest pkg: it exits with 0", all.code == 0);
            check("with an honest pkg: the bench ran all the " + lines.size() + " lines of the script",
                    all.asked.size() == lines.size() && lines.size() > 0);

            // Each package of the Dovecot line as it is in the script is removed, one at a time: the
            // real solver removed now one, now the other.
            List<String> dovecotLine = lines.stream().filter(l -> l.contains(dovecotName)).findFirst().orElse(List.of());
            check("the script has a line with " + dovecotName + " " + dovecotLine, !dovecotLine.isEmpty());
            for (String drop : dovecotLine) {
                Run r = run(dir, drop, "0");
                check("pkg removes " + drop + " and exits with 0: the script does NOT reach the end",
                        !r.out.contains("REACHED-THE-END"));
                check("pkg removes " + drop + ": the script exits other than 0", r.code != 0);
                check("pkg removes " + drop + ": the message names it",
                        r.out.contains("NOT installed: " + drop) || r.out.matches("(?s).*NOT installed:.* " + drop + "\\b.*"));
                check("pkg removes " + drop + ": it stops on the Dovecot line, the line after (rspamd) does not start",
                        r.asked.stream().noneMatch(a -> a.contains("rspamd")));
            }

            Run last = run(dir, "php84-gd", "0");
            check("on the LAST line too (php84-gd removed) it does not reach the end", !last.out.contains("REACHED-THE-END"));
            check("and it says so", last.out.contains("php84-gd") && last.out.contains("NOT installed"));

            Run fails = run(dir, "", "1");
            check("pkg exits with 1 even without removing anything: the script stops",
                    !fails.out.contains("REACHED-THE-END") && fails.code != 0);
            check("and it says pkg's exit code", fails.out.contains("pkg exit code: 1"));
        } finally {
            Shell.runShell(Duration.ofSeconds(30), "rm -rf '" + dir + "'");
        }
    }

    record Run(int code, String out, List<String> asked) {}

    static Run run(Path dir, String drop, String rc) throws Exception {
        Files.deleteIfExists(dir.resolve("installed"));
        Files.deleteIfExists(dir.resolve("asked"));
        Shell.Result r = Shell.runShell(Duration.ofSeconds(60),
                "cd '" + dir + "' && PATH='" + dir + "/bin':/bin:/usr/bin FAKE_DIR='" + dir + "' FAKE_DROP='" + drop
                        + "' FAKE_RC=" + rc + " sh bench.sh 2>&1");
        Path asked = dir.resolve("asked");
        List<String> a = Files.exists(asked) ? Files.readAllLines(asked) : List.of();
        return new Run(r.exitCode(), r.output(), a);
    }

    // ------------------------------------------------------------------ C

    /** pkg's plan as on a freshly installed machine, line by line and all together. */
    static void realSolver(List<List<String>> lines) {
        System.out.println("\n== C. pkg's real solver, on the real catalog ==");
        String db = sh("pkg config PKG_DBDIR 2>/dev/null", 30).trim();
        if (!db.matches("/[A-Za-z0-9._/-]{1,200}")) db = "/var/db/pkg";
        String tmp = sh("mktemp -d /var/tmp/install-packages-test.XXXXXX", 30).trim();
        if (!tmp.matches("/var/tmp/install-packages-test\\.[A-Za-z0-9]{6,}")) {
            check("temporary folder created (" + tmp + ")", false);
            return;
        }
        try {
            // A copy of pkg's database: the catalog as it is, and the installed packages all removed
            // except pkg itself. It is the freshly installed machine, as the solver sees it. The
            // emptying touches only the copy: PKG_DBDIR points there.
            Shell.Result cp = Shell.runShell(Duration.ofSeconds(300),
                    "cp -Rp " + db + "/repos " + tmp + "/ && cp -p " + db + "/local.sqlite " + tmp + "/ && mkdir " + tmp + "/cache 2>&1");
            check("copy of the catalog and of the database", cp.success());
            String p = "pkg -o PKG_DBDIR=" + tmp + " -o PKG_CACHEDIR=" + tmp + "/cache";
            Shell.Result empty = Shell.runShell(Duration.ofSeconds(60),
                    "printf 'PRAGMA foreign_keys=ON;\\nDELETE FROM packages WHERE name <> \\047pkg\\047;\\nSELECT count(*) FROM packages;\\n' | "
                            + p + " shell 2>&1");
            check("in the copy only pkg stays installed (" + empty.outputTrim() + ")", empty.outputTrim().equals("1"));

            List<List<String>> plans = new ArrayList<>(lines);
            List<String> together = new ArrayList<>();
            for (List<String> l : lines) for (String n : l) if (!together.contains(n)) together.add(n);
            plans.add(together);

            for (int i = 0; i < plans.size(); i++) {
                List<String> asked = plans.get(i);
                String label = i < lines.size() ? "line " + (i + 1) + " " + asked : "all the lines together (" + asked.size() + " packages)";
                String list = String.join(" ", asked);
                // First they are downloaded: without the files pkg does not see the conflicts between packages.
                Shell.Result f = Shell.runShell(Duration.ofSeconds(900), p + " fetch -d -U -y " + list + " 2>&1");
                if (!f.success()) {
                    check(label + ": pkg fetch succeeded", false);
                    System.out.println(indent(tail(f.outputTrim(), 15)));
                    continue;
                }
                Shell.Result plan = Shell.runShell(Duration.ofSeconds(300), p + " install -n -U " + list + " 2>&1");
                Set<String> planned = lastInstallBlock(plan.output());
                List<String> missing = new ArrayList<>();
                for (String a : asked) {
                    String name = a.contains("/") ? sh(p + " rquery -U %n " + a + " 2>/dev/null", 60).trim() : a;
                    if (!planned.contains(name)) missing.add(a);
                }
                check(label + ": the plan has every requested package"
                        + (missing.isEmpty() ? "" : " -- MISSING " + missing), missing.isEmpty() && !planned.isEmpty());
                if (plan.output().contains("Cannot solve problem")) {
                    for (String l : plan.output().split("\n"))
                        if (l.contains("conflicts with") || l.contains("Cannot solve")) System.out.println("           pkg: " + l.trim());
                }
            }
        } finally {
            Shell.runShell(Duration.ofSeconds(300), "rm -rf " + tmp);
        }
    }

    /** The names of the LAST "New packages to be INSTALLED" list: after a fallback, that one counts. */
    static Set<String> lastInstallBlock(String out) {
        Set<String> names = new LinkedHashSet<>();
        int at = out.lastIndexOf("New packages to be INSTALLED:");
        if (at < 0) return names;
        for (String l : out.substring(at).split("\n")) {
            if (l.startsWith("New packages")) continue;
            if (l.isBlank()) break;
            String t = l.trim();
            int colon = t.indexOf(':');
            if (colon > 0) names.add(t.substring(0, colon));
        }
        return names;
    }

    // ------------------------------------------------------------------ D

    static void updaterLabels() throws Exception {
        System.out.println("\n== D. The updater recognises the packages with flavours ==");
        Method role = UpdateManager.class.getDeclaredMethod("roleOf", String.class);
        role.setAccessible(true);
        Object dovecot = role.invoke(null, "dovecot");
        check("dovecot-mysql has the same role as dovecot (" + dovecot + ")",
                dovecot != null && dovecot.equals(role.invoke(null, "dovecot-mysql")));
        check("dovecot24-mysql too", dovecot != null && dovecot.equals(role.invoke(null, "dovecot24-mysql")));
        Object sieve = role.invoke(null, "dovecot-pigeonhole");
        check("dovecot-pigeonhole-mysql has the role of Sieve (" + sieve + ")",
                sieve != null && sieve.equals(role.invoke(null, "dovecot-pigeonhole-mysql")));

        Method services = UpdateManager.class.getDeclaredMethod("directServices", String.class);
        services.setAccessible(true);
        check("updating dovecot-mysql restarts dovecot", List.of("dovecot").equals(services.invoke(null, "dovecot-mysql")));
        check("updating dovecot-pigeonhole-mysql restarts dovecot",
                List.of("dovecot").equals(services.invoke(null, "dovecot-pigeonhole-mysql")));

        String family = UpdateManager.familyOf("dovecot-mysql");
        check("dovecot-mysql and dovecot-pigeonhole-mysql move together (same family)",
                family != null && family.equals(UpdateManager.familyOf("dovecot-pigeonhole-mysql")));
        // Reperto 215: where the catalog offers 2.4, an installation from scratch puts in these two.
        check("dovecot24-pigeonhole-mysql has the role of Sieve too",
                sieve != null && sieve.equals(role.invoke(null, "dovecot24-pigeonhole-mysql")));
        check("updating dovecot24-mysql or dovecot24-pigeonhole-mysql restarts dovecot",
                List.of("dovecot").equals(services.invoke(null, "dovecot24-mysql"))
                && List.of("dovecot").equals(services.invoke(null, "dovecot24-pigeonhole-mysql")));
        String family24 = UpdateManager.familyOf("dovecot24-mysql");
        check("dovecot24-mysql and dovecot24-pigeonhole-mysql move together (same family)",
                family24 != null && family24.equals(UpdateManager.familyOf("dovecot24-pigeonhole-mysql")));
        // Reperto 203: the overview hands the family to the page, which makes it ONE step of the Packages row. On the
        // real server 27 of the 30 mail server updates were php84 and its extensions.
        String php = UpdateManager.familyOf("php84");
        check("php84 and its extensions are one family (php84-ctype, php84-pdo_mysql)", php != null
                && php.equals(UpdateManager.familyOf("php84-ctype")) && php.equals(UpdateManager.familyOf("php84-pdo_mysql")));
        check("  with the reason the page can say", !UpdateManager.familyReason("php84-ctype").isEmpty());
        check("  but Roundcube for PHP 8.4 is not in it, nor is a package alone", UpdateManager.familyOf("roundcube-php84") == null
                && UpdateManager.familyOf("nginx") == null && UpdateManager.familyOf("redis") == null);
    }

    // ------------------------------------------------------------------ tools

    /** The script's installation lines, each as a list of packages. */
    static List<List<String>> installLines(String script) {
        List<List<String>> out = new ArrayList<>();
        for (String l : script.split("\n")) {
            String t = l.trim();
            String rest;
            if (t.startsWith("install_packages ")) rest = t.substring("install_packages ".length());
            else if (t.startsWith("pkg install -y ")) rest = t.substring("pkg install -y ".length());
            else continue;
            List<String> names = new ArrayList<>();
            for (String w : rest.split("\\s+")) {
                if (w.startsWith("2>") || w.equals("||") || w.equals("true") || w.equals("&&")) break;
                if (w.matches("[A-Za-z0-9._/+-]{1,80}")) names.add(w);
            }
            if (!names.isEmpty()) out.add(names);
        }
        return out;
    }

    /** The text of the install_packages function as it is in the script, or "" if it is not there. */
    static String functionText(String script) {
        int a = script.indexOf("install_packages() {");
        if (a < 0) return "";
        int b = script.indexOf("\n}\n", a);
        return b < 0 ? "" : script.substring(a, b + 2);
    }

    static boolean onFreeBsdAsRoot() {
        return sh("uname -s", 10).trim().equals("FreeBSD") && sh("id -u", 10).trim().equals("0");
    }

    static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).output();
    }

    static String tail(String s, int n) {
        String[] l = s.split("\n");
        return String.join("\n", java.util.Arrays.copyOfRange(l, Math.max(0, l.length - n), l.length));
    }

    static String indent(String s) {
        return s.replaceAll("(?m)^", "           ");
    }
}
