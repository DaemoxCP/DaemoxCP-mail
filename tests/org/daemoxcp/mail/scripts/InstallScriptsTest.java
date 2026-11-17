package org.daemoxcp.mail.scripts;

import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * The installation scripts on disk are always those of the running jar (InstallScripts, reperto 169).
 *
 *  1. Writing is all or nothing: whoever opened the old script (a script that is running) keeps
 *     reading its own; the new one is there whole, 700, with no temporary files left.
 *  2. An old script on disk is rewritten (before, six classes out of seven wrote "only if missing").
 *  3. The scripts nobody writes any more are set aside (.retired); repeating changes nothing; with a
 *     .retired already next to it both are left.
 *  4. The jar's fingerprint and the check sit right after the #! line, even where the #! was indented.
 *  5. With -De2e.vm=yes (VM, root): a real start of the panel (Main --create-admin without arguments:
 *     it goes through the start and stops on the usage) rewrites the old script and sets aside the retired ones.
 * Everything in a temporary folder as the panel's folder.
 *
 * Usage: java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.scripts.InstallScriptsTest
 */
public class InstallScriptsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }
        Path d = Files.createTempDirectory("install-scripts");
        try {
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process p = new ProcessBuilder(java, "-cp", absolute(System.getProperty("java.class.path")),
                    InstallScriptsTest.class.getName(), "child").directory(d.toFile()).inheritIO().start();
            int code = p.waitFor();
            if (code != 0) failed++;
            if ("yes".equals(System.getProperty("e2e.vm"))) wiring(d);
            else System.out.println("\n(skipped: the real start of the panel, it needs -De2e.vm=yes)");
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Checks 1-4, with the temporary folder as the current folder. */
    static void child(String[] a) throws Exception {
        Path dir = Path.of(InstallScripts.DIR);
        Files.createDirectories(dir);

        System.out.println("== 1. All or nothing, even with the old script open ==");
        Path script = dir.resolve("install_mail_server.sh");
        Files.writeString(script, "#!/bin/sh\necho before\n");
        try (RandomAccessFile running = new RandomAccessFile(script.toFile(), "r")) {
            check("rewritten", InstallScripts.write(script.toString(), "#!/bin/sh\necho after, much longer than before\n"));
            byte[] b = new byte[(int) running.length()];
            running.readFully(b);
            check("whoever had it open still reads the old one", new String(b, StandardCharsets.UTF_8).equals("#!/bin/sh\necho before\n"));
        }
        String now = Files.readString(script);
        check("the new one is there whole", now.startsWith("#!/bin/sh\n") && now.endsWith("echo after, much longer than before\n"));
        check("700", PosixFilePermissions.toString(Files.getPosixFilePermissions(script)).equals("rwx------"));
        check("no temporary file left", !Files.exists(dir.resolve("install_mail_server.sh.tmp")));

        System.out.println("\n== 2. An old script is rewritten ==");
        Files.writeString(script, "#!/bin/sh\n# a script from an older version\nexit 42\n");
        Path tz = dir.resolve("setup_timezone_and_dns.sh");
        Files.writeString(tz, "#!/bin/sh\n# old as well\nexit 43\n");
        InstallScripts.refreshAtStartup();
        String fresh = new FullMailServerScript().getScriptContent();
        check("install_mail_server.sh is the jar's", Files.readString(script).equals(InstallScripts.stamped(fresh)));
        check("setup_timezone_and_dns.sh is the jar's", !Files.readString(tz).contains("exit 43")
                && Files.readString(tz).contains("System Time and DNS Configuration"));

        System.out.println("\n== 3. The scripts nobody writes any more ==");
        List<Path> old = new ArrayList<>();
        for (String n : InstallScripts.RETIRED) {
            Path f = dir.resolve(n);
            Files.writeString(f, "#!/bin/sh\n# from an older version\n");
            old.add(f);
        }
        InstallScripts.refreshAtStartup();
        boolean allAside = true;
        for (Path f : old) allAside &= !Files.exists(f) && Files.exists(Path.of(f + ".retired"));
        check("all five set aside, with their content", allAside
                && Files.readString(Path.of(old.get(0) + ".retired")).contains("from an older version"));
        InstallScripts.refreshAtStartup();
        check("repeating changes nothing", allAside && old.stream().noneMatch(Files::exists));
        Files.writeString(old.get(0), "#!/bin/sh\n# back again\n");
        InstallScripts.refreshAtStartup();
        check("with a .retired already next to it: both stay", Files.exists(old.get(0)) && Files.exists(Path.of(old.get(0) + ".retired")));

        System.out.println("\n== 4. The fingerprint and the check after the #! ==");
        String s = InstallScripts.stamped("#!/bin/sh\necho x\n");
        check("the #! line stays the first", s.startsWith("#!/bin/sh\n# --- Written by DaemoxCP Mail"));
        check("the fingerprint is the running jar's", s.contains("DAEMOXCP_MAIL_WRITTEN_BY_JAR=\"" + InstallScripts.jarSha256() + "\"")
                && InstallScripts.jarSha256().matches("[0-9a-f]{64}"));
        check("an indented #! goes back to the start of the file", Files.readString(tz).startsWith("#!/bin/sh\n# --- Written by DaemoxCP Mail"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** 5: the real start of the panel (Main.main) rewrites and sets aside. */
    static void wiring(Path d) throws Exception {
        System.out.println("\n== 5. A real start of the panel ==");
        Path panel = d.resolve("panel");
        Path dir = panel.resolve("install_scripts");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("install_mail_server.sh"), "#!/bin/sh\nexit 42\n");
        Files.writeString(dir.resolve("install_dovecot.sh"), "#!/bin/sh\n# old\n");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-Ddaemoxcp.mail.secrets.dir=" + d.resolve("secrets"), "-cp",
                absolute(System.getProperty("java.class.path")), "org.daemoxcp.mail.Main", "--create-admin")
                .directory(panel.toFile()).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        check("the panel started and stopped on the usage", out.contains("Usage"));
        check("the old script is rewritten", !Files.readString(dir.resolve("install_mail_server.sh")).contains("exit 42"));
        check("the retired one is set aside", !Files.exists(dir.resolve("install_dovecot.sh"))
                && Files.exists(dir.resolve("install_dovecot.sh.retired")));
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
        }
    }
}
