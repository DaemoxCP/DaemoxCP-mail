package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.integration.SieveGeneratorTest;
import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Pigeonhole's sievec run as the user sievec, never as root (finding 218, SieveCompiler).
 *
 *  1. What can be proven without a system: the binary's name beside the script; the minimal configuration (empty for
 *     Dovecot 2.3, the two version lines of the panel's own 2.4 dovecot.conf, nothing that is not a version number);
 *     sievec's output read as a refusal only when it names a line of the script (an unreadable or missing script is
 *     not a refusal: measured, it exits 89 like a syntax error); the command runs through chroot as sievec with only
 *     its group; the environment carries nothing of root's; the user sievec is accepted only as the panel creates it.
 *  2. With -De2e.vm=yes, as root on the VM: a script of the panel in a folder like /var/mail/sieve compiles, and its
 *     binary is installed beside it with the script's owner, group and mode, newer than the script, byte for byte what
 *     root's sievec makes with Dovecot's real configuration; a script with an error is refused and the binary of before
 *     stays; a script sievec cannot read, a folder others can write and a link are not compiled and nothing is
 *     installed; validate() says the same as root's sievec on three texts; no working folder is left behind.
 *
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveCompilerTest
 */
public class SieveCompilerTest {

    private static int failures = 0;

    /** sievec's output, as measured on the VM (Dovecot 2.3.21, Pigeonhole 0.5.21). */
    static final String SYNTAX_ERROR = "bad: line 2: error: expected end of command ';' or the beginning of a compound block '{', but found '}'.\n"
            + "bad: error: parse failed.\nsievec(nobody): Fatal: failed to compile sieve script '/var/tmp/sievec-probe/s/bad.sieve'\n";
    static final String UNKNOWN_EXTENSION = "ext: line 1: error: require command: unknown Sieve capability `vnd.dovecot.pipe'.\n"
            + "ext: error: validation failed.\nsievec(nobody): Fatal: failed to compile sieve script '/var/tmp/x/ext.sieve'\n";
    static final String UNREADABLE = "sievec(nobody): Error: sieve: file storage: script: Failed to open sieve script: "
            + "open(/var/tmp/sievec-probe/s/priv.sieve) failed: Permission denied (euid=65534(nobody) egid=65534(nobody) missing +r perm: "
            + "/var/tmp/sievec-probe/s/priv.sieve, dir owned by 0:0 mode=0755)\npriv: error: parse failed.\n"
            + "sievec(nobody): Fatal: failed to compile sieve script '/var/tmp/sievec-probe/s/priv.sieve'\n";
    static final String MISSING = "error: script not found.\nsievec(nobody): Fatal: failed to compile sieve script '/var/tmp/none.sieve'\n";
    static final String NO_CONFIG = "doveconf: Fatal: Error in configuration file /usr/local/etc/dovecot/conf.d/10-auth.conf line 7: "
            + "Couldn't open include file /usr/local/etc/dovecot/conf.d/auth-sql.conf.ext: Permission denied\n";

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. Without a system ==");
        check("the panel's script: .dovecot.sieve -> .dovecot.svbin",
                SieveCompiler.binaryFor(Path.of("/var/mail/sieve/example.test/alice/.dovecot.sieve"))
                        .equals(Path.of("/var/mail/sieve/example.test/alice/.dovecot.svbin")));
        check("a named script: rules.sieve -> rules.svbin", SieveCompiler.binaryFor(Path.of("/x/rules.sieve")).equals(Path.of("/x/rules.svbin")));
        check("not a .sieve, or no name before it: nothing", SieveCompiler.binaryFor(Path.of("/x/rules.txt")) == null
                && SieveCompiler.binaryFor(Path.of("/x/.sieve")) == null);

        String conf24 = DovecotConfig.file24().stream().filter(f -> f.path().equals("dovecot.conf")).findFirst().orElseThrow().content();
        check("Dovecot 2.4, the panel's dovecot.conf: the two version lines, nothing else",
                SieveCompiler.minimalConfig(conf24).equals("dovecot_config_version = 2.4.0\ndovecot_storage_version = 2.4.0\n"));
        check("Dovecot 2.3 (no version line): an empty configuration",
                SieveCompiler.minimalConfig("protocols = imap lmtp sieve\n!include conf.d/*.conf\n").isEmpty());
        check("a version line in a comment does not count",
                SieveCompiler.minimalConfig("# dovecot_config_version = 2.4.0\nprotocols = imap\n").isEmpty());
        check("anything but a version number does not pass",
                SieveCompiler.minimalConfig("dovecot_config_version = 2.4.0 \"\n!include /etc/x\n").isEmpty()
                && SieveCompiler.minimalConfig("dovecot_config_version = 2.4.0\ndovecot_storage_version = </etc/x\n")
                        .equals("dovecot_config_version = 2.4.0\n"));
        check("no file: an empty configuration", SieveCompiler.minimalConfig(null).isEmpty());

        check("a syntax error: refused", SieveCompiler.failed(SYNTAX_ERROR).status() == SieveCompiler.Status.REFUSED);
        check("an extension Dovecot does not have: refused", SieveCompiler.failed(UNKNOWN_EXTENSION).refused());
        check("a script sievec cannot read: not compiled, not refused", SieveCompiler.failed(UNREADABLE).status() == SieveCompiler.Status.NOT_COMPILED);
        check("a missing script: not compiled", SieveCompiler.failed(MISSING).status() == SieveCompiler.Status.NOT_COMPILED);
        check("Dovecot's configuration not readable: not compiled", SieveCompiler.failed(NO_CONFIG).status() == SieveCompiler.Status.NOT_COMPILED);
        check("no output at all: not compiled", SieveCompiler.failed("").status() == SieveCompiler.Status.NOT_COMPILED);

        List<String> cmd = SieveCompiler.asCompiler("/usr/local/bin/sievec", "-c", "/tmp/w/dovecot.conf", "/a.sieve", "/tmp/w/out/x.svbin");
        check("the command: chroot as sievec, only its group, root /, then sievec with its arguments (" + String.join(" ", cmd) + ")",
                cmd.subList(0, 8).equals(List.of("/usr/sbin/chroot", "-u", "sievec", "-g", "sievec", "-G", "sievec", "/"))
                && cmd.subList(8, cmd.size()).equals(List.of("/usr/local/bin/sievec", "-c", "/tmp/w/dovecot.conf", "/a.sieve", "/tmp/w/out/x.svbin")));
        check("no root anywhere in the command", cmd.stream().noneMatch(a -> a.equals("root") || a.equals("0") || a.equals("wheel")));
        check("the environment: only PATH, HOME, USER and LOGNAME, none of them root's",
                SieveCompiler.ENVIRONMENT.keySet().equals(java.util.Set.of("PATH", "HOME", "USER", "LOGNAME"))
                && SieveCompiler.ENVIRONMENT.get("USER").equals("sievec") && SieveCompiler.ENVIRONMENT.get("HOME").equals("/nonexistent")
                && SieveCompiler.ENVIRONMENT.values().stream().noneMatch(v -> v.contains("root")));

        String good = "sievec:*:1005:1005::0:0:DaemoxCP Mail Sieve compiler:/nonexistent:/usr/sbin/nologin";
        String group = "sievec:*:1005:";
        check("the user sievec as the panel creates it: accepted", SieveCompiler.COMPILER_USER.problem(good, group) == null);
        String[][] bad = {
                {good.replace("DaemoxCP Mail Sieve compiler", "Someone"), group, "comment"},
                {good.replace("/usr/sbin/nologin", "/bin/sh"), group, "shell"},
                {good.replace(":1005:1005:", ":0:1005:"), group, "uid 0"},
                {good, "sievec:*:1005:vmail", "other members"},
                {good, "sievec:*:6:", "group"}};
        for (String[] b : bad) {
            String why = SieveCompiler.COMPILER_USER.problem(b[0], b[1]);
            check("refused, " + b[2] + ": " + why, why != null && why.contains(b[2]));
        }

        if ("yes".equals(System.getProperty("e2e.vm")) && "root".equals(System.getProperty("user.name"))
                && SieveCompiler.sievec() != null) {
            onTheVm();
        } else {
            System.out.println("\n  (2. skipped: needs sievec, as root, turned on with -De2e.vm=yes on the VM)");
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void onTheVm() throws Exception {
        System.out.println("\n== 2. On the VM, as root ==");
        Path tmp = SieveCompiler.WORK_BASE;
        List<Path> before = workDirs(tmp);
        Path root = Files.createTempDirectory(Path.of("/var/tmp"), "sievec-test");
        try {
            // Like /var/mail/sieve: root's, 0755, a folder per domain and per mailbox.
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"));
            SieveGenerator generator = new SieveGenerator();
            String rules = generator.generateSieveScript(1, new SieveGeneratorTest.Rules().filter("spam", "move", "Junk")
                    .forward("bob@example.test", true).away("Away", "Back on Monday"));
            Path alice = write(root.resolve("example.test/alice/.dovecot.sieve"), rules);
            UserPrincipalLookupService names = alice.getFileSystem().getUserPrincipalLookupService();
            Files.setAttribute(alice, "posix:group", names.lookupPrincipalByGroupName("mail"));

            SieveCompiler.Outcome o = SieveCompiler.compile(alice);
            check("the panel's script compiles (" + o.status() + (o.message().isEmpty() ? "" : ": " + o.message()) + ")",
                    o.status() == SieveCompiler.Status.COMPILED);
            Path binary = alice.resolveSibling(".dovecot.svbin");
            check("  its binary is beside it", Files.isRegularFile(binary));
            if (Files.isRegularFile(binary)) {
                check("  with the script's owner, group and mode (" + attrs(binary) + ")", attrs(binary).equals(attrs(alice)));
                check("  newer than the script, as Pigeonhole wants",
                        Files.getLastModifiedTime(binary).compareTo(Files.getLastModifiedTime(alice)) > 0);
                Path reference = root.resolve("reference.svbin");
                Shell.Result r = Shell.run("/usr/local/bin/sievec", alice.toString(), reference.toString());
                check("  byte for byte what root's sievec makes with Dovecot's real configuration",
                        r.success() && Arrays.equals(Files.readAllBytes(binary), Files.readAllBytes(reference)));
            }
            check("  no temporary file left beside it", siblings(alice).equals(List.of(".dovecot.sieve", ".dovecot.svbin")));
            check("  the user sievec exists and is the panel's", SieveCompiler.COMPILER_USER.problem(
                    Shell.run("pw", "usershow", "sievec").outputTrim(), Shell.run("pw", "groupshow", "sievec").outputTrim()) == null);

            byte[] kept = Files.readAllBytes(binary);
            var keptTime = Files.getLastModifiedTime(binary);
            Thread.sleep(20);
            Files.writeString(alice, rules.replace("\"Junk\";", "\"Junk\""));
            SieveCompiler.Outcome refused = SieveCompiler.compile(alice);
            check("a script with an error: refused, with its line (" + firstLine(refused.message()) + ")",
                    refused.refused() && refused.message().contains(": line "));
            check("  the binary of before stays as it was", Arrays.equals(Files.readAllBytes(binary), kept)
                    && Files.getLastModifiedTime(binary).equals(keptTime));
            check("  and no temporary file", siblings(alice).equals(List.of(".dovecot.sieve", ".dovecot.svbin")));

            Path bob = write(root.resolve("example.test/bob/.dovecot.sieve"), rules);
            Files.setPosixFilePermissions(bob, PosixFilePermissions.fromString("rw-------"));
            SieveCompiler.Outcome unreadable = SieveCompiler.compile(bob);
            check("a script only root can read: not compiled, not refused (" + firstLine(unreadable.message()) + ")",
                    unreadable.status() == SieveCompiler.Status.NOT_COMPILED);
            check("  nothing installed", siblings(bob).equals(List.of(".dovecot.sieve")));

            Path carol = write(root.resolve("example.test/carol/.dovecot.sieve"), rules);
            Files.setPosixFilePermissions(carol.getParent(), PosixFilePermissions.fromString("rwxrwxr-x"));
            SieveCompiler.Outcome open = SieveCompiler.compile(carol);
            check("a folder others can write: not compiled (" + open.message() + ")",
                    open.status() == SieveCompiler.Status.NOT_COMPILED && open.message().contains("written by others"));
            check("  nothing installed", siblings(carol).equals(List.of(".dovecot.sieve")));

            Path dave = Files.createDirectories(root.resolve("example.test/dave"));
            Path daveLink = Files.createSymbolicLink(dave.resolve(".dovecot.sieve"), alice);
            SieveCompiler.Outcome link = SieveCompiler.compile(daveLink);
            check("a link: not compiled (" + link.message() + ")", link.status() == SieveCompiler.Status.NOT_COMPILED);
            check("  nothing installed", siblings(daveLink).equals(List.of(".dovecot.sieve")));

            String[][] texts = {
                    {"valid", rules},
                    {"a syntax error", "require \"fileinto\";\nif true { fileinto \"X\" }\n"},
                    {"an extension Dovecot does not have", "require \"vnd.dovecot.pipe\";\npipe \"x\";\n"}};
            for (String[] t : texts) {
                SieveCompiler.Outcome v = SieveCompiler.validate(t[1]);
                Path f = write(root.resolve("validate.sieve"), t[1]);
                boolean rootSays = Shell.run("/usr/local/bin/sievec", "-d", f.toString(), "/dev/null").success();
                check("validate, " + t[0] + ": " + v.status() + ", as root's sievec says (" + (rootSays ? "valid" : "invalid") + ")",
                        v.status() == (rootSays ? SieveCompiler.Status.COMPILED : SieveCompiler.Status.REFUSED));
            }

            check("no working folder left in " + tmp, workDirs(tmp).equals(before));
        } finally {
            new ProcessBuilder("rm", "-rf", root.toString()).start().waitFor();
        }
    }

    static List<Path> workDirs(Path tmp) throws Exception {
        try (Stream<Path> s = Files.list(tmp)) {
            return s.filter(p -> p.getFileName().toString().startsWith("sievec-")).sorted().toList();
        }
    }

    static List<String> siblings(Path p) throws Exception {
        try (Stream<Path> s = Files.list(p.getParent())) {
            return s.map(x -> x.getFileName().toString()).sorted().toList();
        }
    }

    static String attrs(Path p) throws Exception {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    static String firstLine(String s) {
        return s == null ? "" : s.lines().findFirst().orElse("");
    }

    static Path write(Path file, String content) throws Exception {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, content);
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }

}
