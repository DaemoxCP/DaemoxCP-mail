package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The backup copies of configuration files (ConfigBackups). Found walking every function of the 0.9.0 panel
 * (18/11/2026): every copy the panel made before changing a file stayed forever, 221 of /etc/pf.conf and 267 of the
 * firewall anchor on the real server. Now the latest ten of each file are kept.
 *
 *  1. The name of a copy: only the two forms the panel writes (13-digit milliseconds, or yyyyMMdd-HHmmss).
 *  2. copy(): beside the original, then the old ones beyond ten removed; names written by hand, links and folders
 *     with the name of a copy are left as they are; two copies in the same millisecond get two names.
 *  3. The fail2ban folder: prune before the new copy, so that with it they are ten.
 *  4. The first start: the copies left by the earlier versions removed once; the second start finds nothing.
 *  5. In the sources, every copy goes through ConfigBackups, and the first start calls it.
 *
 * Usage, from the folder with src/ and tests/:
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ConfigBackupsTest
 */
public class ConfigBackupsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("config-backups");
        try {
            names();
            copies(tmp.resolve("beside"));
            fail2banFolder(tmp.resolve("fail2ban"));
            firstStart(tmp.resolve("start"));
            sources();
        } finally {
            try (Stream<Path> s = Files.walk(tmp)) {
                for (Path p : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static void names() {
        System.out.println("== 1. The name of a copy ==");
        check("pf.conf.bak.<13 digits> is a copy of pf.conf", copyOf("pf.conf.bak.1795016660000", "pf.conf"));
        check("mail.local.bak.<yyyyMMdd-HHmmss> is a copy of mail.local", copyOf("mail.local.bak.20261118-101010", "mail.local"));
        for (String other : List.of("pf.conf.bak", "pf.conf.bak.20250101", "pf.conf.bak.179501666000", "pf.conf.bak.17950166600001",
                "pf.conf.bak.1795016660000.tmp", "pf.conf.orig", "jail.local.before-pf-20261118-101010", "pf.conf.bak.2026111-101010"))
            check("not a copy: " + other, !ConfigBackups.COPY.matcher(other).matches());
        check("the time in the name orders the copies (milliseconds)",
                ConfigBackups.moment(Path.of("x.bak.1795016660000")) < ConfigBackups.moment(Path.of("x.bak.1795016660001")));
        check("the time in the name orders the copies (date and time)",
                ConfigBackups.moment(Path.of("x.bak.20261118-095959")) < ConfigBackups.moment(Path.of("x.bak.20261118-100000")));
    }

    static boolean copyOf(String file, String name) {
        var m = ConfigBackups.COPY.matcher(file);
        return m.matches() && m.group(1).equals(name);
    }

    static void copies(Path dir) throws Exception {
        System.out.println("\n== 2. copy(): beside the original, the latest ten kept ==");
        Files.createDirectories(dir);
        Path original = dir.resolve("pf.conf");
        Files.writeString(original, "rules now\n");
        long t0 = System.currentTimeMillis() - 1_000_000;
        for (int i = 0; i < 14; i++) Files.writeString(dir.resolve("pf.conf.bak." + (t0 + i)), "old " + i + "\n");
        // Names written by hand, another file's copy, a folder and a link with the name of a copy (older than all)
        List<String> others = List.of("pf.conf.bak", "pf.conf.bak.20250101", "pf.conf.orig", "other.conf.bak." + (t0 - 5));
        for (String o : others) Files.writeString(dir.resolve(o), "by hand\n");
        Path folder = dir.resolve("pf.conf.bak." + (t0 - 2));
        Files.createDirectory(folder);
        Path link = dir.resolve("pf.conf.bak." + (t0 - 1));
        Files.createSymbolicLink(link, original);

        Path made = ConfigBackups.copy(original);
        check("the copy is beside the original, named pf.conf.bak.<milliseconds>",
                made.getParent().equals(dir) && copyOf(made.getFileName().toString(), "pf.conf"));
        check("the copy has the content of the original", Files.readString(made).equals("rules now\n"));
        List<Path> kept = ConfigBackups.copiesOf(dir, "pf.conf");
        check("ten copies left (" + kept.size() + ")", kept.size() == ConfigBackups.KEEP);
        check("the newest is the one just made", kept.get(kept.size() - 1).equals(made));
        boolean newestPlanted = true;
        for (int i = 0; i < 14; i++) newestPlanted &= Files.exists(dir.resolve("pf.conf.bak." + (t0 + i))) == (i >= 5);
        check("the nine kept with it are the newest planted, the five oldest are gone", newestPlanted);
        boolean othersThere = true;
        for (String o : others) othersThere &= Files.readString(dir.resolve(o)).equals("by hand\n");
        check("names written by hand and another file's copies are left as they are", othersThere);
        check("a folder with the name of a copy is left", Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
        check("a link with the name of a copy is left, and the file it points to too",
                Files.isSymbolicLink(link) && Files.readString(original).equals("rules now\n"));

        Path a = ConfigBackups.copy(original), b = ConfigBackups.copy(original);
        check("two copies one after the other: two names", !a.equals(b) && Files.exists(a) && Files.exists(b));
        check("still ten", ConfigBackups.copiesOf(dir, "pf.conf").size() == ConfigBackups.KEEP);

        FileTime when = FileTime.fromMillis(1_700_000_000_000L);
        Files.setLastModifiedTime(original, when);
        Path withTime = ConfigBackups.copy(original, StandardCopyOption.COPY_ATTRIBUTES);
        check("the copy options are passed on (COPY_ATTRIBUTES keeps the time, as PfPolicy asks)",
                Files.getLastModifiedTime(withTime).equals(when));
    }

    static void fail2banFolder(Path folder) throws Exception {
        System.out.println("\n== 3. The fail2ban folder: pruned before the new copy ==");
        Files.createDirectories(folder);
        for (int i = 0; i < 14; i++) Files.writeString(folder.resolve(String.format("mail.local.bak.20261118-10%02d00", i)), "jail " + i);
        Files.writeString(folder.resolve("jail.local.bak.20261118-090000"), "jail");
        Files.writeString(folder.resolve("mail.local.before-pf-20261118-080000"), "one-off copy of BanActionRepair");
        int removed = ConfigBackups.prune(folder, "mail.local", ConfigBackups.KEEP - 1);
        List<Path> left = ConfigBackups.copiesOf(folder, "mail.local");
        check("five removed, nine left for the new one to make ten (" + removed + ", " + left.size() + ")", removed == 5 && left.size() == 9);
        check("the nine left are the newest", left.get(0).getFileName().toString().equals("mail.local.bak.20261118-100500"));
        check("another file's copies in the folder are left", Files.exists(folder.resolve("jail.local.bak.20261118-090000")));
        check("the one-off copies of BanActionRepair are left", Files.exists(folder.resolve("mail.local.before-pf-20261118-080000")));
    }

    static void firstStart(Path dir) throws Exception {
        System.out.println("\n== 4. The first start: the copies of the earlier versions ==");
        Path etc = dir.resolve("etc"), folder = dir.resolve("fail2ban-backups");
        Files.createDirectories(etc);
        Files.createDirectories(folder);
        long t0 = System.currentTimeMillis() - 10_000_000;
        Files.writeString(etc.resolve("a.conf"), "a");
        for (int i = 0; i < 25; i++) Files.writeString(etc.resolve("a.conf.bak." + (t0 + i)), "a" + i);
        Files.writeString(etc.resolve("b.conf"), "b");
        for (int i = 0; i < 3; i++) Files.writeString(etc.resolve("b.conf.bak." + (t0 + i)), "b" + i);
        for (int i = 0; i < 14; i++) Files.writeString(folder.resolve(String.format("mail.local.bak.20261118-10%02d00", i)), "m" + i);
        for (int i = 0; i < 2; i++) Files.writeString(folder.resolve("jail.local.bak.20261118-09000" + i), "j" + i);
        Files.writeString(folder.resolve("jail.local.before-pf-20261118-080000"), "one-off");
        List<Path> beside = List.of(etc.resolve("a.conf"), etc.resolve("b.conf"), etc.resolve("missing.conf"));

        String done = ConfigBackups.clean(beside, folder);
        check("the report says what was removed (" + done + ")",
                done.contains(etc.resolve("a.conf") + " 15") && done.contains(folder.resolve("mail.local") + " 4") && !done.contains("b.conf"));
        check("a.conf: ten left", ConfigBackups.copiesOf(etc, "a.conf").size() == 10);
        check("b.conf: its three left", ConfigBackups.copiesOf(etc, "b.conf").size() == 3);
        check("fail2ban mail.local: ten left", ConfigBackups.copiesOf(folder, "mail.local").size() == 10);
        check("fail2ban jail.local: its two left", ConfigBackups.copiesOf(folder, "jail.local").size() == 2);
        check("the one-off copy is left", Files.exists(folder.resolve("jail.local.before-pf-20261118-080000")));
        check("the second start finds nothing to do", ConfigBackups.clean(beside, folder).isEmpty());
        check("folders that are not there: nothing, no error",
                ConfigBackups.clean(List.of(dir.resolve("none/x.conf")), dir.resolve("none-folder")).isEmpty());
    }

    static void sources() throws Exception {
        System.out.println("\n== 5. In the sources ==");
        Path src = Path.of("src/main/java");
        if (!Files.isDirectory(src)) {
            check("the sources are here (run from the folder with src/)", false);
            return;
        }
        // A string ending in ".bak." followed by + (or by the end of the line, continued on the next): a copy name built
        Pattern built = Pattern.compile("\"[^\"]*\\.bak\\.\"\\s*(\\+|$)");
        List<String> outside = new ArrayList<>();
        try (Stream<Path> s = Files.walk(src)) {
            for (Path f : s.filter(p -> p.toString().endsWith(".java")).toList()) {
                String file = f.getFileName().toString();
                if (file.equals("ConfigBackups.java")) continue;
                List<String> lines = Files.readAllLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String t = lines.get(i).trim();
                    if (t.startsWith("//") || t.startsWith("*")) continue;
                    if (built.matcher(t).find() && !file.equals("Fail2banManager.java")) outside.add(file + ":" + (i + 1));
                }
            }
        }
        check("no copy name built outside ConfigBackups " + outside, outside.isEmpty());
        String f2b = Files.readString(src.resolve("org/daemoxcp/mail/security/Fail2banManager.java"));
        int at = f2b.indexOf("private Path backupCopy(");
        check("Fail2banManager.backupCopy prunes the folder before the new copy",
                at > 0 && f2b.indexOf("ConfigBackups.prune(", at) > at && f2b.indexOf("ConfigBackups.prune(", at) < f2b.indexOf("return dir.resolve(", at));
        String server = Files.readString(src.resolve("org/daemoxcp/mail/webserver/SSLMailServer.java"));
        check("the first start calls ConfigBackups.ensureAtBoot()", server.contains("org.daemoxcp.mail.system.ConfigBackups.ensureAtBoot();"));
        Path cbFile = src.resolve("org/daemoxcp/mail/system/ConfigBackups.java");
        String cb = Files.exists(cbFile) ? Files.readString(cbFile) : "";
        boolean listed = true;
        for (String p : List.of("/etc/pf.conf", "/etc/pf.anchors/panel-fw.conf", "/etc/sysctl.conf", "/etc/resolv.conf",
                "/usr/local/etc/unbound/unbound.conf", "/var/unbound/unbound.conf", "/var/unbound/forward.conf",
                "/usr/local/etc/rspamd/local.d/antivirus.conf"))
            listed &= cb.contains("Path.of(\"" + p + "\")");
        check("every file the panel copies beside itself is in the list of the first start", listed);
    }
}
