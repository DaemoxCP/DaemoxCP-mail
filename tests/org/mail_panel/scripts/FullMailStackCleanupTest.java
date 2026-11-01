package org.mail_panel.scripts;

import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The cleanup of FullMailStackScript (the «all» installation) removes only the users it creates again itself: never
 * one of the base system, never the one of a package.
 *
 * The fault, measured on the FreeBSD 15.1 VM on 01/11/2026: phase 1 ran pw userdel on www, a base system user (uid
 * 80), and on the users of clamav, redis, mysql and rspamd. pw userdel www also took away the group www and www's
 * crontab. Only nginx's pre-install created it again, and the script never got there: with the panel running nginx is
 * locked (pkg delete and pkg install refuse it), and without locks the pkg install of step 7 failed whole because
 * php84-fpm was not in the catalog. At the end nginx -t said getpwnam("www") failed. mysql belongs to mysql84-server,
 * which the cleanup does not remove.
 *
 * What is tested here:
 *  - the text: every user and every group phase 1 removes, phase 2 creates again with pw useradd or pw groupadd, and
 *    none belongs to the base system (the stock master.passwd and group, the ones etcupdate keeps). The line
 *    recogniser is tried first on a known text, because one that sees nothing would make everything green;
 *  - the cleanup's pw lines run for real, with pw -R on a copy of the stock users plus the packages' users and vmail:
 *    www, its group and the packages' users stay, and exactly what the lines name goes away. The machine's own users
 *    are not touched, and the test checks it.
 *
 * As root on the VM (pw -R writes the files and calls pwd_mkdb):
 *   javac -cp &lt;dir&gt;/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/scripts/FullMailStackCleanupTest.java
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.FullMailStackCleanupTest
 */
public class FullMailStackCleanupTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The base system's users and groups as FreeBSD installs them, without packages. */
    static final Path BASE_PASSWD = Path.of("/var/db/etcupdate/current/etc/master.passwd");
    static final Path BASE_GROUP = Path.of("/var/db/etcupdate/current/etc/group");

    /** The packages' users the cleanup used to remove, with their uid on the VM. */
    static final Map<String, String> PACKAGE_USERS = Map.of("clamav", "106", "redis", "535", "mysql", "88", "rspamd", "236");

    static final String NAME = "([A-Za-z_][A-Za-z0-9_-]*)";
    static final Pattern USER_DEL = Pattern.compile("\\b(?:pw\\s+(?:userdel|user\\s+del)|rmuser(?:\\s+-y)?)\\s+(?:-n\\s+)?" + NAME);
    static final Pattern GROUP_DEL = Pattern.compile("\\bpw\\s+(?:groupdel|group\\s+del)\\s+(?:-n\\s+)?" + NAME);
    static final Pattern USER_ADD = Pattern.compile("\\bpw\\s+(?:useradd|user\\s+add)\\s+(?:-n\\s+)?" + NAME);
    static final Pattern GROUP_ADD = Pattern.compile("\\bpw\\s+(?:groupadd|group\\s+add)\\s+(?:-n\\s+)?" + NAME);

    /** The only pw lines that may run with pw -R: nothing else touches the machine. */
    static final Pattern RUNNABLE = Pattern.compile("\\s*pw\\s+(?:userdel|groupdel|user\\s+del|group\\s+del)\\s+" + NAME
            + "(?:\\s+2>/dev/null)?(?:\\s*\\|\\|\\s*true)?\\s*");

    /** The lines that are not comments: a comment about pw userdel removes nothing. */
    static List<String> commandLines(String script) {
        return script.lines().filter(l -> !l.strip().startsWith("#")).toList();
    }

    static Set<String> names(Pattern p, String script) {
        Set<String> r = new TreeSet<>();
        for (String line : commandLines(script)) {
            Matcher m = p.matcher(line);
            while (m.find()) r.add(m.group(1));
        }
        return r;
    }

    /** The names in the first column of a master.passwd or a group file. */
    static Map<String, String> entries(Path file) throws Exception {
        Map<String, String> r = new TreeMap<>();
        for (String l : Files.readAllLines(file)) {
            if (l.isBlank() || l.startsWith("#")) continue;
            String[] f = l.split(":", -1);
            // master.passwd: name:password:uid:gid:...  group: name:password:gid:members
            r.put(f[0], f.length > 9 ? f[2] + ":" + f[3] : f[2]);
        }
        return r;
    }

    record Run(int code, String out) {}

    static Run run(Map<String, String> env, String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
        pb.environment().putAll(env);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new Run(p.waitFor(), out);
    }

    static String sha256(Path file) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name")) || !System.getProperty("os.name").contains("FreeBSD")) {
            OUT.println("This test runs pw -R and pwd_mkdb: run it as root on the FreeBSD VM.");
            System.exit(2);
        }
        if (!Files.isReadable(BASE_PASSWD) || !Files.isReadable(BASE_GROUP)) {
            check("the stock master.passwd and group are there (" + BASE_PASSWD.getParent() + ")", false);
            OUT.println("\n" + failed + " FAILED");
            System.exit(1);
        }

        OUT.println("== The line recogniser");
        String known = "pw userdel a 2>/dev/null || true\n  x || pw user del -n b\nrmuser -y c\n# pw userdel d\n"
                + "pw groupdel e\npw usershow f || pw useradd f -g f\npw group add g -g 7\n";
        check("it sees pw userdel, pw user del and rmuser, not the comments", names(USER_DEL, known).equals(Set.of("a", "b", "c")));
        check("it sees pw groupdel", names(GROUP_DEL, known).equals(Set.of("e")));
        check("it sees pw useradd after ||, and pw group add", names(USER_ADD, known).equals(Set.of("f"))
                && names(GROUP_ADD, known).equals(Set.of("g")));
        check("a plain pw line may run, one with anything else may not",
                RUNNABLE.matcher("            pw userdel vmail 2>/dev/null || true").matches()
                && !RUNNABLE.matcher("pw userdel vmail; rm -rf /x").matches()
                && !RUNNABLE.matcher("rmuser -y www").matches());

        OUT.println("\n== The script's text");
        String script = new FullMailStackScript().getScriptContent();
        int phase2 = script.indexOf("PHASE 2: FRESH INSTALLATION");
        check("phase 1 and phase 2 are found", phase2 > 0);
        String cleanup = phase2 > 0 ? script.substring(0, phase2) : script;
        String install = phase2 > 0 ? script.substring(phase2) : "";

        Map<String, String> baseUsers = entries(BASE_PASSWD), baseGroups = entries(BASE_GROUP);
        check("the base system is read: www with uid 80 and gid 80, and the group www with gid 80",
                "80:80".equals(baseUsers.get("www")) && "80".equals(baseGroups.get("www")));

        Set<String> deletedUsers = names(USER_DEL, cleanup), deletedGroups = names(GROUP_DEL, cleanup);
        Set<String> createdUsers = names(USER_ADD, install), createdGroups = names(GROUP_ADD, install);
        OUT.println("     the cleanup removes the users " + deletedUsers + " and the groups " + deletedGroups);
        OUT.println("     the installation creates the users " + createdUsers + " and the groups " + createdGroups);
        check("the installation creates vmail (the net sees the script's pw lines)", createdUsers.contains("vmail"));
        check("www is not removed", !deletedUsers.contains("www"));
        check("the group www is not removed (nginx opens Roundcube's socket with it)", !deletedGroups.contains("www"));
        for (String u : deletedUsers) {
            check("user " + u + ": not a base system user", !baseUsers.containsKey(u));
            check("user " + u + ": phase 2 creates it again with pw useradd", createdUsers.contains(u));
        }
        for (String g : deletedGroups) {
            check("group " + g + ": not a base system group", !baseGroups.containsKey(g));
            check("group " + g + ": phase 2 creates it again with pw groupadd", createdGroups.contains(g));
        }

        OUT.println("\n== The cleanup's pw lines, run with pw -R on a copy");
        List<String> pwLines = new ArrayList<>();
        for (String l : commandLines(cleanup))
            if (USER_DEL.matcher(l).find() || GROUP_DEL.matcher(l).find()) pwLines.add(l);
        boolean runnable = pwLines.stream().allMatch(l -> RUNNABLE.matcher(l).matches());
        check("every line removing users or groups is a plain pw (" + pwLines.size() + " lines)", runnable);
        if (!runnable) {
            pwLines.stream().filter(l -> !RUNNABLE.matcher(l).matches()).forEach(l -> OUT.println("     not run: " + l.strip()));
        } else {
            Path machinePasswd = Path.of("/etc/master.passwd"), machineGroup = Path.of("/etc/group");
            String machineBefore = sha256(machinePasswd) + sha256(machineGroup);
            Path root = Files.createTempDirectory(Path.of("/var/tmp"), "stack-cleanup-");
            try {
                Path etc = Files.createDirectories(root.resolve("etc"));
                Files.copy(BASE_PASSWD, etc.resolve("master.passwd"));
                Files.setPosixFilePermissions(etc.resolve("master.passwd"), PosixFilePermissions.fromString("rw-------"));
                Files.copy(BASE_GROUP, etc.resolve("group"));
                Run mkdb = run(Map.of(), "pwd_mkdb", "-d", etc.toString(), "-p", etc.resolve("master.passwd").toString());
                check("pwd_mkdb on the copy" + (mkdb.code() == 0 ? "" : ": " + mkdb.out().strip()), mkdb.code() == 0);
                boolean added = true;
                Map<String, String> toAdd = new TreeMap<>(PACKAGE_USERS);
                toAdd.put("vmail", "5000");
                for (Map.Entry<String, String> e : toAdd.entrySet()) {
                    added &= run(Map.of(), "pw", "-R", root.toString(), "groupadd", e.getKey(), "-g", e.getValue()).code() == 0;
                    added &= run(Map.of(), "pw", "-R", root.toString(), "useradd", e.getKey(), "-u", e.getValue(), "-g", e.getValue(),
                            "-d", "/nonexistent", "-s", "/usr/sbin/nologin").code() == 0;
                }
                check("the copy has the packages' users and vmail", added);
                Map<String, String> usersBefore = entries(etc.resolve("master.passwd")), groupsBefore = entries(etc.resolve("group"));

                Path sh = root.resolve("cleanup-users.sh");
                Files.writeString(sh, "pw() { /usr/sbin/pw -R \"$ROOT\" \"$@\"; }\n" + String.join("\n", pwLines) + "\n");
                Run cleaned = run(Map.of("ROOT", root.toString()), "/bin/sh", sh.toString());
                check("the lines run (exit " + cleaned.code() + ")", cleaned.code() == 0);
                Map<String, String> usersAfter = entries(etc.resolve("master.passwd")), groupsAfter = entries(etc.resolve("group"));

                check("www stays, with uid 80 and gid 80", "80:80".equals(usersAfter.get("www")));
                check("the group www stays, with gid 80", "80".equals(groupsAfter.get("www")));
                List<String> baseChanged = baseUsers.keySet().stream()
                        .filter(u -> !java.util.Objects.equals(usersBefore.get(u), usersAfter.get(u))).toList();
                check("no base system user changes " + (baseChanged.isEmpty() ? "" : baseChanged), baseChanged.isEmpty());
                List<String> baseGroupsChanged = baseGroups.keySet().stream()
                        .filter(g -> !java.util.Objects.equals(groupsBefore.get(g), groupsAfter.get(g))).toList();
                check("no base system group changes " + (baseGroupsChanged.isEmpty() ? "" : baseGroupsChanged), baseGroupsChanged.isEmpty());
                for (String u : PACKAGE_USERS.keySet())
                    check("the user " + u + " of its package stays", usersAfter.containsKey(u) && groupsAfter.containsKey(u));
                Set<String> goneUsers = new TreeSet<>(usersBefore.keySet());
                goneUsers.removeAll(usersAfter.keySet());
                check("exactly the users the lines name go away " + goneUsers, goneUsers.equals(deletedUsers));
            } finally {
                try (Stream<Path> s = Files.walk(root)) {
                    s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
                }
            }
            check("the machine's users and groups were not touched",
                    machineBefore.equals(sha256(machinePasswd) + sha256(machineGroup)));
        }

        OUT.println("\n" + (failed == 0 ? "ALL OK" : failed + " FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
