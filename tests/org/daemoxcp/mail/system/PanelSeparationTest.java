package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Set;

/**
 * The root part's preparation of the separated panel:
 *
 *  1. the user daemoxcp_mail is used only if it is the one the panel creates: the pw lines of a user with
 *     another comment, home or shell, a password, uid 0, another group, or a group with other members
 *     are refused, each with its reason;
 *  2. the daemon(8) line: the web part as daemoxcp_mail, supervised and restarted, pid files and log written
 *     by the supervisor, --web-part last, and the switch that turns the separation off never passed on;
 *  3. as root on the VM (-De2e.vm=yes): a folder opened to the web part is 0750 root:daemoxcp_mail, its data
 *     files 0640 root:daemoxcp_mail, and every other file in it loses group and other permissions; a symbolic
 *     link where a data file should be is refused. The group daemoxcp_mail is created if missing, and
 *     removed after.
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelSeparationTest
 */
public class PanelSeparationTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String mode(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    static String owner(Path p) throws Exception {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class);
        return a.owner().getName() + ":" + a.group().getName();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The user ==");
        String good = "daemoxcp_mail:*:1003:1003::0:0:DaemoxCP Mail web part:/nonexistent:/usr/sbin/nologin";
        String group = "daemoxcp_mail:*:1003:";
        check("the panel's own user is accepted", PanelSeparation.userProblem(good, group) == null);
        check("a locked account is accepted too", PanelSeparation.userProblem(good.replace(":*:", ":*LOCKED**:"), group) == null);
        String[][] bad = {
                {good.replace("DaemoxCP Mail web part", "Someone"), group, "comment"},
                {good.replace("/nonexistent", "/home/daemoxcp_mail"), group, "home"},
                {good.replace("/usr/sbin/nologin", "/bin/sh"), group, "shell"},
                {good.replace(":*:", ":$6$abc$def:"), group, "password"},
                {good.replace(":1003:1003:", ":0:1003:"), group, "uid 0"},
                {good, "daemoxcp_mail:*:1004:", "group"},
                {good, "daemoxcp_mail:*:1003:www", "other members"},
                {"", group, "cannot be read"}};
        for (String[] b : bad) {
            String why = PanelSeparation.userProblem(b[0], b[1]);
            check("refused, " + b[2] + ": " + why, why != null && why.contains(b[2]));
        }

        System.out.println("\n== 2. The daemon(8) line ==");
        List<String> cmd = PanelSeparation.command("/usr/local/openjdk25/bin/java", "/home/panel/daemoxcp-mail-1.0.jar");
        String line = String.join(" ", cmd);
        check("daemon runs the web part as daemoxcp_mail (" + line + ")", cmd.get(0).equals("/usr/sbin/daemon")
                && line.contains(" -u daemoxcp_mail ") && line.contains(" -r ") && line.contains(" -H "));
        check("the supervisor writes both pid files and the log", line.contains(" -P " + PanelSeparation.supervisorPid())
                && line.contains(" -p " + PanelSeparation.webPid()) && line.contains(" -o " + PanelSeparation.webLog));
        check("its title is the one stop() looks for", line.contains(" -t " + PanelSeparation.TITLE + " "));
        check("--web-part last, after the jar", cmd.get(cmd.size() - 1).equals("--web-part")
                && cmd.get(cmd.size() - 2).equals("/home/panel/daemoxcp-mail-1.0.jar") && cmd.get(cmd.size() - 3).equals("-jar"));
        check("the switch that turns the separation off is never passed on", cmd.stream().noneMatch(a -> a.startsWith("-Ddaemoxcp.mail.separation")));

        if ("yes".equals(System.getProperty("e2e.vm")) && "root".equals(System.getProperty("user.name"))) {
            System.out.println("\n== 3. A folder opened to the web part, as root ==");
            String g = PanelSeparation.GROUP;
            boolean created = !org.daemoxcp.mail.util.Shell.run("pw", "groupshow", g).success()
                    && org.daemoxcp.mail.util.Shell.run("pw", "groupadd", g).success();
            Path dir = Files.createTempDirectory("separation-files");
            try {
                for (String n : new String[]{"panel-secrets.properties", "master.key", "root-secrets.properties", "firewall.json"})
                    Files.writeString(dir.resolve(n), n);
                Files.setPosixFilePermissions(dir.resolve("firewall.json"), PosixFilePermissions.fromString("rw-r--r--"));
                Files.setPosixFilePermissions(dir.resolve("root-secrets.properties"), PosixFilePermissions.fromString("rw-------"));
                // master.key as the separated panel left it before the asymmetric vault: 0640 in the web part's group.
                Files.setPosixFilePermissions(dir.resolve("master.key"), PosixFilePermissions.fromString("rw-r-----"));
                Files.getFileAttributeView(dir.resolve("master.key"), java.nio.file.attribute.PosixFileAttributeView.class).setGroup(
                        dir.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(g));
                String r = PanelSeparation.openToWeb(dir, PanelSeparation.SECRETS_FOR_WEB);
                check("opened (" + r + ")", r == null);
                check("the folder is 0750 root:" + g + " (" + mode(dir) + " " + owner(dir) + ")", mode(dir).equals("rwxr-x---") && owner(dir).equals("root:" + g));
                for (String n : PanelSeparation.SECRETS_FOR_WEB)
                    check(n + " is 0640 root:" + g + " (" + mode(dir.resolve(n)) + " " + owner(dir.resolve(n)) + ")",
                            mode(dir.resolve(n)).equals("rw-r-----") && owner(dir.resolve(n)).equals("root:" + g));
                check("a file that was 0644 is now only root's (" + mode(dir.resolve("firewall.json")) + ")", mode(dir.resolve("firewall.json")).equals("rw-------"));
                check("the old vault key (master.key) is not the web part's any more: 0600 root:wheel (" + mode(dir.resolve("master.key"))
                        + " " + owner(dir.resolve("master.key")) + ")", !PanelSeparation.SECRETS_FOR_WEB.contains("master.key")
                        && mode(dir.resolve("master.key")).equals("rw-------") && owner(dir.resolve("master.key")).equals("root:wheel"));
                check("the root secrets stay 0600 and not in the group (" + owner(dir.resolve("root-secrets.properties")) + ")",
                        mode(dir.resolve("root-secrets.properties")).equals("rw-------") && !owner(dir.resolve("root-secrets.properties")).endsWith(":" + g));
                // A file created after the folder went to the group: on FreeBSD it takes the folder's group.
                Path late = dir.resolve("firewall.json.new");
                Files.writeString(late, "x");
                Files.setPosixFilePermissions(late, PosixFilePermissions.fromString("rw-------"));
                String lateBefore = owner(late);
                PanelSeparation.openToWeb(dir, PanelSeparation.SECRETS_FOR_WEB);
                check("a root file created later in the folder (" + lateBefore + ") goes back to root's group (" + owner(late) + ")",
                        owner(late).equals("root:wheel") && mode(late).equals("rw-------"));
                PanelSeparation.changed.clear();
                check("the second time nothing changes (" + PanelSeparation.changed + ")",
                        PanelSeparation.openToWeb(dir, PanelSeparation.SECRETS_FOR_WEB) == null && PanelSeparation.changed.isEmpty());

                Files.delete(dir.resolve("panel-secrets.properties"));
                Files.createSymbolicLink(dir.resolve("panel-secrets.properties"), Path.of("/etc/master.passwd"));
                String link = PanelSeparation.openToWeb(dir, PanelSeparation.SECRETS_FOR_WEB);
                check("a symbolic link instead of a data file is refused (" + link + ")", link != null && link.contains("symbolic link"));
                check("  and what it points to is untouched (" + mode(Path.of("/etc/master.passwd")) + " " + owner(Path.of("/etc/master.passwd")) + ")",
                        mode(Path.of("/etc/master.passwd")).equals("rw-------") && owner(Path.of("/etc/master.passwd")).equals("root:wheel"));
                check("a missing folder is refused", PanelSeparation.openToWeb(dir.resolve("none"), Set.of("x")) != null);
            } finally {
                org.daemoxcp.mail.util.Shell.run("rm", "-rf", dir.toString());
                if (created) org.daemoxcp.mail.util.Shell.run("pw", "groupdel", g);
            }
        } else {
            System.out.println("\n  (part 3 skipped: it changes owners, turned on with -De2e.vm=yes as root on the VM)");
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
