package org.daemoxcp.mail.system;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The web part's user moves from its name of before (mailpanel) to today's (daemoxcp_mail) with the same uid and gid
 * (PanelUserRename.rename), with a fake pw that keeps users and groups in memory. pw usermod -l moves neither the
 * crontab nor the system mailbox that pw useradd created in /var/mail: the rename moves both, in temporary folders.
 * Seen on the VM on 17/11/2026: /var/mail/mailpanel stayed, the file of a user that no longer exists.
 *
 * It runs anywhere (it calls nothing):
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.PanelUserRenameTest
 */
public class PanelUserRenameTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String OLD = "mailpanel", NEW = Product.ID;

    /** pw with users (master.passwd lines) and groups (group lines) in memory. */
    static final class FakePw implements PanelUserRename.Services {
        final Map<String, String> users = new LinkedHashMap<>(), groups = new LinkedHashMap<>();
        final Path tabs, spool;
        final List<String> calls = new ArrayList<>();

        FakePw(Path root) throws Exception {
            tabs = Files.createDirectories(root.resolve("cron/tabs"));
            spool = Files.createDirectories(root.resolve("mail"));
        }

        @Override public String user(String name) { return users.get(name); }
        @Override public String group(String name) { return groups.get(name); }
        @Override public List<String> groups() { return new ArrayList<>(groups.values()); }
        @Override public Path cronTabs() { return tabs; }
        @Override public Path mailSpool() { return spool; }

        @Override public String pw(String... a) {
            calls.add(String.join(" ", a));
            if (a[0].equals("groupmod") && a.length == 4 && a[2].equals("-l")) {
                String g = groups.remove(a[1]);
                if (g == null) return "no group " + a[1];
                groups.put(a[3], a[3] + g.substring(g.indexOf(':')));
                return null;
            }
            if (a[0].equals("usermod") && a[2].equals("-l")) {
                String u = users.remove(a[1]);
                if (u == null) return "no user " + a[1];
                String[] f = u.split(":", -1);
                f[0] = a[3];
                if (a.length >= 6 && a[4].equals("-c")) f[7] = a[5];
                users.put(a[3], String.join(":", f));
                return null;
            }
            return "not faked: " + String.join(" ", a);
        }
    }

    static String userLine(String name, String gecos) {
        return name + ":*:5002:5002::0:0:" + gecos + ":" + PanelUser.HOME + ":" + PanelUser.SHELL;
    }

    public static void main(String[] args) throws Exception {
        List<String> oldComments = PanelUserRename.oldComments(PanelSeparation.GECOS);
        check("the data file has the user of before and its comment of before",
                LegacyNames.oldNamesOf("unixUsers", NEW).contains(OLD) && !oldComments.isEmpty());

        OUT.println("\n== A server installed before: user, group, crontab and system mailbox ==");
        FakePw pw = new FakePw(Files.createTempDirectory("panel-user-rename"));
        pw.users.put(OLD, userLine(OLD, oldComments.get(0)));
        pw.groups.put(OLD, OLD + ":*:5002:");
        Files.writeString(pw.tabs.resolve(OLD), "*/5 * * * * true\n");
        Files.writeString(pw.spool.resolve(OLD), "");
        PanelUserRename.Report r = PanelUserRename.rename(OLD, NEW, PanelSeparation.GECOS, pw);
        OUT.println("        -> " + r.outcome() + ": " + r.detail());
        check("DONE, same uid and gid, today's comment",
                r.outcome() == PanelUserRename.Outcome.DONE && pw.user(OLD) == null && pw.user(NEW) != null
                        && pw.user(NEW).split(":", -1)[2].equals("5002") && pw.user(NEW).split(":", -1)[7].equals(PanelSeparation.GECOS)
                        && pw.group(NEW) != null && pw.group(OLD) == null);
        check("the crontab has the new name", Files.exists(pw.tabs.resolve(NEW)) && !Files.exists(pw.tabs.resolve(OLD)));
        check("the system mailbox has the new name, and the report says so",
                Files.exists(pw.spool.resolve(NEW)) && !Files.exists(pw.spool.resolve(OLD))
                        && r.detail().contains("its system mailbox moved"));

        OUT.println("\n== The second start ==");
        int calls = pw.calls.size();
        r = PanelUserRename.rename(OLD, NEW, PanelSeparation.GECOS, pw);
        check("nothing to do, no pw call", r.outcome() == PanelUserRename.Outcome.NOTHING && pw.calls.size() == calls);

        OUT.println("\n== A mailbox already there with today's name ==");
        pw = new FakePw(Files.createTempDirectory("panel-user-rename"));
        pw.users.put(OLD, userLine(OLD, oldComments.get(0)));
        pw.groups.put(OLD, OLD + ":*:5002:");
        Files.writeString(pw.spool.resolve(OLD), "old\n");
        Files.writeString(pw.spool.resolve(NEW), "new\n");
        r = PanelUserRename.rename(OLD, NEW, PanelSeparation.GECOS, pw);
        check("the user is renamed, neither mailbox is overwritten",
                r.outcome() == PanelUserRename.Outcome.DONE && "old\n".equals(Files.readString(pw.spool.resolve(OLD)))
                        && "new\n".equals(Files.readString(pw.spool.resolve(NEW))) && !r.detail().contains("mailbox"));

        OUT.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }
}
