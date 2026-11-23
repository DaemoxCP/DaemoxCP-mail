package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * At service startup: the panel's system users take the new name (DaemoxCP Mail, 2026-11-17).
 *
 * <p>The web part's user and group, mailpanel, become daemoxcp_mail; its comment and sievec's state the new
 * name. They are renamed with pw, which keeps uid and gid: the web part's files (the secrets it reads, the SQLite
 * database, the pages, the socket) remain its own without touching any of them, because the system knows them by
 * number. PanelUser checks the comment word for word: without this switch the earlier user would no longer be
 * "the panel's", and the web part would not start.
 *
 * <p>Only the user the panel created is renamed: name, earlier comment, its own group, no other member
 * (PanelUser.problem). If a user with the new name already exists, or the old one does not belong to the panel,
 * nothing is touched and this is said. After the rename we check that the new name has the same uid and the same
 * gid as before, and that no group still mentions it by the old name; if that does not add up, the earlier name
 * is put back.
 *
 * <p>The earlier names and comments are in legacy-names.json (sections "unixUsers" and "unixUserComments").
 */
public final class PanelUserRename {

    private static final Logger LOGGER = Logger.getLogger(PanelUserRename.class.getName());
    private static final Duration T = Duration.ofSeconds(20);

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** pw and the system files, kept separate so they can be tested without touching the real users. */
    interface Services {
        /** The pw usershow line (master.passwd format), or null if the user does not exist. */
        String user(String name);
        /** The pw groupshow line (name:password:gid:members), or null if the group does not exist. */
        String group(String name);
        /** Runs pw with these arguments: null if it worked, otherwise what it says. */
        String pw(String... args);
        /** The lines of /etc/group. */
        List<String> groups();
        /** The folder of the users' crontabs. */
        Path cronTabs();
        /** The folder of the system mailboxes (/var/mail), where pw useradd creates the user's empty one. */
        Path mailSpool();
    }

    private PanelUserRename() {}

    public static void ensureAtBoot() {
        Services sv = new RealServices();
        for (String[] p : LegacyNames.pairs("unixUsers")) report(rename(p[0], p[1], PanelSeparation.GECOS, sv));
        // sievec's comment: the user does not change name, only the comment by which the panel recognises it.
        report(recomment(SieveCompiler.USER, SieveCompiler.COMPILER_USER.gecos(), sv));
    }

    private static void report(Report r) {
        if (r.outcome() == Outcome.NOTHING) return;
        String line = "[PanelUserRename] " + r.outcome() + ": " + r.detail();
        if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
    }

    /** The earlier comments that are now {@code gecos}. */
    static List<String> oldComments(String gecos) {
        return LegacyNames.oldNamesOf("unixUserComments", gecos);
    }

    static Report rename(String oldName, String newName, String gecos, Services sv) {
        String oldUser = sv.user(oldName);
        if (oldUser == null) return new Report(Outcome.NOTHING, "");
        if (sv.user(newName) != null)
            return new Report(Outcome.LEFT, "both the users " + oldName + " and " + newName + " exist: " + oldName + " left as it is");
        String oldGroup = sv.group(oldName);
        if (oldGroup == null) return new Report(Outcome.LEFT, "the user " + oldName + " has no group of its own: left as it is");
        String[] u = oldUser.split(":", -1);
        if (u.length < 10) return new Report(Outcome.LEFT, "the user " + oldName + " cannot be read");
        // The panel's: as it was on the day it created it (the earlier comment or already the current one).
        String why = null;
        for (String c : with(oldComments(gecos), gecos)) {
            why = new PanelUser(oldName, c).problem(oldUser, oldGroup);
            if (why == null) break;
        }
        if (why != null) return new Report(Outcome.LEFT, why + ": not renamed");
        if (sv.group(newName) != null)
            return new Report(Outcome.LEFT, "the group " + newName + " already exists: " + oldName + " left as it is");
        String uid = u[2], gid = u[3];

        String problem = sv.pw("groupmod", oldName, "-l", newName);
        if (problem != null) return new Report(Outcome.LEFT, "pw groupmod: " + problem + ": nothing changed");
        problem = sv.pw("usermod", oldName, "-l", newName, "-c", gecos);
        if (problem != null) {
            sv.pw("groupmod", newName, "-l", oldName);
            return new Report(Outcome.ROLLED_BACK, "pw usermod: " + problem + "; the group got its name back");
        }

        // The check: same uid, same gid, its own group, and no group that mentions it by the earlier name.
        String after = sv.user(newName), afterGroup = sv.group(newName);
        String[] a = after == null ? new String[0] : after.split(":", -1);
        String[] g = afterGroup == null ? new String[0] : afterGroup.split(":", -1);
        String wrong = null;
        if (a.length < 10 || !uid.equals(a[2]) || !gid.equals(a[3])) wrong = "the renamed user has another uid or gid";
        else if (g.length < 4 || !gid.equals(g[2])) wrong = "the renamed group has another gid";
        else if (new PanelUser(newName, gecos).problem(after, afterGroup) != null)
            wrong = new PanelUser(newName, gecos).problem(after, afterGroup);
        if (wrong == null) {
            for (String line : sv.groups()) {
                String[] f = line.split(":", -1);
                if (f.length < 4 || f[3].isEmpty()) continue;
                for (String m : f[3].split(",")) {
                    if (!m.equals(oldName)) continue;
                    // A group that still mentions the earlier name: it is brought to the new name.
                    String p = sv.pw("groupmod", f[0], "-d", oldName, "-m", newName);
                    if (p != null) wrong = "the group " + f[0] + " still names " + oldName + ": " + p;
                }
            }
        }
        if (wrong != null) {
            sv.pw("usermod", newName, "-l", oldName, "-c", u[7]);
            sv.pw("groupmod", newName, "-l", oldName);
            return new Report(Outcome.ROLLED_BACK, wrong + "; the old names put back");
        }

        // The user's crontab, if it has one: cron looks for it by name.
        String cron = "";
        Path oldTab = sv.cronTabs().resolve(oldName), newTab = sv.cronTabs().resolve(newName);
        try {
            if (Files.exists(oldTab, LinkOption.NOFOLLOW_LINKS) && !Files.exists(newTab, LinkOption.NOFOLLOW_LINKS)) {
                Files.move(oldTab, newTab, StandardCopyOption.ATOMIC_MOVE);
                cron = ", its crontab moved";
            }
        } catch (IOException e) {
            cron = ", its crontab NOT moved (" + e.getMessage() + ")";
        }
        // The system mailbox: pw usermod -l does not move it, and with the earlier name there would remain in
        // /var/mail (outside the boot environments) a file of a user who no longer exists. The content belongs to the
        // same uid: it is simply moved.
        Path oldBox = sv.mailSpool().resolve(oldName), newBox = sv.mailSpool().resolve(newName);
        String box = "";
        try {
            if (Files.isRegularFile(oldBox, LinkOption.NOFOLLOW_LINKS) && !Files.exists(newBox, LinkOption.NOFOLLOW_LINKS)) {
                Files.move(oldBox, newBox, StandardCopyOption.ATOMIC_MOVE);
                box = ", its system mailbox moved";
            }
        } catch (IOException e) {
            box = ", its system mailbox NOT moved (" + e.getMessage() + ")";
        }
        return new Report(Outcome.DONE, "the user and group " + oldName + " are now " + newName + " (uid " + uid
                + ", gid " + gid + ", comment '" + gecos + "')" + cron + box);
    }

    /** The comment of a panel user that does not change name: if it is an earlier one, it becomes the current one. */
    static Report recomment(String name, String gecos, Services sv) {
        String line = sv.user(name);
        if (line == null) return new Report(Outcome.NOTHING, "");
        String[] u = line.split(":", -1);
        if (u.length < 10 || gecos.equals(u[7]) || !oldComments(gecos).contains(u[7])) return new Report(Outcome.NOTHING, "");
        String group = sv.group(name);
        if (group == null || new PanelUser(name, u[7]).problem(line, group) != null)
            return new Report(Outcome.LEFT, "the user " + name + " is not the panel's: comment left as it is");
        String p = sv.pw("usermod", name, "-c", gecos);
        return p == null ? new Report(Outcome.DONE, "the comment of " + name + " is now '" + gecos + "'")
                         : new Report(Outcome.LEFT, "pw usermod " + name + ": " + p);
    }

    private static List<String> with(List<String> list, String last) {
        List<String> out = new ArrayList<>(list);
        out.add(last);
        return out;
    }

    static final class RealServices implements Services {
        @Override public String user(String name) {
            Shell.Result r = Shell.run(T, "pw", "usershow", name);
            return r.success() ? r.outputTrim() : null;
        }
        @Override public String group(String name) {
            Shell.Result r = Shell.run(T, "pw", "groupshow", name);
            return r.success() ? r.outputTrim() : null;
        }
        @Override public String pw(String... args) {
            String[] cmd = new String[args.length + 1];
            cmd[0] = "pw";
            System.arraycopy(args, 0, cmd, 1, args.length);
            Shell.Result r = Shell.run(T, cmd);
            return r.success() ? null : r.outputTrim();
        }
        @Override public List<String> groups() {
            try {
                return Files.readAllLines(Path.of("/etc/group"));
            } catch (IOException e) {
                return List.of();
            }
        }
        @Override public Path cronTabs() { return Path.of("/var/cron/tabs"); }
        @Override public Path mailSpool() { return Path.of("/var/mail"); }
    }
}
