package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.time.Duration;

/**
 * A system user that the panel creates to run something without root: no password, no shell, home
 * /nonexistent, a group of its own with the same name and no other member. If it already exists in another form
 * it does not belong to the panel, and is not used.
 *
 * The check was in PanelSeparation for daemoxcp_mail; it is here because a second one is needed, sievec
 * (SieveCompiler, finding 218), and the two must be checked in the same way.
 *
 * @param name  the name of the user, and of its group
 * @param gecos the comment with which the panel creates it: a user with that name and another comment is not its own
 */
public record PanelUser(String name, String gecos) {

    public static final String HOME = "/nonexistent";
    public static final String SHELL = "/usr/sbin/nologin";

    /** How it went: null if the user exists and is the panel's, otherwise the reason; created if it was created now. */
    public record Ensured(String problem, boolean created) {}

    /**
     * Creates the group and the user if missing, then checks them. The format of pw usershow is that of
     * master.passwd: name:password:uid:gid:class:change:expire:gecos:home_dir:shell (pw(8)); that of pw groupshow
     * is name:password:gid:members.
     */
    public Ensured ensure() {
        Duration t = Duration.ofSeconds(15);
        boolean created = false;
        if (!Shell.run(t, "pw", "groupshow", name).success()) {
            if (!Shell.run(t, "pw", "groupadd", name).success()) return new Ensured("the group " + name + " could not be created", false);
            created = true;
        }
        if (!Shell.run(t, "pw", "usershow", name).success()) {
            if (!Shell.run(t, "pw", "useradd", name, "-g", name, "-d", HOME, "-s", SHELL, "-c", gecos, "-w", "no").success())
                return new Ensured("the user " + name + " could not be created", created);
            created = true;
        }
        return new Ensured(problem(Shell.run(t, "pw", "usershow", name).outputTrim(),
                Shell.run(t, "pw", "groupshow", name).outputTrim()), created);
    }

    /** Null if the lines from pw are those of the user created by the panel; otherwise what does not add up. Pure. */
    public String problem(String userLine, String groupLine) {
        String[] u = userLine.split(":", -1);
        String[] g = groupLine.split(":", -1);
        if (u.length < 10 || g.length < 4) return "the user " + name + " or its group cannot be read";
        String other = "the user " + name + " exists and is not the panel's: ";
        if (!name.equals(u[0])) return other + "name " + u[0];
        if ("0".equals(u[2])) return other + "uid 0";
        if (!gecos.equals(u[7])) return other + "comment '" + u[7] + "'";
        if (!HOME.equals(u[8])) return other + "home " + u[8];
        if (!SHELL.equals(u[9])) return other + "shell " + u[9];
        if (!"*".equals(u[1]) && !u[1].startsWith("*LOCKED*")) return other + "it has a password";
        if (!name.equals(g[0]) || !g[2].equals(u[3])) return other + "its group is not " + name;
        if (!g[3].isEmpty()) return "the group " + name + " has other members (" + g[3] + "): they would read the panel's files";
        return null;
    }
}
