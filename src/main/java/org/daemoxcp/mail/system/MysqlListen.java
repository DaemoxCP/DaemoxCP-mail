package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MysqlRoot;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MySQL accepts connections only from this machine, and without the X protocol.
 *
 * Measured on 2026-11-07 on the production server (MySQL 8.4.11, my.cnf equal to the
 * package's my.cnf.sample): 3306 on 127.0.0.1, but 33060 of the X protocol on all addresses,
 * because the package's file does not mention it and its default is "*". The panel, Postfix,
 * Dovecot and Roundcube use only the classic protocol. On the VM there was no my.cnf at all:
 * 3306 too was on all addresses.
 *
 * The MySQL 8.4 manual (x-plugin-disabling, x-plugin-options-system-variables): the X plugin
 * is turned off at startup with mysqlx=0 (or OFF), and mysqlx_bind_address is read only at
 * startup. So here: in the [mysqld] section, bind-address = 127.0.0.1 and mysqlx = OFF are
 * added, only if missing; a choice already written by someone is not touched. If my.cnf is
 * not there, one is written with just those two lines: copying the package's file would also
 * change binary logs, memory and folders.
 *
 * Then: `mysqld --validate-config` as the mysql user, the restart, and the checks (MySQL
 * answers, listens only on 127.0.0.1 and not on 33060, Dovecot and Postfix still find the
 * mailboxes). If one does not match, my.cnf goes back as it was and MySQL is restarted again.
 * At the second startup there is nothing to do.
 */
public final class MysqlListen {

    private static final Logger LOGGER = Logger.getLogger(MysqlListen.class.getName());

    static Path myCnf = Path.of("/usr/local/etc/mysql/my.cnf");
    static final String MYSQLD = "/usr/local/libexec/mysqld";
    static final String POSTFIX_MAP = "/usr/local/etc/postfix/mysql-virtual-mailboxes.cf";

    private static final Pattern SECTION = Pattern.compile("^\\s*\\[([^\\]]+)\\]\\s*$");
    private static final Pattern OPTION = Pattern.compile("^\\s*(?:loose[-_])?([A-Za-z0-9_-]+)\\s*(=.*)?$");

    static final String COMMENT = "# Added by the panel: MySQL only from this machine, and no X protocol (port 33060).";

    private MysqlListen() {}

    /** The name of an option as MySQL understands it: lowercase, with '-' instead of '_'. */
    static String key(String option) {
        return option.toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /**
     * The my.cnf with the two missing lines, or null if nothing is missing. Pure function.
     *
     * @param text the current my.cnf, or null if it is not there
     */
    static String harden(String text) {
        if (text == null) return "[mysqld]\n" + COMMENT + "\nbind-address = 127.0.0.1\nmysqlx = OFF\n";
        List<String> lines = new ArrayList<>(List.of(text.split("\n", -1)));
        int header = -1, last = -1;
        boolean bind = false, mysqlx = false;
        String section = "";
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            Matcher s = SECTION.matcher(l);
            if (s.matches()) {
                section = s.group(1).trim().toLowerCase(Locale.ROOT);
                if (section.equals("mysqld") && header < 0) { header = i; last = i; }
                continue;
            }
            if (!section.equals("mysqld") || l.trim().isEmpty() || l.trim().startsWith("#") || l.trim().startsWith(";")) continue;
            Matcher o = OPTION.matcher(l);
            if (!o.matches()) continue;
            String k = key(o.group(1));
            if (k.equals("bind-address")) bind = true;
            if (k.equals("mysqlx") || k.equals("skip-mysqlx") || k.equals("mysqlx-bind-address")) mysqlx = true;
            if (header >= 0 && i > last) last = i;
        }
        if (bind && mysqlx) return null;
        List<String> add = new ArrayList<>();
        add.add(COMMENT);
        if (!bind) add.add("bind-address                    = 127.0.0.1");
        if (!mysqlx) add.add("mysqlx                          = OFF");
        if (header < 0) {
            String sep = text.endsWith("\n") || text.isEmpty() ? "" : "\n";
            return text + sep + "\n[mysqld]\n" + String.join("\n", add) + "\n";
        }
        lines.addAll(last + 1, add);
        return String.join("\n", lines);
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(MYSQLD))) return;
            String before = Files.exists(myCnf) ? Files.readString(myCnf) : null;
            String after = harden(before);
            if (after == null) return;
            apply(before, after);
        } catch (Throwable t) {
            LOGGER.warning("[MysqlListen] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply(String before, String after) throws Exception {
        boolean running = Shell.run(Duration.ofSeconds(15), "service", "mysql-server", "status").success();
        String lookupsBefore = running ? lookups() : "";
        write(after);
        Shell.Result valid = Shell.run(Duration.ofSeconds(120), "su", "-m", "mysql", "-c", MYSQLD + " --validate-config");
        if (!valid.success()) {
            putBack(before, false);
            LOGGER.warning("[MysqlListen] ROLLED_BACK: mysqld --validate-config refuses the new my.cnf ("
                    + firstLine(valid.outputTrim()) + "): nothing changed");
            return false;
        }
        if (!running) {
            LOGGER.info("[MysqlListen] DONE: my.cnf now keeps MySQL on 127.0.0.1 without the X protocol; MySQL is not"
                    + " running, it applies at its next start");
            return true;
        }
        Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
        String problem = verify(lookupsBefore);
        if (problem != null) {
            putBack(before, true);
            String again = waitForMysql() ? "MySQL answers again" : "MySQL DOES NOT ANSWER";
            LOGGER.warning("[MysqlListen] ROLLED_BACK: " + problem + "; my.cnf put back and MySQL restarted (" + again + ")");
            return false;
        }
        LOGGER.info("[MysqlListen] DONE: MySQL listens only on 127.0.0.1, the X protocol (33060) is off;"
                + " Dovecot and Postfix still find the mailboxes");
        return true;
    }

    /**
     * After the restart: MySQL answers, listens only locally, and the mail lookups give the same results as
     * before.
     */
    static String verify(String lookupsBefore) throws InterruptedException {
        if (!waitForMysql()) return "MySQL does not answer after the restart";
        List<String> open = new ArrayList<>();
        for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l").outputTrim().split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 6 && f[1].startsWith("mysqld")) {
                String addr = f[5];
                if (addr.endsWith(":33060") || !(addr.startsWith("127.0.0.1:") || addr.startsWith("[::1]:"))) open.add(addr);
            }
        }
        if (!open.isEmpty()) return "MySQL still listens on " + open;
        // Dovecot and Postfix keep a connection to MySQL: after the restart the first query finds the
        // connection dropped and answers "try again" (Dovecot 75), the next one reconnects. Measured on the
        // VM on 2026-11-07 in the test of the change: it waits for them to reconnect, up to 30 seconds.
        String lookupsAfter = "";
        for (int i = 0; i < 30; i++) {
            lookupsAfter = lookups();
            if (lookupsAfter.equals(lookupsBefore)) return null;
            Thread.sleep(1000);
        }
        return "mail lookups changed: before " + lookupsBefore + ", after " + lookupsAfter + " for 30 seconds";
    }

    static boolean waitForMysql() throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            if ("1".equals(MysqlRoot.query(org.daemoxcp.mail.database.SqlCatalog.MYSQL_ROOT_PING))) return true;
            Thread.sleep(1000);
        }
        return false;
    }

    /**
     * The lookups the mail server makes in MySQL, with an address that does not exist: Dovecot (passdb sql)
     * and Postfix (the mailbox map). They are compared before and after: a connection error changes the
     * output, "not found" does not.
     */
    static String lookups() {
        StringBuilder b = new StringBuilder();
        if (Files.isExecutable(Path.of(DovecotAuthWorker.DOVEADM)))
            b.append("dovecot=").append(DovecotAuthWorker.lookup());
        if (Files.exists(Path.of(POSTFIX_MAP)) && Shell.resolve("postmap") != null) {
            Shell.Result r = Shell.run(Duration.ofSeconds(20), "postmap", "-q", DovecotAuthWorker.PROBE, "mysql:" + POSTFIX_MAP);
            b.append(b.length() > 0 ? " " : "").append("postfix=").append(r.exitCode());
        }
        return b.toString();
    }

    private static void write(String text) throws Exception {
        if (myCnf.getParent() != null) Files.createDirectories(myCnf.getParent());
        Path tmp = myCnf.resolveSibling("." + myCnf.getFileName() + ".daemoxcp-mail.tmp");
        Files.writeString(tmp, text);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, myCnf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(String before, boolean restart) throws Exception {
        if (before == null) Files.deleteIfExists(myCnf); else write(before);
        if (restart) Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
