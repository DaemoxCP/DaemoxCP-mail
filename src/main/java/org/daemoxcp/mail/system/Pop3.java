package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * POP3 on or off, as the administrator chooses in the Settings; off until they choose
 * (decided by the owner on 2026-11-08).
 *
 * <p>Measured on the production server: in the 8 days of mail log, 0 successful POP3 logins and from 28 to
 * 149 connections a day on ports 110 and 995 without any login (scans and attempts), while IMAP
 * has hundreds of logins a day. A port that nobody uses is just a port to attack: that is why
 * the default is off. Whoever has a mail program that wants POP3 turns it on from the panel.
 *
 * <p>The choice lives in panel_settings ({@link #SETTING}, "1" or "0"). The panel applies it to Dovecot
 * through the {@code protocols} line of dovecot.conf alone, the one it used to write: it adds or removes
 * {@code pop3} and nothing else (the pop3-login services, default or in conf.d, do not start without the
 * protocol). First it tests with doveconf, then reloads Dovecot and checks the ports: off, 110 and 995 do
 * not listen; on, they listen; IMAP (993) always. If something does not add up it puts the file back as it
 * was. The pf ports (PfPolicy) and those of the country rules (PfFirewallManager) follow the same choice.
 */
public final class Pop3 {

    private static final Logger LOGGER = Logger.getLogger(Pop3.class.getName());

    /** The choice, in panel_settings: "1" on, otherwise off. */
    public static final String SETTING = "pop3_enabled";
    static final String DOVECOT_CONF = "/usr/local/etc/dovecot/dovecot.conf";
    static final String DOVECONF = "/usr/local/bin/doveconf";
    private static final Pattern PROTOCOLS = Pattern.compile("(?m)^(\\s*protocols\\s*=\\s*)(.*)$");

    private Pop3() {}

    /** What the administrator chose; off if they have not chosen or the database does not answer. */
    public static boolean wanted() {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        return db != null && "1".equals(db.getSetting(SETTING, "0"));
    }

    /**
     * dovecot.conf with pop3 on or off in the protocols line, or null if there is nothing to change
     * (either the protocols line is missing, or there is more than one: then it is not the file the
     * panel used to write, or turning pop3 off would leave Dovecot without protocols).
     */
    static String withPop3(String conf, boolean on) {
        if (conf == null) return null;
        Matcher m = PROTOCOLS.matcher(conf);
        if (!m.find()) return null;
        int start = m.start(), end = m.end();
        String prefix = m.group(1), value = m.group(2);
        if (m.find()) return null;
        List<String> protocols = new ArrayList<>();
        for (String p : value.trim().split("\\s+")) if (!p.isEmpty()) protocols.add(p);
        boolean has = protocols.contains("pop3");
        if (has == on) return null;
        if (on) protocols.add(protocols.contains("imap") ? protocols.indexOf("imap") + 1 : protocols.size(), "pop3");
        else protocols.removeIf("pop3"::equals);
        if (protocols.isEmpty()) return null;
        return conf.substring(0, start) + prefix + String.join(" ", protocols) + conf.substring(end);
    }

    /** True if the TCP port is listening, from the output of sockstat -46l -P tcp. */
    static boolean listens(String sockstat, int port) {
        if (sockstat == null) return false;
        for (String line : sockstat.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 6 && f[5].endsWith(":" + port)) return true;
        }
        return false;
    }

    /** At root part startup: Dovecot as per the choice (off if there is none). On the second startup it does nothing. */
    public static void ensureAtBoot() {
        String problem = align(wanted());
        if (problem != null) LOGGER.warning("[Pop3] " + problem);
    }

    /**
     * The administrator's choice from the Settings: saves it, applies it to Dovecot and to the pf ports.
     * Null if done; otherwise the reason, and the previous choice stays (saved and applied).
     */
    public static synchronized String choose(boolean on) {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        if (db == null) return "the panel's database does not answer";
        String before = db.getSetting(SETTING, "0");
        db.setSetting(SETTING, on ? "1" : "0");
        String problem = align(on);
        if (problem != null) {
            db.setSetting(SETTING, before);
            return problem;
        }
        org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();
        return null;
    }

    /** Dovecot on or off as requested. Null if it already is, or if it is done. */
    private static synchronized String align(boolean on) {
        try {
            Path conf = Path.of(DOVECOT_CONF);
            if (!Files.isRegularFile(conf) || !Files.isExecutable(Path.of(DOVECONF))) return null;
            String current = Files.readString(conf, StandardCharsets.UTF_8);
            String next = withPop3(current, on);
            if (next == null) return null;
            if (!Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success()) {
                LOGGER.info("[Pop3] Dovecot is not running: POP3 left as it is, retrying at the next start");
                return null;
            }
            return apply(conf, current, next, on);
        } catch (Exception e) {
            return "not applied: " + e.getMessage();
        }
    }

    private static String apply(Path conf, String current, String next, boolean on) throws Exception {
        Path tmp = conf.resolveSibling(".dovecot.conf.pop3");
        Files.copy(conf, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.move(tmp, conf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Shell.Result check = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
        if (!check.success()) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            return "ROLLED_BACK: doveconf refuses dovecot.conf with POP3 " + (on ? "on" : "off") + ", nothing changed";
        }
        if (!reloadAndCheck(on)) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
            return "ROLLED_BACK: after a reload and a restart, ports 110/995 were not " + (on ? "open" : "closed")
                    + " or IMAP (993) was not open; dovecot.conf put back and Dovecot restarted";
        }
        LOGGER.info("[Pop3] DONE: POP3 " + (on ? "on (ports 110 and 995 open)" : "off (ports 110 and 995 closed)")
                + " in " + DOVECOT_CONF + "; IMAP still answers");
        return null;
    }

    /**
     * Reloads, then 110 and 995 as requested and 993 open, and, when on, the real POP3 greeting on 110; a restart
     * if the reload is not enough. On 2.4 the reload that turns POP3 on is never enough: the ports open, but
     * pop3-login dies at every connection because the folder of the new service (/var/run/dovecot/srv.pop3-login)
     * is missing, and Dovecot creates it only at startup (finding 213). Before, only the ports were checked, and the
     * tab said "open" on a broken POP3.
     */
    private static boolean reloadAndCheck(boolean on) throws InterruptedException {
        for (String how : new String[]{"reload", "restart"}) {
            if (!Shell.run(Duration.ofSeconds(60), "service", "dovecot", how).success()) continue;
            boolean ports = false;
            for (int i = 0; i < 20 && !ports; i++) {
                Thread.sleep(500);
                String s = Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output();
                ports = listens(s, 110) == on && listens(s, 995) == on && listens(s, 993);
            }
            if (!ports) continue;
            if (!on) return true;
            // A few short attempts: a pop3-login that dies does not recover by itself, and the restart
            // is the next step. With twenty five-second attempts the tab stayed on "Applying" for
            // almost two minutes.
            for (int i = 0; i < 3; i++) {
                if (MailProbes.pop3Greeting("127.0.0.1", 110, 2000) == null) return true;
                Thread.sleep(1000);
            }
        }
        return false;
    }
}
