package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Postfix delivers to Dovecot through a Unix socket in its own queue, 0600 and its own, and no longer through port
 * 24 (finding 234).
 *
 * <p>Before, Dovecot listened for LMTP on 127.0.0.1:24 (and Postfix delivered there, lmtp:inet:127.0.0.1:24) and on
 * its socket /var/run/dovecot/lmtp, 0666: any process on the machine (the webmail, rspamd, a compromised service)
 * could deliver into any mailbox without going through Postfix or rspamd. The Dovecot guide "Postfix and Dovecot
 * LMTP" (2.3 and 2.4): unix_listener /var/spool/postfix/private/dovecot-lmtp, mode 0600, user and group postfix,
 * and in Postfix virtual_transport = lmtp:unix:private/dovecot-lmtp. The Dovecot socket in /var/run/dovecot stays,
 * 0600 owned by root. While at it, last_valid_uid and last_valid_gid equal to those of vmail (5000), as Dovecot's
 * security page asks: all mail belongs to vmail.
 *
 * <p>On servers installed before, at startup, in three steps so that mail is never left without a path:
 * <ol>
 *   <li>Dovecot opens the new socket while also keeping port 24 (once reloaded, the socket must be there, owned by
 *       postfix, 0600, and answer a delivery stopped before the message);</li>
 *   <li>Postfix switches to the socket (postconf -e, reload);</li>
 *   <li>Dovecot closes port 24 and the 0666 socket; then the queue drains.</li>
 * </ol>
 * An error in the first two steps puts everything back as it was; in the third the intermediate state remains,
 * which works (Dovecot listens on both sides), and the next startup resumes from there. Only the block the panel
 * itself had written is changed, identical line by line, and only if Postfix delivers where the panel had put it.
 *
 * <p>After every reload it waits until Dovecot has really changed its listeners, up to {@link #SETTLE_SECONDS}
 * seconds: in the third step until port 24 is closed, in both until the test delivery answers. The Dovecot reload
 * returns before the master has rebuilt the listeners, and in the third step the Postfix socket is already there
 * since the first one, with its permissions: a single test right after fell in the middle of the change
 * ("Connection reset") and the migration ended INCOMPLETE with everything already in place (finding 240, on the VM
 * installed with build 587 and upgraded to 632).
 */
public final class LmtpSocket {

    private static final Logger LOGGER = Logger.getLogger(LmtpSocket.class.getName());

    private LmtpSocket() {}

    static final String TRANSPORT = "lmtp:unix:private/dovecot-lmtp";
    static final String OLD_TRANSPORT = "lmtp:inet:127.0.0.1:24";
    static final String SOCKET = "/var/spool/postfix/private/dovecot-lmtp";

    /** The block the panel wrote for 2.3 (identical on the production server and on the VM). */
    static final String OLD23 = """
            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              # LMTP su porta 24 per Postfix (virtual_transport = lmtp:inet:127.0.0.1:24)
              inet_listener lmtp {
                address = 127.0.0.1
                port = 24
              }
            }
            """;

    /** And for 2.4. */
    static final String OLD24 = """
            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              # address non esiste piu' nei listener: si chiama listen (provato sulla 2.4.5 il 09/11/2026).
              inet_listener lmtp {
                listen = 127.0.0.1
                port = 24
              }
            }
            """;

    /** The current block, the same one DovecotConfig writes. */
    static final String NEW = """
            service lmtp {
              # Only Postfix delivers: the socket is in its queue, 0600 and its own (doc.dovecot.org, "Postfix and Dovecot
              # LMTP"; virtual_transport = lmtp:unix:private/dovecot-lmtp). No more port 24 on 127.0.0.1 nor the
              # 0666 socket, through which any process of the machine delivered into any mailbox (finding 234).
              unix_listener /var/spool/postfix/private/dovecot-lmtp {
                mode = 0600
                user = postfix
                group = postfix
              }
              # Dovecot's socket in /var/run/dovecot is 0666 by default: root only.
              unix_listener lmtp {
                mode = 0600
              }
            }
            """;

    /** The intermediate state: the new block plus the old port 24, in the version's syntax. */
    static String transition(boolean v24) {
        String inet = v24 ? """
                  # Only while Postfix moves to the socket: removed afterwards (LmtpSocket).
                  inet_listener lmtp {
                    listen = 127.0.0.1
                    port = 24
                  }
                """ : """
                  # Only while Postfix moves to the socket: removed afterwards (LmtpSocket).
                  inet_listener lmtp {
                    address = 127.0.0.1
                    port = 24
                  }
                """;
        return NEW.substring(0, NEW.lastIndexOf("}\n")) + inet + "}\n";
    }

    static final String UIDS = "first_valid_uid = 5000\nfirst_valid_gid = 5000\n";
    static final String UIDS_RANGE = UIDS + "last_valid_uid = 5000\nlast_valid_gid = 5000\n";

    /**
     * dovecot.conf with last_valid_uid/gid, if it has the panel's two lines and does not have them yet; otherwise as
     * it is. Pure.
     */
    static String withUidRange(String conf) {
        if (conf == null || conf.contains("last_valid_uid") || conf.contains("last_valid_gid")) return conf;
        int at = conf.indexOf(UIDS);
        if (at < 0 || conf.indexOf(UIDS, at + 1) >= 0) return conf;
        return conf.substring(0, at) + UIDS_RANGE + conf.substring(at + UIDS.length());
    }

    /** What is needed, to test it without Postfix and Dovecot. */
    interface Services {
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        String transport();
        /** postconf -e and Postfix reload; true if it now delivers there. */
        boolean setTransport(String transport);
        /** doveconf -n without errors. */
        boolean dovecotAccepts();
        /** Reloads Dovecot and waits for the Postfix socket (owned by postfix, 0600); true if it is there. */
        boolean dovecotReload(boolean expectSocket);
        /** The delivery stopped before the message, on the socket; null if Dovecot answers as it should. */
        String probe();
        boolean port24Listening();
        /** The Dovecot socket in /var/run/dovecot belongs to root only. */
        boolean baseSocketRootOnly();
        void flushQueue();
        /** One second of waiting, while Dovecot rebuilds its listeners after a reload. */
        default void pause() {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** How long to wait after a reload for Dovecot to listen as the written configuration says (finding 240). */
    static final int SETTLE_SECONDS = 20;

    /**
     * The test delivery once Dovecot has finished the reload: if closing, it first waits for port 24 to be closed; then
     * the test, repeated until it answers. Null if it answers; otherwise the last wrong answer. At most
     * {@link #SETTLE_SECONDS} seconds in all; port 24 still open is reported by the caller.
     */
    static String settledProbe(Services sv, boolean closing) {
        int waited = 0;
        while (closing && waited < SETTLE_SECONDS && sv.port24Listening()) {
            sv.pause();
            waited++;
        }
        String p = sv.probe();
        while (p != null && waited < SETTLE_SECONDS) {
            sv.pause();
            waited++;
            p = sv.probe();
        }
        return p;
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    static final Path MASTER_CONF = Path.of("/usr/local/etc/dovecot/conf.d/10-master.conf");
    static final Path DOVECOT_CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");

    /** The switchover, pure with respect to {@link Services}. */
    static Result run(Services sv, Path master, Path main) {
        String m, d;
        try {
            // The blocks written in Italian by earlier versions count as the current ones (EnglishComments);
            // OLD23 and OLD24 describe earlier servers and stay as they are.
            m = EnglishComments.english(sv.read(master));
            d = sv.read(main);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "Dovecot's configuration cannot be read: " + e.getClass().getSimpleName());
        }
        if (m == null) return new Result(Outcome.NOTHING, "");   // Dovecot not configured by the panel
        String transport = sv.transport();
        boolean v24 = d != null && d.contains("dovecot_config_version");
        String mid = transition(v24);

        if (m.contains(NEW) && TRANSPORT.equals(transport)) return new Result(Outcome.NOTHING, "");
        boolean fromOld = count(m, OLD23) + count(m, OLD24) == 1;
        boolean fromMid = count(m, mid) == 1;
        if (!fromOld && !fromMid)
            return new Result(Outcome.LEFT, "the lmtp service of conf.d/10-master.conf is not the one the panel writes: left as it is");
        if (!OLD_TRANSPORT.equals(transport) && !TRANSPORT.equals(transport))
            return new Result(Outcome.LEFT, "Postfix delivers with " + transport + ", not where the panel put it: left as it is");

        String old = fromOld ? (count(m, OLD23) == 1 ? OLD23 : OLD24) : mid;
        String dNew = withUidRange(d);
        try {
            // 1. Dovecot on the new socket, with port 24 still open.
            if (fromOld) {
                sv.write(master, m.replace(old, mid));
                if (dNew != null && !dNew.equals(d)) sv.write(main, dNew);
                if (!sv.dovecotAccepts()) return back(sv, master, m, main, d, transport, "doveconf refuses the configuration with the socket");
                if (!sv.dovecotReload(true)) return back(sv, master, m, main, d, transport, "after the reload Dovecot has no socket " + SOCKET + " of postfix, 0600");
                String p = settledProbe(sv, false);
                if (p != null) return back(sv, master, m, main, d, transport, "the socket does not deliver: " + p);
            }
            // 2. Postfix on the socket.
            if (!TRANSPORT.equals(sv.transport()) && !sv.setTransport(TRANSPORT)) {
                sv.setTransport(transport);
                return back(sv, master, m, main, d, transport, "Postfix did not take " + TRANSPORT);
            }
        } catch (IOException e) {
            return back(sv, master, m, main, d, transport, "a file could not be written: " + e.getClass().getSimpleName());
        }
        // 3. Port 24 and the 0666 socket go away. From here the intermediate state works: an error leaves it,
        // the next startup resumes.
        String withMid;
        try {
            withMid = EnglishComments.english(sv.read(master));
            sv.write(master, withMid.replace(mid, NEW));
        } catch (IOException e) {
            return new Result(Outcome.INCOMPLETE, "Postfix delivers through the socket, Dovecot still also listens on port 24: "
                    + e.getClass().getSimpleName());
        }
        if (!sv.dovecotAccepts() || !sv.dovecotReload(true)) {
            try { sv.write(master, withMid); } catch (IOException ignored) { }
            sv.dovecotReload(true);
            return new Result(Outcome.INCOMPLETE, "Postfix delivers through the socket; closing port 24 was refused by Dovecot,"
                    + " so it stays open until the next start");
        }
        String p = settledProbe(sv, true);
        boolean closed = !sv.port24Listening();
        boolean rootOnly = sv.baseSocketRootOnly();
        sv.flushQueue();
        if (p != null || !closed || !rootOnly)
            return new Result(Outcome.INCOMPLETE, "after closing port 24: delivery " + (p == null ? "ok" : p) + ", port 24 "
                    + (closed ? "closed" : "still open") + ", /var/run/dovecot/lmtp " + (rootOnly ? "root only" : "still open to others"));
        return new Result(Outcome.DONE, "Postfix delivers through " + SOCKET + " (postfix, 0600); port 24 and the 0666 socket are"
                + " closed" + (dNew != null && !dNew.equals(d) ? "; last_valid_uid/gid = 5000" : ""));
    }

    private static Result back(Services sv, Path master, String m, Path main, String d, String transport, String why) {
        boolean ok = true;
        try {
            sv.write(master, m);
            if (d != null) sv.write(main, d);
        } catch (IOException e) {
            ok = false;
        }
        if (!transport.equals(sv.transport())) ok &= sv.setTransport(transport);
        ok &= sv.dovecotReload(false);
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting it back failed"));
    }

    static int count(String s, String part) {
        int n = 0;
        for (int i = s.indexOf(part); i >= 0; i = s.indexOf(part, i + 1)) n++;
        return n;
    }

    // ===================== The production server =====================

    static Services real() {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public String transport() {
                return Shell.runShell(Duration.ofSeconds(20), "postconf -h virtual_transport 2>/dev/null").outputTrim();
            }
            @Override public boolean setTransport(String t) {
                if (!t.matches("lmtp:(unix:private/dovecot-lmtp|inet:127\\.0\\.0\\.1:24)")) return false;
                Shell.Result r = Shell.run(Duration.ofSeconds(30), "postconf", "-e", "virtual_transport=" + t);
                if (!r.success()) return false;
                Shell.Result running = Shell.run(Duration.ofSeconds(20), "service", "postfix", "status");
                if (running.success()) Shell.run(Duration.ofSeconds(60), "service", "postfix", "reload");
                return t.equals(transport());
            }
            @Override public boolean dovecotAccepts() {
                Shell.Result r = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
                return r.success() && r.outputTrim().isEmpty();
            }
            @Override public boolean dovecotReload(boolean expectSocket) {
                Shell.run(Duration.ofSeconds(60), "doveadm", "reload");
                if (!expectSocket) return true;
                if (waitSocket(15)) return true;
                // On 2.4 a reload does not create everything (measured with POP3): a restart, once.
                Shell.run(Duration.ofSeconds(120), "service", "dovecot", "restart");
                return waitSocket(30);
            }
            private boolean waitSocket(int seconds) {
                for (int i = 0; i < seconds * 2; i++) {
                    if (socketReady()) return true;
                    try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
                }
                return false;
            }
            private boolean socketReady() {
                try {
                    Path s = Path.of(SOCKET);
                    if (!Files.exists(s, LinkOption.NOFOLLOW_LINKS)) return false;
                    PosixFileAttributes a = Files.readAttributes(s, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    return a.isOther() && "postfix".equals(a.owner().getName())
                            && PosixFilePermissions.toString(a.permissions()).equals("rw-------");
                } catch (IOException e) {
                    return false;
                }
            }
            @Override public String probe() {
                String mailbox = anActiveMailbox();
                return mailbox == null ? MailProbes.lmtpHello(Path.of(SOCKET), 15_000)
                        : MailProbes.lmtpRecipient(Path.of(SOCKET), mailbox, 15_000);
            }
            @Override public boolean port24Listening() {
                return Shell.runShell(Duration.ofSeconds(20), "sockstat -46lq -p 24 2>/dev/null").outputTrim().length() > 0;
            }
            @Override public boolean baseSocketRootOnly() {
                try {
                    PosixFileAttributes a = Files.readAttributes(Path.of("/var/run/dovecot/lmtp"), PosixFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS);
                    return "root".equals(a.owner().getName()) && PosixFilePermissions.toString(a.permissions()).equals("rw-------");
                } catch (IOException e) {
                    return true;   // not there: nobody delivers to it
                }
            }
            @Override public void flushQueue() {
                Shell.run(Duration.ofSeconds(60), "postqueue", "-f");
            }
        };
    }

    private static String anActiveMailbox() {
        try {
            MailDatabase db = Main.mailDatabase;
            if (db == null || !Main.mysqlAvailable) return null;
            for (MailDatabase.Mailbox m : db.getAllMailboxes()) if (m.active) return m.email;
        } catch (Exception e) {
            // no mailbox to test: the greeting is enough
        }
        return null;
    }

    /** At the start of the root part, after MailDbUsers and DovecotHome. */
    public static void ensureAtBoot() {
        try {
            Result r = run(real(), MASTER_CONF, DOVECOT_CONF);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[LmtpSocket] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[LmtpSocket] left as it is: " + r.detail());
                default -> LOGGER.warning("[LmtpSocket] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[LmtpSocket] failed: " + t.getClass().getName());
        }
    }

    /**
     * After the panel has rewritten the Dovecot configuration (regeneration, move to 2.4) with the new block: Postfix
     * on the socket, if it still delivered on port 24, and the queue drained. The text for the log.
     */
    public static String alignPostfix() {
        Services sv = real();
        try {
            String m = sv.read(MASTER_CONF);
            String t = sv.transport();
            if (m == null || !m.contains(NEW) || TRANSPORT.equals(t)) return "";
            if (!OLD_TRANSPORT.equals(t)) return I18n.tr("server.lmtp.otherTransport", java.util.Map.of("transport", t));
            if (!sv.setTransport(TRANSPORT)) return I18n.tr("server.lmtp.notTaken", java.util.Map.of("transport", TRANSPORT));
            sv.flushQueue();
            return I18n.tr("server.lmtp.aligned", java.util.Map.of("socket", SOCKET));
        } catch (IOException e) {
            return I18n.tr("server.lmtp.unreadable");
        }
    }
}
