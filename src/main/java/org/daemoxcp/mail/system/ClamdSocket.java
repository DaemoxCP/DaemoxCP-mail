package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * The clamd socket for the clamav group only, 0660, and rspamd in that group (finding 237).
 *
 * <p>The package's clamd.conf leaves LocalSocketMode commented out: "Default: disabled (socket is world accessible)",
 * and the socket was created 0666. Any process on the machine could have clamd scan files (and keep it busy) or ask
 * it to SHUTDOWN. ClamAV's example clamd.conf suggests LocalSocketGroup and LocalSocketMode 660; the only ones that
 * talk to clamd are rspamd (the antivirus module, on the socket), freshclam (which runs as clamav) and the panel
 * (root).
 *
 * <p>On servers installed earlier, at startup: rspamd joins the clamav group and restarts (a process's groups are
 * read only when it starts); then clamd.conf gets the two lines and clamd restarts (with the signatures to reload: up
 * to five minutes). The test is a message with EICAR given to rspamd to scan before and after: if rspamd recognised it
 * before, it must still recognise it afterwards. rspamd keeps the antivirus result in memory per attachment content
 * (measured on the VM on 2026-11-16: the same attachment a second time does not reach clamd), so each test has
 * different spaces at the end of the file, which EICAR allows, and clamd really scans it. An error puts everything
 * back as it was. It is changed only if clamd.conf does not already have LocalSocketGroup or LocalSocketMode active:
 * a choice made by hand stays.
 */
public final class ClamdSocket {

    private static final Logger LOGGER = Logger.getLogger(ClamdSocket.class.getName());

    private ClamdSocket() {}

    static final Path CLAMD_CONF = Path.of("/usr/local/etc/clamd.conf");
    static final String SOCKET = "/var/run/clamav/clamd.sock";
    static final String GROUP = "clamav";
    static final String RSPAMD = "rspamd";

    static final String MARK = "# daemoxcp-mail: clamd's socket only for the clamav group, which rspamd is in (finding 237)\n";
    public static final String BLOCK = MARK + "LocalSocketGroup clamav\nLocalSocketMode 660\n";

    /** What is needed, to test it without clamd and rspamd. */
    interface Services {
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        boolean isMember(String group, String user);
        boolean setMember(String group, String user, boolean member);
        boolean restartRspamd();
        /** Restarts clamd and waits for the socket; true if it answers. */
        boolean restartClamd();
        /** The socket belongs to clamav:clamav, 0660. */
        boolean socketGroupOnly();
        /** rspamd recognises EICAR in an attachment never seen before (so clamd really scans it). */
        boolean rspamdFindsEicar();
        /** clamd answers VERSION on its socket (to root). */
        boolean clamdAnswers();
        /** rspamd scans a message now. */
        boolean rspamdScans();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** clamd.conf has the panel's socket and no active LocalSocketGroup or LocalSocketMode. Pure. */
    static boolean packageLike(String conf) {
        boolean socket = false;
        for (String l : conf.split("\n")) {
            String t = l.trim();
            if (t.startsWith("#") || t.isEmpty()) continue;
            String[] w = t.split("\\s+");
            if (w[0].equals("LocalSocketGroup") || w[0].equals("LocalSocketMode")) return false;
            if (w[0].equals("LocalSocket")) {
                if (w.length != 2 || !w[1].equals(SOCKET)) return false;
                socket = true;
            }
        }
        return socket;
    }

    /** The switchover, pure with respect to {@link Services}. */
    static Result run(Services sv, Path clamdConf) {
        String conf;
        try {
        // The block written in Italian by earlier versions counts as the current one (EnglishComments).
            conf = EnglishComments.english(sv.read(clamdConf));
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "clamd.conf cannot be read: " + e.getClass().getSimpleName());
        }
        if (conf == null) return new Result(Outcome.NOTHING, "");   // ClamAV is not there
        boolean member = sv.isMember(GROUP, RSPAMD);
        boolean has = conf.contains(BLOCK);
        if (has && member && sv.socketGroupOnly()) return new Result(Outcome.NOTHING, "");
        if (!has && !packageLike(conf))
            return new Result(Outcome.LEFT, "clamd.conf already sets the socket's group or mode, or another socket: left as it is");

        if (!sv.clamdAnswers()) return new Result(Outcome.LEFT, "clamd does not answer now: nothing changed");
        if (!sv.rspamdScans()) return new Result(Outcome.LEFT, "rspamd does not scan a message now: nothing changed");
        boolean before = sv.rspamdFindsEicar();
        try {
            // 1. rspamd in the clamav group, and restarted so that it knows.
            if (!member) {
                if (!sv.setMember(GROUP, RSPAMD, true))
                    return back(sv, clamdConf, conf, member, "rspamd could not be added to the group " + GROUP);
                if (!sv.restartRspamd())
                    return back(sv, clamdConf, conf, member, "rspamd does not scan a message after joining the group " + GROUP);
            }
            // 2. The 0660 socket of the clamav group.
            if (!has) sv.write(clamdConf, conf + (conf.endsWith("\n") ? "" : "\n") + "\n" + BLOCK);
            if (!sv.restartClamd() || !sv.socketGroupOnly())
                return back(sv, clamdConf, conf, member, "clamd does not answer on " + SOCKET + " as clamav:clamav 0660");
            if (before && !sv.rspamdFindsEicar())
                return back(sv, clamdConf, conf, member, "rspamd no longer reaches clamd: EICAR is not found");
        } catch (IOException e) {
            return back(sv, clamdConf, conf, member, "a file could not be written: " + e.getClass().getSimpleName());
        }
        return new Result(Outcome.DONE, "clamd's socket is clamav:clamav 0660 and rspamd is in the group clamav"
                + (before ? "; rspamd still finds EICAR through it" : "; rspamd's antivirus did not find EICAR before either"));
    }

    private static Result back(Services sv, Path clamdConf, String conf, boolean member, String why) {
        boolean ok = true;
        try {
            sv.write(clamdConf, conf);
        } catch (IOException e) {
            ok = false;
        }
        ok &= sv.restartClamd();
        if (!member) {
            ok &= sv.setMember(GROUP, RSPAMD, false);
            ok &= sv.restartRspamd();
        }
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting it back failed"));
    }

    // ===================== The production server =====================

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The EICAR test file, written backwards: in plain text in the jar or in the sources an antivirus would
     * quarantine them. At the end, 1 to 40 random spaces and tabs, which the EICAR standard allows.
     */
    static String eicar() {
        String e = new StringBuilder("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X").reverse().toString();
        StringBuilder tail = new StringBuilder();
        for (int i = 0, n = 1 + RANDOM.nextInt(40); i < n; i++) tail.append(RANDOM.nextBoolean() ? ' ' : '\t');
        return e + tail;
    }

    static String eicarMessage() {
        long id = RANDOM.nextLong() & Long.MAX_VALUE;
        return "From: probe@daemoxcp-mail.invalid\nTo: probe@daemoxcp-mail.invalid\nSubject: daemoxcp-mail antivirus probe\n"
                + "Message-ID: <clamd-probe-" + id + "@daemoxcp-mail.invalid>\nMIME-Version: 1.0\n"
                + "Content-Type: multipart/mixed; boundary=\"daemoxcp-mail-probe\"\n\n"
                + "--daemoxcp-mail-probe\nContent-Type: text/plain\n\nThis message only checks that rspamd reaches clamd.\n"
                + "--daemoxcp-mail-probe\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"probe.com\"\n\n"
                + eicar() + "\n--daemoxcp-mail-probe--\n";
    }

    static Services real() {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public boolean isMember(String group, String user) {
                return RspamdUser.members(group).contains(user);
            }
            @Override public boolean setMember(String group, String user, boolean member) {
                return RspamdUser.setMember(group, user, member);
            }
            @Override public boolean restartRspamd() {
                try {
                    return RspamdUser.restart();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            @Override public boolean restartClamd() {
                Shell.run(Duration.ofSeconds(300), "service", "clamav_clamd", "restart");
                // The signatures are reloaded: on the VM 15 seconds, on a small server longer.
                for (int i = 0; i < 300; i++) {
                    if (SoftwareVersions.askClamd(Path.of(SOCKET)) != null) return true;
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return false;
                    }
                }
                return false;
            }
            @Override public boolean socketGroupOnly() {
                try {
                    PosixFileAttributes a = Files.readAttributes(Path.of(SOCKET), PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    return a.isOther() && "clamav".equals(a.owner().getName()) && "clamav".equals(a.group().getName())
                            && PosixFilePermissions.toString(a.permissions()).equals("rw-rw----");
                } catch (IOException e) {
                    return false;
                }
            }
            @Override public boolean clamdAnswers() {
                return SoftwareVersions.askClamd(Path.of(SOCKET)) != null;
            }
            @Override public boolean rspamdScans() {
                return RspamdUser.scan() != null;
            }
            @Override public boolean rspamdFindsEicar() {
                String out = RspamdUser.symbols(eicarMessage());
                return out != null && out.contains("CLAM_VIRUS") && !out.contains("CLAM_VIRUS_FAIL");
            }
        };
    }

    /** At startup of the root part, after RspamdUser. */
    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of("/usr/local/sbin/clamd")) || !Files.isExecutable(Path.of("/usr/local/bin/rspamd"))) return;
            Result r = run(real(), CLAMD_CONF);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[ClamdSocket] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[ClamdSocket] left as it is: " + r.detail());
                default -> LOGGER.warning("[ClamdSocket] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[ClamdSocket] failed: " + t.getClass().getName());
        }
    }
}
