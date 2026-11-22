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
 * Il socket di clamd solo del gruppo clamav, 0660, e rspamd in quel gruppo (reperto 237).
 *
 * <p>Il clamd.conf del pacchetto lascia LocalSocketMode commentato: «Default: disabled (socket is world accessible)», e
 * il socket nasceva 0666. Qualunque processo della macchina poteva far analizzare file a clamd (e tenerlo occupato) o
 * chiedergli SHUTDOWN. Il clamd.conf d'esempio di ClamAV propone LocalSocketGroup e LocalSocketMode 660; chi parla con
 * clamd e' solo rspamd (il modulo antivirus, sul socket), freshclam (che gira come clamav) e il pannello (root).
 *
 * <p>Sui server installati prima, all'avvio: rspamd entra nel gruppo clamav e riparte (i gruppi di un processo si leggono
 * solo quando parte); poi clamd.conf con le due righe e clamd riparte (con le firme da ricaricare: fino a cinque minuti).
 * La prova e' un messaggio con EICAR fatto analizzare a rspamd prima e dopo: se prima rspamd lo riconosceva, dopo deve
 * riconoscerlo ancora. rspamd tiene in memoria il risultato dell'antivirus per contenuto dell'allegato (misurato sulla
 * VM il 16/11/2026: lo stesso allegato una seconda volta non arriva a clamd), quindi ogni prova ha in coda al file degli
 * spazi diversi, che EICAR ammette, e clamd lo analizza davvero. Un errore rimette tutto com'era. Si cambia solo se
 * clamd.conf non ha gia' LocalSocketGroup o LocalSocketMode attivi: una scelta fatta a mano resta.
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

    /** Quello che serve, per provarlo senza clamd e rspamd. */
    interface Services {
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        boolean isMember(String group, String user);
        boolean setMember(String group, String user, boolean member);
        boolean restartRspamd();
        /** Riavvia clamd e aspetta il socket; vero se risponde. */
        boolean restartClamd();
        /** Il socket e' di clamav:clamav, 0660. */
        boolean socketGroupOnly();
        /** rspamd riconosce EICAR in un allegato mai visto prima (quindi clamd lo analizza davvero). */
        boolean rspamdFindsEicar();
        /** clamd risponde a VERSION sul suo socket (a root). */
        boolean clamdAnswers();
        /** rspamd analizza un messaggio adesso. */
        boolean rspamdScans();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** clamd.conf ha il socket del pannello e nessun LocalSocketGroup o LocalSocketMode attivo. Pura. */
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

    /** Il passaggio, puro rispetto a {@link Services}. */
    static Result run(Services sv, Path clamdConf) {
        String conf;
        try {
        // Il blocco scritto in italiano dalle versioni di prima vale come quello di adesso (EnglishComments).
            conf = EnglishComments.english(sv.read(clamdConf));
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "clamd.conf cannot be read: " + e.getClass().getSimpleName());
        }
        if (conf == null) return new Result(Outcome.NOTHING, "");   // ClamAV non c'e'
        boolean member = sv.isMember(GROUP, RSPAMD);
        boolean has = conf.contains(BLOCK);
        if (has && member && sv.socketGroupOnly()) return new Result(Outcome.NOTHING, "");
        if (!has && !packageLike(conf))
            return new Result(Outcome.LEFT, "clamd.conf already sets the socket's group or mode, or another socket: left as it is");

        if (!sv.clamdAnswers()) return new Result(Outcome.LEFT, "clamd does not answer now: nothing changed");
        if (!sv.rspamdScans()) return new Result(Outcome.LEFT, "rspamd does not scan a message now: nothing changed");
        boolean before = sv.rspamdFindsEicar();
        try {
            // 1. rspamd nel gruppo clamav, e riavviato perche' lo sappia.
            if (!member) {
                if (!sv.setMember(GROUP, RSPAMD, true))
                    return back(sv, clamdConf, conf, member, "rspamd could not be added to the group " + GROUP);
                if (!sv.restartRspamd())
                    return back(sv, clamdConf, conf, member, "rspamd does not scan a message after joining the group " + GROUP);
            }
            // 2. Il socket 0660 del gruppo clamav.
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

    // ===================== Il server vero =====================

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Il file di prova EICAR, scritto al contrario: in chiaro nel jar o nei sorgenti un antivirus li metterebbe in
     * quarantena. In coda da 1 a 40 spazi e tabulazioni a caso, che lo standard EICAR ammette.
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
                // Le firme si ricaricano: sulla VM 15 secondi, su un server piccolo di piu'.
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

    /** All'avvio della parte root, dopo RspamdUser. */
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
