package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * I tre socket di Dovecot aperti a chiunque e che il pannello non usa, chiusi.
 *
 * Nella 2.4 Dovecot crea in /var/run/dovecot (0755) alcuni socket con mode 0666: qualunque utente della macchina ci si
 * collega. Misurato sulla VM e sul server vero il 17/11/2026: indexer, imap-urlauth, auth-token e dns-client (gli altri
 * 0666 stanno in login/ e token-login/, cartelle 0750 di dovenull). Nessuno di quei tre serve al pannello:
 *   - indexer serve alla ricerca nel testo (fts) e a `doveadm index -q`: il pannello non configura fts. 0660 root:vmail,
 *     cosi' i processi delle caselle (vmail) lo raggiungono se un giorno la ricerca ci sara';
 *   - imap-urlauth (del servizio imap-urlauth-login, non di imap-urlauth: un nome sbagliato e Dovecot non parte, visto
 *     sulla VM) e auth-token servono a IMAP URLAUTH, spento (imap_urlauth_host vuoto). 0600 root.
 * dns-client resta com'e': fa solo ricerche DNS.
 *
 * Non danno dati a nessuno, ma un servizio della macchina preso da qualcuno (la webmail, per esempio) non deve poter
 * parlare con Dovecot dove non serve. L'installatore scrive il file per la 2.4 (DovecotConfig, conf.d/10-sockets.conf);
 * sui server installati prima lo scrive questa riparazione all'avvio, con lo stesso file. Dovecot crea i socket solo
 * quando parte: serve un riavvio, non un reload (reload non ricrea i socket, misurato). Prima si controlla che
 * l'autenticazione funzioni; dopo il riavvio che Dovecot giri, che l'autenticazione funzioni ancora, che il socket di
 * LMTP e la porta IMAP ci siano e che i tre socket abbiano i permessi nuovi. Se qualcosa non torna si toglie il file e
 * si riavvia: Dovecot torna com'era. Solo nella 2.4: nella 2.3 auth-token non e' detto che ci sia, e non si e' provata.
 */
public final class DovecotSockets {

    private static final Logger LOGGER = Logger.getLogger(DovecotSockets.class.getName());

    public static final String FILE_NAME = "10-sockets.conf";
    static final Path RUN = Path.of("/var/run/dovecot");
    static final Path LMTP_SOCKET = Path.of("/var/spool/postfix/private/dovecot-lmtp");

    /** I socket e i permessi che devono avere (rwx dell'utente, del gruppo, degli altri). */
    static final Map<String, String> WANTED = new LinkedHashMap<>();
    static {
        WANTED.put("indexer", "rw-rw----");
        WANTED.put("imap-urlauth", "rw-------");
        WANTED.put("auth-token", "rw-------");
    }

    private DovecotSockets() {}

    /** Il contenuto del file: lo stesso per l'installatore (DovecotConfig) e per la riparazione. */
    public static String fileContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Socket che Dovecot crea aperti a tutti (0666) e che il pannello non usa: indexer serve alla ricerca\n"
             + "# nel testo (fts, non configurata), imap-urlauth e auth-token a IMAP URLAUTH (spento).\n"
             + "service indexer {\n"
             + "  unix_listener indexer {\n"
             + "    mode = 0660\n"
             + "    user = root\n"
             + "    group = vmail\n"
             + "  }\n"
             + "}\n"
             + "service imap-urlauth-login {\n"
             + "  unix_listener imap-urlauth {\n"
             + "    mode = 0600\n"
             + "  }\n"
             + "}\n"
             + "service auth {\n"
             + "  unix_listener auth-token {\n"
             + "    mode = 0600\n"
             + "  }\n"
             + "}\n";
    }

    enum Action { NOTHING, NOT_24, APPLY, RESTART_ONLY }

    /**
     * Che cosa fare. Funzione pura, per provarla.
     *
     * @param version    `dovecot --version`
     * @param fileNow    il file com'e' adesso, o null se non c'e'
     * @param wrongNow   i socket che oggi non hanno i permessi voluti
     */
    static Action decide(String version, String fileNow, List<String> wrongNow) {
        if (version == null || !version.trim().startsWith("2.4")) return Action.NOT_24;
        boolean fileRight = fileContent().equals(fileNow);
        if (fileRight && wrongNow.isEmpty()) return Action.NOTHING;
        return fileRight ? Action.RESTART_ONLY : Action.APPLY;
    }

    /** I socket di WANTED che ci sono e non hanno i permessi voluti. Uno che manca non conta (Dovecot spento). */
    static List<String> wrong(Path run) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, String> e : WANTED.entrySet()) {
            Path s = run.resolve(e.getKey());
            try {
                if (!Files.exists(s, LinkOption.NOFOLLOW_LINKS)) continue;
                String perms = PosixFilePermissions.toString(Files.getPosixFilePermissions(s, LinkOption.NOFOLLOW_LINKS));
                if (!perms.equals(e.getValue())) out.add(e.getKey() + " " + perms);
            } catch (Exception x) {
                out.add(e.getKey() + " unreadable");
            }
        }
        return out;
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF))) return;
            Shell.Result v = Shell.run(Duration.ofSeconds(15), "dovecot", "--version");
            if (!v.success()) return;
            Path file = Path.of(DovecotAuthWorker.CONF_D, FILE_NAME);
            String now = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file) : null;
            Action a = decide(v.outputTrim(), now, wrong(RUN));
            if (a == Action.NOTHING || a == Action.NOT_24) return;
            apply(file, fileContent());
        } catch (Throwable t) {
            LOGGER.warning("[DovecotSockets] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Scrive il file, valida, riavvia e verifica; se la verifica non torna, rimette com'era e riavvia. */
    static boolean apply(Path file, String content) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[DovecotSockets] Dovecot is not running: sockets left as they are, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[DovecotSockets] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): sockets left as they are");
            return false;
        }
        Path saved = Files.exists(file, LinkOption.NOFOLLOW_LINKS)
                ? Files.createTempFile(file.getParent().getParent(), ".sockets-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, content);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[DovecotSockets] ROLLED_BACK: doveconf refuses the file (" + firstLine(check.outputTrim()) + "): nothing changed");
                return false;
            }
            restart();
            String problem = verify();
            if (problem != null) {
                putBack(file, saved, true);
                String after = verifyRunning();
                LOGGER.warning("[DovecotSockets] ROLLED_BACK: " + problem + "; file removed and Dovecot restarted"
                        + (after == null ? " (running again)" : " (" + after + ")"));
                return false;
            }
            LOGGER.info("[DovecotSockets] DONE: indexer 0660 root:vmail, imap-urlauth and auth-token 0600 root (" + file
                    + "); Dovecot restarted, authentication, LMTP and IMAP checked");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /** Dopo il riavvio, fino a 20 s: Dovecot gira, l'autenticazione passa, LMTP e IMAP ci sono, i permessi sono quelli. */
    static String verify() throws InterruptedException {
        String last = "unreachable";
        for (int i = 0; i < 40; i++) {
            last = verifyRunning();
            if (last == null) {
                List<String> w = wrong(RUN);
                List<String> missing = new ArrayList<>();
                for (String s : WANTED.keySet()) if (!Files.exists(RUN.resolve(s), LinkOption.NOFOLLOW_LINKS)) missing.add(s);
                if (w.isEmpty() && missing.isEmpty()) return null;
                last = "sockets " + (w.isEmpty() ? "" : "with other permissions " + w) + (missing.isEmpty() ? "" : " missing " + missing);
            }
            Thread.sleep(500);
        }
        return last;
    }

    /** null se Dovecot gira e risponde; altrimenti che cosa manca. */
    static String verifyRunning() {
        if (!DovecotAuthWorker.running()) return "Dovecot does not run after the restart";
        int rc = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) return "doveadm auth lookup fails (exit " + rc + ")";
        if (!Files.exists(LMTP_SOCKET, LinkOption.NOFOLLOW_LINKS)) return "the LMTP socket " + LMTP_SOCKET + " is missing";
        Shell.Result imap = Shell.run(Duration.ofSeconds(10), "sockstat", "-46l", "-p", "993");
        if (!imap.outputTrim().contains(":993")) return "nothing listens on port 993";
        return null;
    }

    static void restart() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Shell.run(Duration.ofSeconds(10), "chown", "root:wheel", tmp.toString());
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean restart) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (restart) {
            restart();
            // Il riavvio di prima puo' aver lasciato Dovecot spento: si riprova ad accenderlo
            if (!DovecotAuthWorker.running()) Shell.run(Duration.ofSeconds(60), "service", "dovecot", "start");
        }
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
