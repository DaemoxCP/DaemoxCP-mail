package org.mail_panel.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Setup automatico di Fail2ban per il mail panel al boot.
 *
 * Operazioni (TUTTE idempotenti, fail-safe):
 *   1. Crea /var/log/mail-panel-auth.log con perms 640 root:wheel
 *   2. Scrive il filter Fail2ban in /usr/local/etc/fail2ban/filter.d/mail-panel-auth.conf
 *   3. Aggiunge la jail [mail-panel-auth] a /usr/local/etc/fail2ban/jail.local
 *      (solo se non esiste già — non sovrascrive customizzazioni)
 *   4. Aggiunge log rotation in /usr/local/etc/newsyslog.conf.d/
 *   5. Reload Fail2ban
 *
 * Tutti i passi sono best-effort: se uno fallisce (permessi, fail2ban non
 * installato, ecc.) viene loggato un warning ma il pannello continua.
 *
 * Da chiamare UNA VOLTA al boot dopo l'inizializzazione del Fail2banManager.
 */
public final class Fail2banAutoSetup {
    private static final Logger LOGGER = Logger.getLogger(Fail2banAutoSetup.class.getName());

    private static final String LOG_FILE          = "/var/log/mail-panel-auth.log";
    private static final String FILTER_DIR        = "/usr/local/etc/fail2ban/filter.d";
    private static final String FILTER_FILE       = FILTER_DIR + "/mail-panel-auth.conf";
    private static final String JAIL_LOCAL        = "/usr/local/etc/fail2ban/jail.local";
    private static final String NEWSYSLOG_DIR     = "/usr/local/etc/newsyslog.conf.d";
    private static final String NEWSYSLOG_CONF    = NEWSYSLOG_DIR + "/mail-panel-auth.conf";
    private static final String FAIL2BAN_CLIENT   = "/usr/local/bin/fail2ban-client";

    private static final String JAIL_MARKER = "[mail-panel-auth]";

    /** Avvia il setup. Idempotente: chiamabile più volte senza danni. */
    public static void run() {
        try {
            // 1. Log file
            ensureLogFile();
            // 2. Filter
            boolean filterChanged = writeFilterIfMissing();
            // 3. Jail
            boolean jailChanged = appendJailIfMissing();
            // 4. Log rotation
            writeNewsyslogIfMissing();
            // 5. Permaban setup (file + pf anchor)
            ensurePermabanSetup();
            // 6. Reload Fail2ban se abbiamo cambiato qualcosa
            if (filterChanged || jailChanged) {
                reloadFail2ban();
            }
        } catch (Throwable t) {
            // Non propagare mai — il setup non deve far crashare il pannello
            LOGGER.warning("[Fail2banAutoSetup] Setup failed: " + t.getMessage());
        }
    }

    /**
     * Setup della feature permaban:
     *  1. Crea /var/db/mail-panel/permaban.list se manca
     *  2. Aggiunge a /etc/pf.conf (se esiste): table <permaban> persist + block rule
     *  3. Ricarica pf e popola la tabella runtime dal file
     */
    private static void ensurePermabanSetup() {
        try {
            // 1. File
            Path dir = Paths.get(Fail2banManager.PERMABAN_DIR);
            if (!Files.isDirectory(dir)) Files.createDirectories(dir);
            Path file = Paths.get(Fail2banManager.PERMABAN_FILE);
            if (!Files.exists(file)) {
                String header = "# Permaban list — gestito dal mail panel\n"
                    + "# Aggiungi/rimuovi IP dall'UI del pannello, NON modificare a mano.\n\n";
                Files.writeString(file, header);
                try {
                    Files.setPosixFilePermissions(file,
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));
                } catch (Exception ignored) {}
                LOGGER.info("[Fail2banAutoSetup] Created " + Fail2banManager.PERMABAN_FILE);
            }

            // 2. Anchor / tabella in pf.conf
            Path pfConf = Paths.get("/etc/pf.conf");
            if (Files.exists(pfConf)) {
                String content = Files.readString(pfConf, java.nio.charset.StandardCharsets.UTF_8);
                boolean hasTable = content.contains("table <permaban>");
                boolean hasBlock = content.matches("(?s).*block\\s+in\\s+quick\\s+from\\s+<permaban>.*");
                boolean hasF2bAnchor = hasF2bAnchor(content);
                if (!hasTable || !hasBlock || !hasF2bAnchor) {
                    // Backup
                    Path bak = Paths.get("/etc/pf.conf.bak." + System.currentTimeMillis());
                    Files.copy(pfConf, bak);
                    StringBuilder additions = new StringBuilder();
                    additions.append("\n# === Permaban (auto-gestito dal mail panel) ===\n");
                    if (!hasTable) {
                        additions.append("table <permaban> persist file \"")
                            .append(Fail2banManager.PERMABAN_FILE).append("\"\n");
                    }
                    if (!hasBlock) {
                        additions.append("block in quick from <permaban>\n");
                    }
                    if (!hasF2bAnchor) {
                        // L'anchor di fail2ban. La jail [mail-panel-auth] ha
                        // "action = pf[...]", e l'azione pf di fail2ban mette le sue regole
                        // dentro l'anchor "f2b/<nome>". Un anchor che pf.conf non nomina non
                        // viene MAI guardato: fail2ban annota il blocco, lo scrive nel suo
                        // registro, dice di averlo fatto, e il pacchetto passa lo stesso.
                        // Il pannello sapeva aggiungerlo, ma solo dalla pagina Firewall, a
                        // pulsante premuto: all'avvio no. Le regole dell'anchor hanno
                        // "quick", quindi valgono anche messe in fondo.
                        additions.append("anchor \"f2b/*\"\n");
                    }
                    // Append (regole con 'quick' funzionano anche se piazzate in fondo)
                    String newContent = content + (content.endsWith("\n") ? "" : "\n") + additions.toString();

                    // Pre-flight syntax check con file temporaneo
                    Path tmp = Files.createTempFile("pf-permaban-", ".conf");
                    Files.writeString(tmp, newContent);
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", tmp.toString());
                    org.mail_panel.util.Shell.applicaPath(testPb);
                    testPb.redirectErrorStream(true);
                    Process tp = testPb.start();
                    String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                    if (tp.exitValue() != 0) {
                        LOGGER.warning("[Fail2banAutoSetup] pf.conf permaban check failed, NOT applied: " + testOut);
                        Files.deleteIfExists(tmp);
                    } else {
                        Files.move(tmp, pfConf, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        // Ricarica live
                        try {
                            // TODO: migrate to Shell.run when touched
                            ProcessBuilder loadPb = new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf");
                            org.mail_panel.util.Shell.applicaPath(loadPb);
                            loadPb.redirectErrorStream(true);
                            Process lp = loadPb.start();
                            lp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                        } catch (Exception ignored) {}
                        LOGGER.info("[Fail2banAutoSetup] Permaban anchor added to /etc/pf.conf");
                    }
                }
            }

            // 3. Ricarica la tabella runtime dal file (se pf è attivo)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", Fail2banManager.PERMABAN_TABLE,
                    "-T", "replace", "-f", Fail2banManager.PERMABAN_FILE);
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignored) {}

        } catch (Exception e) {
            LOGGER.warning("[Fail2banAutoSetup] ensurePermabanSetup failed: " + e.getMessage());
        }
    }

    /**
     * Un filtro gia' sul disco: lo riscriviamo?
     *
     * <p>Si', solo se e' ancora quello del pannello ed e' diverso da quello che il pannello
     * scriverebbe oggi. Un file modificato a mano non si tocca, e si riconosce dal fatto che
     * non comincia piu' con la firma.
     */
    static boolean shouldRewriteFilter(String existing) {
        if (existing == null) return true;
        if (existing.equals(filterContent())) return false;
        return existing.startsWith(MARKER);
    }

    /**
     * In questo pf.conf c'e' gia' la riga che fa guardare a pf le regole di fail2ban?
     *
     * <p>Si accettano le forme che pf accetta: col nome fra virgolette o senza. Non si guarda
     * dentro i commenti, perche' una riga commentata non e' una regola — e quel file i
     * commenti li contiene davvero, scritti dal pannello stesso.
     */
    public static boolean hasF2bAnchor(String pfConf) {
        for (String line : pfConf.split("\n")) {
            String t = line.trim();
            if (t.startsWith("#")) continue;
            if (t.startsWith("anchor \"f2b/*\"") || t.startsWith("anchor f2b/*")) return true;
        }
        return false;
    }

    /** Crea il file di log con perms 640 root:wheel se non esiste. */
    private static void ensureLogFile() {
        try {
            Path logPath = Paths.get(LOG_FILE);
            if (!Files.exists(logPath)) {
                Path parent = logPath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    Files.createDirectories(parent);
                }
                Files.createFile(logPath);
                LOGGER.info("[Fail2banAutoSetup] Created " + LOG_FILE);
            }
            // Setta sempre i perms (640 = rw-r-----)
            try {
                Set<PosixFilePermission> perms = new HashSet<>();
                perms.add(PosixFilePermission.OWNER_READ);
                perms.add(PosixFilePermission.OWNER_WRITE);
                perms.add(PosixFilePermission.GROUP_READ);
                Files.setPosixFilePermissions(logPath, perms);
            } catch (UnsupportedOperationException ignored) {
                // FS non POSIX — ignora
            }
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot create " + LOG_FILE + ": " + e.getMessage());
        }
    }

    /**
     * Scrive il filter se manca, e lo riscrive se e' ancora quello del pannello ed e'
     * vecchio. Ritorna true se ha scritto.
     *
     * <p>"Scrivi solo se manca" lasciava per sempre il filtro rotto a chi aveva gia' avviato
     * il pannello una volta: il file c'era, quindi la correzione non sarebbe mai arrivata.
     * Un filtro modificato da chi amministra la macchina invece non si tocca, e si riconosce
     * dal fatto che la prima riga non e' piu' la firma del pannello.
     */
    private static boolean writeFilterIfMissing() {
        try {
            Path filterDir = Paths.get(FILTER_DIR);
            if (!Files.isDirectory(filterDir)) {
                LOGGER.info("[Fail2banAutoSetup] " + FILTER_DIR + " does not exist — Fail2ban not installed? Skipping.");
                return false;
            }
            Path filterPath = Paths.get(FILTER_FILE);
            String wanted = filterContent();
            if (Files.exists(filterPath)) {
                String existing = Files.readString(filterPath, StandardCharsets.UTF_8);
                if (!shouldRewriteFilter(existing)) {
                    if (!existing.equals(wanted))
                        LOGGER.info("[Fail2banAutoSetup] " + FILTER_FILE + " was edited by hand — left alone");
                    return false;
                }
                LOGGER.info("[Fail2banAutoSetup] Rewriting our own older " + FILTER_FILE);
            }
            Files.writeString(filterPath, wanted, StandardCharsets.UTF_8);
            try { Files.setPosixFilePermissions(filterPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Wrote " + FILTER_FILE);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot write filter: " + e.getMessage());
            return false;
        }
    }

    /** Aggiunge la sezione [mail-panel-auth] a jail.local solo se manca. */
    private static boolean appendJailIfMissing() {
        try {
            Path jailPath = Paths.get(JAIL_LOCAL);
            String existing = Files.exists(jailPath)
                ? Files.readString(jailPath, StandardCharsets.UTF_8)
                : "";

            if (existing.contains(JAIL_MARKER)) {
                return false; // jail già presente, rispetta customizzazioni
            }

            // Assicura newline finale prima di appendere
            String prefix = existing.isEmpty() ? "" : (existing.endsWith("\n") ? "" : "\n");
            String toAppend = prefix + "\n" + JAIL_BLOCK;

            // Crea jail.local se non esiste
            if (!Files.exists(jailPath)) {
                Path parent = jailPath.getParent();
                if (parent != null && !Files.exists(parent)) {
                    LOGGER.info("[Fail2banAutoSetup] " + parent + " does not exist — Fail2ban not installed? Skipping jail.");
                    return false;
                }
                Files.writeString(jailPath, JAIL_BLOCK, StandardCharsets.UTF_8);
            } else {
                Files.writeString(jailPath, toAppend, StandardCharsets.UTF_8,
                    StandardOpenOption.APPEND);
            }
            try { Files.setPosixFilePermissions(jailPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Added jail [mail-panel-auth] to " + JAIL_LOCAL);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot modify jail.local: " + e.getMessage());
            return false;
        }
    }

    /**
     * Scrive la conf di log rotation se manca.
     *
     * <p>La cartella si <strong>crea</strong>, non si salta: su una FreeBSD appena installata
     * {@code /usr/local/etc/newsyslog.conf.d} non esiste ancora, ma {@code /etc/newsyslog.conf}
     * la include gia' (riga {@code <include> /usr/local/etc/newsyslog.conf.d/[!.]*.conf}).
     * Saltare voleva dire proprio il caso normale: nessuna rotazione, e un registro di
     * autenticazione che cresce senza fine.
     */
    private static void writeNewsyslogIfMissing() {
        try {
            Path dir = Paths.get(NEWSYSLOG_DIR);
            if (!Files.isDirectory(dir)) Files.createDirectories(dir);
            Path conf = Paths.get(NEWSYSLOG_CONF);
            if (Files.exists(conf)) return; // già presente
            String content = "# Log rotation per mail-panel auth log (auto-generato dal pannello)\n"
                + "/var/log/mail-panel-auth.log    root:wheel    640    7    1024    *    JC\n";
            Files.writeString(conf, content, StandardCharsets.UTF_8);
            LOGGER.info("[Fail2banAutoSetup] Wrote " + NEWSYSLOG_CONF);
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Cannot write newsyslog conf: " + e.getMessage());
        }
    }

    /** Reload Fail2ban con fail2ban-client se disponibile e in esecuzione. */
    private static void reloadFail2ban() {
        try {
            if (!Files.isExecutable(Paths.get(FAIL2BAN_CLIENT))) {
                LOGGER.info("[Fail2banAutoSetup] " + FAIL2BAN_CLIENT + " not executable — skipping reload");
                return;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(FAIL2BAN_CLIENT, "reload");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean done = p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                LOGGER.warning("[Fail2banAutoSetup] Reload Fail2ban timeout");
                return;
            }
            int exit = p.exitValue();
            if (exit == 0) {
                LOGGER.info("[Fail2banAutoSetup] Fail2ban reloaded");
            } else {
                LOGGER.warning("[Fail2banAutoSetup] Reload Fail2ban exit=" + exit);
            }
        } catch (Exception e) {
            LOGGER.warning("[Fail2banAutoSetup] Fail2ban reload failed: " + e.getMessage());
        }
    }

    // ================== EMBEDDED CONFIG CONTENT ==================

    /** La riga con cui il pannello firma i file che scrive lui: solo quelli li riscrive. */
    static final String MARKER = "# Fail2ban filter per FreeBSD-Mail-Panel (auto-generato dal pannello)";

    private static final String FAILURES = "LOGIN_FAILURE|LOGIN_2FA_FAILURE|LOGIN_INVALID_INPUT"
        + "|LOGIN_BLOCKED|CSRF_FAILURE|SSL_CERT_[A-Z_]+_FAILED|FAIL2BAN_[A-Z_]+_FAILED"
        + "|PASSKEY_REGISTER_FAILED|2FA_[A-Z_]+_FAILED|ADMIN_PASSWORD_CHANGE_FAILED";

    private static final String SUCCESSES = "LOGIN_SUCCESS|PASSKEY_LOGIN_SUCCESS|DOMAIN_CREATED"
        + "|DOMAIN_UPDATED|DOMAIN_DELETED|ALIAS_CREATED|ALIAS_DELETED|SSL_CERT_RENEWED"
        + "|SSL_CERT_ISSUED_HTTP01|SSL_CERT_ISSUED_DNS01|SSL_CERT_DEPLOYED"
        + "|SSL_CERT_INSTALLED_MANUAL|SSL_AUTO_RENEWAL_SETTINGS_CHANGED|SSL_MANUAL_CHECK_TRIGGERED"
        + "|FAIL2BAN_IP_BANNED|FAIL2BAN_IP_UNBANNED|2FA_ENABLED|2FA_DISABLED"
        + "|2FA_BACKUP_CODES_REGENERATED|PASSKEY_REGISTERED|PASSKEY_DELETED|ADMIN_PASSWORD_CHANGED"
        + "|HOSTNAME_CHANGED|ROUNDCUBE_DOMAIN_CHANGED|ROUNDCUBE_SSL_UPDATED";

    /**
     * Il filtro.
     *
     * <p>Il {@code failregex} deve reggere <strong>due</strong> forme della stessa riga, perche'
     * fail2ban, quando il {@code datepattern} prende, toglie la data dalla riga prima di
     * cercarci dentro, e quando non prende la lascia. Prima era {@code ^\S+ \[}, cioe' scritto
     * per la sola forma con la data: tolta la data resta uno spazio davanti alla parentesi, e
     * {@code \S+} non puo' mangiarlo. Misurato con {@code fail2ban-regex}: funzionava per
     * caso, perche' l'ora aveva i decimali e quei decimali facevano da {@code \S+}; delle 42
     * righe di prova le due col secondo intero erano le sole che fail2ban si perdeva. Un
     * filtro che non trova niente ha lo stesso aspetto di un sistema senza attacchi, quindi
     * nessuno se ne sarebbe accorto.
     *
     * <p>Il {@code %%z} in fondo al {@code datepattern} prende la Z dell'ora UTC. I due pezzi
     * vanno insieme con il formato della riga ({@code SSLMailServer.auditLine}): cambiarne uno
     * solo non rompe niente a vista, semplicemente smette di bloccare qualcuno.
     */
    public static String filterContent() {
        return MARKER + "\n"
        + "#\n"
        + "# Il pannello scrive su " + LOG_FILE + " righe cosi':\n"
        + "#   2026-10-17T21:20:28Z [LOGIN_FAILURE] ip=1.2.3.4 user=admin details=\"...\"\n"
        + "#\n"
        + "# Prova:  fail2ban-regex " + LOG_FILE + " " + FILTER_FILE + "\n"
        + "\n"
        + "[Definition]\n"
        + "\n"
        + "failregex = ^\\s*(?:\\S+\\s+)?\\[(?:" + FAILURES + ")\\] ip=<HOST>\n"
        + "\n"
        + "ignoreregex = ^\\s*(?:\\S+\\s+)?\\[(?:" + SUCCESSES + ")\\]\n"
        + "\n"
        + "datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S%%z\n";
    }

    private static final String JAIL_BLOCK = ""
        + "# Auto-generato da FreeBSD-Mail-Panel — modifica i parametri liberamente,\n"
        + "# il pannello NON sovrascrive questa sezione una volta presente.\n"
        + "[mail-panel-auth]\n"
        + "enabled  = true\n"
        + "filter   = mail-panel-auth\n"
        + "logpath  = /var/log/mail-panel-auth.log\n"
        + "maxretry = 5\n"
        + "findtime = 600\n"
        + "bantime  = 3600\n"
        + "backend  = auto\n"
        + "action   = pf[name=mail-panel-auth, port=\"0:65535\"]\n";
}
