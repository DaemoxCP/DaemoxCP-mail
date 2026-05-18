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
            LOGGER.warning("[Fail2banAutoSetup] Setup non riuscito: " + t.getMessage());
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
                LOGGER.info("[Fail2banAutoSetup] Creato " + Fail2banManager.PERMABAN_FILE);
            }

            // 2. Anchor / tabella in pf.conf
            Path pfConf = Paths.get("/etc/pf.conf");
            if (Files.exists(pfConf)) {
                String content = Files.readString(pfConf, java.nio.charset.StandardCharsets.UTF_8);
                boolean hasTable = content.contains("table <permaban>");
                boolean hasBlock = content.matches("(?s).*block\\s+in\\s+quick\\s+from\\s+<permaban>.*");
                if (!hasTable || !hasBlock) {
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
                    // Append (regole con 'quick' funzionano anche se piazzate in fondo)
                    String newContent = content + (content.endsWith("\n") ? "" : "\n") + additions.toString();

                    // Pre-flight syntax check con file temporaneo
                    Path tmp = Files.createTempFile("pf-permaban-", ".conf");
                    Files.writeString(tmp, newContent);
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", tmp.toString());
                    testPb.redirectErrorStream(true);
                    Process tp = testPb.start();
                    String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                    if (tp.exitValue() != 0) {
                        LOGGER.warning("[Fail2banAutoSetup] pf.conf permaban check fallito, NON applicato: " + testOut);
                        Files.deleteIfExists(tmp);
                    } else {
                        Files.move(tmp, pfConf, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                        // Ricarica live
                        try {
                            // TODO: migrate to Shell.run when touched
                            ProcessBuilder loadPb = new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf");
                            loadPb.redirectErrorStream(true);
                            Process lp = loadPb.start();
                            lp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                        } catch (Exception ignored) {}
                        LOGGER.info("[Fail2banAutoSetup] Anchor permaban aggiunto a /etc/pf.conf");
                    }
                }
            }

            // 3. Ricarica la tabella runtime dal file (se pf è attivo)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", Fail2banManager.PERMABAN_TABLE,
                    "-T", "replace", "-f", Fail2banManager.PERMABAN_FILE);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignored) {}

        } catch (Exception e) {
            LOGGER.warning("[Fail2banAutoSetup] ensurePermabanSetup fallito: " + e.getMessage());
        }
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
                LOGGER.info("[Fail2banAutoSetup] Creato " + LOG_FILE);
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
            LOGGER.warning("[Fail2banAutoSetup] Impossibile creare " + LOG_FILE + ": " + e.getMessage());
        }
    }

    /** Scrive il filter solo se manca. Ritorna true se ha scritto. */
    private static boolean writeFilterIfMissing() {
        try {
            Path filterDir = Paths.get(FILTER_DIR);
            if (!Files.isDirectory(filterDir)) {
                LOGGER.info("[Fail2banAutoSetup] " + FILTER_DIR + " non esiste — Fail2ban non installato? Salto.");
                return false;
            }
            Path filterPath = Paths.get(FILTER_FILE);
            if (Files.exists(filterPath)) {
                return false; // già presente, non sovrascrivere
            }
            Files.writeString(filterPath, FILTER_CONTENT, StandardCharsets.UTF_8);
            try { Files.setPosixFilePermissions(filterPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Scritto " + FILTER_FILE);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Impossibile scrivere filter: " + e.getMessage());
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
                    LOGGER.info("[Fail2banAutoSetup] " + parent + " non esiste — Fail2ban non installato? Salto jail.");
                    return false;
                }
                Files.writeString(jailPath, JAIL_BLOCK, StandardCharsets.UTF_8);
            } else {
                Files.writeString(jailPath, toAppend, StandardCharsets.UTF_8,
                    StandardOpenOption.APPEND);
            }
            try { Files.setPosixFilePermissions(jailPath, PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            LOGGER.info("[Fail2banAutoSetup] Aggiunta jail [mail-panel-auth] a " + JAIL_LOCAL);
            return true;
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Impossibile modificare jail.local: " + e.getMessage());
            return false;
        }
    }

    /** Scrive la conf di log rotation se manca. */
    private static void writeNewsyslogIfMissing() {
        try {
            Path dir = Paths.get(NEWSYSLOG_DIR);
            if (!Files.isDirectory(dir)) return; // sistema senza newsyslog.conf.d, salto
            Path conf = Paths.get(NEWSYSLOG_CONF);
            if (Files.exists(conf)) return; // già presente
            String content = "# Log rotation per mail-panel auth log (auto-generato dal pannello)\n"
                + "/var/log/mail-panel-auth.log    root:wheel    640    7    1024    *    JC\n";
            Files.writeString(conf, content, StandardCharsets.UTF_8);
            LOGGER.info("[Fail2banAutoSetup] Scritto " + NEWSYSLOG_CONF);
        } catch (IOException e) {
            LOGGER.warning("[Fail2banAutoSetup] Impossibile scrivere newsyslog conf: " + e.getMessage());
        }
    }

    /** Reload Fail2ban con fail2ban-client se disponibile e in esecuzione. */
    private static void reloadFail2ban() {
        try {
            if (!Files.isExecutable(Paths.get(FAIL2BAN_CLIENT))) {
                LOGGER.info("[Fail2banAutoSetup] " + FAIL2BAN_CLIENT + " non eseguibile — salto reload");
                return;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(FAIL2BAN_CLIENT, "reload");
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
            LOGGER.warning("[Fail2banAutoSetup] Reload Fail2ban fallito: " + e.getMessage());
        }
    }

    // ================== EMBEDDED CONFIG CONTENT ==================

    private static final String FILTER_CONTENT = ""
        + "# Fail2ban filter per FreeBSD-Mail-Panel (auto-generato dal pannello)\n"
        + "#\n"
        + "# Il pannello scrive su /var/log/mail-panel-auth.log linee del tipo:\n"
        + "#   2026-05-08T12:34:56 [LOGIN_FAILURE] ip=1.2.3.4 user=admin details=\"...\"\n"
        + "\n"
        + "[Definition]\n"
        + "\n"
        + "failregex = ^\\S+ \\[(?:LOGIN_FAILURE|LOGIN_2FA_FAILURE|LOGIN_INVALID_INPUT|LOGIN_BLOCKED|CSRF_FAILURE|SSL_CERT_[A-Z_]+_FAILED|FAIL2BAN_[A-Z_]+_FAILED|PASSKEY_REGISTER_FAILED|2FA_[A-Z_]+_FAILED|ADMIN_PASSWORD_CHANGE_FAILED)\\] ip=<HOST>\n"
        + "\n"
        + "ignoreregex = ^\\S+ \\[(?:LOGIN_SUCCESS|PASSKEY_LOGIN_SUCCESS|DOMAIN_CREATED|DOMAIN_UPDATED|DOMAIN_DELETED|ALIAS_CREATED|ALIAS_DELETED|SSL_CERT_RENEWED|SSL_CERT_ISSUED_HTTP01|SSL_CERT_ISSUED_DNS01|SSL_CERT_DEPLOYED|SSL_CERT_INSTALLED_MANUAL|SSL_AUTO_RENEWAL_SETTINGS_CHANGED|SSL_MANUAL_CHECK_TRIGGERED|FAIL2BAN_IP_BANNED|FAIL2BAN_IP_UNBANNED|2FA_ENABLED|2FA_DISABLED|2FA_BACKUP_CODES_REGENERATED|PASSKEY_REGISTERED|PASSKEY_DELETED|ADMIN_PASSWORD_CHANGED|HOSTNAME_CHANGED|ROUNDCUBE_DOMAIN_CHANGED|ROUNDCUBE_SSL_UPDATED)\\]\n"
        + "\n"
        + "datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S\n";

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
        + "backend  = auto\n";
}
