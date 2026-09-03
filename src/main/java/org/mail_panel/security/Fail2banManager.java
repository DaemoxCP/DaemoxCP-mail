package org.mail_panel.security;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

/**
 * Fail2ban Manager for FreeBSD Mail Panel
 *
 * Manages Fail2ban for mail server security:
 * - View banned IPs
 * - Manual ban/unban
 * - Jail status and statistics
 * - Configuration management
 *
 * Default jails for mail:
 * - dovecot: Failed IMAP/POP3 logins
 * - postfix-auth: Failed SMTP auth (Postfix/Dovecot SASL)
 * - roundcube-auth: Failed webmail logins
 *
 * FreeBSD paths:
 * - /usr/local/etc/fail2ban/
 * - /var/log/fail2ban.log
 */
public class Fail2banManager {

    // Paths
    private static final String FAIL2BAN_DIR = "/usr/local/etc/fail2ban";
    private static final String JAIL_LOCAL = FAIL2BAN_DIR + "/jail.local";
    private static final String JAIL_D = FAIL2BAN_DIR + "/jail.d";
    private static final String FILTER_D = FAIL2BAN_DIR + "/filter.d";
    private static final String ACTION_D = FAIL2BAN_DIR + "/action.d";
    private static final String FAIL2BAN_LOG = "/var/log/fail2ban.log";

    // Commands
    private static final String FAIL2BAN_CLIENT = "/usr/local/bin/fail2ban-client";
    private static final String SERVICE_CMD = "/usr/sbin/service";

    // Default ban settings
    private static final int DEFAULT_BAN_TIME = 3600;      // 1 hour
    private static final int DEFAULT_FIND_TIME = 600;      // 10 minutes
    private static final int DEFAULT_MAX_RETRY = 5;

    // Mail-related jails
    private static final String[] MAIL_JAILS = {
        "dovecot",
        "postfix-auth",
        "roundcube-auth",
        "rspamd"
    };

    /**
     * Check if Fail2ban is installed
     */
    public boolean isInstalled() {
        return Files.exists(Paths.get(FAIL2BAN_CLIENT));
    }

    /**
     * Check if Fail2ban service is running
     */
    public boolean isRunning() {
        try {
            String output = executeCommand(SERVICE_CMD + " fail2ban status");
            return output.toLowerCase().contains("running") ||
                   output.toLowerCase().contains("is running");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get Fail2ban status overview
     */
    public Fail2banStatus getStatus() {
        Fail2banStatus status = new Fail2banStatus();

        status.installed = isInstalled();
        if (!status.installed) {
            status.error = "Fail2ban not installed. Install with: pkg install py39-fail2ban";
            return status;
        }

        status.running = isRunning();

        try {
            // Get overall status
            String output = executeCommand(FAIL2BAN_CLIENT + " status");

            // Parse number of jails
            Pattern jailListPattern = Pattern.compile("Jail list:\\s*(.+)");
            java.util.regex.Matcher matcher = jailListPattern.matcher(output);
            if (matcher.find()) {
                String jailList = matcher.group(1).trim();
                if (!jailList.isEmpty()) {
                    status.activeJails = Arrays.asList(jailList.split(",\\s*"));
                }
            }

            // Get status for each jail
            status.jails = new ArrayList<>();
            for (String jailName : status.activeJails) {
                JailStatus jail = getJailStatus(jailName.trim());
                if (jail != null) {
                    status.jails.add(jail);
                    status.totalBanned += jail.currentlyBanned;
                    status.totalBannedTotal += jail.totalBanned;
                }
            }

            // Get recent bans from log
            status.recentBans = getRecentBans(20);

        } catch (Exception e) {
            status.error = e.getMessage();
        }

        return status;
    }

    /**
     * Get status of a specific jail
     */
    public JailStatus getJailStatus(String jailName) {
        JailStatus jail = new JailStatus();
        jail.name = jailName;

        try {
            // SECURITY: validate before shell concatenation
            if (!isValidJailName(jailName)) {
                jail.exists = false;
                return jail;
            }
            String output = executeCommand(FAIL2BAN_CLIENT + " status " + jailName);

            if (output.contains("does not exist") || output.contains("not found")) {
                jail.exists = false;
                return jail;
            }

            jail.exists = true;
            jail.enabled = true;

            // Quale porta protegge.
            //
            // Non e' una proprieta' della jail ma dell'AZIONE: fail2ban-client(1) espone
            // "get <JAIL> actions" e poi "get <JAIL> action <ACT> <proprieta'>". Una jail puo'
            // avere piu' azioni, ognuna con la sua porta.
            //
            // Quando nessuna la dichiara, la casella NON resta vuota: vuoto si legge come
            // "non protegge niente", mentre con l'azione predefinita il ban vale per
            // l'indirizzo e non per una porta sola. Si scrive che non e' dichiarata.
            try {
                String azioni = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " actions");
                java.util.LinkedHashSet<String> porte = new java.util.LinkedHashSet<>();
                String coda = azioni.contains(":") ? azioni.substring(azioni.lastIndexOf(':') + 1) : azioni;
                for (String az : coda.split(",")) {
                    String a = az.trim();
                    if (a.isEmpty() || !isValidJailName(a)) continue;
                    String v = executeCommand(FAIL2BAN_CLIENT + " get " + jailName
                            + " action " + a + " port").trim();
                    if (!v.isEmpty() && !v.toLowerCase().contains("not ") && !v.toLowerCase().contains("error"))
                        porte.add(v);
                }
                jail.porte = String.join(", ", porte);
                jail.portaDichiarata = !porte.isEmpty();

                // Il comando di ban nomina la porta? E' l'unica cosa che dice se quell'elenco
                // conti qualcosa. Si guarda il comando vero, non il nome dell'azione.
                for (String az : coda.split(",")) {
                    String a = az.trim();
                    if (a.isEmpty() || !isValidJailName(a)) continue;
                    String cmd = executeCommand(FAIL2BAN_CLIENT + " get " + jailName
                            + " action " + a + " actionban").trim();
                    if (cmd.isEmpty() || cmd.toLowerCase().contains("error")) continue;
                    if (jail.comandoBan.isEmpty()) jail.comandoBan = cmd;
                    if (cmd.contains("<port>") || cmd.contains("$port") || cmd.contains("port=")) {
                        jail.banUsaLaPorta = true;
                        jail.comandoBan = cmd;
                    }
                }
            } catch (Exception ignora) {
                jail.portaDichiarata = false;
            }

            // Parse currently banned
            Pattern currentPattern = Pattern.compile("Currently banned:\\s*(\\d+)");
            java.util.regex.Matcher currentMatcher = currentPattern.matcher(output);
            if (currentMatcher.find()) {
                jail.currentlyBanned = Integer.parseInt(currentMatcher.group(1));
            }

            // Parse total banned
            Pattern totalPattern = Pattern.compile("Total banned:\\s*(\\d+)");
            java.util.regex.Matcher totalMatcher = totalPattern.matcher(output);
            if (totalMatcher.find()) {
                jail.totalBanned = Integer.parseInt(totalMatcher.group(1));
            }

            // Parse currently failed
            Pattern failedPattern = Pattern.compile("Currently failed:\\s*(\\d+)");
            java.util.regex.Matcher failedMatcher = failedPattern.matcher(output);
            if (failedMatcher.find()) {
                jail.currentlyFailed = Integer.parseInt(failedMatcher.group(1));
            }

            // Parse total failed
            Pattern totalFailedPattern = Pattern.compile("Total failed:\\s*(\\d+)");
            java.util.regex.Matcher totalFailedMatcher = totalFailedPattern.matcher(output);
            if (totalFailedMatcher.find()) {
                jail.totalFailed = Integer.parseInt(totalFailedMatcher.group(1));
            }

            // Parse banned IP list
            Pattern bannedListPattern = Pattern.compile("Banned IP list:\\s*(.*)");
            java.util.regex.Matcher bannedMatcher = bannedListPattern.matcher(output);
            if (bannedMatcher.find()) {
                String ips = bannedMatcher.group(1).trim();
                if (!ips.isEmpty()) {
                    jail.bannedIps = Arrays.asList(ips.split("\\s+"));
                }
            }

            // Il log sorvegliato: stessa funzione che usa la verifica del filtro, cosi' le
            // due non possono contraddirsi come e' successo con roundcube-auth.
            java.util.List<String> lp = logPathDi(jailName);
            if (!lp.isEmpty()) jail.logFile = String.join(", ", lp);

        } catch (Exception e) {
            jail.error = e.getMessage();
        }

        return jail;
    }

    /**
     * Get all banned IPs across all jails
     */
    public List<BannedIp> getAllBannedIps() {
        List<BannedIp> banned = new ArrayList<>();

        try {
            Fail2banStatus status = getStatus();

            for (JailStatus jail : status.jails) {
                if (jail.bannedIps != null) {
                    for (String ip : jail.bannedIps) {
                        banned.add(new BannedIp(ip, jail.name, true, null, null));
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("Failed to get banned IPs: " + e.getMessage());
        }

        return banned;
    }

    /**
     * Get recent ban/unban events from log
     */
    public List<BanEvent> getRecentBans(int limit) {
        List<BanEvent> events = new ArrayList<>();

        try {
            if (!Files.exists(Paths.get(FAIL2BAN_LOG))) {
                return events;
            }

            // Read last N lines of log
            String output = executeCommand("tail -500 " + FAIL2BAN_LOG + " | grep -E 'Ban|Unban' | tail -" + limit);

            // Parse log lines
            // Format: 2024-01-15 10:30:45,123 fail2ban.actions [12345]: NOTICE [dovecot] Ban 192.168.1.100
            Pattern pattern = Pattern.compile(
                "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}).*?\\[(\\w+)\\]\\s+(Ban|Unban)\\s+([\\d.]+|[a-f0-9:]+)"
            );

            for (String line : output.split("\n")) {
                java.util.regex.Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    events.add(new BanEvent(
                        parseDateTime(matcher.group(1)),
                        matcher.group(3).toLowerCase(),
                        matcher.group(2),
                        matcher.group(4)
                    ));
                }
            }

            // Reverse to show newest first
            Collections.reverse(events);

        } catch (Exception e) {
            System.err.println("Failed to read ban events: " + e.getMessage());
        }

        return events;
    }

    /**
     * Manually ban an IP
     */
    public BanAction banIp(String ip, String jail) {
        BanAction action = new BanAction();
        action.action = "ban";
        action.ip = ip;
        action.jail = jail;

        try {
            // Validate IP format
            if (!isValidIp(ip)) {
                action.success = false;
                action.message = "Invalid IP address format";
                return action;
            }

            // SECURITY: validate jail name (concatenato in shell)
            if (!isValidJailName(jail)) {
                action.success = false;
                action.message = "Invalid jail name";
                return action;
            }

            // Check jail exists
            JailStatus jailStatus = getJailStatus(jail);
            if (!jailStatus.exists) {
                action.success = false;
                action.message = "Jail '" + jail + "' does not exist";
                return action;
            }

            // Execute ban
            String output = executeCommand(FAIL2BAN_CLIENT + " set " + jail + " banip " + ip);

            action.success = !output.toLowerCase().contains("error") &&
                            !output.toLowerCase().contains("already");
            action.output = output;

            if (action.success) {
                action.message = "IP " + ip + " banned in jail " + jail;
            } else if (output.toLowerCase().contains("already")) {
                action.success = true;
                action.message = "IP " + ip + " is already banned in jail " + jail;
            } else {
                action.message = "Failed to ban IP: " + output;
            }

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Unban an IP from a specific jail
     */
    public BanAction unbanIp(String ip, String jail) {
        BanAction action = new BanAction();
        action.action = "unban";
        action.ip = ip;
        action.jail = jail;

        try {
            // SECURITY: validate before shell concatenation
            if (!isValidIp(ip)) {
                action.success = false;
                action.message = "Invalid IP address format";
                return action;
            }
            if (!isValidJailName(jail)) {
                action.success = false;
                action.message = "Invalid jail name";
                return action;
            }
            String output = executeCommand(FAIL2BAN_CLIENT + " set " + jail + " unbanip " + ip);

            action.success = !output.toLowerCase().contains("error") &&
                            !output.toLowerCase().contains("not banned");
            action.output = output;

            if (action.success) {
                action.message = "IP " + ip + " unbanned from jail " + jail;
            } else {
                action.message = "Failed to unban IP: " + output;
            }

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Unban an IP from all jails
     */
    public BanAction unbanIpFromAll(String ip) {
        BanAction action = new BanAction();
        action.action = "unban_all";
        action.ip = ip;

        try {
            // SECURITY: validate before shell concatenation
            if (!isValidIp(ip)) {
                action.success = false;
                action.message = "Invalid IP address format";
                return action;
            }
            String output = executeCommand(FAIL2BAN_CLIENT + " unban " + ip);

            action.success = !output.toLowerCase().contains("error");
            action.output = output;
            action.message = "IP " + ip + " unbanned from all jails";

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Reload Fail2ban configuration
     */
    public BanAction reload() {
        BanAction action = new BanAction();
        action.action = "reload";

        try {
            String output = executeCommand(FAIL2BAN_CLIENT + " reload");

            action.success = output.toLowerCase().contains("ok") ||
                            !output.toLowerCase().contains("error");
            action.output = output;
            action.message = action.success ? "Fail2ban reloaded" : "Failed to reload: " + output;

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Start Fail2ban service
     */
    public BanAction start() {
        BanAction action = new BanAction();
        action.action = "start";

        try {
            String output = executeCommand(SERVICE_CMD + " fail2ban start");
            action.success = true;
            action.output = output;
            action.message = "Fail2ban started";
        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Stop Fail2ban service
     */
    public BanAction stop() {
        BanAction action = new BanAction();
        action.action = "stop";

        try {
            String output = executeCommand(SERVICE_CMD + " fail2ban stop");
            action.success = true;
            action.output = output;
            action.message = "Fail2ban stopped";
        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Install mail server jails configuration
     */
    public InstallResult installMailJails() {
        InstallResult result = new InstallResult();

        try {
            if (!isInstalled()) {
                result.success = false;
                result.error = "Fail2ban not installed";
                return result;
            }

            // Create jail.d directory if not exists
            Files.createDirectories(Paths.get(JAIL_D));

            // Prereq: abilita logging in Roundcube e crea il file userlogins se manca,
            // altrimenti Fail2ban si rifiuta di caricare la jail roundcube-auth.
            ensureRoundcubeLoggingEnabled();

            // Create mail jails configuration
            String mailJailsConfig = generateMailJailsConfig();
            Path mailJailsPath = Paths.get(JAIL_D, "mail.local");
            Files.writeString(mailJailsPath, mailJailsConfig);

            // Create custom filters if needed
            createCustomFilters();

            // Reload fail2ban
            reload();

            result.success = true;
            result.message = "Mail jails installed successfully";
            result.configPath = mailJailsPath.toString();

        } catch (Exception e) {
            result.success = false;
            result.error = "Installation failed: " + e.getMessage();
        }

        return result;
    }

    /**
     * Roundcube ha 'log_logins = false' di default — nessun login viene loggato,
     * quindi /usr/local/www/roundcube/logs/userlogins non esiste e Fail2ban si
     * rifiuta di caricare la jail "roundcube-auth".
     *
     * Questo metodo:
     *  1. Aggiunge le direttive di logging mancanti a config.inc.php (idempotente)
     *  2. Crea il file userlogins vuoto se non esiste, con perms www:www 640
     *
     * Best-effort: se Roundcube non è installato o il file di config non è scrivibile,
     * il metodo non blocca l'install della jail (fail2ban segnalerà comunque l'errore).
     */
    /**
     * Path comuni di Roundcube su FreeBSD. Il primo trovato vince.
     */
    private static final String[] ROUNDCUBE_CANDIDATE_PATHS = {
        "/usr/local/www/roundcube",
        "/usr/local/www/roundcubemail",
        "/usr/local/share/roundcube",
        "/usr/local/share/roundcubemail",
        "/usr/local/www/apache24/data/roundcube",
        "/usr/local/www/apache24/data/roundcubemail"
    };

    /**
     * Auto-detect del path di installazione di Roundcube.
     * Ritorna null se non viene trovato un'installazione plausibile.
     */
    public String detectRoundcubeInstallPath() {
        for (String p : ROUNDCUBE_CANDIDATE_PATHS) {
            Path candidate = Paths.get(p);
            // Plausibile install: ha una directory config/ + un index.php (o similar)
            if (Files.isDirectory(candidate)
                && Files.exists(candidate.resolve("config"))
                && (Files.exists(candidate.resolve("index.php"))
                    || Files.exists(candidate.resolve("public_html/index.php")))) {
                return p;
            }
        }
        return null;
    }

    /**
     * Il file su cui Roundcube scrive DAVVERO i login. null se Roundcube non c'e'.
     *
     * Qui c'era scritto "userlogins", senza estensione, e la jail roundcube-auth sorvegliava
     * quello. Ma rcube::write_log() costruisce il nome cosi':
     *
     *     $name .= $config->get('log_file_ext', '.log');
     *
     * cioe' aggiunge SEMPRE un'estensione, ".log" quando non e' configurata altrimenti. Il
     * pannello creava e sorvegliava un file che Roundcube non scrive mai: la jail si caricava
     * senza errori, restava a zero tentativi per sempre, e ogni schermata la dava per attiva.
     * Un attacco alla webmail non sarebbe mai stato rilevato.
     *
     * Adesso: si legge l'estensione dalla configurazione, e se uno dei due file esiste ed e'
     * gia' scritto vince quello — la prova batte la deduzione.
     */
    public String getRoundcubeUserloginsPath() {
        String base = detectRoundcubeInstallPath();
        if (base == null) return null;
        String dir = base + "/logs";
        Path conEstensione = Paths.get(dir, "userlogins" + estensioneLogRoundcube(base));
        Path senzaEstensione = Paths.get(dir, "userlogins");
        try {
            if (Files.exists(conEstensione) && Files.size(conEstensione) > 0) return conEstensione.toString();
            if (Files.exists(senzaEstensione) && Files.size(senzaEstensione) > 0) return senzaEstensione.toString();
        } catch (Exception ignora) { }
        // Nessuno dei due e' scritto: si usa il nome che Roundcube userebbe.
        return conEstensione.toString();
    }

    /** L'estensione dei log di Roundcube: "log_file_ext" se impostata, altrimenti ".log". */
    public String estensioneLogRoundcube(String installPath) {
        try {
            Path cfg = Paths.get(installPath + "/config/config.inc.php");
            if (Files.exists(cfg)) {
                String t = Files.readString(cfg, java.nio.charset.StandardCharsets.UTF_8);
                java.util.regex.Matcher m = Pattern.compile(
                        "\\$config\\[['\"]log_file_ext['\"]\\]\\s*=\\s*['\"]([^'\"]*)['\"]").matcher(t);
                if (m.find()) return m.group(1);
            }
        } catch (Exception ignora) { }
        return ".log";
    }

    public void ensureRoundcubeLoggingEnabled() {
        try {
            String installPath = detectRoundcubeInstallPath();
            if (installPath == null) {
                System.out.println("[Fail2banManager] Roundcube non trovato in nessuno dei path standard");
                return;
            }
            Path configPath = Paths.get(installPath + "/config/config.inc.php");
            if (!Files.exists(configPath)) {
                System.out.println("[Fail2banManager] Roundcube config non trovata in " + configPath);
                return;
            }
            String config = Files.readString(configPath, java.nio.charset.StandardCharsets.UTF_8);
            StringBuilder additions = new StringBuilder();

            // log_logins = true (richiesto per loggare i tentativi)
            if (!config.matches("(?s).*\\$config\\[['\"]log_logins['\"]\\]\\s*=.*")) {
                additions.append("\n$config['log_logins'] = true;\n");
            }
            // log_driver = file (assicurati che scriva su file, non su syslog)
            if (!config.matches("(?s).*\\$config\\[['\"]log_driver['\"]\\]\\s*=.*")) {
                additions.append("$config['log_driver'] = 'file';\n");
            }
            // log_dir esplicito basato sull'install detect-ato
            if (!config.matches("(?s).*\\$config\\[['\"]log_dir['\"]\\]\\s*=.*")) {
                additions.append("$config['log_dir'] = '" + installPath + "/logs/';\n");
            }

            if (additions.length() > 0) {
                // Backup
                Path bak = Paths.get(configPath.toString() + ".bak." + System.currentTimeMillis());
                Files.copy(configPath, bak);
                Files.writeString(configPath,
                    config + (config.endsWith("\n") ? "" : "\n")
                        + "\n// === Login logging abilitato dal mail panel per Fail2ban ===\n"
                        + additions.toString(),
                    java.nio.charset.StandardCharsets.UTF_8);
                System.out.println("[Fail2banManager] Roundcube config aggiornata (log_logins/log_driver/log_dir)");
            }

            // Crea il file userlogins vuoto se non esiste, perms www:www 640
            Path logsDir = Paths.get(installPath + "/logs");
            if (!Files.isDirectory(logsDir)) Files.createDirectories(logsDir);
            // Lo stesso nome che usa la jail e che Roundcube scrivera': una funzione sola.
            Path userlogins = Paths.get(getRoundcubeUserloginsPath());
            if (!Files.exists(userlogins)) {
                Files.createFile(userlogins);
                System.out.println("[Fail2banManager] Creato " + userlogins);
            }
            try { executeCommand("chown www:www " + userlogins); } catch (Exception ignored) {}
            try { executeCommand("chmod 640 " + userlogins); } catch (Exception ignored) {}

            // Verifica post-operazione
            if (!Files.exists(userlogins)) {
                System.err.println("[Fail2banManager] ATTENZIONE: " + userlogins + " ancora inesistente dopo il setup!");
            } else {
                System.out.println("[Fail2banManager] " + userlogins + " esiste ed è pronto per Fail2ban");
            }
        } catch (Exception e) {
            System.err.println("[Fail2banManager] ensureRoundcubeLoggingEnabled fallito: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generate mail jails configuration.
     * Il logpath di Roundcube viene determinato dall'install path effettivo
     * (auto-detect). Se Roundcube non è trovato, la sezione roundcube-auth
     * viene comunque scritta con un commento esplicativo.
     */
    private String generateMailJailsConfig() {
        String roundcubeLogpath = getRoundcubeUserloginsPath();
        if (roundcubeLogpath == null) {
            roundcubeLogpath = "/usr/local/www/roundcube/logs/userlogins";
        }
        return generateMailJailsConfigImpl(roundcubeLogpath);
    }

    private String generateMailJailsConfigImpl(String roundcubeLogpath) {
        return ("" + """
            # Mail Panel - Fail2ban Mail Jails Configuration
            # Generated automatically - Do not edit manually

            # Dovecot (IMAP/POP3 authentication failures)
            [dovecot]
            enabled = true
            port = pop3,pop3s,imap,imaps,submission,465,sieve
            filter = dovecot
            logpath = /var/log/maillog
            maxretry = 5
            findtime = 600
            bantime = 3600
            action = pf[name=dovecot, port="pop3,pop3s,imap,imaps,submission,465,sieve"]

            # Postfix SASL authentication failures
            [postfix-auth]
            enabled = true
            port = smtp,465,submission
            filter = postfix-sasl
            logpath = /var/log/maillog
            maxretry = 5
            findtime = 600
            bantime = 3600
            action = pf[name=postfix, port="smtp,465,submission"]

            # Roundcube webmail authentication failures
            # Il nome del file NON si presume: rcube::write_log() aggiunge sempre
            # l'estensione ('.log' se log_file_ext non e' impostata), quindi il percorso
            # arriva da getRoundcubeUserloginsPath(), che la legge dalla configurazione e
            # preferisce comunque il file gia' scritto, se ce n'e' uno.
            [roundcube-auth]
            enabled = true
            port = http,https
            filter = roundcube-auth
            logpath = """ + roundcubeLogpath + """

            maxretry = 5
            findtime = 600
            bantime = 3600
            action = pf[name=roundcube, port="http,https"]

            # Rspamd web UI authentication failures
            [rspamd]
            enabled = true
            port = 11334
            filter = rspamd
            logpath = /var/log/rspamd/rspamd.log
            maxretry = 5
            findtime = 600
            bantime = 3600
            action = pf[name=rspamd, port="11334"]

            # Aggressive repeat offenders
            [recidive]
            enabled = true
            filter = recidive
            logpath = /var/log/fail2ban.log
            maxretry = 3
            findtime = 86400
            bantime = 604800
            action = pf[name=recidive]
            """);
    }

    /**
     * Create custom filter files for mail services
     */
    private void createCustomFilters() throws Exception {
        Files.createDirectories(Paths.get(FILTER_D));

        // Postfix SASL filter (postfix-sasl.conf)
        String postfixFilter = """
            # Mail Panel - Postfix SASL Filter
            [Definition]
            failregex = ^.*postfix/smtpd\\[\\d+\\]: warning: .*\\[<HOST>\\]: SASL \\w+ authentication failed.*$
                        ^.*postfix/smtpd\\[\\d+\\]: warning: unknown\\[<HOST>\\]: SASL \\w+ authentication failed.*$
                        ^.*postfix/submission/smtpd\\[\\d+\\]: warning: .*\\[<HOST>\\]: SASL \\w+ authentication failed.*$

            ignoreregex =
            """;
        Files.writeString(Paths.get(FILTER_D, "postfix-sasl.conf"), postfixFilter);

        // Rspamd filter
        String rspamdFilter = """
            # Mail Panel - Rspamd Web UI Filter
            [Definition]
            failregex = ^.*\\[controller\\].*: <HOST> auth failed.*$
                        ^.*controller:.*password_check.*<HOST>.*auth failure.*$

            ignoreregex =
            """;
        Files.writeString(Paths.get(FILTER_D, "rspamd.conf"), rspamdFilter);

        // Roundcube auth filter — formato del file 'userlogins' di Roundcube su FreeBSD:
        //   [DD-Mon-YYYY HH:MM:SS +ZZZZ]: <token> Failed login for user@dom from 1.2.3.4 in session ...
        //   [DD-Mon-YYYY HH:MM:SS +ZZZZ]: <token> Successful login for user@dom (ID: 1) from 1.2.3.4 ...
        // SOVRASCRIVIAMO sempre il filter (anche se esiste con pattern obsoleto)
        Path rcFilter = Paths.get(FILTER_D, "roundcube-auth.conf");
        String roundcubeFilter = """
            # Mail Panel - Roundcube Authentication Filter
            # Cattura tentativi falliti dal file logs/userlogins di Roundcube
            [Definition]
            failregex = ^\\[[^\\]]+\\]:\\s*<[^>]*>\\s+Failed login for .* from <HOST>.*$
                        ^.*FAILED login for .* from <HOST>.*$
                        ^.*Login failed for .* from <HOST>.*$
                        ^.*Authentication failed for .* \\[client <HOST>\\].*$

            ignoreregex =
            """;
        Files.writeString(rcFilter, roundcubeFilter);

        // Set permissions
        executeCommand("chmod 644 " + FILTER_D + "/*.conf");
    }

    /**
     * Get jail configuration
     */
    public JailConfig getJailConfig(String jailName) {
        JailConfig config = new JailConfig();
        config.name = jailName;

        try {
            // Cerca la sezione [jailName] in TUTTI i possibili file:
            //   1. /usr/local/etc/fail2ban/jail.local                     (jail principale)
            //   2. /usr/local/etc/fail2ban/jail.d/*.local                 (jail aggiuntive in jail.d)
            //   3. /usr/local/etc/fail2ban/jail.d/*.conf                  (idem ma .conf)
            // Si ferma al primo file dove trova [jailName].
            java.util.List<Path> candidates = new java.util.ArrayList<>();
            candidates.add(Paths.get(JAIL_LOCAL));
            try {
                Path jailDir = Paths.get(JAIL_D);
                if (Files.isDirectory(jailDir)) {
                    try (java.util.stream.Stream<Path> stream = Files.list(jailDir)) {
                        stream.filter(p -> {
                                String n = p.getFileName().toString();
                                return n.endsWith(".local") || n.endsWith(".conf");
                            })
                            .forEach(candidates::add);
                    }
                }
            } catch (Exception ignored) {}

            Pattern sectionPattern = Pattern.compile(
                "\\[" + Pattern.quote(jailName) + "\\]([^\\[]+)",
                Pattern.CASE_INSENSITIVE
            );

            for (Path candidate : candidates) {
                if (!Files.exists(candidate)) continue;
                String jailContent = Files.readString(candidate);
                java.util.regex.Matcher matcher = sectionPattern.matcher(jailContent);
                if (matcher.find()) {
                    String section = matcher.group(1);
                    config.found = true;

                    // Parse values
                    config.enabled = parseConfigBool(section, "enabled");
                    config.port = parseConfigValue(section, "port");
                    config.filter = parseConfigValue(section, "filter");
                    config.logpath = parseConfigValue(section, "logpath");
                    config.maxRetry = parseConfigInt(section, "maxretry", DEFAULT_MAX_RETRY);
                    config.findTime = parseConfigInt(section, "findtime", DEFAULT_FIND_TIME);
                    config.banTime = parseConfigInt(section, "bantime", DEFAULT_BAN_TIME);
                    break;
                }
            }

        } catch (Exception e) {
            config.error = e.getMessage();
        }

        return config;
    }

    /**
     * Update jail configuration
     */
    public BanAction updateJailConfig(String jailName, int maxRetry, int findTime, int banTime) {
        BanAction action = new BanAction();
        action.action = "update_config";
        action.jail = jailName;

        try {
            // SECURITY: validate jail name before shell concatenation
            if (!isValidJailName(jailName)) {
                action.success = false;
                action.message = "Invalid jail name";
                return action;
            }
            // 1. Runtime: applica subito via fail2ban-client (gli int sono safe)
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " maxretry " + maxRetry);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " findtime " + findTime);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " bantime " + banTime);

            // 2. Persistenza: aggiorna anche jail.local così i valori sopravvivono
            //    al restart di fail2ban
            boolean persisted = persistJailConfig(jailName, maxRetry, findTime, banTime);

            action.success = true;
            action.message = persisted
                ? "Configuration updated and persisted for jail " + jailName
                : "Configuration applied at runtime (could not persist to jail.local)";

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Applica gli stessi maxRetry/findTime/banTime a TUTTE le jail attualmente
     * attive (cosi' l'utente non deve impostarle una per una).
     * Restituisce un report per-jail.
     */
    public BulkJailConfigResult updateAllJailsConfig(int maxRetry, int findTime, int banTime) {
        BulkJailConfigResult res = new BulkJailConfigResult();
        Fail2banStatus st = getStatus();
        if (!st.installed) { res.error = "Fail2ban non installato"; return res; }
        if (!st.running)   { res.error = "Fail2ban non in esecuzione"; return res; }
        for (String jail : st.activeJails) {
            BanAction a = updateJailConfig(jail, maxRetry, findTime, banTime);
            res.results.add(new JailConfigOutcome(jail, a.success, a.message));
            if (a.success) res.successCount++; else res.failCount++;
        }
        res.success = res.failCount == 0;
        return res;
    }

    public static class BulkJailConfigResult {
        public boolean success;
        public String error;
        public int successCount;
        public int failCount;
        public List<JailConfigOutcome> results = new ArrayList<>();
    }
    /**
     * Esito della modifica di una singola jail nel ciclo updateAllJailsConfig.
     * Record immutabile (Java 14+).
     */
    public record JailConfigOutcome(String jail, boolean success, String message) {}

    /** Path standard di jail.local su FreeBSD pkg installation. */
    private static final String JAIL_LOCAL_PATH = "/usr/local/etc/fail2ban/jail.local";

    /**
     * Aggiorna in jail.local i valori maxretry/findtime/bantime per la sezione
     * [jailName]. Crea le righe se mancano. Lascia tutto il resto del file
     * intatto (compresi commenti e altre sezioni).
     *
     * Ritorna true se il file è stato scritto con successo.
     */
    private boolean persistJailConfig(String jailName, int maxRetry, int findTime, int banTime) {
        try {
            // Cerca la sezione [jailName] in tutti i file di config possibili e modifica
            // quello dove la trova. Se non la trova, ritorna false (caller deciderà).
            java.util.List<java.nio.file.Path> candidates = new java.util.ArrayList<>();
            candidates.add(java.nio.file.Paths.get(JAIL_LOCAL_PATH));
            try {
                java.nio.file.Path jailDir = java.nio.file.Paths.get(JAIL_D);
                if (java.nio.file.Files.isDirectory(jailDir)) {
                    try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(jailDir)) {
                        s.filter(p -> {
                            String n = p.getFileName().toString();
                            return n.endsWith(".local") || n.endsWith(".conf");
                        }).forEach(candidates::add);
                    }
                }
            } catch (Exception ignored) {}

            String marker = "[" + jailName + "]";
            for (java.nio.file.Path path : candidates) {
                if (!java.nio.file.Files.exists(path)) continue;
                String content = java.nio.file.Files.readString(path, java.nio.charset.StandardCharsets.UTF_8);
                int sectionStart = content.indexOf(marker);
                if (sectionStart < 0) continue;

                int next = content.indexOf("\n[", sectionStart + marker.length());
                int sectionEnd = (next < 0) ? content.length() : next + 1;

                String section = content.substring(sectionStart, sectionEnd);
                String updated = section;
                updated = setOrAddKey(updated, "maxretry", String.valueOf(maxRetry));
                updated = setOrAddKey(updated, "findtime", String.valueOf(findTime));
                updated = setOrAddKey(updated, "bantime",  String.valueOf(banTime));

                String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
                java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);

                reloadFail2banQuiet();
                return true;
            }

            // Fallback: la sezione [jailName] non esiste in NESSUN file modificabile
            // (succede per jail tipo dovecot/postfix-auth definite solo in /usr/local/etc/fail2ban/jail.conf,
            // file del pacchetto che non andrebbe toccato).
            // → Creiamo/appendiamo la sezione in jail.local: e' il pattern raccomandato da fail2ban per
            //   overridare i default di jail.conf senza modificarlo.
            java.nio.file.Path jailLocal = java.nio.file.Paths.get(JAIL_LOCAL_PATH);
            StringBuilder appended = new StringBuilder();
            if (java.nio.file.Files.exists(jailLocal)) {
                String existing = java.nio.file.Files.readString(jailLocal, java.nio.charset.StandardCharsets.UTF_8);
                appended.append(existing);
                if (!existing.endsWith("\n")) appended.append("\n");
                appended.append("\n");
            } else {
                // Crea anche le directory parent se necessario
                try { java.nio.file.Files.createDirectories(jailLocal.getParent()); } catch (Exception ignored) {}
                appended.append("# Generato dal pannello\n\n");
            }
            appended.append("[").append(jailName).append("]\n");
            appended.append("enabled  = true\n");
            appended.append("maxretry = ").append(maxRetry).append("\n");
            appended.append("findtime = ").append(findTime).append("\n");
            appended.append("bantime  = ").append(banTime).append("\n");
            java.nio.file.Files.writeString(jailLocal, appended.toString(), java.nio.charset.StandardCharsets.UTF_8);
            reloadFail2banQuiet();
            return true;
        } catch (Exception e) {
            System.err.println("[Fail2banManager] persistJailConfig failed: " + e.getMessage());
            return false;
        }
    }

    /** Reload fail2ban ignorando errori (best-effort dopo una modifica di file). */
    private void reloadFail2banQuiet() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(FAIL2BAN_CLIENT, "reload");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {}
    }

    /**
     * Cambia il valore di "filter = ..." in una jail (con backup automatico).
     * Esempio: setJailFilter("postfix-auth", "postfix[mode=aggressive]").
     *
     * Cerca la sezione [jailName] in jail.local e jail.d/*.local|conf, fa il
     * backup del file modificato, scrive il nuovo valore, ricarica fail2ban.
     */
    public BanAction setJailFilter(String jailName, String newFilter) {
        BanAction r = new BanAction();
        r.action = "set_filter";
        r.jail = jailName;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = "Nome jail non valido";
            return r;
        }
        // Validation: il filter name deve essere alfanumerico, con dash/underscore,
        // ed eventualmente "[mode=xxx]" come opzione. NIENTE shell metachars.
        if (newFilter == null || newFilter.isBlank()
                || !newFilter.matches("^[a-zA-Z0-9_\\-]+(?:\\[[a-zA-Z0-9_=,\\-\\s]*\\])?$")) {
            r.success = false;
            r.message = "Filter non valido (atteso: nome[opzione=valore])";
            return r;
        }
        try {
            // Cerca in tutti i file possibili
            java.util.List<java.nio.file.Path> candidates = new java.util.ArrayList<>();
            candidates.add(java.nio.file.Paths.get(JAIL_LOCAL_PATH));
            try {
                java.nio.file.Path jd = java.nio.file.Paths.get(JAIL_D);
                if (java.nio.file.Files.isDirectory(jd)) {
                    try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(jd)) {
                        s.filter(p -> {
                            String n = p.getFileName().toString();
                            return n.endsWith(".local") || n.endsWith(".conf");
                        }).forEach(candidates::add);
                    }
                }
            } catch (Exception ignored) {}

            String marker = "[" + jailName + "]";
            for (java.nio.file.Path path : candidates) {
                if (!java.nio.file.Files.exists(path)) continue;
                String content = java.nio.file.Files.readString(path, java.nio.charset.StandardCharsets.UTF_8);
                int sectionStart = content.indexOf(marker);
                if (sectionStart < 0) continue;
                int next = content.indexOf("\n[", sectionStart + marker.length());
                int sectionEnd = (next < 0) ? content.length() : next + 1;

                String section = content.substring(sectionStart, sectionEnd);
                String updated = setOrAddKey(section, "filter", newFilter);

                // Backup prima di scrivere
                java.nio.file.Files.copy(path,
                    java.nio.file.Paths.get(path.toString() + ".bak." + System.currentTimeMillis()));

                String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
                java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);

                reloadFail2banQuiet();
                r.success = true;
                r.message = "Filter aggiornato a '" + newFilter + "' in " + path.getFileName()
                          + " (backup creato). Fail2ban reload eseguito.";
                return r;
            }
            r.success = false;
            r.message = "Sezione [" + jailName + "] non trovata in jail.local o jail.d/";
        } catch (Exception e) {
            r.success = false;
            r.message = "Errore: " + e.getMessage();
        }
        return r;
    }

    /**
     * Lista degli IP attualmente nella whitelist (ignoreip) per una specifica jail,
     * a runtime (tramite fail2ban-client get).
     */
    public java.util.List<String> getIgnoreIps(String jailName) {
        java.util.List<String> ips = new java.util.ArrayList<>();
        if (!isValidJailName(jailName)) return ips;
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " ignoreip");
            if (out == null) return ips;
            // L'output ha tipicamente una riga per IP, possibilmente con prefisso "|-" o "`-"
            for (String line : out.split("\\r?\\n")) {
                String t = line.trim().replaceAll("^[`|]-\\s*", "").replaceAll("^[|]\\s*", "");
                if (t.isEmpty() || t.startsWith("|") || t.startsWith("`")) continue;
                // Skip header lines like "No IP address/network is ignored"
                if (t.toLowerCase().contains("no ip") || t.toLowerCase().contains("ignored:")) continue;
                // Tieni solo cose che assomigliano a IP/CIDR
                if (t.matches("^[0-9a-fA-F:.]+(/[0-9]+)?$")) ips.add(t);
            }
        } catch (Exception ignored) {}
        return ips;
    }

    /**
     * Aggiunge un IP/CIDR alla whitelist di una jail.
     * Applicato a runtime (fail2ban-client) E in modo persistente (jail.local DEFAULT
     * section, cosi' vale per tutte le jail al prossimo restart).
     */
    public BanAction addIgnoreIp(String jailName, String ip) {
        BanAction r = new BanAction();
        r.action = "add_ignoreip";
        r.jail = jailName;
        r.ip = ip;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = "Nome jail non valido";
            return r;
        }
        if (!isValidIpOrCidr(ip)) {
            r.success = false;
            r.message = "IP/CIDR non valido";
            return r;
        }
        try {
            // 1. Runtime
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " addignoreip " + ip);
            // 2. Persistenza: appende a ignoreip nella sezione [jailName] di jail.local
            persistIgnoreIpAdd(jailName, ip);
            r.success = true;
            r.message = "IP " + ip + " aggiunto a ignoreip di " + jailName + " (runtime + persistente)";
        } catch (Exception e) {
            r.success = false;
            r.message = "Errore: " + e.getMessage();
        }
        return r;
    }

    /**
     * Rimuove un IP/CIDR dalla whitelist di una jail.
     */
    public BanAction removeIgnoreIp(String jailName, String ip) {
        BanAction r = new BanAction();
        r.action = "remove_ignoreip";
        r.jail = jailName;
        r.ip = ip;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = "Nome jail non valido";
            return r;
        }
        if (!isValidIpOrCidr(ip)) {
            r.success = false;
            r.message = "IP/CIDR non valido";
            return r;
        }
        try {
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " delignoreip " + ip);
            persistIgnoreIpRemove(jailName, ip);
            r.success = true;
            r.message = "IP " + ip + " rimosso da ignoreip di " + jailName;
        } catch (Exception e) {
            r.success = false;
            r.message = "Errore: " + e.getMessage();
        }
        return r;
    }

    /** Validazione IP/CIDR (v4 e v6 base, no shell metachars). */
    private boolean isValidIpOrCidr(String s) {
        if (s == null || s.isBlank()) return false;
        // Solo caratteri ammessi per IPv4/IPv6/CIDR
        return s.matches("^[0-9a-fA-F:.]+(/[0-9]{1,3})?$");
    }

    /** Aggiunge ip a ignoreip della sezione [jailName] in jail.local (idempotente). */
    private void persistIgnoreIpAdd(String jailName, String ip) {
        try {
            java.nio.file.Path path = findJailConfigFile(jailName);
            if (path == null) return;
            String content = java.nio.file.Files.readString(path, java.nio.charset.StandardCharsets.UTF_8);
            String marker = "[" + jailName + "]";
            int sectionStart = content.indexOf(marker);
            if (sectionStart < 0) return;
            int next = content.indexOf("\n[", sectionStart + marker.length());
            int sectionEnd = (next < 0) ? content.length() : next + 1;
            String section = content.substring(sectionStart, sectionEnd);

            // Trova riga ignoreip esistente
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "(?m)^(\\s*)ignoreip\\s*=\\s*(.*)$");
            java.util.regex.Matcher m = p.matcher(section);
            String updated;
            if (m.find()) {
                String existing = m.group(2).trim();
                if (existing.contains(ip)) return; // gia' presente
                String indent = m.group(1);
                String newVal = existing.isEmpty() ? ip : existing + " " + ip;
                updated = m.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    indent + "ignoreip = " + newVal));
            } else {
                // Aggiungi la chiave
                updated = setOrAddKey(section, "ignoreip", ip);
            }
            // Backup
            java.nio.file.Files.copy(path,
                java.nio.file.Paths.get(path.toString() + ".bak." + System.currentTimeMillis()));
            String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
            java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    /** Rimuove ip da ignoreip della sezione [jailName] in jail.local. */
    private void persistIgnoreIpRemove(String jailName, String ip) {
        try {
            java.nio.file.Path path = findJailConfigFile(jailName);
            if (path == null) return;
            String content = java.nio.file.Files.readString(path, java.nio.charset.StandardCharsets.UTF_8);
            String marker = "[" + jailName + "]";
            int sectionStart = content.indexOf(marker);
            if (sectionStart < 0) return;
            int next = content.indexOf("\n[", sectionStart + marker.length());
            int sectionEnd = (next < 0) ? content.length() : next + 1;
            String section = content.substring(sectionStart, sectionEnd);

            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "(?m)^(\\s*)ignoreip\\s*=\\s*(.*)$");
            java.util.regex.Matcher m = p.matcher(section);
            if (!m.find()) return;
            String existing = m.group(2).trim();
            String newVal = java.util.Arrays.stream(existing.split("\\s+"))
                .filter(s -> !s.equals(ip))
                .collect(java.util.stream.Collectors.joining(" "));
            String indent = m.group(1);
            String updated = m.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                newVal.isEmpty()
                    ? "# ignoreip rimosso dal pannello (era: " + existing + ")"
                    : indent + "ignoreip = " + newVal));
            // Backup
            java.nio.file.Files.copy(path,
                java.nio.file.Paths.get(path.toString() + ".bak." + System.currentTimeMillis()));
            String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
            java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    /** Trova il file di config che contiene la sezione [jailName]. */
    private java.nio.file.Path findJailConfigFile(String jailName) {
        java.util.List<java.nio.file.Path> candidates = new java.util.ArrayList<>();
        candidates.add(java.nio.file.Paths.get(JAIL_LOCAL_PATH));
        try {
            java.nio.file.Path jd = java.nio.file.Paths.get(JAIL_D);
            if (java.nio.file.Files.isDirectory(jd)) {
                try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(jd)) {
                    s.filter(p -> {
                        String n = p.getFileName().toString();
                        return n.endsWith(".local") || n.endsWith(".conf");
                    }).forEach(candidates::add);
                }
            }
        } catch (Exception ignored) {}
        String marker = "[" + jailName + "]";
        for (java.nio.file.Path path : candidates) {
            try {
                if (java.nio.file.Files.exists(path)
                        && java.nio.file.Files.readString(path).contains(marker)) {
                    return path;
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    /**
     * Sostituisce una riga "key = ..." nella sezione (regex-based, conserva
     * indentazione). Se la chiave non esiste la aggiunge in fondo prima della
     * prossima sezione.
     */
    private String setOrAddKey(String section, String key, String value) {
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "(?m)^(\\s*)" + java.util.regex.Pattern.quote(key) + "\\s*=.*$"
        );
        java.util.regex.Matcher m = p.matcher(section);
        if (m.find()) {
            String indent = m.group(1) == null ? "" : m.group(1);
            return m.replaceFirst(java.util.regex.Matcher.quoteReplacement(indent + key + " = " + value));
        } else {
            // Append before trailing newline (se la sezione finisce con \n) o append diretto
            if (section.endsWith("\n")) {
                return section + key + " = " + value + "\n";
            } else {
                return section + "\n" + key + " = " + value + "\n";
            }
        }
    }


    /**
     * Get IP info (whois lookup)
     */
    public IpInfo getIpInfo(String ip) {
        IpInfo info = new IpInfo();
        info.ip = ip;

        try {
            // SECURITY: validate before shell concatenation
            if (!isValidIp(ip)) {
                info.found = false;
                return info;
            }

            // 1. Whois — fornisce dati di REGISTRAZIONE (organization, netRange, country di registrazione)
            String output = executeCommand("whois " + ip + " 2>/dev/null | head -50");
            String whoisCountry = null;

            if (!output.isEmpty()) {
                info.found = true;
                info.rawWhois = output;

                // Parse common fields
                Pattern countryPattern = Pattern.compile("(?:country|Country):\\s*(.+)", Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher countryMatcher = countryPattern.matcher(output);
                if (countryMatcher.find()) {
                    whoisCountry = countryMatcher.group(1).trim();
                    info.country = whoisCountry;
                }

                Pattern orgPattern = Pattern.compile("(?:OrgName|org-name|Organization):\\s*(.+)", Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher orgMatcher = orgPattern.matcher(output);
                if (orgMatcher.find()) {
                    info.organization = orgMatcher.group(1).trim();
                }

                Pattern netPattern = Pattern.compile("(?:NetRange|inetnum):\\s*(.+)", Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher netMatcher = netPattern.matcher(output);
                if (netMatcher.find()) {
                    info.netRange = netMatcher.group(1).trim();
                }
            }

            // 2. GeoIP via ip-api.com — fornisce la posizione FISICA reale dell'IP
            //    (whois ritorna il paese di REGISTRAZIONE che spesso è la sede legale,
            //    non dove l'IP è effettivamente assegnato. Es. 80.94.95.242 è registrato
            //    in UK ma fisicamente è in Romania).
            enrichWithGeoIP(info, ip, whoisCountry);

        } catch (Exception e) {
            info.error = e.getMessage();
        }

        return info;
    }

    /**
     * Arricchisce IpInfo con dati di geolocalizzazione da ipapi.co (HTTPS).
     * Best-effort: se l'API è offline / rate-limited / il pannello non ha
     * accesso a internet, info rimane com'è (whois only).
     * Free tier: 1000 req/giorno, HTTPS, no auth richiesta.
     *
     * Endpoint: https://ipapi.co/<ip>/json/
     * Campi rilevanti: country_code, country_name, region, city, org, asn, latitude, longitude
     * Errore (es. IP privato): {"error": true, "reason": "...", "message": "..."}
     */
    private void enrichWithGeoIP(IpInfo info, String ip, String whoisCountry) {
        try {
            String urlStr = "https://ipapi.co/" + ip + "/json/";
            java.net.URL url = new java.net.URI(urlStr).toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "FreeBSD-Mail-Panel/1.0");
            conn.setRequestProperty("Accept", "application/json");
            int code = conn.getResponseCode();
            // ipapi.co usa 200 anche per errori di lookup (campo "error: true" nel body),
            // ma può tornare 429 per rate limit
            java.io.InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                if (whoisCountry != null) info.geoSource = "whois (geoip http " + code + ")";
                return;
            }
            String body;
            try (java.io.InputStream stream = is) {
                body = new String(stream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }
            org.json.JSONObject json = new org.json.JSONObject(body);

            // Errore esplicito da ipapi.co (es. IP privato, rate limited)
            if (json.optBoolean("error", false)) {
                String reason = json.optString("reason", json.optString("message", "unknown"));
                if (whoisCountry != null) info.geoSource = "whois (geoip: " + reason + ")";
                return;
            }

            // GeoIP è più accurato per la posizione fisica: prevale su whois country
            info.country = json.optString("country_code", info.country);
            info.countryName = json.optString("country_name", null);
            info.region = json.optString("region", null);
            info.city = json.optString("city", null);
            info.asn = json.optString("asn", null);
            // ipapi.co non distingue ISP da org — usa "org" per entrambi
            String org = json.optString("org", null);
            if (org != null && !org.isEmpty()) {
                if (info.isp == null) info.isp = org;
                if (info.organization == null || info.organization.isEmpty()) {
                    info.organization = org;
                }
            }
            if (json.has("latitude") && !json.isNull("latitude")) info.latitude = json.getDouble("latitude");
            if (json.has("longitude") && !json.isNull("longitude")) info.longitude = json.getDouble("longitude");
            info.geoSource = (whoisCountry != null) ? "ipapi.co + whois" : "ipapi.co";
        } catch (Exception e) {
            // Non fatale — whois data resta disponibile
            if (whoisCountry != null) info.geoSource = "whois (geoip non raggiungibile)";
        }
    }

    // Utility methods

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        // IPv4
        if (ip.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return true;
        }
        // IPv6 (simplified check)
        if (ip.contains(":") && ip.matches("^[a-fA-F0-9:]+$")) {
            return true;
        }
        return false;
    }

    // Validazione difensiva del nome jail per prevenire command injection.
    // Il nome jail viene concatenato in shell, quindi DEVE rispettare
    // un pattern molto restrittivo.
    private boolean isValidJailName(String jail) {
        return jail != null && jail.matches("^[a-zA-Z0-9_-]{1,64}$");
    }

    private LocalDateTime parseDateTime(String dateStr) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            return LocalDateTime.parse(dateStr, formatter);
        } catch (Exception e) {
            return null;
        }
    }

    private String parseConfigValue(String section, String key) {
        Pattern pattern = Pattern.compile("^\\s*" + key + "\\s*=\\s*(.+)$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(section);
        return matcher.find() ? matcher.group(1).trim() : null;
    }

    private boolean parseConfigBool(String section, String key) {
        String value = parseConfigValue(section, key);
        return value != null && (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes") || value.equals("1"));
    }

    private int parseConfigInt(String section, String key, int defaultValue) {
        String value = parseConfigValue(section, key);
        if (value != null) {
            try {
                return Integer.parseInt(value.replaceAll("[^0-9]", ""));
            } catch (NumberFormatException e) {
                // Handle time formats like "1h", "30m"
                if (value.endsWith("h")) {
                    return Integer.parseInt(value.replace("h", "")) * 3600;
                } else if (value.endsWith("m")) {
                    return Integer.parseInt(value.replace("m", "")) * 60;
                } else if (value.endsWith("d")) {
                    return Integer.parseInt(value.replace("d", "")) * 86400;
                }
            }
        }
        return defaultValue;
    }

    /**
     * La jail aggancia davvero quel log, oppure gira a vuoto?
     *
     * Perche' serve. "0 ban, 0 tentativi falliti" ha due letture opposte: nessuno ha mai
     * attaccato quel servizio, oppure il filtro non corrisponde a nessuna riga e la jail e'
     * accesa senza vedere niente. La scheda mostrava lo zero e basta, e uno zero che puo'
     * voler dire due cose contrarie non e' un'informazione.
     *
     * Si risponde con fail2ban-regex(1), che prende un log e un filtro e dice quante righe
     * combaciano. Confrontando con quante righe ha il log si distinguono i due casi:
     *   - log vuoto            -> non si puo' dire niente, e si dice cosi'
     *   - log pieno, 0 agganci -> il filtro non vede quel formato: la jail e' cieca
     *   - agganci > 0          -> la jail funziona, e semplicemente non ci sono stati attacchi
     *
     * Legge e basta. La regex NON passa da una shell: si costruisce la riga di comando come
     * lista di argomenti, altrimenti i suoi metacaratteri verrebbero interpretati due volte.
     */
    public FiltroCheck verificaFiltro(String jailName) {
        FiltroCheck c = new FiltroCheck();
        c.jail = jailName;
        try {
            if (!isValidJailName(jailName)) { c.messaggio = "nome di jail non valido"; return c; }

            java.util.List<String> logs = logPathDi(jailName);
            if (logs.isEmpty()) { c.messaggio = "questa jail non sorveglia un file di log"; return c; }
            String log = logs.get(0);
            c.log = log;

            java.io.File f = new java.io.File(log);
            if (!f.canRead()) { c.messaggio = "il log non e' leggibile dal pannello: " + log; return c; }
            c.righeLog = contaRighe(f);
            if (c.righeLog == 0) {
                // Un log vuoto ha una terza spiegazione, ed e' la piu' insidiosa: il file
                // giusto e' un altro, a un'estensione di distanza. Prima di dire "non lo so"
                // si guarda accanto — e' un controllo che costa una lettura di cartella e
                // trasforma un dubbio in una diagnosi.
                String vicino = vicinoScritto(new java.io.File(log));
                if (vicino != null) {
                    c.messaggio = "il log sorvegliato e' VUOTO, ma nella stessa cartella c'e' "
                                + vicino + ", che invece e' scritto. Quasi certamente la jail "
                                + "sorveglia il file sbagliato: cosi' non vedra' mai niente, e "
                                + "resterebbe a zero tentativi per sempre sembrando a posto.";
                    return c;
                }
                c.messaggio = "il log e' vuoto e nella stessa cartella non c'e' un file simile gia' "
                            + "scritto: non c'e' niente su cui il filtro possa corrispondere, quindi "
                            + "lo zero di questa jail non dice ne' che funziona ne' che non funziona.";
                return c;
            }

            // Il secondo argomento di fail2ban-regex puo' essere il NOME di un filtro. Si prova
            // con quello della jail, che e' la convenzione; se non esiste si ripiega sulla
            // failregex vera, chiesta a fail2ban.
            String uscita = eseguiArgv(java.util.List.of(FAIL2BAN_REGEX, log, jailName));
            if (uscita == null || !uscita.contains("Lines:")) {
                String fr = primaFailregex(jailName);
                if (fr == null) {
                    c.messaggio = "non sono riuscito a ottenere ne' il filtro ne' la failregex: "
                                + "non posso dire se la jail agganci qualcosa.";
                    return c;
                }
                uscita = eseguiArgv(java.util.List.of(FAIL2BAN_REGEX, log, fr));
            }
            if (uscita == null || !uscita.contains("Lines:")) {
                c.messaggio = "fail2ban-regex non ha risposto in modo leggibile: non posso dire "
                            + "se la jail agganci qualcosa.";
                return c;
            }
            c.uscita = uscita.length() > 3000 ? uscita.substring(uscita.length() - 3000) : uscita;

            java.util.regex.Matcher m = Pattern.compile("(\\d+)\\s+matched").matcher(uscita);
            c.agganci = m.find() ? Integer.parseInt(m.group(1)) : 0;
            c.verificato = true;
            c.messaggio = c.agganci > 0
                ? "Il filtro aggancia " + c.agganci + " righe di questo log: la jail vede, e lo zero "
                  + "dei ban vuol dire che non ci sono stati abbastanza tentativi, non che sia cieca."
                : "Il log ha " + c.righeLog + " righe e il filtro non ne aggancia NESSUNA. La jail e' "
                  + "accesa ma non vede niente: o quel log non contiene tentativi falliti, o il filtro "
                  + "non corrisponde al formato che ci viene scritto. In questo secondo caso i ban non "
                  + "scatterebbero mai, e lo zero a schermo sembrerebbe una buona notizia.";
            return c;
        } catch (Exception e) {
            c.messaggio = "errore durante la verifica: " + e.getMessage();
            return c;
        }
    }

    /**
     * I file di log che una jail sorveglia. Una funzione sola, usata da chi mostra e da chi
     * verifica.
     *
     * Ce n'erano due che leggevano la stessa cosa in modi diversi: la scheda prendeva la riga
     * "File list:" dall'uscita di "status", il controllo del filtro chiedeva "get <jail>
     * logpath" e pretendeva una riga che COMINCIASSE con "/". Quell'uscita elenca i percorsi
     * preceduti da un carattere di albero, quindi nessuna riga comincia con "/": il controllo
     * annunciava "questa jail non sorveglia un file di log" mentre due righe piu' sotto la
     * stessa scheda mostrava il log. Due letture della stessa cosa divergono sempre.
     *
     * Qui si cerca un percorso assoluto ovunque nella riga, e si prova la seconda fonte se la
     * prima non da' niente.
     */
    private java.util.List<String> logPathDi(String jailName) {
        java.util.List<String> out = new ArrayList<>();
        for (String comando : new String[] {
                FAIL2BAN_CLIENT + " get " + jailName + " logpath",
                FAIL2BAN_CLIENT + " status " + jailName }) {
            try {
                for (String v : percorsiIn(executeCommand(comando)))
                    if (!out.contains(v)) out.add(v);
                if (!out.isEmpty()) return out;
            } catch (Exception ignora) { }
        }
        return out;
    }

    /**
     * I percorsi assoluti contenuti in un'uscita di fail2ban-client.
     *
     * Sta in un metodo suo per poter essere provato: le due uscite da cui va estratto hanno
     * forme diverse — "get <jail> logpath" elenca i file preceduti da caratteri di albero
     * ("`-", "|-"), "status <jail>" li mette dopo "File list:" — e una lettura che funziona
     * su una sola delle due e' esattamente il difetto che si sta correggendo.
     */
    static java.util.List<String> percorsiIn(String uscita) {
        java.util.List<String> out = new ArrayList<>();
        if (uscita == null) return out;
        java.util.regex.Matcher m = Pattern.compile("(/[^\\s,]+)").matcher(uscita);
        while (m.find()) {
            String v = m.group(1).trim();
            // L'uscita nomina anche il comando invocato: non e' un log sorvegliato.
            if (v.length() <= 1 || v.contains("fail2ban-client") || v.contains("fail2ban-regex")) continue;
            if (!out.contains(v)) out.add(v);
        }
        return out;
    }

    /**
     * Un file "fratello" nella stessa cartella, con lo stesso nome a meno dell'estensione, che
     * a differenza di quello sorvegliato contiene qualcosa. Descrizione leggibile, o null.
     *
     * Serve a distinguere il caso peggiore fra quelli che producono un log vuoto: non "nessuno
     * ha attaccato", ma "stiamo guardando il file sbagliato di un'estensione". E' successo con
     * roundcube-auth: la jail sorvegliava "userlogins" mentre Roundcube scrive "userlogins.log".
     */
    private String vicinoScritto(java.io.File sorvegliato) {
        try {
            java.io.File dir = sorvegliato.getParentFile();
            if (dir == null || !dir.isDirectory()) return null;
            String nome = sorvegliato.getName();
            String radice = nome.contains(".") ? nome.substring(0, nome.indexOf('.')) : nome;
            java.io.File[] tutti = dir.listFiles();
            if (tutti == null) return null;
            for (java.io.File f : tutti) {
                if (f.equals(sorvegliato) || !f.isFile()) continue;
                String n = f.getName();
                if (!n.equals(radice) && !n.startsWith(radice + ".")) continue;
                if (f.length() <= 0) continue;
                return "\"" + n + "\" (" + f.length() + " byte)";
            }
        } catch (Exception ignora) { }
        return null;
    }

    public static class FiltroCheck {
        public String jail = "", log = "", messaggio = "", uscita = "";
        public boolean verificato;
        public int agganci;
        public long righeLog;
    }

    private static final String FAIL2BAN_REGEX = "/usr/local/bin/fail2ban-regex";

    private long contaRighe(java.io.File f) {
        try (BufferedReader r = new BufferedReader(new java.io.FileReader(f))) {
            long n = 0;
            while (r.readLine() != null) { n++; if (n > 200000) break; }
            return n;
        } catch (Exception e) { return 0; }
    }

    private String primaFailregex(String jail) {
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jail + " failregex");
            java.util.regex.Matcher m = Pattern.compile("'(.+?)'", Pattern.DOTALL).matcher(out);
            return m.find() ? m.group(1) : null;
        } catch (Exception e) { return null; }
    }

    /** Esegue senza shell: gli argomenti restano argomenti, i metacaratteri non si interpretano. */
    private String eseguiArgv(java.util.List<String> argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l;
                while ((l = r.readLine()) != null) sb.append(l).append('\n');
            }
            if (!p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    private String executeCommand(String command) throws Exception {
        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        org.mail_panel.util.Shell.applicaPath(pb);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        process.waitFor();
        return output.toString().trim();
    }

    /**
     * Esegue per una specifica jail i comandi:
     *   fail2ban-client get <jail> maxretry
     *   fail2ban-client get <jail> findtime
     *   fail2ban-client get <jail> bantime
     *   fail2ban-client get <jail> logpath
     *   fail2ban-client get <jail> ignoreip
     *   fail2ban-client get <jail> filter
     *   fail2ban-client status <jail>
     *
     * Restituisce un oggetto strutturato con l'output testuale di ogni comando
     * + i valori parsati delle statistiche per la UI.
     */
    public JailLiveState getJailLiveState(String jailName) {
        JailLiveState s = new JailLiveState();
        s.name = jailName;
        if (!isValidJailName(jailName)) {
            s.error = "Nome jail non valido: " + jailName;
            return s;
        }
        // PARALLELIZZAZIONE: ognuno dei 5 "fail2ban-client get" + lo "status" parte su
        // un virtual thread separato. Tempo totale = tempo del comando piu' lento
        // (~150ms) invece della somma (~900ms).
        // Usiamo CompletableFuture + virtual threads (API stabile, no preview flags).
        try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var maxretryF = java.util.concurrent.CompletableFuture.supplyAsync(() -> runGetCommand(jailName, "maxretry"), executor);
            var findtimeF = java.util.concurrent.CompletableFuture.supplyAsync(() -> runGetCommand(jailName, "findtime"), executor);
            var bantimeF  = java.util.concurrent.CompletableFuture.supplyAsync(() -> runGetCommand(jailName, "bantime"),  executor);
            var logpathF  = java.util.concurrent.CompletableFuture.supplyAsync(() -> runGetCommand(jailName, "logpath"),  executor);
            var ignoreipF = java.util.concurrent.CompletableFuture.supplyAsync(() -> runGetCommand(jailName, "ignoreip"), executor);
            // Nota: `fail2ban-client get <jail> filter` non e' supportato in tutte
            // le versioni di fail2ban-client. Leggiamo da config (file I/O, veloce).
            var filterF   = java.util.concurrent.CompletableFuture.supplyAsync(() -> readFilterNameFromConfig(jailName), executor);
            // Status: testo multilinea, lo manteniamo intero per il parsing
            var statusF   = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try { return executeCommand(FAIL2BAN_CLIENT + " status " + jailName); }
                catch (Exception e) { throw new RuntimeException(e); }
            }, executor);

            // Aspetta tutti — join() rilancia eventuali eccezioni
            java.util.concurrent.CompletableFuture.allOf(
                maxretryF, findtimeF, bantimeF, logpathF, ignoreipF, filterF, statusF
            ).orTimeout(15, java.util.concurrent.TimeUnit.SECONDS).join();

            s.maxretry  = maxretryF.join();
            s.findtime  = findtimeF.join();
            s.bantime   = bantimeF.join();
            s.logpath   = logpathF.join();
            s.ignoreip  = ignoreipF.join();
            s.filter    = filterF.join();
            s.statusRaw = statusF.join();
            parseStatusFields(s);
            s.success = true;
        } catch (Exception e) {
            s.error = e.getMessage();
        }
        return s;
    }

    private String runGetCommand(String jailName, String key) {
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " " + key);
            if (out == null) return "";
            String trimmed = out.trim();
            // fail2ban-client get a volte ritorna prefissi tipo "`-" o "|-" per liste — li puliamo
            // Esempio: get <jail> ignoreip può ritornare "127.0.0.1/8\n::1"
            return trimmed;
        } catch (Exception e) {
            return "(errore: " + e.getMessage() + ")";
        }
    }

    private void parseStatusFields(JailLiveState s) {
        if (s.statusRaw == null) return;
        for (String line : s.statusRaw.split("\\r?\\n")) {
            String l = line.trim().replaceAll("[`|]-\\s+", "").replaceAll("[|]\\s+", "");
            int colon = l.indexOf(':');
            if (colon < 0) continue;
            String key = l.substring(0, colon).trim().toLowerCase();
            String val = l.substring(colon + 1).trim();
            // Switch arrow syntax (Java 14+): nessun fall-through, nessun break.
            switch (key) {
                case "currently failed" -> s.currentlyFailed = parseIntSafe(val);
                case "total failed"     -> s.totalFailed     = parseIntSafe(val);
                case "currently banned" -> s.currentlyBanned = parseIntSafe(val);
                case "total banned"     -> s.totalBanned     = parseIntSafe(val);
                case "banned ip list"   -> s.bannedIpsRaw    = val;
                case "file list"        -> s.fileListRaw     = val;
                default -> { /* ignora chiavi sconosciute */ }
            }
        }
    }

    /**
     * Cerca il valore di "filter = ..." nella sezione [jailName] dentro:
     *   /usr/local/etc/fail2ban/jail.local
     *   /usr/local/etc/fail2ban/jail.d/*.conf|local
     * Restituisce il nome del filtro, "(default: jailName)" se la sezione esiste ma
     * non specifica filter (fail2ban usa il nome della jail come default), oppure
     * "(non trovato)" se la sezione manca del tutto.
     */
    private String readFilterNameFromConfig(String jailName) {
        List<Path> candidates = new ArrayList<>();
        candidates.add(Paths.get(JAIL_LOCAL));
        try {
            Path jd = Paths.get(JAIL_D);
            if (Files.isDirectory(jd)) {
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(jd, "*.{conf,local}")) {
                    for (Path p : ds) candidates.add(p);
                }
            }
        } catch (Exception ignored) {}

        boolean sectionFound = false;
        for (Path file : candidates) {
            try {
                if (!Files.exists(file)) continue;
                List<String> lines = Files.readAllLines(file);
                boolean inSection = false;
                for (String raw : lines) {
                    String line = raw.trim();
                    if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue;
                    if (line.startsWith("[") && line.endsWith("]")) {
                        String section = line.substring(1, line.length() - 1).trim();
                        inSection = section.equals(jailName);
                        if (inSection) sectionFound = true;
                        continue;
                    }
                    if (inSection && line.toLowerCase().startsWith("filter")) {
                        int eq = line.indexOf('=');
                        if (eq > 0) {
                            String val = line.substring(eq + 1).trim();
                            if (!val.isEmpty()) return val;
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
        return sectionFound ? "(default: " + jailName + ")" : "(non trovato nei file di config)";
    }

    private int parseIntSafe(String s) {
        if (s == null) return 0;
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return 0; }
    }

    // Data classes

    public static class JailLiveState {
        public String name;
        public boolean success;
        public String error;
        // Output dei comandi "get"
        public String maxretry;
        public String findtime;
        public String bantime;
        public String logpath;
        public String ignoreip;
        public String filter;
        // Output completo di "status"
        public String statusRaw;
        // Campi parsati da status (con default 0/null se non disponibili)
        public int currentlyFailed;
        public int totalFailed;
        public int currentlyBanned;
        public int totalBanned;
        public String bannedIpsRaw;
        public String fileListRaw;
    }

    public static class Fail2banStatus {
        public boolean installed;
        public boolean running;
        public List<String> activeJails = new ArrayList<>();
        public List<JailStatus> jails = new ArrayList<>();
        public int totalBanned;
        public int totalBannedTotal;
        public List<BanEvent> recentBans = new ArrayList<>();
        public String error;
    }

    public static class JailStatus {
        public String name;
        public boolean exists;
        public boolean enabled;
        public int currentlyBanned;
        public int totalBanned;
        public int currentlyFailed;
        public int totalFailed;
        public List<String> bannedIps = new ArrayList<>();
        public String logFile;
        /** Le porte che la jail protegge, come le dichiara fail2ban. Vuoto = non dichiarata. */
        public String porte = "";
        /** false quando fail2ban non ha saputo dirle: "non dichiarata" non e' "nessuna". */
        public boolean portaDichiarata;
        /**
         * Il comando di ban usa davvero la porta, oppure blocca l'indirizzo e basta?
         *
         * Senza questa distinzione l'elenco delle porte non si sa come leggere. Se il comando
         * NON le nomina — il caso tipico di una tabella di pf — allora il ban vale per
         * l'indirizzo su tutte le porte, e una lista che non corrisponde ai servizi veri non
         * fa alcun danno: e' decorativa. Se invece le nomina, una lista sbagliata e' un buco,
         * perche' l'attaccante viene bloccato su porte che non sta usando.
         */
        public boolean banUsaLaPorta;
        public String comandoBan = "";
        public String error;
    }

    /**
     * IP attualmente bannato in una specifica jail.
     * Record immutabile. bannedAt/expiresAt sono opzionali (possono essere null
     * se fail2ban non li espone — la 'status' attuale non li include).
     */
    public record BannedIp(String ip, String jail, boolean active,
                           LocalDateTime bannedAt, LocalDateTime expiresAt) {}

    /**
     * Evento storico di ban/unban estratto dal log di fail2ban.
     */
    public record BanEvent(LocalDateTime timestamp, String action, String jail, String ip) {}

    public static class BanAction {
        public String action;
        public String ip;
        public String jail;
        public boolean success;
        public String message;
        public String output;
    }

    public static class JailConfig {
        public String name;
        public boolean found;
        public boolean enabled;
        public String port;
        public String filter;
        public String logpath;
        public int maxRetry;
        public int findTime;
        public int banTime;
        public String error;
    }

    public static class InstallResult {
        public boolean success;
        public String message;
        public String configPath;
        public String error;
    }

    // ============== PERMABAN (ban permanente via pf, independent from Fail2ban) ==============
    //
    // Architettura:
    //   - File: /var/db/mail-panel/permaban.list (lista IP, uno per riga)
    //   - Tabella pf: <permaban> persist file ".../permaban.list"
    //   - Regola pf:  block in quick from <permaban>
    //
    // Vantaggi rispetto a fail2ban bantime=-1:
    //   - Sopravvive a riavvii pannello, fail2ban, server
    //   - Funziona anche se fail2ban è giù
    //   - Granulare per singolo IP
    //
    public static final String PERMABAN_DIR  = "/var/db/mail-panel";
    public static final String PERMABAN_FILE = PERMABAN_DIR + "/permaban.list";
    public static final String PERMABAN_TABLE = "permaban";

    /**
     * Aggiunge un IP alla lista permaban.
     * - Aggiunge al file (con dedup)
     * - Aggiunge runtime alla tabella pf
     * Ritorna true se l'IP è stato effettivamente aggiunto (false se già presente).
     */
    public synchronized boolean addPermaban(String ip) throws Exception {
        if (!isValidIp(ip)) throw new IllegalArgumentException("IP non valido: " + ip);

        ensurePermabanFile();
        java.util.Set<String> current = readPermabanFile();
        if (current.contains(ip)) return false; // già presente, no-op
        current.add(ip);
        writePermabanFile(current);

        // Sync runtime con pfctl (se pf è attivo)
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "add", ip);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            // Anche se pfctl fallisce (es. tabella non ancora creata), il file è già scritto
        } catch (Exception ignored) {}

        return true;
    }

    /**
     * Rimuove un IP dalla lista permaban.
     * Ritorna true se rimosso, false se non era presente.
     */
    public synchronized boolean removePermaban(String ip) throws Exception {
        if (!isValidIp(ip)) throw new IllegalArgumentException("IP non valido: " + ip);

        java.util.Set<String> current = readPermabanFile();
        if (!current.contains(ip)) return false;
        current.remove(ip);
        writePermabanFile(current);

        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "delete", ip);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {}

        return true;
    }

    /** Ritorna la lista corrente di IP permabanned. */
    public synchronized java.util.List<String> listPermabans() {
        try {
            return new java.util.ArrayList<>(readPermabanFile());
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }

    /** Ritorna gli IP attualmente caricati nella tabella pf <permaban> (runtime). */
    public java.util.Set<String> listPermabanRuntime() {
        java.util.Set<String> result = new java.util.HashSet<>();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "show");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            for (String line : out.split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && isValidIp(trimmed)) result.add(trimmed);
            }
        } catch (Exception ignored) {}
        return result;
    }

    /**
     * Ricarica la tabella pf dal file (es. dopo restart pannello).
     * Equivale a: pfctl -t permaban -T replace -f <file>
     */
    public boolean reloadPermabanFromFile() {
        try {
            ensurePermabanFile();
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "replace", "-f", PERMABAN_FILE);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void ensurePermabanFile() throws java.io.IOException {
        Path dir = Paths.get(PERMABAN_DIR);
        if (!Files.isDirectory(dir)) Files.createDirectories(dir);
        Path file = Paths.get(PERMABAN_FILE);
        if (!Files.exists(file)) Files.createFile(file);
    }

    /** Legge il file ignorando righe vuote, commenti (#) e IP non validi. */
    private java.util.Set<String> readPermabanFile() throws java.io.IOException {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>();
        Path file = Paths.get(PERMABAN_FILE);
        if (!Files.exists(file)) return set;
        for (String line : Files.readAllLines(file, java.nio.charset.StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            if (isValidIp(trimmed)) set.add(trimmed);
        }
        return set;
    }

    private void writePermabanFile(java.util.Set<String> ips) throws java.io.IOException {
        ensurePermabanFile();
        StringBuilder content = new StringBuilder();
        content.append("# Permaban list — gestito dal mail panel\n");
        content.append("# IP qui dentro vengono caricati nella tabella pf <permaban>\n");
        content.append("# e bloccati con regola: block in quick from <permaban>\n\n");
        for (String ip : ips) content.append(ip).append("\n");
        Files.writeString(Paths.get(PERMABAN_FILE), content.toString(), java.nio.charset.StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(Paths.get(PERMABAN_FILE),
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));
        } catch (Exception ignored) {}
    }

    public static class IpInfo {
        public String ip;
        public boolean found;
        public String country;         // codice (es. "RO") — da geoIP se disponibile, altrimenti whois
        public String countryName;     // nome completo (es. "Romania")
        public String region;          // regione/stato (es. "Bucharest")
        public String city;            // città
        public String organization;    // org registrazione (da whois)
        public String isp;             // ISP (da geoIP)
        public String asn;             // ASN (es. "AS12345")
        public String netRange;        // range di IP (da whois)
        public Double latitude;
        public Double longitude;
        public String geoSource;       // "ip-api.com" oppure "whois" oppure "both"
        public String rawWhois;
        public String error;
    }
}
