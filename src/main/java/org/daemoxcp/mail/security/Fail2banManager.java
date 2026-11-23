package org.daemoxcp.mail.security;

import java.io.*;
import org.daemoxcp.mail.i18n.I18n;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

/**
 * Fail2ban Manager for DaemoxCP Mail
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
            status.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
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

            // Which port it protects.
            //
            // It is not a property of the jail but of the ACTION: fail2ban-client(1) exposes
            // "get <JAIL> actions" and then "get <JAIL> action <ACT> <property>". A jail can
            // have several actions, each with its own port.
            //
            // When none declares it, the field does NOT stay empty: empty reads as
            // "protects nothing", while with the default action the ban applies to
            // the address and not to a single port. It says that it is not declared.
            try {
                String actions = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " actions");
                String queue = actions.contains(":") ? actions.substring(actions.lastIndexOf(':') + 1) : actions;

                // The port is read from the configuration, it is not asked of fail2ban.
                //
                // The command "get <jail> action <a> port" is NOT harmless: the pf action does not
                // define a "port" option (its [Init] has tablename, block, protocol,
                // actiontype, allports, multiport and nothing else), so fail2ban raises
                // AttributeError and WRITES AN ERROR in its own log. Every opening of the page
                // produced several, and they ended up in /var/log/fail2ban.log -- which is the file
                // watched by the recidive jail. A panel that, to show a piece of data, dirties
                // the log that another part of it must read is creating the problem it would then
                // have to diagnose.
                String port = portFromConfiguration(jailName);
                jail.ports = port;
                jail.declaredPort = !port.isEmpty();

                // Does the ban command name the port? It is the only thing that tells whether that list
                // counts for anything. The real command is looked at, not the name of the action.
                for (String az : queue.split(",")) {
                    String a = az.trim();
                    if (a.isEmpty() || !isValidJailName(a)) continue;
                    String cmd = executeCommand(FAIL2BAN_CLIENT + " get " + jailName
                            + " action " + a + " actionban").trim();
                    if (cmd.isEmpty() || cmd.toLowerCase().contains("error")) continue;
                    if (jail.banCommand.isEmpty()) jail.banCommand = cmd;
                    if (cmd.contains("<port>") || cmd.contains("$port") || cmd.contains("port=")) {
                        jail.banUsesPort = true;
                        jail.banCommand = cmd;
                    }
                }
            } catch (Exception ignore) {
                jail.declaredPort = false;
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

            // The watched log: the same function the filter check uses, so the
            // two cannot contradict each other as happened with roundcube-auth.
            java.util.List<String> lp = logPathOf(jailName);
            if (!lp.isEmpty()) jail.logFile = String.join(", ", lp);

        } catch (Exception e) {
            jail.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
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

            // SECURITY: validate jail name (concatenated into a shell command)
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
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

            // Prereq: enable logging in Roundcube and create the userlogins file if missing,
            // otherwise Fail2ban refuses to load the roundcube-auth jail.
            ensureRoundcubeLoggingEnabled();

            // Create mail jails configuration
            String mailJailsConfig = generateMailJailsConfig();
            Path mailJailsPath = Paths.get(JAIL_D, "mail.local");
            Files.writeString(mailJailsPath, mailJailsConfig);

            // Create custom filters if needed
            createCustomFilters();

            // Reload fail2ban
            reload();

            // Writing the configuration and reloading is not finishing the job: the outcome is checked.
            //
            // The reload rereads the files but does NOT restart the jails -- fail2ban-client(1): "reloads the
            // configuration without restarting of the server, the option '--restart' activates
            // completely restarting of affected jails". A jail whose action had FAILED
            // at startup, like recidive with the pf rule rejected by pfctl, does not retry it: it stays
            // with its table and without a rule, and the report would say "installed correctly"
            // while nothing has changed. That is exactly what happened.
            //
            // So the thing that matters is measured -- does each jail have a rule in pf that reads its
            // table? -- and only if it is missing do we go up one step. Without "--unban", which the
            // manual indicates as the option that would instead remove the active bans.
            String restartOutcome = "";
            try {
                int withoutRule = compareBansWithPf().totalWithoutRule();
                if (withoutRule > 0) {
                    org.daemoxcp.mail.util.Shell.Result rs = org.daemoxcp.mail.util.Shell.run(
                        java.time.Duration.ofSeconds(60), FAIL2BAN_CLIENT, "reload", "--restart");
                    int after = compareBansWithPf().totalWithoutRule();
                    restartOutcome = " " + I18n.tr("server.f2bm.reloadRecreated", java.util.Map.of("n", String.valueOf(withoutRule))) + " "
                        + (after == 0 ? I18n.tr("server.f2bm.eachHasRule")
                                     : I18n.tr("server.f2bm.someWithout", java.util.Map.of("n", String.valueOf(after))))
                        + (rs.success() ? "" : " " + I18n.tr("server.f2bm.cmdReported", java.util.Map.of("o", String.valueOf(rs.output().trim()))));
                }
            } catch (Exception e) {
                restartOutcome = " " + I18n.tr("server.f2bm.cannotVerifyPf", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
            }

            result.success = true;
            result.message = "Mail jails installed successfully." + restartOutcome;
            result.configPath = mailJailsPath.toString();

        } catch (Exception e) {
            result.success = false;
            result.error = I18n.tr("server.f2bm.installFailed", java.util.Map.of("e", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }

        return result;
    }

    /**
     * Roundcube has 'log_logins = false' by default -- no login is logged,
     * so /usr/local/www/roundcube/logs/userlogins does not exist and Fail2ban
     * refuses to load the "roundcube-auth" jail.
     *
     * This method:
     *  1. Adds the missing logging directives to config.inc.php (idempotent)
     *  2. Creates the empty userlogins file if it does not exist, owned by the webmail user, 640
     *
     * Best-effort: if Roundcube is not installed or the config file is not writable,
     * the method does not block the install of the jail (fail2ban will report the error anyway).
     */
    /**
     * Common Roundcube paths on FreeBSD. The first one found wins.
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
     * Auto-detect of the Roundcube installation path.
     * Returns null if no plausible installation is found.
     */
    public String detectRoundcubeInstallPath() {
        for (String p : ROUNDCUBE_CANDIDATE_PATHS) {
            Path candidate = Paths.get(p);
            // Plausible install: has a config/ directory + an index.php (or similar)
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
     * The file Roundcube REALLY writes logins to. null if Roundcube is not there.
     *
     * Here it said "userlogins", without an extension, and the roundcube-auth jail watched
     * that. But rcube::write_log() builds the name like this:
     *
     *     $name .= $config->get('log_file_ext', '.log');
     *
     * i.e. it ALWAYS adds an extension, ".log" when not configured otherwise. The
     * panel created and watched a file Roundcube never writes: the jail loaded
     * without errors, stayed at zero attempts forever, and every screen showed it as active.
     * An attack on the webmail would never have been detected.
     *
     * Now: the extension is read from the configuration, and if one of the two files exists and
     * is already written, that one wins -- evidence beats deduction.
     */
    public String getRoundcubeUserloginsPath() {
        String base = detectRoundcubeInstallPath();
        if (base == null) return null;
        String dir = base + "/logs";
        Path withExtension = Paths.get(dir, "userlogins" + roundcubeLogExtension(base));
        Path withoutExtension = Paths.get(dir, "userlogins");
        try {
            if (Files.exists(withExtension) && Files.size(withExtension) > 0) return withExtension.toString();
            if (Files.exists(withoutExtension) && Files.size(withoutExtension) > 0) return withoutExtension.toString();
        } catch (Exception ignore) { }
        // Neither of the two is written: use the name Roundcube would use.
        return withExtension.toString();
    }

    /** The extension of Roundcube's logs: "log_file_ext" if set, otherwise ".log". */
    public String roundcubeLogExtension(String installPath) {
        try {
            Path cfg = Paths.get(installPath + "/config/config.inc.php");
            if (Files.exists(cfg)) {
                String t = Files.readString(cfg, java.nio.charset.StandardCharsets.UTF_8);
                java.util.regex.Matcher m = Pattern.compile(
                        "\\$config\\[['\"]log_file_ext['\"]\\]\\s*=\\s*['\"]([^'\"]*)['\"]").matcher(t);
                if (m.find()) return m.group(1);
            }
        } catch (Exception ignore) { }
        return ".log";
    }

    public void ensureRoundcubeLoggingEnabled() {
        try {
            String installPath = detectRoundcubeInstallPath();
            if (installPath == null) {
                System.out.println("[Fail2banManager] Roundcube not found in any of the standard paths");
                return;
            }
            Path configPath = Paths.get(installPath + "/config/config.inc.php");
            if (!Files.exists(configPath)) {
                System.out.println("[Fail2banManager] Roundcube config not found in " + configPath);
                return;
            }
            String config = Files.readString(configPath, java.nio.charset.StandardCharsets.UTF_8);
            StringBuilder additions = new StringBuilder();

            // log_logins = true (required to log the attempts)
            if (!config.matches("(?s).*\\$config\\[['\"]log_logins['\"]\\]\\s*=.*")) {
                additions.append("\n$config['log_logins'] = true;\n");
            }
            // log_driver = file (make sure it writes to a file, not to syslog)
            if (!config.matches("(?s).*\\$config\\[['\"]log_driver['\"]\\]\\s*=.*")) {
                additions.append("$config['log_driver'] = 'file';\n");
            }
            // explicit log_dir based on the detected install
            if (!config.matches("(?s).*\\$config\\[['\"]log_dir['\"]\\]\\s*=.*")) {
                additions.append("$config['log_dir'] = '" + installPath + "/logs/';\n");
            }

            if (additions.length() > 0) {
                // Backup
                Path bak = backupCopy(configPath);
                Files.copy(configPath, bak);
                Files.writeString(configPath,
                    config + (config.endsWith("\n") ? "" : "\n")
                        + "\n// === Login logging enabled by DaemoxCP Mail for Fail2ban ===\n"
                        + additions.toString(),
                    java.nio.charset.StandardCharsets.UTF_8);
                System.out.println("[Fail2banManager] Roundcube config updated (log_logins/log_driver/log_dir)");
            }

            // Create the empty userlogins file if it does not exist, owned by the webmail user, 640
            Path logsDir = Paths.get(installPath + "/logs");
            if (!Files.isDirectory(logsDir)) Files.createDirectories(logsDir);
            // The same name the jail uses and Roundcube will write: a single function.
            Path userlogins = Paths.get(getRoundcubeUserloginsPath());
            if (!Files.exists(userlogins)) {
                Files.createFile(userlogins);
                System.out.println("[Fail2banManager] Created " + userlogins);
            }
            // Roundcube's PHP writes it: roundcube after the migration (RoundcubeUser), www before.
            String rcUser = org.daemoxcp.mail.system.RoundcubeUser.runtimeUser();
            try { executeCommand("chown " + rcUser + ":" + org.daemoxcp.mail.system.RoundcubeUser.runtimeGroup() + " " + userlogins); } catch (Exception ignored) {}
            try { executeCommand("chmod 640 " + userlogins); } catch (Exception ignored) {}

            // Post-operation check
            if (!Files.exists(userlogins)) {
                System.err.println("[Fail2banManager] WARNING: " + userlogins + " still missing after the setup!");
            } else {
                System.out.println("[Fail2banManager] " + userlogins + " exists and is ready for Fail2ban");
            }
        } catch (Exception e) {
            System.err.println("[Fail2banManager] ensureRoundcubeLoggingEnabled failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generate mail jails configuration.
     * The Roundcube logpath is determined from the actual install path
     * (auto-detect). If Roundcube is not found, the roundcube-auth section
     * is written anyway with an explanatory comment.
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
            # DaemoxCP Mail - Fail2ban mail jails
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
            # The file name is NOT assumed: rcube::write_log() always adds
            # the extension ('.log' if log_file_ext is not set), so the path
            # comes from getRoundcubeUserloginsPath(), which reads it from the configuration and
            # prefers the file already written anyway, if there is one.
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
            # actiontype declared, not inherited. The other jails above pass an explicit
            # port, so the rule pf builds is complete. This one does not: without a port
            # and without actiontype it would take the default "any port $port", with the
            # port inherited from jail.conf's [DEFAULT] — a file the panel neither writes nor
            # checks. If the port is empty there, pf refuses the rule: the table is
            # created anyway and the bans end up in it with nothing reading them. For the jail
            # that bans repeat offenders for seven days it is the worst place for a doubt, and
            # "allports" is also what is really wanted: the repeat offender is blocked on everything.
            action = pf[name=recidive, port="0:65535"]
            """);
    }

    /**
     * Create custom filter files for mail services
     */
    private void createCustomFilters() throws Exception {
        Files.createDirectories(Paths.get(FILTER_D));

        // Postfix SASL filter (postfix-sasl.conf)
        String postfixFilter = """
            # DaemoxCP Mail - Postfix SASL filter
            [Definition]
            failregex = ^.*postfix/smtpd\\[\\d+\\]: warning: .*\\[<HOST>\\]: SASL \\w+ authentication failed.*$
                        ^.*postfix/smtpd\\[\\d+\\]: warning: unknown\\[<HOST>\\]: SASL \\w+ authentication failed.*$
                        ^.*postfix/submission/smtpd\\[\\d+\\]: warning: .*\\[<HOST>\\]: SASL \\w+ authentication failed.*$

            ignoreregex =
            """;
        Files.writeString(Paths.get(FILTER_D, "postfix-sasl.conf"), postfixFilter);

        // Rspamd filter
        String rspamdFilter = """
            # DaemoxCP Mail - Rspamd web UI filter
            [Definition]
            failregex = ^.*\\[controller\\].*: <HOST> auth failed.*$
                        ^.*controller:.*password_check.*<HOST>.*auth failure.*$

            ignoreregex =
            """;
        Files.writeString(Paths.get(FILTER_D, "rspamd.conf"), rspamdFilter);

        // Roundcube auth filter -- format of Roundcube's 'userlogins' file on FreeBSD:
        //   [DD-Mon-YYYY HH:MM:SS +ZZZZ]: <token> Failed login for user@dom from 1.2.3.4 in session ...
        //   [DD-Mon-YYYY HH:MM:SS +ZZZZ]: <token> Successful login for user@dom (ID: 1) from 1.2.3.4 ...
        // We ALWAYS OVERWRITE the filter (even if it exists with an obsolete pattern)
        Path rcFilter = Paths.get(FILTER_D, "roundcube-auth.conf");
        String roundcubeFilter = """
            # DaemoxCP Mail - Roundcube sign-in filter
            # Catches failed attempts from Roundcube's logs/userlogins file
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
            // Look for the [jailName] section in ALL the possible files:
            //   1. /usr/local/etc/fail2ban/jail.local                     (main jail file)
            //   2. /usr/local/etc/fail2ban/jail.d/*.local                 (additional jails in jail.d)
            //   3. /usr/local/etc/fail2ban/jail.d/*.conf                  (same, but .conf)
            // Stop at the first file where [jailName] is found.
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
            config.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
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
            // 1. Runtime: apply right away via fail2ban-client (ints are safe)
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " maxretry " + maxRetry);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " findtime " + findTime);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " bantime " + banTime);

            // 2. Persistence: also update jail.local so the values survive
            //    a restart of fail2ban
            boolean persisted = persistJailConfig(jailName, maxRetry, findTime, banTime);

            action.success = true;
            action.message = persisted
                ? "Configuration updated and persisted for jail " + jailName
                : "Configuration applied at runtime (could not persist to jail.local)";

        } catch (Exception e) {
            action.success = false;
            action.message = I18n.tr("server.errorWith", java.util.Map.of("error", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }

        return action;
    }

    /**
     * Applies the same maxRetry/findTime/banTime to ALL currently
     * active jails (so the user does not have to set them one by one).
     * Returns a per-jail report.
     */
    public BulkJailConfigResult updateAllJailsConfig(int maxRetry, int findTime, int banTime) {
        BulkJailConfigResult res = new BulkJailConfigResult();
        Fail2banStatus st = getStatus();
        if (!st.installed) { res.error = I18n.tr("server.f2bm.notInstalled"); return res; }
        if (!st.running)   { res.error = I18n.tr("server.f2bm.notRunning"); return res; }
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
     * Outcome of changing a single jail in the updateAllJailsConfig loop.
     * Immutable record (Java 14+).
     */
    public record JailConfigOutcome(String jail, boolean success, String message) {}

    /** Standard path of jail.local on a FreeBSD pkg installation. */
    private static final String JAIL_LOCAL_PATH = "/usr/local/etc/fail2ban/jail.local";

    /**
     * Updates the maxretry/findtime/bantime values in jail.local for the
     * [jailName] section. Creates the lines if missing. Leaves all the rest of the file
     * intact (including comments and other sections).
     *
     * Returns true if the file was written successfully.
     */
    private boolean persistJailConfig(String jailName, int maxRetry, int findTime, int banTime) {
        try {
            // Look for the [jailName] section in all possible config files and modify
            // the one where it is found. If not found, return false (the caller will decide).
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

            // Fallback: the [jailName] section does not exist in ANY editable file
            // (this happens for jails like dovecot/postfix-auth defined only in /usr/local/etc/fail2ban/jail.conf,
            // the package's file, which should not be touched).
            // -> We create/append the section in jail.local: it is the pattern fail2ban recommends to
            //   override the jail.conf defaults without modifying it.
            java.nio.file.Path jailLocal = java.nio.file.Paths.get(JAIL_LOCAL_PATH);
            StringBuilder appended = new StringBuilder();
            if (java.nio.file.Files.exists(jailLocal)) {
                String existing = java.nio.file.Files.readString(jailLocal, java.nio.charset.StandardCharsets.UTF_8);
                appended.append(existing);
                if (!existing.endsWith("\n")) appended.append("\n");
                appended.append("\n");
            } else {
                // Also create the parent directories if necessary
                try { java.nio.file.Files.createDirectories(jailLocal.getParent()); } catch (Exception ignored) {}
                appended.append("# Generated by the panel\n\n");
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

    /** Reload fail2ban ignoring errors (best-effort after a file change). */
    private void reloadFail2banQuiet() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(FAIL2BAN_CLIENT, "reload");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {}
    }

    /**
     * Changes the value of "filter = ..." in a jail (with automatic backup).
     * Example: setJailFilter("postfix-auth", "postfix[mode=aggressive]").
     *
     * Looks for the [jailName] section in jail.local and jail.d/*.local|conf, backs up
     * the modified file, writes the new value, reloads fail2ban.
     */
    public BanAction setJailFilter(String jailName, String newFilter) {
        BanAction r = new BanAction();
        r.action = "set_filter";
        r.jail = jailName;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badJail");
            return r;
        }
        // Validation: the filter name must be alphanumeric, with dash/underscore,
        // and optionally "[mode=xxx]" as an option. NO shell metachars.
        if (newFilter == null || newFilter.isBlank()
                || !newFilter.matches("^[a-zA-Z0-9_\\-]+(?:\\[[a-zA-Z0-9_=,\\-\\s]*\\])?$")) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badFilter");
            return r;
        }
        try {
            // Search all the possible files
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

                // Backup before writing
                java.nio.file.Files.copy(path,
                    backupCopy(path));

                String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
                java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);

                reloadFail2banQuiet();
                r.success = true;
                r.message = I18n.tr("server.f2bm.filterUpdated", java.util.Map.of("f", String.valueOf(newFilter), "file", String.valueOf(path.getFileName())));
                return r;
            }
            r.success = false;
            r.message = I18n.tr("server.f2bm.sectionNotFound", java.util.Map.of("j", String.valueOf(jailName)));
        } catch (Exception e) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }
        return r;
    }

    /**
     * List of the IPs currently in the whitelist (ignoreip) for a specific jail,
     * at runtime (via fail2ban-client get).
     */
    public java.util.List<String> getIgnoreIps(String jailName) {
        java.util.List<String> ips = new java.util.ArrayList<>();
        if (!isValidJailName(jailName)) return ips;
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " ignoreip");
            if (out == null) return ips;
            // The output typically has one line per IP, possibly prefixed with "|-" or "`-"
            for (String line : out.split("\\r?\\n")) {
                String t = line.trim().replaceAll("^[`|]-\\s*", "").replaceAll("^[|]\\s*", "");
                if (t.isEmpty() || t.startsWith("|") || t.startsWith("`")) continue;
                // Skip header lines like "No IP address/network is ignored"
                if (t.toLowerCase().contains("no ip") || t.toLowerCase().contains("ignored:")) continue;
                // Keep only things that look like IP/CIDR
                if (t.matches("^[0-9a-fA-F:.]+(/[0-9]+)?$")) ips.add(t);
            }
        } catch (Exception ignored) {}
        return ips;
    }

    /**
     * Adds an IP/CIDR to a jail's whitelist.
     * Applied at runtime (fail2ban-client) AND persistently (jail.local DEFAULT
     * section, so it applies to all jails at the next restart).
     */
    public BanAction addIgnoreIp(String jailName, String ip) {
        BanAction r = new BanAction();
        r.action = "add_ignoreip";
        r.jail = jailName;
        r.ip = ip;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badJail");
            return r;
        }
        if (!isValidIpOrCidr(ip)) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badIp");
            return r;
        }
        try {
            // 1. Runtime
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " addignoreip " + ip);
            // 2. Persistence: append to ignoreip in the [jailName] section of jail.local
            persistIgnoreIpAdd(jailName, ip);
            r.success = true;
            r.message = I18n.tr("server.f2bm.ignoreAdded", java.util.Map.of("ip", String.valueOf(ip), "j", String.valueOf(jailName)));
        } catch (Exception e) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }
        return r;
    }

    /**
     * Removes an IP/CIDR from a jail's whitelist.
     */
    public BanAction removeIgnoreIp(String jailName, String ip) {
        BanAction r = new BanAction();
        r.action = "remove_ignoreip";
        r.jail = jailName;
        r.ip = ip;
        if (!isValidJailName(jailName)) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badJail");
            return r;
        }
        if (!isValidIpOrCidr(ip)) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.badIp");
            return r;
        }
        try {
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " delignoreip " + ip);
            persistIgnoreIpRemove(jailName, ip);
            r.success = true;
            r.message = I18n.tr("server.f2bm.ignoreRemoved", java.util.Map.of("ip", String.valueOf(ip), "j", String.valueOf(jailName)));
        } catch (Exception e) {
            r.success = false;
            r.message = I18n.tr("server.f2bm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }
        return r;
    }

    /** IP/CIDR validation (basic v4 and v6, no shell metachars). */
    private boolean isValidIpOrCidr(String s) {
        if (s == null || s.isBlank()) return false;
        // Only characters allowed for IPv4/IPv6/CIDR
        return s.matches("^[0-9a-fA-F:.]+(/[0-9]{1,3})?$");
    }

    /** Adds ip to ignoreip of the [jailName] section in jail.local (idempotent). */
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

            // Find the existing ignoreip line
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "(?m)^(\\s*)ignoreip\\s*=\\s*(.*)$");
            java.util.regex.Matcher m = p.matcher(section);
            String updated;
            if (m.find()) {
                String existing = m.group(2).trim();
                if (existing.contains(ip)) return; // already present
                String indent = m.group(1);
                String newVal = existing.isEmpty() ? ip : existing + " " + ip;
                updated = m.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    indent + "ignoreip = " + newVal));
            } else {
                // Add the key
                updated = setOrAddKey(section, "ignoreip", ip);
            }
            // Backup
            java.nio.file.Files.copy(path,
                backupCopy(path));
            String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
            java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    /** Removes ip from ignoreip of the [jailName] section in jail.local. */
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
                    ? "# ignoreip removed by the panel (was: " + existing + ")"
                    : indent + "ignoreip = " + newVal));
            // Backup
            java.nio.file.Files.copy(path,
                backupCopy(path));
            String newContent = content.substring(0, sectionStart) + updated + content.substring(sectionEnd);
            java.nio.file.Files.writeString(path, newContent, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ignored) {}
    }

    /** Finds the config file that contains the [jailName] section. */
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
     * Replaces a "key = ..." line in the section (regex-based, preserves
     * indentation). If the key does not exist it adds it at the end, before the
     * next section.
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
            // Append before trailing newline (if the section ends with \n) or append directly
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

            // 1. Whois -- provides REGISTRATION data (organization, netRange, country of registration)
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

            // 2. GeoIP via ip-api.com -- provides the real PHYSICAL location of the IP
            //    (whois returns the country of REGISTRATION, which is often the registered office,
            //    not where the IP is actually assigned. E.g. 80.94.95.242 is registered
            //    in the UK but is physically in Romania).
            enrichWithGeoIP(info, ip, whoisCountry);

        } catch (Exception e) {
            info.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
        }

        return info;
    }

    /**
     * Enriches IpInfo with geolocation data from ipapi.co (HTTPS).
     * Best-effort: if the API is offline / rate-limited / the panel has no
     * internet access, info stays as it is (whois only).
     * Free tier: 1000 req/day, HTTPS, no auth required.
     *
     * Endpoint: https://ipapi.co/<ip>/json/
     * Relevant fields: country_code, country_name, region, city, org, asn, latitude, longitude
     * Error (e.g. private IP): {"error": true, "reason": "...", "message": "..."}
     */
    private void enrichWithGeoIP(IpInfo info, String ip, String whoisCountry) {
        try {
            String urlStr = "https://ipapi.co/" + ip + "/json/";
            java.net.URL url = new java.net.URI(urlStr).toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "DaemoxCP-Mail/1.0");
            conn.setRequestProperty("Accept", "application/json");
            int code = conn.getResponseCode();
            // ipapi.co uses 200 even for lookup errors ("error: true" field in the body),
            // but can return 429 for rate limiting
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

            // Explicit error from ipapi.co (e.g. private IP, rate limited)
            if (json.optBoolean("error", false)) {
                String reason = json.optString("reason", json.optString("message", "unknown"));
                if (whoisCountry != null) info.geoSource = "whois (geoip: " + reason + ")";
                return;
            }

            // GeoIP is more accurate for the physical location: it prevails over the whois country
            info.country = json.optString("country_code", info.country);
            info.countryName = json.optString("country_name", null);
            info.region = json.optString("region", null);
            info.city = json.optString("city", null);
            info.asn = json.optString("asn", null);
            // ipapi.co does not distinguish ISP from org -- use "org" for both
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
            // Not fatal -- whois data stays available
            if (whoisCountry != null) info.geoSource = "whois " + I18n.tr("server.f2bm.geoipDown");
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

    // Defensive validation of the jail name to prevent command injection.
    // The jail name is concatenated into a shell, so it MUST follow
    // a very restrictive pattern.
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
     * Does the jail really hook that log, or does it run idle?
     *
     * Why it is needed. "0 bans, 0 failed attempts" has two opposite readings: nobody has ever
     * attacked that service, or the filter matches no line and the jail is
     * on without seeing anything. The card showed the zero and nothing else, and a zero that
     * can mean two opposite things is not information.
     *
     * The answer comes from fail2ban-regex(1), which takes a log and a filter and says how many
     * lines match. Comparing with how many lines the log has, the two cases can be told apart:
     *   - empty log            -> nothing can be said, and that is what is said
     *   - full log, 0 matches  -> the filter does not see that format: the jail is blind
     *   - matches > 0          -> the jail works, and there simply have been no attacks
     *
     * It only reads. The regex does NOT go through a shell: the command line is built as a
     * list of arguments, otherwise its metacharacters would be interpreted twice.
     */
    public FilterCheck verifyFilter(String jailName) {
        FilterCheck c = new FilterCheck();
        c.jail = jailName;
        try {
            if (!isValidJailName(jailName)) { c.message = I18n.tr("server.f2bm.badJailLower"); return c; }

            java.util.List<String> logs = logPathOf(jailName);
            if (logs.isEmpty()) { c.message = I18n.tr("server.f2bm.noLog"); return c; }
            String log = logs.get(0);
            c.log = log;

            java.io.File f = new java.io.File(log);
            if (!f.canRead()) { c.message = I18n.tr("server.f2bm.logUnreadable", java.util.Map.of("l", String.valueOf(log))); return c; }
            c.logLines2 = countLines(f);
            if (c.logLines2 == 0) {
                // An empty log has a third explanation, and it is the most insidious: the right
                // file is another one, one extension away. Before saying "I don't know"
                // we look next to it -- it is a check that costs one directory read and
                // turns a doubt into a diagnosis.
                String near = nearWritten(new java.io.File(log));
                if (near != null) {
                    c.message = I18n.tr("server.f2bm.logEmptyNeighbor", java.util.Map.of("v", String.valueOf(near)));
                    return c;
                }
                c.message = I18n.tr("server.f2bm.logEmpty");
                return c;
            }

            // The second argument of fail2ban-regex can be the NAME of a filter. We try
            // with the jail's one, which is the convention; if it does not exist we fall back on the
            // real failregex, asked of fail2ban.
            String output = runArgv(java.util.List.of(FAIL2BAN_REGEX, log, jailName));
            if (output == null || !output.contains("Lines:")) {
                String fr = firstFailregex(jailName);
                if (fr == null) {
                    c.message = I18n.tr("server.f2bm.noFilter");
                    return c;
                }
                output = runArgv(java.util.List.of(FAIL2BAN_REGEX, log, fr));
            }
            if (output == null || !output.contains("Lines:")) {
                c.message = I18n.tr("server.f2bm.regexUnreadable");
                return c;
            }
            c.output = output.length() > 3000 ? output.substring(output.length() - 3000) : output;

            java.util.regex.Matcher m = Pattern.compile("(\\d+)\\s+matched").matcher(output);
            c.hooks = m.find() ? Integer.parseInt(m.group(1)) : 0;
            c.verified = true;
            c.message = c.hooks > 0
                ? I18n.tr("server.f2bm.filterMatches", java.util.Map.of("n", String.valueOf(c.hooks)))
                : I18n.tr("server.f2bm.filterNoMatch", java.util.Map.of("n", String.valueOf(c.logLines2)));
            return c;
        } catch (Exception e) {
            c.message = I18n.tr("server.f2bm.checkError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
            return c;
        }
    }

    /**
     * Where to put the backup copy of a configuration file: NEVER next to the original.
     *
     * Fail2ban reads /usr/local/etc/fail2ban/jail.d, and until now the copies ended up right
     * in there: on the server there are six of mail.local, each with its own [recidive] and
     * [dovecot] section. They do not end in .conf, so today they are not loaded -- but they are
     * six files that define the same jails inside the folder fail2ban scans, and the diagnosis
     * showed them next to the real one. In a file that decides who gets in, "today it is not
     * read" is not a sufficient guarantee.
     */
    private Path backupCopy(Path original) throws Exception {
        Path dir = org.daemoxcp.mail.system.ConfigBackups.FAIL2BAN_FOLDER;
        Files.createDirectories(dir);
        // The older copies beyond the latest KEEP - 1: with the one the caller makes now, there are
        // KEEP again (ConfigBackups).
        org.daemoxcp.mail.system.ConfigBackups.prune(dir, original.getFileName().toString(), org.daemoxcp.mail.system.ConfigBackups.KEEP - 1);
        return dir.resolve(original.getFileName().toString() + ".bak."
            + java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
    }

    /**
     * The port a jail declares, read from the configuration files.
     *
     * The action's parameter is looked at first -- "pf[name=x, port=\"http,https\"]" -- because it
     * is what ends up in the pf rule; if missing we fall back on the "port =" line of the section,
     * which is what the action would use. Empty string when neither is there: it is the case
     * of recidive, and that empty value is not a cosmetic detail but the reason why its pf rule
     * does not load.
     */
    private String portFromConfiguration(String jailName) {
        try {
            java.util.List<Path> file = new ArrayList<>();
            file.add(Paths.get("/usr/local/etc/fail2ban/jail.local"));
            Path d = Paths.get(JAIL_D);
            if (Files.isDirectory(d))
                try (var el = Files.list(d)) {
                    el.filter(f -> f.getFileName().toString().endsWith(".conf")
                                || f.getFileName().toString().endsWith(".local"))
                      .sorted().forEach(file::add);
                }
            String fromAction = "", fromSection = "";
            for (Path f : file) {
                if (!Files.isRegularFile(f)) continue;
                boolean inside = false;
                for (String line : Files.readAllLines(f, java.nio.charset.StandardCharsets.UTF_8)) {
                    String t = line.trim();
                    if (t.startsWith("[") && t.endsWith("]")) { inside = t.equals("[" + jailName + "]"); continue; }
                    if (!inside || t.startsWith("#") || !t.contains("=")) continue;
                    String key = t.substring(0, t.indexOf('=')).trim().toLowerCase();
                    String value = t.substring(t.indexOf('=') + 1).trim();
                    if (key.equals("action") || key.equals("banaction")) {
                        java.util.regex.Matcher m =
                            Pattern.compile("port\\s*=\\s*\"?([^\",\\]]+)").matcher(value);
                        if (m.find()) fromAction = m.group(1).trim();
                    } else if (key.equals("port")) {
                        fromSection = value;
                    }
                }
            }
            return !fromAction.isEmpty() ? fromAction : fromSection;
        } catch (Exception ignore) {
            return "";
        }
    }

    /**
     * The log files a jail watches. A single function, used both by what shows and by what
     * checks.
     *
     * There were two that read the same thing in different ways: the card took the
     * "File list:" line from the output of "status", the filter check asked for "get <jail>
     * logpath" and required a line that STARTED with "/". That output lists the paths
     * preceded by a tree character, so no line starts with "/": the check
     * announced "this jail does not watch a log file" while two lines below, the
     * same card showed the log. Two readings of the same thing always diverge.
     *
     * Here an absolute path is searched for anywhere in the line, and the second source is
     * tried if the first gives nothing.
     */
    private java.util.List<String> logPathOf(String jailName) {
        java.util.List<String> out = new ArrayList<>();
        for (String command : new String[] {
                FAIL2BAN_CLIENT + " get " + jailName + " logpath",
                FAIL2BAN_CLIENT + " status " + jailName }) {
            try {
                for (String v : pathsIn(executeCommand(command)))
                    if (!out.contains(v)) out.add(v);
                if (!out.isEmpty()) return out;
            } catch (Exception ignore) { }
        }
        return out;
    }

    /**
     * The absolute paths contained in a fail2ban-client output.
     *
     * It lives in its own method so that it can be tested: the two outputs it must be extracted
     * from have different forms -- "get <jail> logpath" lists the files preceded by tree
     * characters ("`-", "|-"), "status <jail>" puts them after "File list:" -- and a reading that
     * works on only one of the two is exactly the defect being fixed.
     */
    static java.util.List<String> pathsIn(String output) {
        java.util.List<String> out = new ArrayList<>();
        if (output == null) return out;
        java.util.regex.Matcher m = Pattern.compile("(/[^\\s,]+)").matcher(output);
        while (m.find()) {
            String v = m.group(1).trim();
            // The output also names the command invoked: it is not a watched log.
            if (v.length() <= 1 || v.contains("fail2ban-client") || v.contains("fail2ban-regex")) continue;
            if (!out.contains(v)) out.add(v);
        }
        return out;
    }

    /**
     * A "sibling" file in the same folder, with the same name apart from the extension, which
     * unlike the watched one contains something. Readable description, or null.
     *
     * It serves to single out the worst case among those that produce an empty log: not "nobody
     * has attacked", but "we are looking at the wrong file, one extension off". It happened with
     * roundcube-auth: the jail watched "userlogins" while Roundcube writes "userlogins.log".
     */
    private String nearWritten(java.io.File watched) {
        try {
            java.io.File dir = watched.getParentFile();
            if (dir == null || !dir.isDirectory()) return null;
            String name = watched.getName();
            String root = name.contains(".") ? name.substring(0, name.indexOf('.')) : name;
            java.io.File[] allItems = dir.listFiles();
            if (allItems == null) return null;
            for (java.io.File f : allItems) {
                if (f.equals(watched) || !f.isFile()) continue;
                String n = f.getName();
                if (!n.equals(root) && !n.startsWith(root + ".")) continue;
                if (f.length() <= 0) continue;
                return "\"" + n + "\" (" + f.length() + " byte)";
            }
        } catch (Exception ignore) { }
        return null;
    }

    /**
     * The names of the jails loaded in Fail2ban right now.
     *
     * The same "Jail list:" line was already read in two places with two different expressions.
     * A single reading, here, so that what checks and what shows look at the same list.
     */
    public java.util.List<String> activeJailNames() {
        java.util.List<String> out = new ArrayList<>();
        try {
            java.util.regex.Matcher m =
                Pattern.compile("Jail list:\\s*(.+)").matcher(executeCommand(FAIL2BAN_CLIENT + " status"));
            if (m.find())
                for (String n : m.group(1).split(","))
                    if (!n.trim().isEmpty()) out.add(n.trim());
        } catch (Exception ignore) { }
        return out;
    }

    /**
     * The jails that watch a file incapable of telling them anything.
     *
     * Why it is a check of its own. The page's diagnosis asked "is the jail loaded in the
     * runtime?", and for roundcube-auth the answer was yes: the jail was there, on, and the page
     * showed green. It watched, however, "userlogins" while Roundcube wrote "userlogins.log"
     * in the same folder, and in that condition it would never have banned anyone. Loaded and
     * able to see are two different questions: as long as only one was asked, the green of the
     * first covered the second, and there was not even a button to fix it, because according to
     * the diagnosis there was nothing to fix.
     *
     * Here the files are looked at, not the names. The two cases that have no possible second
     * reading are flagged:
     *   - the watched file does not exist
     *   - it is empty, but next to it there is the same name one extension away, already written
     * The empty log without written siblings is left out on purpose: it can really mean that
     * nobody has attacked that service yet, and flagging it would turn the diagnosis into noise.
     *
     * It costs one directory read per jail: no process, no fail2ban-regex. So it can
     * be part of the health check that runs when the page opens.
     */
    public LogReview reviewWatchedLogs(java.util.Collection<String> jails) {
        LogReview e = new LogReview();
        for (String jail : jails) {
            if (!isValidJailName(jail)) { e.skipped.add(jail); continue; }
            java.util.List<String> logs = logPathOf(jail);
            if (logs.isEmpty()) { e.withoutLog.add(jail); continue; }
            e.reviewed.add(jail);
            for (String log : logs) {
                java.io.File f = new java.io.File(log);
                if (!f.exists()) {
                    e.issues.add(new WrongLog(jail, log, null,
                        I18n.tr("server.f2bm.watchesMissing", java.util.Map.of("l", String.valueOf(log)))));
                    continue;
                }
                if (f.length() > 0) continue;
                String near = nearWritten(f);
                if (near != null)
                    e.issues.add(new WrongLog(jail, log, near,
                        I18n.tr("server.f2bm.watchesWrong", java.util.Map.of("l", String.valueOf(log), "v", String.valueOf(near)))));
            }
        }
        return e;
    }

    /** All the jails loaded right now, not only the mail ones. */
    public LogReview reviewWatchedLogs() {
        return reviewWatchedLogs(activeJailNames());
    }

    /**
     * The outcome of the examination, with how many jails were really looked at.
     *
     * The count is not a detail: without it, "no problem found" and "I looked at
     * nothing" produce the same empty list and therefore the same green. A check that
     * turns green when it fails is worse than a check that does not exist, because it invites
     * people to stop looking. Whoever reads this outcome must be able to tell the two cases
     * apart, and to do so must be able to count.
     */
    public static class LogReview {
        /** Jails for which we obtained at least one path and looked at it. */
        public final java.util.List<String> reviewed = new ArrayList<>();
        /** Jails that have no log file to watch, or that did not tell us. */
        public final java.util.List<String> withoutLog = new ArrayList<>();
        /** Names that do not pass validation: no command is built on top of them. */
        public final java.util.List<String> skipped = new ArrayList<>();
        public final java.util.List<WrongLog> issues = new ArrayList<>();
    }

    /** A jail and the log that cannot tell it anything. */
    public static class WrongLog {
        public final String jail, log, near, reason;
        WrongLog(String jail, String log, String near, String reason) {
            this.jail = jail; this.log = log; this.near = near; this.reason = reason;
        }
    }

    /**
     * The addresses Fail2ban believes are banned, and those pf really blocks.
     *
     * Why it is needed. "Currently banned: 1" is the bookkeeping Fail2ban keeps about itself:
     * it says it ran the ban command, not that the address is blocked. If the anchor were not
     * loaded, or the table had another name, or pfctl failed silently, that
     * line would be identical to what it is now. It is the same gap between "I did it" and "it
     * happened" that made roundcube-auth blind while the page showed it as active.
     *
     * How it is measured. The pf target is not guessed from the jail name: it is read from the
     * real ban command, asked of Fail2ban, because anchor and table are configurable and a
     * convention taken for granted is already a hypothesis. From there the table is read with
     * pfctl and the two sets are compared.
     *
     * The differences have opposite readings and must be kept separate:
     *   - only in Fail2ban -> the ban is NOT applied: that address gets through
     *   - only in pf       -> someone Fail2ban has already unbanned stays blocked
     * A table that does not exist is not a read error but the defect itself, and it is
     * reported as such.
     *
     * It only reads: no pfctl that changes anything.
     */
    public PfComparison compareBansWithPf() {
        PfComparison c = new PfComparison();
        for (String jail : activeJailNames()) {
            if (!isValidJailName(jail)) continue;
            JailPf j = new JailPf();
            j.jail = jail;
            j.believedBanned.addAll(ipsBannedByFail2ban(jail));

            banCommandsOf(jail, j);
            PfTarget b = null;
            for (String cmd : j.banCommands) {
                b = targetFromCommand(cmd);
                if (b != null) break;
            }
            if (b == null) {
                // When it was not understood, everything needed to understand is made
                // available: what fail2ban answers, what it wrote in the log after the last
                // reload, and which files define this jail. The three things together answer
                // "what does fail2ban see", which is not the same question as "what did I write".
                j.logFail2ban = BanActionRepair.logErrorsFor(jail);
                j.sections = BanActionRepair.sectionsDefining(jail);
                j.dump = BanActionRepair.readConfiguration(jail);
                // We do not conclude "does not ban via pf": it has not been measured. We say
                // what it really runs, because it is the only way for someone to notice if
                // that command does nothing on this system.
                j.note = j.unreachable
                    ? I18n.tr("server.f2bm.restarting")
                    : j.banCommands.isEmpty()
                    ? I18n.tr("server.f2bm.noBanCmd")
                      + (j.seenActions.isEmpty() ? "" : " " + I18n.tr("server.f2bm.actionsRead", java.util.Map.of("list", String.valueOf(String.join(", ", j.seenActions)))))
                      + (j.discardedActions.isEmpty() ? "" : " " + I18n.tr("server.f2bm.actionsDropped", java.util.Map.of("list", String.valueOf(String.join(", ", j.discardedActions)))))
                      + " " + I18n.tr("server.f2bm.actionsAnswer", java.util.Map.of("o", String.valueOf(j.actionsOutput)))
                    : I18n.tr("server.f2bm.noPfTable", java.util.Map.of("cmd", String.valueOf(String.join(" ; ", j.banCommands))));
                c.jails.add(j);
                continue;
            }
            j.table = b.table;

            // We try where the table can be, and keep the place where it answered. That way
            // "does not exist" is said only after looking in all the sensible places.
            java.util.List<String> candidates = new ArrayList<>();
            if (b.anchor != null) candidates.add(b.anchor);
            if (b.stillLikely != null && !b.stillLikely.equals(b.anchor)) candidates.add(b.stillLikely);
            candidates.add(null);

            TableReading t = null;
            String stillUsed = null;
            for (String cand : candidates) {
                TableReading test = addressesInPfTable(cand, b.table);
                if (test.read && !test.missing) { t = test; stillUsed = cand; break; }
                if (t == null) { t = test; stillUsed = cand; }   // the first outcome, if none finds it
            }
            j.anchor = stillUsed == null ? I18n.tr("server.f2bm.mainRuleset") : stillUsed;
            if (!t.read) {
                j.note = I18n.tr("server.f2bm.tableUnreadable", java.util.Map.of("t", String.valueOf(b.table))) + (t.error.isEmpty() ? "" : " (" + t.error + ")");
                c.jails.add(j);
                continue;
            }
            j.read = true;
            j.missingTable = t.missing;
            // A full table blocks nothing on its own: the rule that reads it is needed. It is the
            // check fail2ban itself does ("pfctl -sr | grep -q <table>"), and it is the only
            // way to notice that actionstart created the table and then failed on the
            // rule -- which is exactly what happens when the port is empty.
            String rules = rulesOf(stillUsed, c);
            if (rules == null) {
                // pfctl did not answer. Saying "no rule" would be a conclusion drawn
                // from not having read, and would accuse five healthy jails of being broken.
                j.ruleVerified = false;
            } else {
                j.ruleVerified = true;
                j.rulePresent = rules.contains(b.table);
            }
            j.inFirewall.addAll(t.addresses);
            for (String ip : j.believedBanned) if (!j.inFirewall.contains(ip)) j.onlyInFail2ban.add(ip);
            for (String ip : j.inFirewall) if (!j.believedBanned.contains(ip)) j.onlyInPf.add(ip);
            c.jails.add(j);
        }
        return c;
    }

    /**
     * The loaded pf rules, per anchor. Read only once and kept for the duration of the
     * comparison: they are identical for all the jails sharing the anchor, and rereading them for
     * every jail would mean running pfctl seven times to get the same text seven times.
     */
    private String rulesOf(String anchor, PfComparison inMemory) {
        String key = anchor == null ? "" : anchor;
        String already = inMemory.rules.get(key);
        if (already != null) return already;
        String text = null;   // null = not read. Different from "read and contains nothing".
        try {
            java.util.List<String> argv = new ArrayList<>();
            argv.add("/sbin/pfctl");
            if (anchor != null) { argv.add("-a"); argv.add(anchor); }
            argv.add("-sr");
            org.daemoxcp.mail.util.Shell.Result r = org.daemoxcp.mail.util.Shell.run(
                java.time.Duration.ofSeconds(20), argv.toArray(new String[0]));
            if (r.success() && r.output() != null) text = r.output();
        } catch (Exception ignore) { }
        if (text != null) inMemory.rules.put(key, text);
        return text;
    }

    /** The addresses Fail2ban lists as banned right now for that jail. */
    private java.util.List<String> ipsBannedByFail2ban(String jail) {
        java.util.List<String> out = new ArrayList<>();
        try {
            java.util.regex.Matcher m = Pattern.compile("Banned IP list:\\s*(.*)")
                .matcher(executeCommand(FAIL2BAN_CLIENT + " status " + jail));
            if (m.find())
                for (String ip : m.group(1).trim().split("\\s+"))
                    if (!ip.trim().isEmpty()) out.add(normalizeAddress(ip));
        } catch (Exception ignore) { }
        return out;
    }

    /**
     * The commands a jail really runs to ban, one per action.
     *
     * All of them are taken, not only the one that seems to talk about pf: when none names a
     * table, the right answer is not "this jail does not use pf" -- which would be a conclusion
     * drawn from not having found anything -- but to show what it runs, and let it be seen.
     */
    private void banCommandsOf(String jail, JailPf j) {
        try {
            String actions = executeCommand(FAIL2BAN_CLIENT + " get " + jail + " actions");
            // The raw output is kept. When nothing can be derived from it, "I could not" is
            // a dead end: whoever reads the card cannot take a step forward, and whoever
            // writes it ends up guessing. Showing what fail2ban answered turns a
            // silent failure into a clue, and costs nothing because we already have the output.
            j.actionsOutput = actions == null ? "" : actions.trim();
            if (actions == null) return;
            // During a "reload --restart" the server does not answer for a few moments. It is a
            // condition of the panel, not a defect of the jail: attributing it to the jail would make
            // an invented fault appear right while something else is being repaired.
            if (j.actionsOutput.contains("Unable to contact server")
                || j.actionsOutput.contains("Connection refused")) {
                j.unreachable = true;
                return;
            }
            String queue = actions.contains(":") ? actions.substring(actions.lastIndexOf(':') + 1) : actions;
            for (String az : queue.split("[,\\n]")) {
                String a = az.trim().replaceAll("^[`|'-]+", "").trim();
                if (a.isEmpty()) continue;
                if (!isValidJailName(a)) { j.discardedActions.add(a); continue; }
                j.seenActions.add(a);
                String cmd = executeCommand(FAIL2BAN_CLIENT + " get " + jail + " action " + a + " actionban");
                if (cmd == null) continue;
                cmd = cmd.trim();
                if (cmd.isEmpty()) continue;
                if (cmd.toLowerCase().contains("error")) { j.discardedActions.add(a + " (" + cmd + ")"); continue; }
                j.banCommands.add(cmd.replace("\n", " "));
            }
        } catch (Exception e) {
            j.actionsOutput = I18n.tr("server.f2bm.actionsError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e)));
        }
    }

    /** The contents of a pf table. A missing table is not an error: it is an answer. */
    private TableReading addressesInPfTable(String anchor, String table) {
        TableReading t = new TableReading();
        try {
            java.util.List<String> argv = new ArrayList<>();
            argv.add("/sbin/pfctl");
            if (anchor != null) { argv.add("-a"); argv.add(anchor); }
            argv.add("-t"); argv.add(table);
            argv.add("-T"); argv.add("show");
            org.daemoxcp.mail.util.Shell.Result r = org.daemoxcp.mail.util.Shell.run(
                java.time.Duration.ofSeconds(20), argv.toArray(new String[0]));
            String out = r.output() == null ? "" : r.output();
            if (!r.success()) {
                // Non-existent table: it is precisely the fault this check looks for,
                // not a failure of the measurement. We go on with the empty set.
                if (out.toLowerCase().contains("does not exist") || out.toLowerCase().contains("no such")) {
                    t.read = true;
                    t.missing = true;
                    return t;
                }
                t.error = out.trim();
                return t;
            }
            for (String line : out.split("\n")) {
                String v = line.trim();
                if (v.isEmpty() || !v.matches("^[0-9a-fA-F:].*")) continue;
                t.addresses.add(normalizeAddress(v));
            }
            t.read = true;
        } catch (Exception e) {
            t.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
        }
        return t;
    }

    /**
     * Same form for the two sets before comparing them.
     *
     * pfctl prints the addresses with the mask ("213.209.159.175/32"), Fail2ban lists them
     * bare. Compared as they were, every banned address would have appeared in
     * only one of the two: the check would have flagged a fault everywhere, and a check that
     * always shouts is no longer read.
     */
    static String normalizeAddress(String v) {
        String s = v.trim();
        int sp = s.indexOf(' ');
        if (sp > 0) s = s.substring(0, sp);
        if (s.endsWith("/32")) s = s.substring(0, s.length() - 3);
        if (s.endsWith("/128")) s = s.substring(0, s.length() - 4);
        return s;
    }

    /**
     * Anchor and table read from a ban command. Separated from execution so that it can be
     * tested: it is the only point of the comparison where a wrong expression would not show --
     * it would give "this jail does not use pf" and the comparison would vanish silently instead
     * of failing.
     */
    static PfTarget targetFromCommand(String cmd) {
        if (cmd == null || !cmd.contains("pfctl")) return null;
        java.util.regex.Matcher mt = Pattern.compile("-t\\s+(\\S+)").matcher(cmd);
        if (!mt.find()) return null;
        PfTarget b = new PfTarget();
        b.table = mt.group(1);

        java.util.regex.Matcher ma = Pattern.compile("-a\\s+(\\S+)").matcher(cmd);
        if (ma.find()) { b.anchor = ma.group(1); return b; }

        // No "-a" in the text does not mean no anchor. The action file defines
        //     pfctl = pfctl -a f2b/<name>
        // and fail2ban returns the commands with the placeholders NOT expanded -- it is easy to see in
        // "<iptables> -I ..." -- so the anchor is hidden inside <pfctl> and searching for it in the
        // text never finds it. Looking for the table without an anchor means looking in the main
        // ruleset, where it is not: one would conclude "table does not exist" for every healthy jail.
        //
        // The anchor is derived from the same definitions: the table is "<tablename>-<name>" and
        // the anchor "f2b/<name>", so they share <name>. It is not a guessed convention,
        // it is the reading of the two lines that compose it. It is still a candidate to
        // try, though, not a certainty: whoever reads tries it and sees whether the table answers.
        int dash = b.table.indexOf('-');
        if (dash > 0 && dash < b.table.length() - 1)
            b.stillLikely = "f2b/" + b.table.substring(dash + 1);
        return b;
    }

    static class PfTarget {
        String anchor;          // written in the command: certain
        String stillLikely; // derived from the action's definitions: to be tried
        String table;
    }

    private static class TableReading {
        boolean read, missing;
        String error = "";
        final java.util.List<String> addresses = new ArrayList<>();
    }

    /** The comparison, jail by jail. */
    public static class PfComparison {
        public final java.util.List<JailPf> jails = new ArrayList<>();
        final java.util.Map<String, String> rules = new java.util.HashMap<>();
        /**
         * Addresses Fail2ban believes are banned and pf does not block: they get through.
         *
         * Those present in the table when no rule reads it end up here too:
         * being in the table is a necessary condition, not a sufficient one, and counting them as
         * blocked would be the same mistake as reading "Currently banned" as proof.
         */
        public int totalNotApplied() {
            int n = 0;
            for (JailPf j : jails) {
                if (!j.read) continue;
                n += (!j.ruleVerified || j.rulePresent)
                        ? j.onlyInFail2ban.size() : j.believedBanned.size();
            }
            return n;
        }

        /** Jails whose table is read by no pf rule: they ban into the void. */
        public int totalWithoutRule() {
            int n = 0;
            for (JailPf j : jails) if (j.read && j.ruleVerified && !j.rulePresent) n++;
            return n;
        }
        /**
         * Jails for which nothing could be measured: their silence is not a go-ahead.
         *
         * ALL the ones not read end up here, whatever the reason. The first version
         * counted only read errors and left out the jails for which no pf table
         * was found: the jail of port 443 had a banned address, no check, and
         * the summary said "Consistent". A green that comes from what was not looked at is
         * the defect this card exists to uncover, and it had it inside.
         */
        public int totalUnmeasured() {
            int n = 0;
            for (JailPf j : jails) if (!j.read) n++;
            return n;
        }

        /** Bans declared by Fail2ban for jails we could not verify. */
        public int unverifiedBans() {
            int n = 0;
            for (JailPf j : jails) if (!j.read) n += j.believedBanned.size();
            return n;
        }
    }

    public static class JailPf {
        public String jail = "", anchor = "", table = "", note = "";
        public boolean read, missingTable;
        /** Is there a pf rule that reads this table? Without one, the table blocks nothing. */
        public boolean rulePresent;
        /** The ruleset was really read. Without this, rulePresent means nothing. */
        public boolean ruleVerified;
        public final java.util.List<String> believedBanned = new ArrayList<>();
        public final java.util.List<String> inFirewall = new ArrayList<>();
        public final java.util.List<String> onlyInFail2ban = new ArrayList<>();
        public final java.util.List<String> onlyInPf = new ArrayList<>();
        /** What it really runs to ban. Shown when it could not be verified. */
        public final java.util.List<String> banCommands = new ArrayList<>();
        /** The raw output of "get <jail> actions": the clue when nothing can be derived from it. */
        public String actionsOutput = "";
        public final java.util.List<String> seenActions = new ArrayList<>();
        public final java.util.List<String> discardedActions = new ArrayList<>();
        /** The lines of fail2ban.log and the sections that define the jail: the evidence to read. */
        public String logFail2ban = "", sections = "", dump = "";
        /** Fail2ban did not answer: it is restarting. It is not a fault of this jail. */
        public boolean unreachable;
    }

    public static class FilterCheck {
        public String jail = "", log = "", message = "", output = "";
        public boolean verified;
        public int hooks;
        public long logLines2;
    }

    private static final String FAIL2BAN_REGEX = "/usr/local/bin/fail2ban-regex";

    private long countLines(java.io.File f) {
        try (BufferedReader r = new BufferedReader(new java.io.FileReader(f))) {
            long n = 0;
            while (r.readLine() != null) { n++; if (n > 200000) break; }
            return n;
        } catch (Exception e) { return 0; }
    }

    private String firstFailregex(String jail) {
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jail + " failregex");
            java.util.regex.Matcher m = Pattern.compile("'(.+?)'", Pattern.DOTALL).matcher(out);
            return m.find() ? m.group(1) : null;
        } catch (Exception e) { return null; }
    }

    /** Runs without a shell: arguments stay arguments, metacharacters are not interpreted. */
    private String runArgv(java.util.List<String> argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
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
        org.daemoxcp.mail.util.Shell.applyPath(pb);
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
     * Runs the following commands for a specific jail:
     *   fail2ban-client get <jail> maxretry
     *   fail2ban-client get <jail> findtime
     *   fail2ban-client get <jail> bantime
     *   fail2ban-client get <jail> logpath
     *   fail2ban-client get <jail> ignoreip
     *   fail2ban-client get <jail> filter
     *   fail2ban-client status <jail>
     *
     * Returns a structured object with the text output of each command
     * + the parsed values of the statistics for the UI.
     */
    public JailLiveState getJailLiveState(String jailName) {
        JailLiveState s = new JailLiveState();
        s.name = jailName;
        if (!isValidJailName(jailName)) {
            s.error = I18n.tr("server.f2bm.badJailNamed", java.util.Map.of("j", String.valueOf(jailName)));
            return s;
        }
        // PARALLELIZATION: each of the 5 "fail2ban-client get" + the "status" starts on
        // a separate virtual thread. Total time = time of the slowest command
        // (~150ms) instead of the sum (~900ms).
        // We use CompletableFuture + virtual threads (stable API, no preview flags).
        try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var maxretryF = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> runGetCommand(jailName, "maxretry")), executor);
            var findtimeF = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> runGetCommand(jailName, "findtime")), executor);
            var bantimeF  = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> runGetCommand(jailName, "bantime")),  executor);
            var logpathF  = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> runGetCommand(jailName, "logpath")),  executor);
            var ignoreipF = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> runGetCommand(jailName, "ignoreip")), executor);
            // Note: `fail2ban-client get <jail> filter` is not supported in all
            // versions of fail2ban-client. We read from config (file I/O, fast).
            var filterF   = java.util.concurrent.CompletableFuture.supplyAsync(I18n.withCurrentSupplier(() -> readFilterNameFromConfig(jailName)), executor);
            // Status: multiline text, we keep it whole for parsing
            var statusF   = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try { return executeCommand(FAIL2BAN_CLIENT + " status " + jailName); }
                catch (Exception e) { throw new RuntimeException(e); }
            }, executor);

            // Wait for all -- join() rethrows any exceptions
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
            s.error = org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e);
        }
        return s;
    }

    private String runGetCommand(String jailName, String key) {
        try {
            String out = executeCommand(FAIL2BAN_CLIENT + " get " + jailName + " " + key);
            if (out == null) return "";
            String trimmed = out.trim();
            // fail2ban-client get sometimes returns prefixes like "`-" or "|-" for lists -- we clean them
            // Example: get <jail> ignoreip can return "127.0.0.1/8\n::1"
            return trimmed;
        } catch (Exception e) {
            return "(" + I18n.tr("server.f2bm.errorLower", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("Fail2banManager", e))) + ")";
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
            // Switch arrow syntax (Java 14+): no fall-through, no break.
            switch (key) {
                case "currently failed" -> s.currentlyFailed = parseIntSafe(val);
                case "total failed"     -> s.totalFailed     = parseIntSafe(val);
                case "currently banned" -> s.currentlyBanned = parseIntSafe(val);
                case "total banned"     -> s.totalBanned     = parseIntSafe(val);
                case "banned ip list"   -> s.bannedIpsRaw    = val;
                case "file list"        -> s.fileListRaw     = val;
                default -> { /* ignore unknown keys */ }
            }
        }
    }

    /**
     * Looks for the value of "filter = ..." in the [jailName] section inside:
     *   /usr/local/etc/fail2ban/jail.local
     *   /usr/local/etc/fail2ban/jail.d/*.conf|local
     * Returns the filter name, "(default: jailName)" if the section exists but
     * does not specify filter (fail2ban uses the jail name as default), or
     * "(not found)" if the section is missing altogether.
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
        return sectionFound ? "(default: " + jailName + ")" : I18n.tr("server.f2bm.notInConfig");
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
        // Output of the "get" commands
        public String maxretry;
        public String findtime;
        public String bantime;
        public String logpath;
        public String ignoreip;
        public String filter;
        // Full output of "status"
        public String statusRaw;
        // Fields parsed from status (with default 0/null if not available)
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
        /** The ports the jail protects, as fail2ban declares them. Empty = not declared. */
        public String ports = "";
        /** false when fail2ban could not tell them: "not declared" is not "none". */
        public boolean declaredPort;
        /**
         * Does the ban command really use the port, or does it just block the address?
         *
         * Without this distinction it is not known how to read the list of ports. If the command
         * does NOT name them -- the typical case of a pf table -- then the ban applies to
         * the address on all ports, and a list that does not match the real services
         * does no harm: it is decorative. If instead it names them, a wrong list is a hole,
         * because the attacker gets blocked on ports they are not using.
         */
        public boolean banUsesPort;
        public String banCommand = "";
        public String error;
    }

    /**
     * IP currently banned in a specific jail.
     * Immutable record. bannedAt/expiresAt are optional (they can be null
     * if fail2ban does not expose them -- the current 'status' does not include them).
     */
    public record BannedIp(String ip, String jail, boolean active,
                           LocalDateTime bannedAt, LocalDateTime expiresAt) {}

    /**
     * Historical ban/unban event extracted from the fail2ban log.
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

    // ============== PERMABAN (permanent ban via pf, independent from Fail2ban) ==============
    //
    // Architecture:
    //   - File: /var/db/daemoxcp-mail/permaban.list (IP list, one per line)
    //   - pf table: <permaban> persist file ".../permaban.list"
    //   - pf rule:  block in quick from <permaban>
    //
    // Advantages over fail2ban bantime=-1:
    //   - Survives restarts of the panel, fail2ban, server
    //   - Works even if fail2ban is down
    //   - Granular per single IP
    public static final String PERMABAN_DIR  = "/var/db/daemoxcp-mail";
    public static final String PERMABAN_FILE = PERMABAN_DIR + "/permaban.list";
    public static final String PERMABAN_TABLE = "permaban";
    /** The comment lines at the top of the list, and the blank line that separates them from the IPs. */
    public static final String PERMABAN_HEADER = "# Permaban list — managed by DaemoxCP Mail\n"
            + "# The IPs in here are loaded into the pf table <permaban>\n"
            + "# and blocked with the rule: block in quick from <permaban>\n\n";

    /**
     * Adds an IP to the permaban list.
     * - Adds it to the file (with dedup)
     * - Adds it at runtime to the pf table
     * Returns true if the IP was actually added (false if already present).
     */
    public synchronized boolean addPermanentBan(String ip) throws Exception {
        if (!isValidIp(ip)) throw org.daemoxcp.mail.util.ShownException.Argument.of("server.badIp");

        ensurePermanentBanFile();
        java.util.Set<String> current = readPermanentBanFile();
        if (current.contains(ip)) return false; // already present, no-op
        current.add(ip);
        writePermabanFile(current);

        // Sync runtime with pfctl (if pf is active)
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "add", ip);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            // Even if pfctl fails (e.g. table not created yet), the file is already written
        } catch (Exception ignored) {}

        return true;
    }

    /**
     * Removes an IP from the permaban list.
     * Returns true if removed, false if it was not present.
     */
    public synchronized boolean removePermanentBan(String ip) throws Exception {
        if (!isValidIp(ip)) throw org.daemoxcp.mail.util.ShownException.Argument.of("server.badIp");

        java.util.Set<String> current = readPermanentBanFile();
        if (!current.contains(ip)) return false;
        current.remove(ip);
        writePermabanFile(current);

        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "delete", ip);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception ignored) {}

        return true;
    }

    /** Returns the current list of permabanned IPs. */
    public synchronized java.util.List<String> listPermanentBans() {
        try {
            return new java.util.ArrayList<>(readPermanentBanFile());
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }

    /** Returns the IPs currently loaded in the pf table <permaban> (runtime). */
    public java.util.Set<String> listPermanentBanRuntime() {
        java.util.Set<String> result = new java.util.HashSet<>();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "show");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
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
     * Reloads the pf table from the file (e.g. after a panel restart).
     * Equivalent to: pfctl -t permaban -T replace -f <file>
     */
    public boolean reloadPermanentBanFromFile() {
        try {
            ensurePermanentBanFile();
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-t", PERMABAN_TABLE, "-T", "replace", "-f", PERMABAN_FILE);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void ensurePermanentBanFile() throws java.io.IOException {
        Path dir = Paths.get(PERMABAN_DIR);
        if (!Files.isDirectory(dir)) Files.createDirectories(dir);
        Path file = Paths.get(PERMABAN_FILE);
        if (!Files.exists(file)) Files.createFile(file);
    }

    /** Reads the file ignoring empty lines, comments (#) and invalid IPs. */
    private java.util.Set<String> readPermanentBanFile() throws java.io.IOException {
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
        ensurePermanentBanFile();
        StringBuilder content = new StringBuilder(PERMABAN_HEADER);
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
        public String country;         // code (e.g. "RO") -- from geoIP if available, otherwise whois
        public String countryName;     // full name (e.g. "Romania")
        public String region;          // regione/stato (es. "Bucharest")
        public String city;            // city
        public String organization;    // registration org (from whois)
        public String isp;             // ISP (da geoIP)
        public String asn;             // ASN (es. "AS12345")
        public String netRange;        // IP range (from whois)
        public Double latitude;
        public Double longitude;
        public String geoSource;       // "ip-api.com" or "whois" or "both"
        public String rawWhois;
        public String error;
    }
}
