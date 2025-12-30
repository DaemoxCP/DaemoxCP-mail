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
            String output = executeCommand(FAIL2BAN_CLIENT + " status " + jailName);

            if (output.contains("does not exist") || output.contains("not found")) {
                jail.exists = false;
                return jail;
            }

            jail.exists = true;
            jail.enabled = true;

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

            // Parse filter file
            Pattern filterPattern = Pattern.compile("File list:\\s*(.+)");
            java.util.regex.Matcher filterMatcher = filterPattern.matcher(output);
            if (filterMatcher.find()) {
                jail.logFile = filterMatcher.group(1).trim();
            }

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
                        BannedIp ban = new BannedIp();
                        ban.ip = ip;
                        ban.jail = jail.name;
                        ban.active = true;
                        banned.add(ban);
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
                    BanEvent event = new BanEvent();
                    event.timestamp = parseDateTime(matcher.group(1));
                    event.jail = matcher.group(2);
                    event.action = matcher.group(3).toLowerCase();
                    event.ip = matcher.group(4);
                    events.add(event);
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
     * Generate mail jails configuration
     */
    private String generateMailJailsConfig() {
        return """
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
            [roundcube-auth]
            enabled = true
            port = http,https
            filter = roundcube-auth
            logpath = /var/log/roundcube/errors.log
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
            """;
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

        // Roundcube auth filter (if not exists)
        Path rcFilter = Paths.get(FILTER_D, "roundcube-auth.conf");
        if (!Files.exists(rcFilter)) {
            String roundcubeFilter = """
                # Mail Panel - Roundcube Authentication Filter
                [Definition]
                failregex = ^.*FAILED login for .* from <HOST>.*$
                            ^.*FAILED login for \\S+ from \\S+ \\[<HOST>\\].*$
                            ^.*Login failed for .* from <HOST>.*$
                            ^.*Authentication failed for .* \\[client <HOST>\\].*$

                ignoreregex =
                """;
            Files.writeString(rcFilter, roundcubeFilter);
        }

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
            // Try to read from jail.d/mail.local or jail.local
            String jailContent = "";
            Path mailJailPath = Paths.get(JAIL_D, "mail.local");
            Path jailLocalPath = Paths.get(JAIL_LOCAL);

            if (Files.exists(mailJailPath)) {
                jailContent = Files.readString(mailJailPath);
            } else if (Files.exists(jailLocalPath)) {
                jailContent = Files.readString(jailLocalPath);
            }

            // Parse jail section
            Pattern sectionPattern = Pattern.compile(
                "\\[" + Pattern.quote(jailName) + "\\]([^\\[]+)",
                Pattern.CASE_INSENSITIVE
            );
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
            // Use fail2ban-client to set values
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " maxretry " + maxRetry);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " findtime " + findTime);
            executeCommand(FAIL2BAN_CLIENT + " set " + jailName + " bantime " + banTime);

            action.success = true;
            action.message = "Configuration updated for jail " + jailName;

        } catch (Exception e) {
            action.success = false;
            action.message = "Error: " + e.getMessage();
        }

        return action;
    }

    /**
     * Get IP info (whois lookup)
     */
    public IpInfo getIpInfo(String ip) {
        IpInfo info = new IpInfo();
        info.ip = ip;

        try {
            // Use whois if available
            String output = executeCommand("whois " + ip + " 2>/dev/null | head -50");

            if (!output.isEmpty()) {
                info.found = true;
                info.rawWhois = output;

                // Parse common fields
                Pattern countryPattern = Pattern.compile("(?:country|Country):\\s*(.+)", Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher countryMatcher = countryPattern.matcher(output);
                if (countryMatcher.find()) {
                    info.country = countryMatcher.group(1).trim();
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

        } catch (Exception e) {
            info.error = e.getMessage();
        }

        return info;
    }

    // Utility methods

    private boolean isValidIp(String ip) {
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

    private String executeCommand(String command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
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

    // Data classes

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
        public String error;
    }

    public static class BannedIp {
        public String ip;
        public String jail;
        public boolean active;
        public LocalDateTime bannedAt;
        public LocalDateTime expiresAt;
    }

    public static class BanEvent {
        public LocalDateTime timestamp;
        public String action; // "ban" or "unban"
        public String jail;
        public String ip;
    }

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

    public static class IpInfo {
        public String ip;
        public boolean found;
        public String country;
        public String organization;
        public String netRange;
        public String rawWhois;
        public String error;
    }
}
