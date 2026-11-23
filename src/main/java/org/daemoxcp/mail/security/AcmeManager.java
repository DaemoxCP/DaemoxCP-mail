package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * ACME/Let's Encrypt Certificate Manager for DaemoxCP Mail
 *
 * Uses acme.sh for certificate management (lightweight, pure shell)
 * Supports:
 * - Certificate issuance via HTTP-01 or DNS-01 challenge
 * - Automatic renewal
 * - Deployment to Dovecot, Postfix, Nginx
 * - Certificate status monitoring
 *
 * Certificate paths:
 * - /usr/local/etc/ssl/mail/fullchain.pem (certificate + chain)
 * - /usr/local/etc/ssl/mail/privkey.pem (private key)
 */
public class AcmeManager {

    /*
     * Where acme.sh lives and which user it runs as is told by AcmeUser.layout(): as acme from
     * /var/db/acme (the security/acme.sh package), or as root in /root/.acme.sh until the
     * boot migration has moved it.
     *
     * Every command carries "--home": this is how acme.sh chooses its own working folder
     * (official source, lines 11 and 3145):
     *     DEFAULT_INSTALL_HOME="$HOME/.$PROJECT_NAME"
     *     if [ -z "$LE_WORKING_DIR" ]; then LE_WORKING_DIR="$DEFAULT_INSTALL_HOME"; fi
     * The panel is started by rc.d, which does NOT pass HOME. With HOME empty that
     * expression becomes "/.acme.sh": acme.sh really issued the certificate, but in the
     * root of the disk, while we copied from /root/.acme.sh, that is, the old file.
     * "--home" (line 8436 of the source) is the documented fix, and it is the same flag
     * that acme.sh writes into its own cron: it does not trust the environment either.
     */
    private static final String SSL_DIR = "/usr/local/etc/ssl/mail";
    private static final String CERT_FILE = SSL_DIR + "/fullchain.pem";
    private static final String KEY_FILE = SSL_DIR + "/privkey.pem";
    private static final String FULLCHAIN_FILE = SSL_DIR + "/fullchain.pem";
    private static final String CA_FILE = SSL_DIR + "/ca.pem";

    // Renewal threshold (days before expiry to renew): default; can be overridden by a DB setting
    private static final int RENEWAL_THRESHOLD_DAYS_DEFAULT = 30;

    // DB settings keys
    public static final String SETTING_AUTO_RENEW_ENABLED   = "acme_auto_renewal_enabled";
    public static final String SETTING_AUTO_RENEW_THRESHOLD = "acme_renewal_threshold_days";
    public static final String SETTING_AUTO_RENEW_LAST_CHECK    = "acme_auto_renewal_last_check";
    public static final String SETTING_AUTO_RENEW_LAST_RESULT   = "acme_auto_renewal_last_result";
    public static final String SETTING_AUTO_RENEW_LAST_RENEWAL  = "acme_auto_renewal_last_renewal";
    // Cloudflare account chosen for the certificate of the MAIL SERVER (Mail Hostname),
    // whose base domain may not be among the managed mail domains.
    public static final String SETTING_CF_ACCOUNT_ID            = "acme_cf_account_id";

    public boolean isAutoRenewalEnabled() {
        String v = database.getSetting(SETTING_AUTO_RENEW_ENABLED, "1");
        return "1".equals(v) || "true".equalsIgnoreCase(v);
    }

    public int getRenewalThresholdDays() {
        try { return Integer.parseInt(database.getSetting(SETTING_AUTO_RENEW_THRESHOLD, String.valueOf(RENEWAL_THRESHOLD_DAYS_DEFAULT))); }
        catch (Exception e) { return RENEWAL_THRESHOLD_DAYS_DEFAULT; }
    }

    public void setAutoRenewalEnabled(boolean enabled) {
        database.setSetting(SETTING_AUTO_RENEW_ENABLED, enabled ? "1" : "0");
    }

    public void setRenewalThresholdDays(int days) {
        database.setSetting(SETTING_AUTO_RENEW_THRESHOLD, String.valueOf(Math.max(1, Math.min(89, days))));
    }

    public String getLastCheckTime()    { return database.getSetting(SETTING_AUTO_RENEW_LAST_CHECK, ""); }
    public String getLastCheckResult()  { return database.getSetting(SETTING_AUTO_RENEW_LAST_RESULT, ""); }
    public String getLastRenewalTime()  { return database.getSetting(SETTING_AUTO_RENEW_LAST_RENEWAL, ""); }

    private final MailDatabase database;
    private final ScheduledExecutorService scheduler;

    public AcmeManager(MailDatabase database) {
        this.database = database;
        // Use daemon thread so JVM can exit even if scheduler is running
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ACME-Renewal-Scheduler");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Start automatic renewal checker (runs daily)
     */
    public void startAutoRenewal() {
        // Run check immediately at startup
        scheduler.execute(() -> {
            // First, on servers installed earlier: acme.sh from /root, as root, to /var/db/acme as
            // acme. Here and not in the rest of startup, because it may install the package (minutes,
            // if the network is slow), and before the check, which would otherwise renew with the old one.
            AcmeUser.ensureAtBoot();
            // The plaintext copy of the Cloudflare token that acme.sh had saved: removed (AcmeCloudflareCopy)
            AcmeCloudflareCopy.ensureAtBoot();
            // Which user each service runs as, and the warnings in the log. Here, after the migration
            // of acme.sh: before it, it would warn that acme.sh runs as root while it is being moved
            // (seen on the VM on 2026-10-31, a false warning on the first start).
            org.daemoxcp.mail.system.ServiceUsers.logAtBoot();
            try {
                System.out.println("[ACME] Checking certificate status at startup...");
                checkAndRenewCertificates();
            } catch (Exception e) {
                System.err.println("[ACME] Startup check failed: " + e.getMessage());
            }
        });

        // Then schedule daily checks
        scheduler.scheduleAtFixedRate(() -> {
            try {
                System.out.println("[ACME] Daily certificate check...");
                checkAndRenewCertificates();
            } catch (Exception e) {
                System.err.println("[ACME] Auto-renewal check failed: " + e.getMessage());
            }
        }, 24, 24, TimeUnit.HOURS);

        System.out.println("[ACME] Auto-renewal scheduler started (checks at startup + daily)");
    }

    /**
     * Stop the auto-renewal scheduler
     */
    public void stopAutoRenewal() {
        scheduler.shutdownNow();
        try {
            if (!scheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                System.err.println("ACME scheduler did not terminate in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Check if acme.sh is installed
     */
    public boolean isAcmeInstalled() {
        return AcmeUser.layout() != null;
    }

    /** acme.sh with the folders and the user of this machine; null if it is not there. */
    private AcmeUser.Layout layout() {
        return AcmeUser.layout();
    }

    /** Runs acme.sh (as acme, or as root before the migration) with those arguments. */
    private String acme(String args) throws Exception {
        return acme(args, null);
    }

    private String acme(String args, Map<String, String> env) throws Exception {
        AcmeUser.Layout l = layout();
        if (l == null) throw org.daemoxcp.mail.util.ShownException.of("server.acme.notInstalled");
        try {
            return AcmeUser.run(l, args, env);
        } finally {
            // The panel passes it the token every time: the copy acme.sh saves of it is not needed (AcmeCloudflareCopy)
            if (env != null && env.containsKey("CF_Token")) AcmeCloudflareCopy.afterRun(l);
        }
    }

    /**
     * The HTTP challenge. As acme, acme.sh cannot open port 80 (--standalone): it writes the challenge
     * file into its folder, and the panel opens the port for the duration of the command. With
     * a webroot given by the administrator (a site that already answers on 80) acme only writes
     * the challenge folder there. As root, before the migration, everything stays as before.
     */
    private String acmeWithHttpChallenge(String args, String webroot) throws Exception {
        AcmeUser.Layout l = layout();
        if (l == null) throw org.daemoxcp.mail.util.ShownException.of("server.acme.notInstalled");
        boolean own = webroot == null || webroot.isEmpty() || AcmeUser.WEBROOT.equals(webroot);
        if (!l.asAcme())
            return AcmeUser.run(l, args + (own ? " --standalone" : " -w " + webroot), null);
        if (!own) {
            AcmeUser.allowChallengeIn(webroot);
            return AcmeUser.run(l, args + " -w " + webroot, null);
        }
        return withPort80(l, args + " -w " + AcmeUser.WEBROOT);
    }

    /** acme.sh as acme with port 80 opened by the panel on the challenge folder. */
    private String withPort80(AcmeUser.Layout l, String args) throws Exception {
        AcmeUser.prepareWebroot();
        try (AcmeUser.Challenge c = AcmeUser.Challenge.open()) {
            return AcmeUser.run(l, args, null);
        } catch (java.net.BindException e) {
            return I18n.tr("server.acme.port80Busy", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e)));
        }
    }

    /** The Let's Encrypt account of acme.sh exists (the file that acme.sh writes when registration succeeds). */
    public boolean hasAccount() {
        AcmeUser.Layout l = layout();
        return l != null && java.nio.file.Files.isRegularFile(java.nio.file.Path.of(l.home(),
                "ca/acme-v02.api.letsencrypt.org/directory/account.json"), java.nio.file.LinkOption.NOFOLLOW_LINKS);
    }

    /** The error line of acme.sh, short, to tell whoever pressed the button. */
    static String acmeError(String output) {
        String best = "";
        for (String line : String.valueOf(output).split("\n")) {
            String l = line.replaceAll("^\\[[^]]*\\]\\s*", "").trim();
            if (l.isEmpty()) continue;
            String low = l.toLowerCase(java.util.Locale.ROOT);
            if (low.contains("error") || low.contains("invalid") || low.contains("failed")) best = l;
        }
        if (best.isEmpty()) best = "no answer";
        return best.length() > 200 ? best.substring(0, 200) + "…" : best;
    }

    /**
     * Install acme.sh: the security/acme.sh package, which creates the acme user and installs the
     * program in /usr/local/sbin. Before: "curl https://get.acme.sh | sh" as root.
     */
    public InstallResult installAcme(String email) {
        if (!InputValidator.isValidEmail(email))
            return new InstallResult(false, I18n.tr("server.acme.badEmail"), null);
        try {
            org.daemoxcp.mail.util.Shell.Result r = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofMinutes(10),
                    "pkg", "install", "-y", AcmeUser.PACKAGE);
            String output = r.outputTrim();
            if (isAcmeInstalled() && layout().asAcme()) {
                AcmeUser.prepareWebroot();
                // The account with the CA, with the email for expiry warnings. --server on every command.
                output += "\n" + acme("--register-account -m " + email + " --server letsencrypt");
            }

            if (isAcmeInstalled()) {
                // Save email to database
                database.setSetting("acme_email", email);
                // The account is checked, not inferred (finding 247): with an address that Let's Encrypt rejects the
                // package is there but the account is not, and without an account there is no certificate.
                if (hasAccount()) return new InstallResult(true, I18n.tr("server.acme.installed"), output);
                return new InstallResult(false, I18n.tr("server.acme.noAccount", java.util.Map.of("why", acmeError(output))), output);
            } else {
                return new InstallResult(false, I18n.tr("server.acme.installFailed"), output);
            }

        } catch (Exception e) {
            return new InstallResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Issue a new certificate for a domain
     *
     * @param domain Main domain (e.g., example.com)
     * @param mailHostname Mail server hostname (e.g., mail.example.com)
     * @param challengeType "http" or "dns"
     * @param webroot Path to webroot for HTTP challenge (optional)
     */
    public CertificateResult issueCertificate(String domain, String mailHostname, String challengeType, String webroot) {
        if (!isAcmeInstalled()) {
            return new CertificateResult(false, I18n.tr("server.acme.notInstalled"), null);
        }

        // SECURITY: validate hostname/domain before putting them in a shell command
        if (!InputValidator.isValidHostname(mailHostname) || !InputValidator.isValidDomain(domain)) {
            return new CertificateResult(false, I18n.tr("server.acme.badHostOrDomain"), null);
        }
        if (webroot != null && !webroot.isEmpty() && (webroot.contains("..") || webroot.contains(";") || webroot.contains("|") || webroot.contains("&") || webroot.contains("`") || webroot.contains("$"))) {
            return new CertificateResult(false, I18n.tr("server.acme.badWebroot"), null);
        }

        try {
            // The names to put in the certificate: the server's hostname and autoconfig.
            //
            // "autodiscover" was removed together with the rest: it was only for Outlook. It is not
            // cosmetic cleanup: acme.sh VALIDATES every name it is asked for, so leaving it
            // here after we stopped proposing its record would mean, on a new domain,
            // making the issuance of the WHOLE certificate fail for a name that does not exist
            // and that nobody uses. A certificate that is not issued stops the mail.
            List<String> domains = new ArrayList<>();
            domains.add(mailHostname);
            domains.add("autoconfig." + domain);
            // MTA-STS: it is this very certificate that proves the policy comes from the
            // owner of the domain, because the protocol does not use DNSSEC. Without the name
            // in here, sending servers ignore the policy.
            domains.add("mta-sts." + domain);

            // Build acme.sh command
            StringBuilder cmd = new StringBuilder();
            // See the note in emitWithNames: the CA is declared on every command.
            cmd.append("--issue --server letsencrypt");

            // Add all domains
            for (String d : domains) {
                cmd.append(" -d ").append(d);
            }

            // Force issue even if cert exists
            cmd.append(" --force");

            // Challenge type. HTTP: port 80 is opened by the panel (acmeWithHttpChallenge).
            String output = "dns".equals(challengeType)
                    ? acme(cmd + " --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please")
                    : acmeWithHttpChallenge(cmd.toString(), webroot);

            // Check if certificate was issued (check both regular and ECC directories)
            if (layout().certDir(mailHostname) != null) {
                // Deploy certificate
                DeployResult deployResult = deployCertificate(mailHostname);
                if (deployResult.success) {
                    // Save to database
                    saveCertificateInfo(domain, mailHostname);
                    return new CertificateResult(true, I18n.tr("server.acme.issuedInstalled"), output + "\n" + deployResult.output);
                } else {
                    return new CertificateResult(false, I18n.tr("server.acme.issuedDeployFailed", java.util.Map.of("m", String.valueOf(deployResult.message))), output);
                }
            }

            // Check for DNS challenge instructions
            if ("dns".equals(challengeType) && output.contains("TXT value")) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.dnsChallengeNeeded"),
                    output);
            }

            return new CertificateResult(false, I18n.tr("server.acme.issueFailed"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Deploy certificate to mail services
     */
    /**
     * The installed certificate and key are the same pair.
     *
     * The PUBLIC keys are compared, not the moduli: "openssl rsa" does not work on an
     * elliptic-curve key, and acme.sh issues ECC certificates by default.
     * With "openssl pkey -pubout" the comparison works for both types.
     */
    /** The certificate the services are using contains that name among its SANs. */
    private boolean installedCertificateCovers(String name) {
        for (String n : installedCertificateNames())
            if (n.equalsIgnoreCase(name)) return true;
        return false;
    }

    private static boolean nameCharacter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '.' || c == '-';
    }

    /** Only letters, digits, dots and hyphens: what a DNS name can contain. */
    static boolean allowedName(String n) {
        if (n == null || n.isBlank() || n.length() > 253) return false;
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                      || (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!ok) return false;
        }
        return n.indexOf('.') > 0 && !n.startsWith("-") && !n.startsWith(".") && !n.endsWith(".");
    }

    public static java.util.List<String> namesFromSubjectAltName(String opensslOutput) {
        java.util.List<String> names = new java.util.ArrayList<>();
        if (opensslOutput == null) return names;
        // Splitting the text on commas does not work: with "openssl -text" the LAST name is
        // not followed by a comma, so its piece stretches up to the next comma, much
        // further on, inside another extension, and the name disappears.
        // With "-ext", instead, the header is attached to the FIRST name. So I do not split:
        // I look for every "DNS:", read the allowed characters that follow and require them
        // to end at a comma or at the end of the line. This way the two formats give the same
        // result, and no character other than those of a DNS name can end up in the command line.
        final int end = opensslOutput.length();
        int i = 0;
        while ((i = opensslOutput.indexOf("DNS:", i)) >= 0) {
            i += 4;
            int j = i;
            while (j < end && nameCharacter(opensslOutput.charAt(j))) j++;
            char after = j < end ? opensslOutput.charAt(j) : '\n';
            boolean closed = (after == ',' || after == '\n' || after == '\r');
            String name = opensslOutput.substring(i, j);
            if (closed && allowedName(name) && !names.contains(name)) names.add(name);
            i = j;
        }
        return names;
    }

    /**
     * The names covered by the certificate CURRENTLY in use.
     * They are needed for renewal: "--issue --force" with a single "-d" redefines the set of names,
     * so renewing without rereading them would make the mta-sts.* and autoconfig.* disappear:
     * with the MTA-STS records already published, mail would be rejected.
     */
    public java.util.List<String> installedCertificateNames() {
        try {
            String out = executeCommand("openssl x509 -in " + FULLCHAIN_FILE
                    + " -noout -ext subjectAltName 2>/dev/null");
            if (out == null || out.isBlank())
                out = executeCommand("openssl x509 -in " + CERT_FILE
                        + " -noout -ext subjectAltName 2>/dev/null");
            return namesFromSubjectAltName(out);
        } catch (Exception e) {
            return new java.util.ArrayList<>();
        }
    }

    private boolean consistentPair() {
        try {
            String fromCert = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -pubkey 2>/dev/null");
            String fromKey = executeCommand("openssl pkey -in " + KEY_FILE + " -pubout 2>/dev/null");
            if (fromCert == null || fromKey == null) return false;
            String a = fromCert.replaceAll("\\s+", ""), b = fromKey.replaceAll("\\s+", "");
            return !a.isEmpty() && a.equals(b);
        } catch (Exception e) {
            // Failing to verify is not a promotion: we go back.
            return false;
        }
    }

    public DeployResult deployCertificate(String mailHostname) {
        return deployCertificate(mailHostname, null);
    }

    /**
     * The services that present the mail certificate, after the files have changed: each one checked and
     * reloaded on its own, then looked at live. Returns the problems (empty if everything is fine); in out, what
     * happened.
     *
     * Before, the deploy rewrote conf.d/10-ssl.conf with Dovecot 2.3 syntax and reloaded everything with
     * "service X reload 2>/dev/null || echo". On 2026-11-17, at the first real renewal on the server with Dovecot
     * 2.4, the Dovecot configuration became invalid (ssl_cert: Unknown setting), the reload was refused without
     * anyone knowing, 993 kept presenting the old certificate, and at the first restart Dovecot would not have come
     * back up. The configurations are written by the installation, and already point to these files: they are not
     * touched here.
     */
    java.util.List<String> reloadAndVerify(StringBuilder out) {
        java.util.List<String> problems = new java.util.ArrayList<>();
        java.time.Duration t = java.time.Duration.ofSeconds(60);
        java.util.List<int[]> ports = new java.util.ArrayList<>();
        java.util.List<String> portNames = new java.util.ArrayList<>();

        // First the configuration check and the reload; only with a good configuration does it make sense to ask which
        // file it uses (when it is broken, doveconf does not answer and it would look like "does not use the
        // certificate").
        if (org.daemoxcp.mail.util.Shell.run(t, "service", "dovecot", "status").success()) {
            if (reloadChecked("Dovecot", "doveconf -n", "service dovecot reload", problems, out)) {
                String file = org.daemoxcp.mail.util.Shell.runShell(t,
                        "doveconf -h ssl_server_cert_file 2>/dev/null || doveconf -h ssl_cert 2>/dev/null").outputTrim();
                if (!CERT_FILE.equals(file.replaceFirst("^<", "").trim()))
                    problems.add(I18n.tr("server.acme.notUsing", java.util.Map.of("s", "Dovecot", "f", CERT_FILE)));
            }
            ports.add(new int[]{993});
            portNames.add("Dovecot");
        }
        if (org.daemoxcp.mail.util.Shell.run(t, "service", "postfix", "status").success()) {
            if (reloadChecked("Postfix", "postfix check", "service postfix reload", problems, out)) {
                String files = org.daemoxcp.mail.util.Shell.runShell(t,
                        "postconf -h smtpd_tls_chain_files smtpd_tls_cert_file 2>/dev/null").output();
                if (files == null || !files.contains(CERT_FILE))
                    problems.add(I18n.tr("server.acme.notUsing", java.util.Map.of("s", "Postfix", "f", CERT_FILE)));
            }
            ports.add(new int[]{465});
            portNames.add("Postfix");
        }
        String sni443 = null;
        if (org.daemoxcp.mail.util.Shell.run(t, "service", "nginx", "status").success()) {
            reloadChecked("nginx", "nginx -t", "service nginx reload", problems, out);
            sni443 = sniFor443(installedCertificateNames());
            if (sni443 != null) {
                ports.add(new int[]{443});
                portNames.add("nginx");
            }
        }
        if (!problems.isEmpty()) return problems;

        // The look that counts: what whoever connects is really presented with. Dovecot reloads at a moment of its own,
        // so it retries for a few seconds before saying that it still has the previous certificate.
        String expected = serialOf(Paths.get(CERT_FILE));
        if (expected == null) {
            problems.add(I18n.tr("server.acme.unreadable", java.util.Map.of("f", CERT_FILE)));
            return problems;
        }
        for (int i = 0; i < ports.size(); i++) {
            int port = ports.get(i)[0];
            String sni = port == 443 ? sni443 : null;
            String seen = null;
            for (int attempt = 0; attempt < 15; attempt++) {
                seen = servedSerial("127.0.0.1", port, sni, 5000);
                if (expected.equals(seen)) break;
                try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            }
            out.append(portNames.get(i)).append(" on ").append(port).append(": ")
                    .append(expected.equals(seen) ? "the new certificate" : "certificate " + seen).append('\n');
            if (!expected.equals(seen))
                problems.add(I18n.tr("server.acme.stillOld", java.util.Map.of("s", portNames.get(i), "p", String.valueOf(port))));
        }
        return problems;
    }

    /**
     * The configuration check, then the reload; a refusal becomes a stated problem, never a "reloaded".
     * True if the service was reloaded. Of the check, the error (stderr) is kept, not what it prints when it goes
     * well (doveconf -n prints the whole configuration).
     */
    private static boolean reloadChecked(String name, String check, String reload, java.util.List<String> problems, StringBuilder out) {
        java.time.Duration t = java.time.Duration.ofSeconds(60);
        org.daemoxcp.mail.util.Shell.Result c = org.daemoxcp.mail.util.Shell.runShell(t, check + " 2>&1 >/dev/null");
        if (!c.success()) {
            String why = lastLine(c.outputTrim());
            out.append(name).append(": configuration refused, not reloaded: ").append(why).append('\n');
            problems.add(I18n.tr("server.acme.serviceRefused", java.util.Map.of("s", name, "e", why)));
            return false;
        }
        org.daemoxcp.mail.util.Shell.Result r = org.daemoxcp.mail.util.Shell.runShell(t, reload + " 2>&1");
        out.append(name).append(": ").append(r.success() ? "reloaded" : "reload failed: " + lastLine(r.outputTrim())).append('\n');
        if (!r.success())
            problems.add(I18n.tr("server.acme.reloadFailed", java.util.Map.of("s", name, "e", lastLine(r.outputTrim()))));
        return r.success();
    }

    private static String lastLine(String text) {
        if (text == null || text.isBlank()) return "?";
        String[] lines = text.trim().split("\n");
        String l = lines[lines.length - 1].trim();
        return l.length() > 300 ? l.substring(0, 300) : l;
    }

    /** The name with which to ask nginx on 443 for the mail certificate: an mta-sts.* that the certificate covers. */
    static String sniFor443(java.util.List<String> names) {
        if (names == null) return null;
        for (String n : names) if (n != null && n.toLowerCase(java.util.Locale.ROOT).startsWith("mta-sts.")) return n;
        return null;
    }

    /** The serial number (hexadecimal, uppercase) of the first certificate in the file, or null. */
    static String serialOf(Path pem) {
        try (java.io.InputStream in = Files.newInputStream(pem)) {
            java.security.cert.X509Certificate c = (java.security.cert.X509Certificate)
                    java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
            return c.getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The serial number of the certificate presented by whoever listens on host:port (TLS straight away, like 993,
     * 465 and 443), or null. It is only read: no trust is needed to look at a certificate, and nothing is sent.
     */
    static String servedSerial(String host, int port, String sni, int timeoutMs) {
        try {
            javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(null, new javax.net.ssl.TrustManager[]{new javax.net.ssl.X509TrustManager() {
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
            }}, null);
            try (java.net.Socket raw = new java.net.Socket()) {
                raw.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
                raw.setSoTimeout(timeoutMs);
                try (javax.net.ssl.SSLSocket s = (javax.net.ssl.SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, false)) {
                    if (sni != null) {
                        javax.net.ssl.SSLParameters p = s.getSSLParameters();
                        p.setServerNames(java.util.List.of(new javax.net.ssl.SNIHostName(sni)));
                        s.setSSLParameters(p);
                    }
                    s.startHandshake();
                    java.security.cert.Certificate[] chain = s.getSession().getPeerCertificates();
                    return ((java.security.cert.X509Certificate) chain[0]).getSerialNumber().toString(16).toUpperCase(java.util.Locale.ROOT);
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts from the output of acme.sh the folder where it REALLY wrote.
     * acme.sh always declares it: "Your cert is in: /path/host.cer".
     * Reading it instead of rebuilding it is the only way not to copy an old file
     * again when acme.sh worked elsewhere: that was exactly the case in which
     * HOME was missing and the folder became "/.acme.sh".
     */
    static Path declaredFolder(String acmeOutput) {
        if (acmeOutput == null) return null;
        for (String line : acmeOutput.split("\n")) {
            int i = line.indexOf("Your cert is in:");
            if (i < 0) continue;
            String path = line.substring(i + "Your cert is in:".length()).trim();
            if (path.isEmpty()) continue;
            // acme.sh can print "//.acme.sh/..." when HOME is empty: I normalize
            while (path.contains("//")) path = path.replace("//", "/");
            Path f = Paths.get(path);
            Path dir = f.getParent();
            if (dir != null && Files.isDirectory(dir)) return dir;
        }
        return null;
    }

    public DeployResult deployCertificate(String mailHostname, String acmeOutput) {
        // SECURITY: validate hostname before Paths.get and shell usage
        if (!InputValidator.isValidHostname(mailHostname)) {
            return new DeployResult(false, I18n.tr("server.acme.badHostname"), null);
        }
        try {
            // Create SSL directory
            Files.createDirectories(Paths.get(SSL_DIR));

            // The folder that acme.sh DECLARED beats any reconstruction of ours.
            Path source = declaredFolder(acmeOutput);
            if (source != null && !Files.exists(source.resolve(mailHostname + ".cer"))) source = null;

            if (source == null) {
                // Source paths (acme.sh storage) - ECC first, as acme.sh does by default
                AcmeUser.Layout l = layout();
                source = l == null ? null : l.certDir(mailHostname);
                if (source == null)
                    return new DeployResult(false, I18n.tr("server.acme.filesNotFound", java.util.Map.of("d",
                            String.valueOf(l == null ? AcmeUser.CERT_HOME : l.certHome()))), null);
            }

            Path acmeCert = source.resolve(mailHostname + ".cer");
            Path acmeKey = source.resolve(mailHostname + ".key");
            Path acmeFullchain = source.resolve("fullchain.cer");
            Path acmeCa = source.resolve("ca.cer");

            // Check source files exist
            if (!Files.exists(acmeCert) || !Files.exists(acmeKey)) {
                return new DeployResult(false, I18n.tr("server.acme.filesNotFound", java.util.Map.of("d", String.valueOf(source))), null);
            }

            // BACKUP COPY before overwriting.
            //
            // Here the certificate that dovecot, postfix and nginx answer with is replaced:
            // if the new one were faulty, the old one, which worked, would no longer exist,
            // and the three services would be reloaded with a broken certificate. An
            // irreversible operation on something that works is not done without a way back.
            java.util.Map<String, String> saved = new java.util.HashMap<>();
            try {
                Path copyDir = Paths.get("/var/db/daemoxcp-mail/ssl-previous");
                Files.createDirectories(copyDir);
                for (String f : new String[] { CERT_FILE, KEY_FILE, FULLCHAIN_FILE, CA_FILE }) {
                    Path orig = Paths.get(f);
                    if (!Files.exists(orig)) continue;
                    Path dest = copyDir.resolve(orig.getFileName().toString());
                    Files.copy(orig, dest, StandardCopyOption.REPLACE_EXISTING);
                    saved.put(f, dest.toString());
                }
            } catch (Exception e) {
                return new DeployResult(false, I18n.tr("server.acme.noBackup", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
            }

            // Copy files
            Files.copy(acmeCert, Paths.get(CERT_FILE), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(acmeKey, Paths.get(KEY_FILE), StandardCopyOption.REPLACE_EXISTING);
            if (Files.exists(acmeFullchain)) {
                Files.copy(acmeFullchain, Paths.get(FULLCHAIN_FILE), StandardCopyOption.REPLACE_EXISTING);
            }
            if (Files.exists(acmeCa)) {
                Files.copy(acmeCa, Paths.get(CA_FILE), StandardCopyOption.REPLACE_EXISTING);
            }

            // Does the key match the certificate?
            //
            // The two PUBLIC keys are compared: the one inside the certificate and the one
            // derived from the private key. If they do not match, the services restart with an
            // inconsistent pair and every TLS connection fails: mail stops completely.
            // Better to notice it here, with the copy still at hand.
            if (!consistentPair()) {
                for (java.util.Map.Entry<String, String> e : saved.entrySet()) {
                    try {
                        Files.copy(Paths.get(e.getValue()), Paths.get(e.getKey()),
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (Exception ignore) {}
                }
                return new DeployResult(false, I18n.tr("server.acme.keyMismatchRestored"), null);
            }

            // Set permissions
            String permScript = """
                chmod 644 %s
                chmod 600 %s
                chmod 644 %s 2>/dev/null || true
                chmod 644 %s 2>/dev/null || true
                chown root:wheel %s/*
                """.formatted(CERT_FILE, KEY_FILE, FULLCHAIN_FILE, CA_FILE, SSL_DIR);

            executeScript(permScript);

            // The configurations of the services are not rewritten: they already point to these files. The services are
            // reloaded one by one after their check, and then what they present is looked at live (reloadAndVerify).
            StringBuilder reloadOutput = new StringBuilder();
            java.util.List<String> problems = reloadAndVerify(reloadOutput);
            if (!problems.isEmpty())
                return new DeployResult(false, I18n.tr("server.acme.deployIncomplete",
                        java.util.Map.of("list", String.join(" ", problems))), reloadOutput.toString());
            return new DeployResult(true, I18n.tr("server.acme.deployed"), reloadOutput.toString());

        } catch (Exception e) {
            return new DeployResult(false, I18n.tr("server.acme.deployError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Renew certificate
     */
    public CertificateResult renewCertificate(String mailHostname) {
        if (!isAcmeInstalled()) {
            return new CertificateResult(false, I18n.tr("server.acme.notInstalled"), null);
        }

        // SECURITY: validate hostname before shell concatenation
        if (!InputValidator.isValidHostname(mailHostname)) {
            return new CertificateResult(false, I18n.tr("server.acme.badHostname"), null);
        }

        // If the domain has a linked Cloudflare account, it renews in a
        // fully automatic way via the Cloudflare API (acme.sh dns_cf).
        // This is the only way to auto-renew certificates issued in
        // manual DNS mode, which acme.sh CANNOT renew on its own.
        MailDatabase.CloudflareAccount cf = cloudflareAccountForHostname(mailHostname);
        if (cf != null && cf.apiToken != null && !cf.apiToken.isBlank()) {
            return renewViaCloudflare(mailHostname, cf);
        }

        return renewStandard(mailHostname);
    }

    /**
     * "Standard" renewal: it works for HTTP-01 certificates and for those already
     * configured with a DNS API provider. Certificates in manual DNS mode
     * CANNOT be renewed automatically by acme.sh: in that case we return
     * an explicit message instead of the generic "Renewal failed".
     */
    private CertificateResult renewStandard(String mailHostname) {
        try {
            // A certificate requested with the HTTP challenge is renewed with the same one: port 80 again.
            String cmd = "--renew -d " + mailHostname + " --force";
            AcmeUser.Layout l = layout();
            Path dir = l == null ? null : l.certDir(mailHostname);
            boolean http = l != null && l.asAcme() && dir != null
                    && AcmeUser.WEBROOT.equals(AcmeUser.savedWebroot(dir, mailHostname));
            String output = http ? withPort80(l, cmd) : acme(cmd);

            // Check success
            if (output.contains("Cert success") || output.contains("Skip")) {
                // Redeploy
                DeployResult deployResult = deployCertificate(mailHostname);
                return new CertificateResult(deployResult.success,
                    deployResult.success ? I18n.tr("server.acme.renewed") : I18n.tr("server.acme.renewedDeployFailed") + " " + deployResult.message,
                    output + "\n" + (deployResult.output != null ? deployResult.output : ""));
            }

            // acme.sh cannot automatically renew manual-DNS certificates
            if (output.contains("manual mode") || output.contains("can not be renewed")
                    || output.contains("cannot be renewed")) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.manualDns"),
                    output);
            }

            return new CertificateResult(false, I18n.tr("server.acme.renewFailed"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Renewal via the Cloudflare API (acme.sh --dns dns_cf). Re-issues the certificate
     * using the CF token of the account linked to the domain; this also migrates a
     * manual-DNS certificate to automatic renewal for the following times.
     * The token is passed as an environment variable, never on the command line.
     */
    /**
     * Issues the certificate for the hostname PLUS the given names, via the Cloudflare API.
     *
     * It is needed because MTA-STS and the automatic configuration of clients live on dedicated
     * names (mta-sts.<domain> and autoconfig.<domain>) and the certificate must cover them:
     * without that, the client or the sending server stops at the TLS error and reads nothing.
     *
     * A limit to be aware of: acme.sh validates all the names with ONE SINGLE Cloudflare token.
     * Domains that are on another account cannot be included here, and the caller must
     * exclude them first instead of making the whole issuance fail because of one of them.
     */
    public CertificateResult emitWithNames(String mailHostname, java.util.List<String> extraNames) {
        MailDatabase.CloudflareAccount cf = cloudflareAccountForHostname(mailHostname);
        if (cf == null)
            return new CertificateResult(false,
                I18n.tr("server.acme.noCfForHost", java.util.Map.of("h", String.valueOf(mailHostname))), null);
        if (!InputValidator.isValidHostname(mailHostname))
            return new CertificateResult(false, I18n.tr("server.acme.badHostnameNamed", java.util.Map.of("h", String.valueOf(mailHostname))), null);

        // --server letsencrypt on EVERY command, not just once at installation time.
        // The acme.sh documentation says: "For now, the default CA is zerossl. If you want
        // to use another CA, you need to specify --server for each command." The default was
        // set by the installation script, but an update of acme.sh puts it back to
        // ZeroSSL, which demands a registration with an email and makes the issuance fail with a
        // message that has nothing to do with the certificate. A default set elsewhere
        // is a hidden dependency: better to say it every time.
        StringBuilder cmd = new StringBuilder("--issue --server letsencrypt --dns dns_cf -d " + mailHostname);
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        seen.add(mailHostname.toLowerCase(java.util.Locale.ROOT));
        if (extraNames != null) for (String n : extraNames) {
            if (n == null) continue;
            String x = n.trim().toLowerCase(java.util.Locale.ROOT);
            // Every name ends up in a command line: it is checked, not hoped for.
            if (x.isEmpty() || !InputValidator.isValidHostname(x) || !seen.add(x)) continue;
            cmd.append(" -d ").append(x);
        }
        cmd.append(" --force");

        try {
            Map<String, String> env = new HashMap<>();
            env.put("CF_Token", cf.apiToken);
            String output = sanitize(acme(cmd.toString(), env), cf.apiToken);
            // "Skipping. Next renewal time" is NOT a success when new names are requested:
            // it means that acme.sh left the certificate as it was. Counting it as successful
            // got the old one installed and declared "issued with 11 names" something that
            // had the same names as before.
            boolean issued = output.contains("Cert success") || output.contains("Cert renewed");
            if (!issued) {
                String why = output.contains("Skipping. Next renewal time")
                        ? I18n.tr("server.acme.skipped")
                        : I18n.tr("server.acme.issueFailedShort");
                return new CertificateResult(false, why, output);
            }

            DeployResult dep = deployCertificate(mailHostname, output);
            if (!dep.success)
                return new CertificateResult(false, I18n.tr("server.acme.issueOkDeployFailed", java.util.Map.of("m", String.valueOf(dep.message))), output + "\n" + (dep.output != null ? dep.output : ""));

            // THE check that counts: does the INSTALLED certificate really contain the requested names?
            // That acme.sh did not complain is not enough: it may have written into a folder
            // other than the one the deploy copies from, and the outcome would be "successful" with the
            // old certificate still in its place.
            java.util.List<String> missing = new java.util.ArrayList<>();
            for (String n : seen) if (!installedCertificateCovers(n)) missing.add(n);
            if (!missing.isEmpty())
                return new CertificateResult(false,
                        I18n.tr("server.acme.namesMissing", java.util.Map.of("n", String.valueOf(missing.size()), "list", String.valueOf(String.join(", ", missing)))),
                        output + "\n" + (dep.output != null ? dep.output : ""));

            return new CertificateResult(true, I18n.tr("server.acme.issuedWithNames", java.util.Map.of("n", String.valueOf(seen.size()))),
                    output + "\n" + (dep.output != null ? dep.output : ""));
        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /** The Cloudflare account linked to a domain, to know whether it shares the one of the certificate. */
    public MailDatabase.CloudflareAccount accountOf(int domainId) {
        try {
            return database.getCloudflareAccountForDomain(domainId);
        } catch (Exception e) {
            return null;
        }
    }

    /** The account used for the hostname's certificate. */
    public MailDatabase.CloudflareAccount certificateAccount(String mailHostname) {
        return cloudflareAccountForHostname(mailHostname);
    }

    private CertificateResult renewViaCloudflare(String mailHostname, MailDatabase.CloudflareAccount cf) {
        try {
            Map<String, String> env = new HashMap<>();
            // Cloudflare "scoped" token: requires the Zone:DNS:Edit + Zone:Read permissions
            env.put("CF_Token", cf.apiToken);

            // "--issue --force" REDEFINES the set of names. If we renewed with the hostname
            // alone, the certificate would go back to covering only it and the mta-sts.* would disappear:
            // with the MTA-STS records already published that means mail REJECTED, weeks later,
            // without anyone having touched anything. So I reread the names from the one in use.
            StringBuilder cmd = new StringBuilder(
                    "--issue --server letsencrypt --dns dns_cf -d " + mailHostname);
            java.util.List<String> keep = new java.util.ArrayList<>();
            for (String n : installedCertificateNames())
                if (!n.equalsIgnoreCase(mailHostname)) keep.add(n);
            java.util.Collections.sort(keep);
            for (String n : keep) cmd.append(" -d ").append(n);
            cmd.append(" --force");
            String output = sanitize(acme(cmd.toString(), env), cf.apiToken);

            if (output.contains("Cert success") || output.contains("Cert renewed")
                    || output.contains("Skipping. Next renewal time")) {
                DeployResult deployResult = deployCertificate(mailHostname, output);
                return new CertificateResult(deployResult.success,
                    deployResult.success ? I18n.tr("server.acme.renewedCf")
                                         : I18n.tr("server.acme.renewedCfDeployFailed") + " " + deployResult.message,
                    output + "\n" + (deployResult.output != null ? deployResult.output : ""));
            }

            return new CertificateResult(false, I18n.tr("server.acme.renewCfFailed"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.cfError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Works out the Cloudflare account to use for the mail server's certificate.
     *
     * The certificate is issued for the <b>Mail Hostname</b> (e.g. mail.company.com), whose
     * base domain (company.com) is NOT necessarily among the managed mail domains.
     * That is why the account is chosen explicitly from the Cloudflare page and is
     * saved in {@link #SETTING_CF_ACCOUNT_ID}. Only as a fallback do we try to infer it
     * from the mail domains (in case the hostname is under a mail domain already linked).
     */
    private MailDatabase.CloudflareAccount cloudflareAccountForHostname(String hostname) {
        try {
            // 1) Explicit choice for the mail server's certificate
            String idStr = database.getSetting(SETTING_CF_ACCOUNT_ID, "");
            if (idStr != null && !idStr.isBlank()) {
                int id = Integer.parseInt(idStr.trim());
                if (id > 0) {
                    MailDatabase.CloudflareAccount a = database.getCloudflareAccount(id);
                    if (a != null) return a;
                }
            }
            // 2) Fallback: a hostname that falls under a mail domain already assigned
            // mail.example.com -> example.com (but also try the whole hostname)
            String domain = hostname.replaceFirst("^[^.]+\\.", "");
            MailDatabase.Domain d = database.getDomainByName(domain);
            if (d == null) {
                d = database.getDomainByName(hostname);
            }
            if (d == null) return null;
            return database.getCloudflareAccountForDomain(d.id);
        } catch (Exception e) {
            System.err.println("[ACME] Cloudflare account lookup failed: " + e.getMessage());
            return null;
        }
    }

    /** Id of the Cloudflare account chosen for the mail server's certificate (0 = none). */
    public int getMailCertCloudflareAccountId() {
        try {
            String v = database.getSetting(SETTING_CF_ACCOUNT_ID, "");
            return (v == null || v.isBlank()) ? 0 : Integer.parseInt(v.trim());
        } catch (Exception e) { return 0; }
    }

    /** Sets (or clears with 0) the Cloudflare account used for the mail server's certificate. */
    public void setMailCertCloudflareAccountId(int accountId) {
        database.setSetting(SETTING_CF_ACCOUNT_ID, accountId > 0 ? String.valueOf(accountId) : "");
    }

    /** Removes the token from the output before returning/logging it. */
    private String sanitize(String output, String token) {
        if (output == null || token == null || token.isBlank()) return output;
        return output.replace(token, "***");
    }

    /**
     * Check and renew certificates that are about to expire.
     * Always saves last_check, last_result and (if renewed) last_renewal.
     * If forceRun = false, it is skipped when auto-renewal is disabled.
     */
    public CertificateResult checkAndRenewCertificates(boolean forceRun) {
        String now = LocalDateTime.now().toString();
        try {
            if (!forceRun && !isAutoRenewalEnabled()) {
                String msg = I18n.tr("server.acme.autoOff");
                System.out.println("[ACME] Auto-renewal disabled — check skipped");
                database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
                database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, "SKIP|" + msg);
                return new CertificateResult(true, msg, null);
            }

            CertificateInfo info = getCertificateInfo();
            if (info == null || info.expiresAt == null) {
                String msg = I18n.tr("server.acme.noCertInfo");
                System.out.println("[ACME] No certificate installed or expiry date not readable");
                database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
                database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, "INFO|" + msg);
                return new CertificateResult(false, msg, null);
            }

            long daysUntilExpiry = ChronoUnit.DAYS.between(LocalDateTime.now(), info.expiresAt);
            int threshold = getRenewalThresholdDays();

            if (daysUntilExpiry <= 0) {
                System.err.println("[ACME] WARNING: certificate EXPIRED! Trying to renew it...");
                CertificateResult result = renewCertificate(info.commonName);
                String resStr = (result.success ? "OK" : "FAIL") + "|" + renewalSummary(result, daysUntilExpiry, true);
                database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
                database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, resStr);
                if (result.success) database.setSetting(SETTING_AUTO_RENEW_LAST_RENEWAL, now);
                return result;
            } else if (daysUntilExpiry <= threshold) {
                System.out.println("[ACME] Certificate expires in " + daysUntilExpiry + " days (threshold: " + threshold + "), renewing...");
                CertificateResult result = renewCertificate(info.commonName);
                String resStr = (result.success ? "OK" : "FAIL") + "|" + renewalSummary(result, daysUntilExpiry, false);
                database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
                database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, resStr);
                if (result.success) database.setSetting(SETTING_AUTO_RENEW_LAST_RENEWAL, now);
                return result;
            } else {
                String msg = I18n.tr("server.acme.certOk", java.util.Map.of("n", String.valueOf(daysUntilExpiry), "cn", String.valueOf(info.commonName)));
                System.out.println("[ACME] Certificate OK — expires in " + daysUntilExpiry + " days (" + info.commonName + ")");
                database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
                database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, "OK|" + msg);
                return new CertificateResult(true, msg, null);
            }

        } catch (Exception e) {
            System.err.println("[ACME] Certificate check failed: " + e.getMessage());
            database.setSetting(SETTING_AUTO_RENEW_LAST_CHECK, now);
            database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, "FAIL|" + I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))));
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Builds the message with the outcome of the renewal.
     * On SUCCESS it shows the NEW expiry (rereading the certificate just installed),
     * not the days that were left before, so it does not look as if it "renews and expires at once".
     * On FAILURE it keeps the context (how many days were left).
     */
    private String renewalSummary(CertificateResult result, long daysBefore, boolean wasExpired) {
        if (result.success) {
            long newDays = -1;
            try {
                CertificateInfo fresh = getCertificateInfo();
                if (fresh != null && fresh.expiresAt != null) {
                    newDays = ChronoUnit.DAYS.between(LocalDateTime.now(), fresh.expiresAt);
                }
            } catch (Exception ignore) { /* best-effort */ }
            return result.message + (newDays >= 0 ? " — " + I18n.tr("server.acme.newExpiry", java.util.Map.of("n", String.valueOf(newDays))) : "");
        }
        return (wasExpired ? I18n.tr("server.acme.expiredRenew") : I18n.tr("server.acme.renewDaysLeft", java.util.Map.of("n", String.valueOf(daysBefore)))) + " " + result.message;
    }

    /** Backward-compatible -- calls checkAndRenewCertificates(false) */
    public void checkAndRenewCertificates() {
        checkAndRenewCertificates(false);
    }

    /**
     * Get current certificate information
     */
    public CertificateInfo getCertificateInfo() {
        try {
            Path certPath = Paths.get(CERT_FILE);
            if (!Files.exists(certPath)) {
                return null;
            }

            // Use openssl to read certificate info
            String output = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -subject -dates -issuer");

            CertificateInfo info = new CertificateInfo();
            info.installed = true;
            info.certPath = CERT_FILE;
            info.keyPath = KEY_FILE;

            // Parse subject (CN)
            Pattern cnPattern = Pattern.compile("CN\\s*=\\s*([^,/\\n]+)");
            java.util.regex.Matcher cnMatcher = cnPattern.matcher(output);
            if (cnMatcher.find()) {
                info.commonName = cnMatcher.group(1).trim();
            }

            // Parse issuer: extract both the Organization (O=, the real name of the CA)
            // and the CN (the short code of the intermediate). Show both: "O (CN)".
            String issuerLine = "";
            Pattern issuerLinePattern = Pattern.compile("issuer\\s*=\\s*(.+)");
            java.util.regex.Matcher issuerLineMatcher = issuerLinePattern.matcher(output);
            if (issuerLineMatcher.find()) {
                issuerLine = issuerLineMatcher.group(1).trim();
            }
            String issuerOrg = null;
            java.util.regex.Matcher orgMatcher =
                Pattern.compile("\\bO\\s*=\\s*([^,/\\n]+)").matcher(issuerLine);
            if (orgMatcher.find()) issuerOrg = orgMatcher.group(1).trim();

            String issuerCn = null;
            java.util.regex.Matcher cnIssMatcher =
                Pattern.compile("\\bCN\\s*=\\s*([^,/\\n]+)").matcher(issuerLine);
            if (cnIssMatcher.find()) issuerCn = cnIssMatcher.group(1).trim();

            if (issuerOrg != null && issuerCn != null) {
                info.issuer = issuerOrg + " (" + issuerCn + ")";
            } else if (issuerOrg != null) {
                info.issuer = issuerOrg;
            } else if (issuerCn != null) {
                info.issuer = issuerCn;
            }
            // "Let's Encrypt" is recognized by the Organization, not by the code of the intermediate
            String issuerLc = (issuerOrg != null ? issuerOrg : "").toLowerCase();
            info.letsEncrypt = issuerLc.contains("let's encrypt") || issuerLc.contains("lets encrypt");

            // Parse dates
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss yyyy z", Locale.ENGLISH);
            DateTimeFormatter altFormatter = DateTimeFormatter.ofPattern("MMM  d HH:mm:ss yyyy z", Locale.ENGLISH);

            Pattern notBeforePattern = Pattern.compile("notBefore=(.+)");
            java.util.regex.Matcher notBeforeMatcher = notBeforePattern.matcher(output);
            if (notBeforeMatcher.find()) {
                String dateStr = notBeforeMatcher.group(1).trim();
                try {
                    info.issuedAt = LocalDateTime.parse(dateStr, formatter);
                } catch (Exception e) {
                    try {
                        info.issuedAt = LocalDateTime.parse(dateStr, altFormatter);
                    } catch (Exception e2) {
                        // ignore
                    }
                }
            }

            Pattern notAfterPattern = Pattern.compile("notAfter=(.+)");
            java.util.regex.Matcher notAfterMatcher = notAfterPattern.matcher(output);
            if (notAfterMatcher.find()) {
                String dateStr = notAfterMatcher.group(1).trim();
                try {
                    info.expiresAt = LocalDateTime.parse(dateStr, formatter);
                } catch (Exception e) {
                    try {
                        info.expiresAt = LocalDateTime.parse(dateStr, altFormatter);
                    } catch (Exception e2) {
                        // ignore
                    }
                }
            }

            // Calculate days until expiry
            if (info.expiresAt != null) {
                info.daysUntilExpiry = (int) ChronoUnit.DAYS.between(LocalDateTime.now(), info.expiresAt);
                info.expired = info.daysUntilExpiry < 0;
                info.expiringSoon = info.daysUntilExpiry <= getRenewalThresholdDays() && info.daysUntilExpiry >= 0;
            }

            // Get SANs (Subject Alternative Names)
            String sanOutput = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -text | grep -A1 'Subject Alternative Name'");
            if (sanOutput.contains("DNS:")) {
                info.subjectAltNames = new ArrayList<>();
                Pattern sanPattern = Pattern.compile("DNS:([^,\\s]+)");
                java.util.regex.Matcher sanMatcher = sanPattern.matcher(sanOutput);
                while (sanMatcher.find()) {
                    info.subjectAltNames.add(sanMatcher.group(1));
                }
            }

            // Get serial number
            String serialOutput = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -serial");
            Pattern serialPattern = Pattern.compile("serial=([A-F0-9]+)", Pattern.CASE_INSENSITIVE);
            java.util.regex.Matcher serialMatcher = serialPattern.matcher(serialOutput);
            if (serialMatcher.find()) {
                info.serial = serialMatcher.group(1);
            }

            // Get signature algorithm
            String algoOutput = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -text | grep 'Signature Algorithm' | head -1");
            Pattern algoPattern = Pattern.compile("Signature Algorithm:\\s*(.+)");
            java.util.regex.Matcher algoMatcher = algoPattern.matcher(algoOutput);
            if (algoMatcher.find()) {
                info.algorithm = algoMatcher.group(1).trim();
            }

            return info;

        } catch (Exception e) {
            System.err.println("Error reading certificate: " + e.getMessage());
            return null;
        }
    }

    /**
     * Save certificate info to database
     */
    private void saveCertificateInfo(String domain, String mailHostname) {
        try {
            database.setSetting("ssl_domain", domain);
            database.setSetting("ssl_hostname", mailHostname);
            database.setSetting("ssl_issued_at", LocalDateTime.now().toString());
            database.setSetting("ssl_type", "letsencrypt");
        } catch (Exception e) {
            System.err.println("Error saving certificate info: " + e.getMessage());
        }
    }

    // ============== DNS-01 Challenge Methods ==============

    /**
     * Generate DNS challenge for DNS-01 verification
     * Step 1: Generate the TXT record that needs to be added
     */
    public DnsChallengeResult generateDnsChallenge(String hostname) {
        return generateDnsChallenge(hostname, false);
    }

    public DnsChallengeResult generateDnsChallenge(String hostname, boolean forceRegenerate) {
        if (!isAcmeInstalled()) {
            return new DnsChallengeResult(false, I18n.tr("server.acme.notInstalled"), null, null);
        }

        // SECURITY: validate hostname before shell concatenation and Paths.get
        if (!InputValidator.isValidHostname(hostname)) {
            return new DnsChallengeResult(false, I18n.tr("server.acme.badHostname"), null, null);
        }

        try {
            // Check if a valid certificate already exists
            if (layout().certDir(hostname) != null && !forceRegenerate) {
                // Certificate exists - return special status so user can choose
                return new DnsChallengeResult(false, "CERT_EXISTS", null, null);
            }

            // Request certificate with DNS manual mode - this will output the TXT record needed
            String output = acme("--issue --server letsencrypt -d " + hostname
                    + " --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --force");

            // Parse the output to extract TXT record info
            // acme.sh outputs something like:
            // Add the following TXT record:
            // Domain: '_acme-challenge.mail.example.com'
            // TXT value: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxx'

            Pattern domainPattern = Pattern.compile("Domain:\\s*'([^']+)'");
            Pattern valuePattern = Pattern.compile("TXT value:\\s*'([^']+)'");

            java.util.regex.Matcher domainMatcher = domainPattern.matcher(output);
            java.util.regex.Matcher valueMatcher = valuePattern.matcher(output);

            if (domainMatcher.find() && valueMatcher.find()) {
                String txtDomain = domainMatcher.group(1);
                String txtValue = valueMatcher.group(1);

                // Save challenge info for verification step
                database.setSetting("dns_challenge_hostname", hostname);
                database.setSetting("dns_challenge_domain", txtDomain);
                database.setSetting("dns_challenge_value", txtValue);
                database.setSetting("dns_challenge_time", LocalDateTime.now().toString());

                return new DnsChallengeResult(true, I18n.tr("server.acme.txtGenerated"), txtDomain, txtValue);
            }

            // Check if certificate already exists
            if (output.contains("already verified") || output.contains("Cert success")) {
                return new DnsChallengeResult(false, I18n.tr("server.acme.alreadyExists"), null, null);
            }

            return new DnsChallengeResult(false, I18n.tr("server.acme.challengeFailed", java.util.Map.of("o", String.valueOf(output))), null, null);

        } catch (Exception e) {
            return new DnsChallengeResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null, null);
        }
    }

    /**
     * Verify DNS challenge and issue certificate
     * Step 2: After user adds TXT record, verify and complete issuance
     */
    public CertificateResult verifyDnsAndIssue(String hostname) {
        if (!isAcmeInstalled()) {
            return new CertificateResult(false, I18n.tr("server.acme.notInstalled"), null);
        }

        // SECURITY: validate hostname before shell concatenation and Paths.get
        if (!InputValidator.isValidHostname(hostname)) {
            return new CertificateResult(false, I18n.tr("server.acme.badHostname"), null);
        }

        try {
            // Get saved challenge info
            String savedHostname = database.getSetting("dns_challenge_hostname", null);
            String txtDomain = database.getSetting("dns_challenge_domain", null);
            String expectedValue = database.getSetting("dns_challenge_value", null);

            if (savedHostname == null || !savedHostname.equals(hostname)) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.noChallenge"), null);
            }

            // Verify TXT record exists using dig. The record name is not taken from MySQL (dns_challenge_domain):
            // with the separated panel, MySQL is also written by the web part, and the name ended up in a shell command
            // run by root. It is always _acme-challenge.<name> (RFC 8555, 8.4), and the name has already been checked
            // above; dig starts without a shell.
            String challengeName = "_acme-challenge." + hostname;
            if (txtDomain != null && !txtDomain.equalsIgnoreCase(challengeName))
                java.util.logging.Logger.getLogger(AcmeManager.class.getName()).warning("[ACME] the saved challenge record " + (SafeNames.domain(txtDomain.replace("_", "x")) ? txtDomain : "(invalid name)")
                        + " is not " + challengeName + ": checking " + challengeName);
            String digOutput = org.daemoxcp.mail.util.Shell.run(java.time.Duration.ofSeconds(30),
                    "dig", "+short", "TXT", challengeName, "@1.1.1.1").outputTrim();

            if (digOutput.isEmpty() || !digOutput.contains(expectedValue)) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.txtWrong", java.util.Map.of("expected", String.valueOf(expectedValue), "found", String.valueOf(digOutput.isEmpty() ? I18n.tr("server.acme.none") : digOutput))), null);
            }

            // TXT record verified, now complete the certificate issuance with --renew
            String output = acme("--renew -d " + hostname
                    + " --yes-I-know-dns-manual-mode-enough-go-ahead-please");

            // Check if certificate was issued (check both regular and ECC directories)
            if (layout().certDir(hostname) != null) {
                // Deploy certificate
                DeployResult deployResult = deployCertificate(hostname);

                // Clear challenge info
                database.deleteSetting("dns_challenge_hostname");
                database.deleteSetting("dns_challenge_domain");
                database.deleteSetting("dns_challenge_value");
                database.deleteSetting("dns_challenge_time");

                if (deployResult.success) {
                    // Extract domain from hostname (mail.example.com -> example.com)
                    String domain = hostname.replaceFirst("^[^.]+\\.", "");
                    saveCertificateInfo(domain, hostname);
                    return new CertificateResult(true, I18n.tr("server.acme.issuedDns01"),
                        output + "\n" + deployResult.output);
                } else {
                    return new CertificateResult(false, I18n.tr("server.acme.issuedDeployFailed", java.util.Map.of("m", String.valueOf(deployResult.message))), output);
                }
            }

            return new CertificateResult(false, I18n.tr("server.acme.verifiedNotIssued"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    // ============== Manual Certificate Methods ==============

    /**
     * Install a manually uploaded certificate
     */
    public CertificateResult installManualCertificate(String certContent, String keyContent, String hostname) {
        try {
            // Validate certificate and key
            if (certContent == null || certContent.trim().isEmpty()) {
                return new CertificateResult(false, I18n.tr("server.acme.emptyCert"), null);
            }
            if (keyContent == null || keyContent.trim().isEmpty()) {
                return new CertificateResult(false, I18n.tr("server.acme.emptyKey"), null);
            }
            // SECURITY: validate hostname (used to write to disk and for the nginx config)
            if (hostname != null && !hostname.isEmpty() && !InputValidator.isValidHostname(hostname)) {
                return new CertificateResult(false, I18n.tr("server.acme.badHostname"), null);
            }

            // Ensure content has proper PEM format
            if (!certContent.contains("-----BEGIN CERTIFICATE-----")) {
                return new CertificateResult(false, I18n.tr("server.acme.badCertFormat"), null);
            }
            if (!keyContent.contains("-----BEGIN") || !keyContent.contains("PRIVATE KEY")) {
                return new CertificateResult(false, I18n.tr("server.acme.badKeyFormat"), null);
            }

            // Create SSL directory
            Files.createDirectories(Paths.get(SSL_DIR));

            // Write certificate
            Files.writeString(Paths.get(CERT_FILE), certContent.trim() + "\n");
            Files.writeString(Paths.get(FULLCHAIN_FILE), certContent.trim() + "\n");

            // Write private key
            Files.writeString(Paths.get(KEY_FILE), keyContent.trim() + "\n");

            // Verify certificate and key match
            String verifyCert = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -modulus 2>&1 | openssl md5");
            String verifyKey = executeCommand("openssl rsa -in " + KEY_FILE + " -noout -modulus 2>&1 | openssl md5");

            if (!verifyCert.equals(verifyKey)) {
                // Rollback
                Files.deleteIfExists(Paths.get(CERT_FILE));
                Files.deleteIfExists(Paths.get(KEY_FILE));
                Files.deleteIfExists(Paths.get(FULLCHAIN_FILE));
                return new CertificateResult(false, I18n.tr("server.acme.certKeyMismatch"), null);
            }

            // Set permissions
            String permScript = """
                chmod 644 %s
                chmod 600 %s
                chmod 644 %s
                chown root:wheel %s/*
                """.formatted(CERT_FILE, KEY_FILE, FULLCHAIN_FILE, SSL_DIR);
            executeScript(permScript);

            // As in the Let's Encrypt deploy: no rewritten configurations, a checked reload and a live look.
            StringBuilder reloadLog = new StringBuilder();
            java.util.List<String> problems = reloadAndVerify(reloadLog);
            String reloadOutput = reloadLog.toString();
            if (!problems.isEmpty())
                return new CertificateResult(false, I18n.tr("server.acme.deployIncomplete",
                        java.util.Map.of("list", String.join(" ", problems))), reloadOutput);

            // Save info to database
            database.setSetting("ssl_type", "manual");
            database.setSetting("ssl_hostname", hostname != null ? hostname : "manual");
            database.setSetting("ssl_issued_at", LocalDateTime.now().toString());

            return new CertificateResult(true, I18n.tr("server.acme.manualInstalled"), reloadOutput);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AcmeManager", e))), null);
        }
    }

    /**
     * Check if current certificate is self-signed
     */
    public boolean isSelfSigned() {
        try {
            Path certPath = Paths.get(CERT_FILE);
            if (!Files.exists(certPath)) {
                return false;
            }

            String output = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -issuer -subject");

            // Self-signed if issuer == subject
            Pattern subjectPattern = Pattern.compile("subject.*?CN\\s*=\\s*([^,/\\n]+)");
            Pattern issuerPattern = Pattern.compile("issuer.*?CN\\s*=\\s*([^,/\\n]+)");

            java.util.regex.Matcher subjectMatcher = subjectPattern.matcher(output);
            java.util.regex.Matcher issuerMatcher = issuerPattern.matcher(output);

            if (subjectMatcher.find() && issuerMatcher.find()) {
                String subject = subjectMatcher.group(1).trim();
                String issuer = issuerMatcher.group(1).trim();
                return subject.equals(issuer);
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Generate script to install acme.sh
     */
    public String getInstallScript(String email) {
        return """
            #!/bin/sh
            # ACME.sh Installation Script for DaemoxCP Mail

            echo "=== Installing acme.sh for Let's Encrypt ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            # The package creates the user acme (home %s) and installs %s
            echo "[1/2] Installing acme.sh..."
            pkg install -y %s

            # The account with the CA, as acme: it never runs as root
            echo "[2/2] Registering the account..."
            mkdir -p %s && chown %s:%s %s
            su -m %s -c "%s --home %s --cert-home %s --register-account -m %s --server letsencrypt"

            echo ""
            echo "=== acme.sh Installation Complete ==="
            echo ""
            echo "You can now request certificates from the panel."
            echo ""
            """.formatted(AcmeUser.BASE, AcmeUser.SCRIPT, AcmeUser.PACKAGE,
                AcmeUser.WEBROOT, AcmeUser.USER, AcmeUser.USER, AcmeUser.WEBROOT,
                AcmeUser.USER, AcmeUser.SCRIPT, AcmeUser.HOME, AcmeUser.CERT_HOME, email);
    }

    // ============== Helper Methods ==============

    private String executeCommand(String command) throws Exception {
        return executeCommand(command, null);
    }

    /**
     * Runs a shell command, optionally with extra environment variables.
     * The env vars are passed via ProcessBuilder.environment() (NOT on the command line),
     * so secrets such as CF_Token do not end up in argv or in the process logs.
     */
    private String executeCommand(String command, Map<String, String> extraEnv) throws Exception {
        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        org.daemoxcp.mail.util.Shell.applyPath(pb);
        // rc.d does not pass HOME. Without it, acme.sh computes "$HOME/.acme.sh" = "/.acme.sh".
        pb.environment().putIfAbsent("HOME", "/root");
        pb.redirectErrorStream(true);
        if (extraEnv != null) {
            pb.environment().putAll(extraEnv);
        }
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        process.waitFor();
        return output.toString();
    }

    private String executeScript(String script) throws Exception {
        Path scriptPath = Files.createTempFile("acme_", ".sh");
        Files.writeString(scriptPath, script);
        scriptPath.toFile().setExecutable(true);

        try {
            return executeCommand(scriptPath.toString());
        } finally {
            Files.deleteIfExists(scriptPath);
        }
    }

    // ============== Result Classes ==============

    public static class InstallResult {
        public final boolean success;
        public final String message;
        public final String output;

        public InstallResult(boolean success, String message, String output) {
            this.success = success;
            this.message = message;
            this.output = output;
        }
    }

    public static class CertificateResult {
        public final boolean success;
        public final String message;
        public final String output;

        public CertificateResult(boolean success, String message, String output) {
            this.success = success;
            this.message = message;
            this.output = output;
        }
    }

    public static class DeployResult {
        public final boolean success;
        public final String message;
        public final String output;

        public DeployResult(boolean success, String message, String output) {
            this.success = success;
            this.message = message;
            this.output = output;
        }
    }

    public static class CertificateInfo {
        public boolean installed;
        public String certPath;
        public String keyPath;
        public String commonName;
        public String issuer;
        public boolean letsEncrypt;
        public LocalDateTime issuedAt;
        public LocalDateTime expiresAt;
        public int daysUntilExpiry;
        public boolean expired;
        public boolean expiringSoon;
        public List<String> subjectAltNames;
        public String algorithm;
        public String serial;
    }

    public static class DnsChallengeResult {
        public final boolean success;
        public final String message;
        public final String txtDomain;
        public final String txtValue;

        public DnsChallengeResult(boolean success, String message, String txtDomain, String txtValue) {
            this.success = success;
            this.message = message;
            this.txtDomain = txtDomain;
            this.txtValue = txtValue;
        }
    }
}
