package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

/**
 * ACME/Let's Encrypt Certificate Manager for FreeBSD Mail Panel
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

    // Paths - MUST match FullMailServerScript.java
    private static final String ACME_HOME = "/root/.acme.sh";
    private static final String ACME_SH = ACME_HOME + "/acme.sh";
    private static final String SSL_DIR = "/usr/local/etc/ssl/mail";
    private static final String CERT_FILE = SSL_DIR + "/fullchain.pem";
    private static final String KEY_FILE = SSL_DIR + "/privkey.pem";
    private static final String FULLCHAIN_FILE = SSL_DIR + "/fullchain.pem";
    private static final String CA_FILE = SSL_DIR + "/ca.pem";

    // Renewal threshold (days before expiry to renew)
    private static final int RENEWAL_THRESHOLD_DAYS = 30;

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
        scheduler.scheduleAtFixedRate(() -> {
            try {
                checkAndRenewCertificates();
            } catch (Exception e) {
                System.err.println("Auto-renewal check failed: " + e.getMessage());
            }
        }, 1, 24, TimeUnit.HOURS);

        System.out.println("ACME auto-renewal scheduler started (checks daily)");
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
        return Files.exists(Paths.get(ACME_SH));
    }

    /**
     * Install acme.sh
     */
    public InstallResult installAcme(String email) {
        try {
            // Download and install acme.sh
            String installScript = """
                #!/bin/sh
                set -e

                # Install dependencies
                pkg install -y curl socat

                # Download acme.sh
                cd /root
                curl -s https://get.acme.sh | sh -s email=%s

                # Set default CA to Let's Encrypt
                %s/acme.sh --set-default-ca --server letsencrypt

                echo "acme.sh installed successfully"
                """.formatted(email, ACME_HOME);

            String output = executeScript(installScript);

            if (isAcmeInstalled()) {
                // Save email to database
                database.setSetting("acme_email", email);
                return new InstallResult(true, "acme.sh installato con successo", output);
            } else {
                return new InstallResult(false, "Installazione fallita", output);
            }

        } catch (Exception e) {
            return new InstallResult(false, "Errore: " + e.getMessage(), null);
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
            return new CertificateResult(false, "acme.sh non installato", null);
        }

        try {
            // Build domains list (mail hostname + autodiscover subdomains)
            List<String> domains = new ArrayList<>();
            domains.add(mailHostname);
            domains.add("autoconfig." + domain);
            domains.add("autodiscover." + domain);

            // Build acme.sh command
            StringBuilder cmd = new StringBuilder();
            cmd.append(ACME_SH).append(" --issue");

            // Add all domains
            for (String d : domains) {
                cmd.append(" -d ").append(d);
            }

            // Challenge type
            if ("dns".equals(challengeType)) {
                cmd.append(" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please");
            } else {
                // HTTP challenge
                if (webroot != null && !webroot.isEmpty()) {
                    cmd.append(" -w ").append(webroot);
                } else {
                    // Standalone mode (requires port 80 to be free)
                    cmd.append(" --standalone");
                }
            }

            // Force issue even if cert exists
            cmd.append(" --force");

            String output = executeCommand(cmd.toString());

            // Check if certificate was issued (check both regular and ECC directories)
            Path certPath = Paths.get(ACME_HOME, mailHostname, mailHostname + ".cer");
            Path certPathEcc = Paths.get(ACME_HOME, mailHostname + "_ecc", mailHostname + ".cer");
            if (Files.exists(certPath) || Files.exists(certPathEcc)) {
                // Deploy certificate
                DeployResult deployResult = deployCertificate(mailHostname);
                if (deployResult.success) {
                    // Save to database
                    saveCertificateInfo(domain, mailHostname);
                    return new CertificateResult(true, "Certificato emesso e installato", output + "\n" + deployResult.output);
                } else {
                    return new CertificateResult(false, "Certificato emesso ma deploy fallito: " + deployResult.message, output);
                }
            }

            // Check for DNS challenge instructions
            if ("dns".equals(challengeType) && output.contains("TXT value")) {
                return new CertificateResult(false,
                    "DNS challenge richiesto. Aggiungi il record TXT indicato e riprova.",
                    output);
            }

            return new CertificateResult(false, "Emissione certificato fallita", output);

        } catch (Exception e) {
            return new CertificateResult(false, "Errore: " + e.getMessage(), null);
        }
    }

    /**
     * Deploy certificate to mail services
     */
    public DeployResult deployCertificate(String mailHostname) {
        try {
            // Create SSL directory
            Files.createDirectories(Paths.get(SSL_DIR));

            // Source paths (acme.sh storage) - check both regular and ECC directories
            String certDir = mailHostname;
            Path eccDir = Paths.get(ACME_HOME, mailHostname + "_ecc");
            Path regularDir = Paths.get(ACME_HOME, mailHostname);

            // Prefer ECC certificates if available (acme.sh default)
            if (Files.exists(eccDir) && Files.exists(eccDir.resolve(mailHostname + ".cer"))) {
                certDir = mailHostname + "_ecc";
            } else if (!Files.exists(regularDir) || !Files.exists(regularDir.resolve(mailHostname + ".cer"))) {
                return new DeployResult(false, "File certificato non trovati in " + ACME_HOME, null);
            }

            Path acmeCert = Paths.get(ACME_HOME, certDir, mailHostname + ".cer");
            Path acmeKey = Paths.get(ACME_HOME, certDir, mailHostname + ".key");
            Path acmeFullchain = Paths.get(ACME_HOME, certDir, "fullchain.cer");
            Path acmeCa = Paths.get(ACME_HOME, certDir, "ca.cer");

            // Check source files exist
            if (!Files.exists(acmeCert) || !Files.exists(acmeKey)) {
                return new DeployResult(false, "File certificato non trovati in " + ACME_HOME + "/" + certDir, null);
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

            // Set permissions
            String permScript = """
                chmod 644 %s
                chmod 600 %s
                chmod 644 %s 2>/dev/null || true
                chmod 644 %s 2>/dev/null || true
                chown root:wheel %s/*
                """.formatted(CERT_FILE, KEY_FILE, FULLCHAIN_FILE, CA_FILE, SSL_DIR);

            executeScript(permScript);

            // Update Dovecot configuration
            updateDovecotSsl();

            // Update Postfix configuration
            updatePostfixSsl();

            // Reload services
            String reloadOutput = executeScript("""
                service dovecot reload 2>/dev/null || echo "Dovecot not running"
                service postfix reload 2>/dev/null || echo "Postfix not running"
                service nginx reload 2>/dev/null || echo "Nginx not running"
                echo "Services reloaded"
                """);

            return new DeployResult(true, "Certificato deployato con successo", reloadOutput);

        } catch (Exception e) {
            return new DeployResult(false, "Errore deploy: " + e.getMessage(), null);
        }
    }

    /**
     * Update Dovecot SSL configuration
     */
    private void updateDovecotSsl() throws IOException {
        String dovecotSslConf = """
            # SSL Configuration - Managed by Mail Panel
            ssl = required
            ssl_cert = <%s
            ssl_key = <%s
            ssl_min_protocol = TLSv1.2
            ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
            ssl_prefer_server_ciphers = yes
            """.formatted(FULLCHAIN_FILE, KEY_FILE);

        Path sslConf = Paths.get("/usr/local/etc/dovecot/conf.d/10-ssl.conf");
        Files.createDirectories(sslConf.getParent());
        Files.writeString(sslConf, dovecotSslConf);
    }

    /**
     * Update Postfix SSL configuration
     */
    private void updatePostfixSsl() throws IOException {
        // Read current config
        Path postfixConf = Paths.get("/usr/local/etc/postfix/main.cf");
        if (!Files.exists(postfixConf)) {
            return;
        }

        String config = Files.readString(postfixConf);

        // Update TLS settings in main.cf
        // Replace or add smtpd_tls_cert_file and smtpd_tls_key_file
        if (config.contains("smtpd_tls_cert_file")) {
            config = config.replaceAll("smtpd_tls_cert_file\\s*=.*", "smtpd_tls_cert_file = " + FULLCHAIN_FILE);
        } else {
            config += "\nsmtpd_tls_cert_file = " + FULLCHAIN_FILE;
        }

        if (config.contains("smtpd_tls_key_file")) {
            config = config.replaceAll("smtpd_tls_key_file\\s*=.*", "smtpd_tls_key_file = " + KEY_FILE);
        } else {
            config += "\nsmtpd_tls_key_file = " + KEY_FILE;
        }

        // Ensure TLS is enabled
        if (!config.contains("smtpd_use_tls")) {
            config += "\nsmtpd_use_tls = yes";
        } else {
            config = config.replaceAll("smtpd_use_tls\\s*=.*", "smtpd_use_tls = yes");
        }

        Files.writeString(postfixConf, config);
    }

    /**
     * Renew certificate
     */
    public CertificateResult renewCertificate(String mailHostname) {
        if (!isAcmeInstalled()) {
            return new CertificateResult(false, "acme.sh non installato", null);
        }

        try {
            String cmd = ACME_SH + " --renew -d " + mailHostname + " --force";
            String output = executeCommand(cmd);

            // Check success
            if (output.contains("Cert success") || output.contains("Skip")) {
                // Redeploy
                DeployResult deployResult = deployCertificate(mailHostname);
                return new CertificateResult(deployResult.success,
                    deployResult.success ? "Certificato rinnovato" : "Rinnovo OK ma deploy fallito",
                    output + "\n" + (deployResult.output != null ? deployResult.output : ""));
            }

            return new CertificateResult(false, "Rinnovo fallito", output);

        } catch (Exception e) {
            return new CertificateResult(false, "Errore: " + e.getMessage(), null);
        }
    }

    /**
     * Check and renew certificates that are about to expire
     */
    public void checkAndRenewCertificates() {
        try {
            CertificateInfo info = getCertificateInfo();
            if (info == null || info.expiresAt == null) {
                return;
            }

            long daysUntilExpiry = ChronoUnit.DAYS.between(LocalDateTime.now(), info.expiresAt);
            if (daysUntilExpiry <= RENEWAL_THRESHOLD_DAYS) {
                System.out.println("Certificate expires in " + daysUntilExpiry + " days, renewing...");
                CertificateResult result = renewCertificate(info.commonName);
                System.out.println("Renewal result: " + result.message);
            }

        } catch (Exception e) {
            System.err.println("Certificate check failed: " + e.getMessage());
        }
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

            // Parse issuer
            Pattern issuerPattern = Pattern.compile("issuer.*?CN\\s*=\\s*([^,/\\n]+)");
            java.util.regex.Matcher issuerMatcher = issuerPattern.matcher(output);
            if (issuerMatcher.find()) {
                info.issuer = issuerMatcher.group(1).trim();
                info.letsEncrypt = info.issuer.toLowerCase().contains("let's encrypt") ||
                                   info.issuer.toLowerCase().contains("r3") ||
                                   info.issuer.toLowerCase().contains("e1");
            }

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
                info.expiringSoon = info.daysUntilExpiry <= RENEWAL_THRESHOLD_DAYS && info.daysUntilExpiry >= 0;
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
            return new DnsChallengeResult(false, "acme.sh non installato", null, null);
        }

        try {
            // Check if a valid certificate already exists
            Path certPathEcc = Paths.get(ACME_HOME, hostname + "_ecc", hostname + ".cer");
            Path certPath = Paths.get(ACME_HOME, hostname, hostname + ".cer");
            if ((Files.exists(certPathEcc) || Files.exists(certPath)) && !forceRegenerate) {
                // Certificate exists - return special status so user can choose
                return new DnsChallengeResult(false, "CERT_EXISTS", null, null);
            }

            // Request certificate with DNS manual mode - this will output the TXT record needed
            String cmd = ACME_SH + " --issue -d " + hostname +
                         " --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --force 2>&1";
            String output = executeCommand(cmd);

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

                return new DnsChallengeResult(true, "Record TXT generato", txtDomain, txtValue);
            }

            // Check if certificate already exists
            if (output.contains("already verified") || output.contains("Cert success")) {
                return new DnsChallengeResult(false, "Certificato già esistente, usa rinnovo", null, null);
            }

            return new DnsChallengeResult(false, "Impossibile generare challenge DNS. Output: " + output, null, null);

        } catch (Exception e) {
            return new DnsChallengeResult(false, "Errore: " + e.getMessage(), null, null);
        }
    }

    /**
     * Verify DNS challenge and issue certificate
     * Step 2: After user adds TXT record, verify and complete issuance
     */
    public CertificateResult verifyDnsAndIssue(String hostname) {
        if (!isAcmeInstalled()) {
            return new CertificateResult(false, "acme.sh non installato", null);
        }

        try {
            // Get saved challenge info
            String savedHostname = database.getSetting("dns_challenge_hostname", null);
            String txtDomain = database.getSetting("dns_challenge_domain", null);
            String expectedValue = database.getSetting("dns_challenge_value", null);

            if (savedHostname == null || !savedHostname.equals(hostname)) {
                return new CertificateResult(false,
                    "Nessun challenge DNS trovato per questo hostname. Genera prima il challenge.", null);
            }

            // Verify TXT record exists using dig
            String verifyCmd = "dig +short TXT " + txtDomain + " @1.1.1.1";
            String digOutput = executeCommand(verifyCmd).trim();

            if (digOutput.isEmpty() || !digOutput.contains(expectedValue)) {
                return new CertificateResult(false,
                    "Record TXT non trovato o valore errato.\n" +
                    "Atteso: " + expectedValue + "\n" +
                    "Trovato: " + (digOutput.isEmpty() ? "(nessuno)" : digOutput) + "\n" +
                    "Attendi qualche minuto per la propagazione DNS e riprova.", null);
            }

            // TXT record verified, now complete the certificate issuance with --renew
            String cmd = ACME_SH + " --renew -d " + hostname +
                         " --yes-I-know-dns-manual-mode-enough-go-ahead-please 2>&1";
            String output = executeCommand(cmd);

            // Check if certificate was issued (check both regular and ECC directories)
            Path certPath = Paths.get(ACME_HOME, hostname, hostname + ".cer");
            Path certPathEcc = Paths.get(ACME_HOME, hostname + "_ecc", hostname + ".cer");
            if (Files.exists(certPath) || Files.exists(certPathEcc)) {
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
                    return new CertificateResult(true, "Certificato emesso e installato via DNS-01",
                        output + "\n" + deployResult.output);
                } else {
                    return new CertificateResult(false, "Certificato emesso ma deploy fallito: " + deployResult.message, output);
                }
            }

            return new CertificateResult(false, "Verifica completata ma emissione fallita", output);

        } catch (Exception e) {
            return new CertificateResult(false, "Errore: " + e.getMessage(), null);
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
                return new CertificateResult(false, "Contenuto certificato vuoto", null);
            }
            if (keyContent == null || keyContent.trim().isEmpty()) {
                return new CertificateResult(false, "Contenuto chiave privata vuoto", null);
            }

            // Ensure content has proper PEM format
            if (!certContent.contains("-----BEGIN CERTIFICATE-----")) {
                return new CertificateResult(false, "Formato certificato non valido (deve essere PEM)", null);
            }
            if (!keyContent.contains("-----BEGIN") || !keyContent.contains("PRIVATE KEY")) {
                return new CertificateResult(false, "Formato chiave non valido (deve essere PEM)", null);
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
                return new CertificateResult(false, "Certificato e chiave non corrispondono", null);
            }

            // Set permissions
            String permScript = """
                chmod 644 %s
                chmod 600 %s
                chmod 644 %s
                chown root:wheel %s/*
                """.formatted(CERT_FILE, KEY_FILE, FULLCHAIN_FILE, SSL_DIR);
            executeScript(permScript);

            // Update Dovecot configuration
            updateDovecotSsl();

            // Update Postfix configuration
            updatePostfixSsl();

            // Reload services
            String reloadOutput = executeScript("""
                service dovecot reload 2>/dev/null || echo "Dovecot not running"
                service postfix reload 2>/dev/null || echo "Postfix not running"
                service nginx reload 2>/dev/null || echo "Nginx not running"
                echo "Services reloaded"
                """);

            // Save info to database
            database.setSetting("ssl_type", "manual");
            database.setSetting("ssl_hostname", hostname != null ? hostname : "manual");
            database.setSetting("ssl_issued_at", LocalDateTime.now().toString());

            return new CertificateResult(true, "Certificato manuale installato con successo", reloadOutput);

        } catch (Exception e) {
            return new CertificateResult(false, "Errore: " + e.getMessage(), null);
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
            # ACME.sh Installation Script for FreeBSD Mail Panel

            echo "=== Installing acme.sh for Let's Encrypt ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            # Install dependencies
            echo "[1/3] Installing dependencies..."
            pkg install -y curl socat

            # Download and install acme.sh
            echo "[2/3] Installing acme.sh..."
            cd /root
            curl https://get.acme.sh | sh -s email=%s

            # Configure
            echo "[3/3] Configuring..."
            . ~/.acme.sh/acme.sh.env
            acme.sh --set-default-ca --server letsencrypt

            echo ""
            echo "=== acme.sh Installation Complete ==="
            echo ""
            echo "You can now request certificates from the panel."
            echo ""
            """.formatted(email);
    }

    // ============== Helper Methods ==============

    private String executeCommand(String command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
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
