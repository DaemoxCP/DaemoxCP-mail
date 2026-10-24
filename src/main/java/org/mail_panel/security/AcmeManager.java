package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;
import org.mail_panel.i18n.I18n;

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
    /**
     * acme.sh sceglie la propria cartella di lavoro cosi' (sorgente ufficiale, riga 11 e 3145):
     *     DEFAULT_INSTALL_HOME="$HOME/.$PROJECT_NAME"
     *     if [ -z "$LE_WORKING_DIR" ]; then LE_WORKING_DIR="$DEFAULT_INSTALL_HOME"; fi
     * Il pannello viene avviato da rc.d, che NON passa HOME. Con HOME vuoto quella
     * espressione diventa "/.acme.sh": acme.sh emetteva davvero il certificato, ma nella
     * radice del disco, mentre noi copiavamo da /root/.acme.sh — cioe' il file vecchio.
     * "--home" (riga 8436 del sorgente) e' il rimedio documentato, ed e' lo stesso flag
     * che acme.sh scrive nel proprio cron: non si fida dell'ambiente nemmeno lui.
     */
    private static final String ACME_CMD = ACME_SH + " --home " + ACME_HOME;
    private static final String SSL_DIR = "/usr/local/etc/ssl/mail";
    private static final String CERT_FILE = SSL_DIR + "/fullchain.pem";
    private static final String KEY_FILE = SSL_DIR + "/privkey.pem";
    private static final String FULLCHAIN_FILE = SSL_DIR + "/fullchain.pem";
    private static final String CA_FILE = SSL_DIR + "/ca.pem";

    // Renewal threshold (days before expiry to renew) — default; può essere overridden da DB setting
    private static final int RENEWAL_THRESHOLD_DAYS_DEFAULT = 30;

    // DB settings keys
    public static final String SETTING_AUTO_RENEW_ENABLED   = "acme_auto_renewal_enabled";
    public static final String SETTING_AUTO_RENEW_THRESHOLD = "acme_renewal_threshold_days";
    public static final String SETTING_AUTO_RENEW_LAST_CHECK    = "acme_auto_renewal_last_check";
    public static final String SETTING_AUTO_RENEW_LAST_RESULT   = "acme_auto_renewal_last_result";
    public static final String SETTING_AUTO_RENEW_LAST_RENEWAL  = "acme_auto_renewal_last_renewal";
    // Account Cloudflare scelto per il certificato del SERVER MAIL (Mail Hostname),
    // il cui dominio base può non essere tra i domini mail gestiti.
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
                export HOME=/root
                curl -s https://get.acme.sh | sh -s email=%s

                # Set default CA to Let's Encrypt
                %s/acme.sh --set-default-ca --server letsencrypt

                echo "acme.sh installed successfully"
                """.formatted(email, ACME_HOME);

            String output = executeScript(installScript);

            if (isAcmeInstalled()) {
                // Save email to database
                database.setSetting("acme_email", email);
                return new InstallResult(true, I18n.tr("server.acme.installed"), output);
            } else {
                return new InstallResult(false, I18n.tr("server.acme.installFailed"), output);
            }

        } catch (Exception e) {
            return new InstallResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
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

        // SECURITY: validate hostname/domain prima di metterli in shell command
        if (!InputValidator.isValidHostname(mailHostname) || !InputValidator.isValidDomain(domain)) {
            return new CertificateResult(false, I18n.tr("server.acme.badHostOrDomain"), null);
        }
        if (webroot != null && !webroot.isEmpty() && (webroot.contains("..") || webroot.contains(";") || webroot.contains("|") || webroot.contains("&") || webroot.contains("`") || webroot.contains("$"))) {
            return new CertificateResult(false, I18n.tr("server.acme.badWebroot"), null);
        }

        try {
            // I nomi da mettere nel certificato: l'hostname del server e autoconfig.
            //
            // "autodiscover" e' stato tolto insieme al resto: serviva solo a Outlook. Non e'
            // pulizia estetica — acme.sh VALIDA ogni nome che gli si chiede, quindi lasciarlo
            // qui dopo aver smesso di proporne il record significherebbe, su un dominio nuovo,
            // far fallire l'emissione dell'INTERO certificato per un nome che non esiste e
            // che nessuno usa. Un certificato che non si emette ferma la posta.
            List<String> domains = new ArrayList<>();
            domains.add(mailHostname);
            domains.add("autoconfig." + domain);
            // MTA-STS: e' proprio questo certificato a dimostrare che la politica viene dal
            // proprietario del dominio, perche' il protocollo non usa DNSSEC. Senza il nome
            // qui dentro, i server mittenti ignorano la politica.
            domains.add("mta-sts." + domain);

            // Build acme.sh command
            StringBuilder cmd = new StringBuilder();
            // Vedi la nota in emitWithNames: la CA si dichiara a ogni comando.
            cmd.append(ACME_CMD).append(" --issue --server letsencrypt");

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
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
        }
    }

    /**
     * Deploy certificate to mail services
     */
    /**
     * Certificato e chiave installati sono la stessa coppia.
     *
     * Si confrontano le chiavi PUBBLICHE, non i moduli: "openssl rsa" non funziona su una
     * chiave ellittica, e acme.sh emette certificati ECC per impostazione predefinita.
     * Con "openssl pkey -pubout" il confronto vale per entrambi i tipi.
     */
    /** Il certificato che i servizi stanno usando contiene quel nome fra i suoi SAN. */
    private boolean installedCertificateCovers(String name) {
        for (String n : installedCertificateNames())
            if (n.equalsIgnoreCase(name)) return true;
        return false;
    }

    private static boolean nameCharacter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9') || c == '.' || c == '-';
    }

    /** Solo lettere, cifre, punti e trattini: quello che un nome DNS puo' contenere. */
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
        // Dividere il testo per virgole non funziona: con "openssl -text" l'ULTIMO nome non
        // e' seguito da una virgola, quindi il suo pezzo si allunga fino alla virgola
        // successiva — molto piu' avanti, dentro un'altra estensione — e il nome sparisce.
        // Con "-ext" invece l'intestazione sta attaccata al PRIMO nome. Quindi non divido:
        // cerco ogni "DNS:", leggo i caratteri ammessi che seguono e pretendo che finiscano
        // su virgola o fine riga. Cosi' i due formati danno lo stesso risultato, e nessun
        // carattere diverso da quelli di un nome DNS puo' finire nella riga di comando.
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
     * I nomi che il certificato ATTUALMENTE in uso copre.
     * Serve al rinnovo: "--issue --force" con un solo "-d" ridefinisce l'insieme dei nomi,
     * quindi rinnovare senza rileggerli farebbe sparire i mta-sts.* e autoconfig.* —
     * con i record MTA-STS gia' pubblicati, la posta verrebbe rifiutata.
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
            String daCert = executeCommand("openssl x509 -in " + CERT_FILE + " -noout -pubkey 2>/dev/null");
            String fromKey = executeCommand("openssl pkey -in " + KEY_FILE + " -pubout 2>/dev/null");
            if (daCert == null || fromKey == null) return false;
            String a = daCert.replaceAll("\\s+", ""), b = fromKey.replaceAll("\\s+", "");
            return !a.isEmpty() && a.equals(b);
        } catch (Exception e) {
            // Non essere riusciti a verificare non e' una promozione: si torna indietro.
            return false;
        }
    }

    public DeployResult deployCertificate(String mailHostname) {
        return deployCertificate(mailHostname, null);
    }

    /**
     * Estrae dall'uscita di acme.sh la cartella in cui ha DAVVERO scritto.
     * acme.sh la dichiara sempre: "Your cert is in: /percorso/host.cer".
     * Leggerla invece di ricostruirla e' l'unico modo per non ricopiare un file
     * vecchio quando acme.sh ha lavorato altrove: era esattamente il caso in cui
     * HOME mancava e la cartella diventava "/.acme.sh".
     */
    static Path declaredFolder(String acmeOutput) {
        if (acmeOutput == null) return null;
        for (String line : acmeOutput.split("\n")) {
            int i = line.indexOf("Your cert is in:");
            if (i < 0) continue;
            String path = line.substring(i + "Your cert is in:".length()).trim();
            if (path.isEmpty()) continue;
            // acme.sh puo' stampare "//.acme.sh/..." quando HOME e' vuoto: normalizzo
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

            // La cartella che acme.sh ha DICHIARATO batte qualunque ricostruzione nostra.
            Path source = declaredFolder(acmeOutput);
            if (source != null && !Files.exists(source.resolve(mailHostname + ".cer"))) source = null;

            if (source == null) {
                // Source paths (acme.sh storage) - check both regular and ECC directories
                Path eccDir = Paths.get(ACME_HOME, mailHostname + "_ecc");
                Path regularDir = Paths.get(ACME_HOME, mailHostname);

                // Prefer ECC certificates if available (acme.sh default)
                if (Files.exists(eccDir) && Files.exists(eccDir.resolve(mailHostname + ".cer"))) {
                    source = eccDir;
                } else if (Files.exists(regularDir) && Files.exists(regularDir.resolve(mailHostname + ".cer"))) {
                    source = regularDir;
                } else {
                    return new DeployResult(false, I18n.tr("server.acme.filesNotFound", java.util.Map.of("d", String.valueOf(ACME_HOME))), null);
                }
            }

            Path acmeCert = source.resolve(mailHostname + ".cer");
            Path acmeKey = source.resolve(mailHostname + ".key");
            Path acmeFullchain = source.resolve("fullchain.cer");
            Path acmeCa = source.resolve("ca.cer");

            // Check source files exist
            if (!Files.exists(acmeCert) || !Files.exists(acmeKey)) {
                return new DeployResult(false, I18n.tr("server.acme.filesNotFound", java.util.Map.of("d", String.valueOf(source))), null);
            }

            // COPIA DI SICUREZZA prima di sovrascrivere.
            //
            // Qui si sostituisce il certificato con cui rispondono dovecot, postfix e nginx:
            // se il nuovo fosse difettoso, il vecchio — che funzionava — non esisterebbe piu',
            // e i tre servizi verrebbero ricaricati con un certificato rotto. Un'operazione
            // irreversibile su qualcosa che funziona non si fa senza una via di ritorno.
            java.util.Map<String, String> saved = new java.util.HashMap<>();
            try {
                Path copyDir = Paths.get("/var/db/mailpanel/ssl-previous");
                Files.createDirectories(copyDir);
                for (String f : new String[] { CERT_FILE, KEY_FILE, FULLCHAIN_FILE, CA_FILE }) {
                    Path orig = Paths.get(f);
                    if (!Files.exists(orig)) continue;
                    Path dest = copyDir.resolve(orig.getFileName().toString());
                    Files.copy(orig, dest, StandardCopyOption.REPLACE_EXISTING);
                    saved.put(f, dest.toString());
                }
            } catch (Exception e) {
                return new DeployResult(false, I18n.tr("server.acme.noBackup", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
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

            // La chiave corrisponde al certificato?
            //
            // Si confrontano le due chiavi PUBBLICHE: quella dentro il certificato e quella
            // ricavata dalla chiave privata. Se non coincidono, i servizi ripartono con una
            // coppia incoerente e ogni connessione TLS fallisce: la posta si ferma del tutto.
            // Meglio accorgersene qui, con la copia ancora a portata di mano.
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

            return new DeployResult(true, I18n.tr("server.acme.deployed"), reloadOutput);

        } catch (Exception e) {
            return new DeployResult(false, I18n.tr("server.acme.deployError", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
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

        // Ensure TLS is enabled (use smtpd_tls_security_level instead of deprecated smtpd_use_tls)
        if (!config.contains("smtpd_tls_security_level")) {
            config += "\nsmtpd_tls_security_level = may";
        } else {
            config = config.replaceAll("smtpd_tls_security_level\\s*=\\s*none", "smtpd_tls_security_level = may");
        }
        // Remove deprecated smtpd_use_tls if present
        config = config.replaceAll("(?m)^smtpd_use_tls\\s*=.*\\n?", "");

        Files.writeString(postfixConf, config);
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

        // Se il dominio ha un account Cloudflare collegato, rinnova in modo
        // completamente automatico via API Cloudflare (acme.sh dns_cf).
        // Questo è l'unico modo per auto-rinnovare i certificati emessi in
        // modalità DNS manuale, che acme.sh NON può rinnovare da solo.
        MailDatabase.CloudflareAccount cf = cloudflareAccountForHostname(mailHostname);
        if (cf != null && cf.apiToken != null && !cf.apiToken.isBlank()) {
            return renewViaCloudflare(mailHostname, cf);
        }

        return renewStandard(mailHostname);
    }

    /**
     * Rinnovo "standard": funziona per i certificati HTTP-01 e per quelli già
     * configurati con un provider DNS API. I certificati in modalità DNS manuale
     * NON sono rinnovabili automaticamente da acme.sh: in quel caso restituiamo
     * un messaggio esplicito invece del generico "Rinnovo fallito".
     */
    private CertificateResult renewStandard(String mailHostname) {
        try {
            String cmd = ACME_CMD + " --renew -d " + mailHostname + " --force 2>&1";
            String output = executeCommand(cmd);

            // Check success
            if (output.contains("Cert success") || output.contains("Skip")) {
                // Redeploy
                DeployResult deployResult = deployCertificate(mailHostname);
                return new CertificateResult(deployResult.success,
                    deployResult.success ? I18n.tr("server.acme.renewed") : I18n.tr("server.acme.renewedDeployFailed"),
                    output + "\n" + (deployResult.output != null ? deployResult.output : ""));
            }

            // acme.sh non può rinnovare automaticamente i certificati DNS-manuali
            if (output.contains("manual mode") || output.contains("can not be renewed")
                    || output.contains("cannot be renewed")) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.manualDns"),
                    output);
            }

            return new CertificateResult(false, I18n.tr("server.acme.renewFailed"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
        }
    }

    /**
     * Rinnovo via API Cloudflare (acme.sh --dns dns_cf). Ri-emette il certificato
     * usando il token CF dell'account collegato al dominio; questo migra anche un
     * certificato DNS-manuale a rinnovo automatico per le volte successive.
     * Il token viene passato come variabile d'ambiente, mai sulla command line.
     */
    /**
     * Emette il certificato per l'hostname PIU' i nomi indicati, via API Cloudflare.
     *
     * Serve perche' MTA-STS e la configurazione automatica dei client vivono su nomi
     * dedicati — mta-sts.<dominio> e autoconfig.<dominio> — e il certificato deve coprirli:
     * senza, il client o il server mittente si ferma all'errore TLS e non legge niente.
     *
     * Un limite da conoscere: acme.sh valida tutti i nomi con UN SOLO token Cloudflare.
     * I domini che stanno su un altro account non si possono includere qui, e chi chiama
     * deve escluderli prima invece di far fallire l'intera emissione per colpa di uno.
     */
    public CertificateResult emitWithNames(String mailHostname, java.util.List<String> extraNames) {
        MailDatabase.CloudflareAccount cf = cloudflareAccountForHostname(mailHostname);
        if (cf == null)
            return new CertificateResult(false,
                I18n.tr("server.acme.noCfForHost", java.util.Map.of("h", String.valueOf(mailHostname))), null);
        if (!InputValidator.isValidHostname(mailHostname))
            return new CertificateResult(false, I18n.tr("server.acme.badHostnameNamed", java.util.Map.of("h", String.valueOf(mailHostname))), null);

        // --server letsencrypt su OGNI comando, non una volta sola in fase di installazione.
        // La documentazione di acme.sh dice: "For now, the default CA is zerossl. If you want
        // to use another CA, you need to specify --server for each command." Il default lo
        // impostava lo script di installazione, ma un aggiornamento di acme.sh lo riporta a
        // ZeroSSL — che pretende una registrazione con email e fa fallire l'emissione con un
        // messaggio che non c'entra niente con il certificato. Un default impostato altrove
        // e' una dipendenza nascosta: meglio dirlo ogni volta.
        StringBuilder cmd = new StringBuilder(ACME_CMD + " --issue --server letsencrypt --dns dns_cf -d " + mailHostname);
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        seen.add(mailHostname.toLowerCase(java.util.Locale.ROOT));
        if (extraNames != null) for (String n : extraNames) {
            if (n == null) continue;
            String x = n.trim().toLowerCase(java.util.Locale.ROOT);
            // Ogni nome finisce in una riga di comando: si controlla, non si spera.
            if (x.isEmpty() || !InputValidator.isValidHostname(x) || !seen.add(x)) continue;
            cmd.append(" -d ").append(x);
        }
        cmd.append(" --force 2>&1");

        try {
            Map<String, String> env = new HashMap<>();
            env.put("CF_Token", cf.apiToken);
            String output = sanitize(executeCommand(cmd.toString(), env), cf.apiToken);
            // "Skipping. Next renewal time" NON e' un successo quando si chiedono nomi nuovi:
            // vuol dire che acme.sh ha lasciato il certificato com'era. Contarlo come riuscito
            // faceva installare quello vecchio e dichiarare "emesso con 11 nomi" una cosa che
            // di nomi ne aveva gli stessi di prima.
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

            // LA verifica che conta: il certificato INSTALLATO contiene davvero i nomi chiesti?
            // Che acme.sh non abbia protestato non basta — puo' aver scritto in una cartella
            // diversa da quella da cui il deploy copia, e l'esito sarebbe "riuscito" con il
            // vecchio certificato ancora al suo posto.
            java.util.List<String> missing = new java.util.ArrayList<>();
            for (String n : seen) if (!installedCertificateCovers(n)) missing.add(n);
            if (!missing.isEmpty())
                return new CertificateResult(false,
                        I18n.tr("server.acme.namesMissing", java.util.Map.of("n", String.valueOf(missing.size()), "elenco", String.valueOf(String.join(", ", missing)))),
                        output + "\n" + (dep.output != null ? dep.output : ""));

            return new CertificateResult(true, I18n.tr("server.acme.issuedWithNames", java.util.Map.of("n", String.valueOf(seen.size()))),
                    output + "\n" + (dep.output != null ? dep.output : ""));
        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
        }
    }

    /** L'account Cloudflare collegato a un dominio, per sapere se condivide quello del certificato. */
    public MailDatabase.CloudflareAccount accountDi(int domainId) {
        try {
            return database.getCloudflareAccountForDomain(domainId);
        } catch (Exception e) {
            return null;
        }
    }

    /** L'account usato per il certificato dell'hostname. */
    public MailDatabase.CloudflareAccount certificateAccount(String mailHostname) {
        return cloudflareAccountForHostname(mailHostname);
    }

    private CertificateResult renewViaCloudflare(String mailHostname, MailDatabase.CloudflareAccount cf) {
        try {
            Map<String, String> env = new HashMap<>();
            // Token "scoped" Cloudflare: richiede permessi Zone:DNS:Edit + Zone:Read
            env.put("CF_Token", cf.apiToken);

            // "--issue --force" RIDEFINISCE l'insieme dei nomi. Se rinnovassimo con il solo
            // hostname, il certificato tornerebbe a coprirlo da solo e i mta-sts.* sparirebbero:
            // con i record MTA-STS gia' pubblicati vuol dire posta RIFIUTATA, settimane dopo,
            // senza che nessuno abbia toccato niente. Quindi rileggo i nomi da quello in uso.
            StringBuilder cmd = new StringBuilder(
                    ACME_CMD + " --issue --server letsencrypt --dns dns_cf -d " + mailHostname);
            java.util.List<String> keep = new java.util.ArrayList<>();
            for (String n : installedCertificateNames())
                if (!n.equalsIgnoreCase(mailHostname)) keep.add(n);
            java.util.Collections.sort(keep);
            for (String n : keep) cmd.append(" -d ").append(n);
            cmd.append(" --force 2>&1");
            String output = sanitize(executeCommand(cmd.toString(), env), cf.apiToken);

            if (output.contains("Cert success") || output.contains("Cert renewed")
                    || output.contains("Skipping. Next renewal time")) {
                DeployResult deployResult = deployCertificate(mailHostname, output);
                return new CertificateResult(deployResult.success,
                    deployResult.success ? I18n.tr("server.acme.renewedCf")
                                         : I18n.tr("server.acme.renewedCfDeployFailed"),
                    output + "\n" + (deployResult.output != null ? deployResult.output : ""));
            }

            return new CertificateResult(false, I18n.tr("server.acme.renewCfFailed"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.cfError", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
        }
    }

    /**
     * Risale all'account Cloudflare da usare per il certificato del server mail.
     *
     * Il certificato è emesso per il <b>Mail Hostname</b> (es. mail.azienda.com), il cui
     * dominio base (azienda.com) NON è necessariamente tra i domini mail gestiti.
     * Per questo l'account si sceglie esplicitamente dalla pagina Cloudflare e viene
     * salvato in {@link #SETTING_CF_ACCOUNT_ID}. Solo come fallback proviamo a dedurlo
     * dai domini mail (nel caso l'hostname stia sotto un dominio mail già collegato).
     */
    private MailDatabase.CloudflareAccount cloudflareAccountForHostname(String hostname) {
        try {
            // 1) Scelta esplicita per il certificato del server mail
            String idStr = database.getSetting(SETTING_CF_ACCOUNT_ID, "");
            if (idStr != null && !idStr.isBlank()) {
                int id = Integer.parseInt(idStr.trim());
                if (id > 0) {
                    MailDatabase.CloudflareAccount a = database.getCloudflareAccount(id);
                    if (a != null) return a;
                }
            }
            // 2) Fallback: hostname che ricade sotto un dominio mail già assegnato
            // mail.example.com -> example.com (ma prova anche l'hostname intero)
            String domain = hostname.replaceFirst("^[^.]+\\.", "");
            MailDatabase.Domain d = database.getDomainByName(domain);
            if (d == null) {
                d = database.getDomainByName(hostname);
            }
            if (d == null) return null;
            return database.getCloudflareAccountForDomain(d.id);
        } catch (Exception e) {
            System.err.println("[ACME] Lookup account Cloudflare fallito: " + e.getMessage());
            return null;
        }
    }

    /** Id dell'account Cloudflare scelto per il certificato del server mail (0 = nessuno). */
    public int getMailCertCloudflareAccountId() {
        try {
            String v = database.getSetting(SETTING_CF_ACCOUNT_ID, "");
            return (v == null || v.isBlank()) ? 0 : Integer.parseInt(v.trim());
        } catch (Exception e) { return 0; }
    }

    /** Imposta (o azzera con 0) l'account Cloudflare usato per il certificato del server mail. */
    public void setMailCertCloudflareAccountId(int accountId) {
        database.setSetting(SETTING_CF_ACCOUNT_ID, accountId > 0 ? String.valueOf(accountId) : "");
    }

    /** Rimuove il token dall'output prima di restituirlo/loggarlo. */
    private String sanitize(String output, String token) {
        if (output == null || token == null || token.isBlank()) return output;
        return output.replace(token, "***");
    }

    /**
     * Check and renew certificates that are about to expire.
     * Salva sempre last_check, last_result e (se rinnovato) last_renewal.
     * Se forceRun = false, viene saltato quando auto-renewal è disabilitato.
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
            database.setSetting(SETTING_AUTO_RENEW_LAST_RESULT, "FAIL|" + I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))));
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
        }
    }

    /**
     * Compone il messaggio d'esito del rinnovo.
     * Su SUCCESSO mostra la NUOVA scadenza (rileggendo il certificato appena installato),
     * non i giorni che mancavano prima — così non sembra che "rinnovi e scada subito".
     * Su FALLIMENTO mantiene il contesto (quanti giorni mancavano).
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

    /** Backward-compatible — chiama checkAndRenewCertificates(false) */
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

            // Parse issuer: estrai sia l'Organizzazione (O=, il nome reale della CA)
            // sia il CN (il codice breve dell'intermedio). Mostra entrambi: "O (CN)".
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
            // "Let's Encrypt" si riconosce dall'Organizzazione, non dal codice dell'intermedio
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
            Path certPathEcc = Paths.get(ACME_HOME, hostname + "_ecc", hostname + ".cer");
            Path certPath = Paths.get(ACME_HOME, hostname, hostname + ".cer");
            if ((Files.exists(certPathEcc) || Files.exists(certPath)) && !forceRegenerate) {
                // Certificate exists - return special status so user can choose
                return new DnsChallengeResult(false, "CERT_EXISTS", null, null);
            }

            // Request certificate with DNS manual mode - this will output the TXT record needed
            String cmd = ACME_CMD + " --issue --server letsencrypt -d " + hostname +
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

                return new DnsChallengeResult(true, I18n.tr("server.acme.txtGenerated"), txtDomain, txtValue);
            }

            // Check if certificate already exists
            if (output.contains("already verified") || output.contains("Cert success")) {
                return new DnsChallengeResult(false, I18n.tr("server.acme.alreadyExists"), null, null);
            }

            return new DnsChallengeResult(false, I18n.tr("server.acme.challengeFailed", java.util.Map.of("o", String.valueOf(output))), null, null);

        } catch (Exception e) {
            return new DnsChallengeResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null, null);
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

            // Verify TXT record exists using dig
            String verifyCmd = "dig +short TXT " + txtDomain + " @1.1.1.1";
            String digOutput = executeCommand(verifyCmd).trim();

            if (digOutput.isEmpty() || !digOutput.contains(expectedValue)) {
                return new CertificateResult(false,
                    I18n.tr("server.acme.txtWrong", java.util.Map.of("atteso", String.valueOf(expectedValue), "trovato", String.valueOf(digOutput.isEmpty() ? I18n.tr("server.acme.none") : digOutput))), null);
            }

            // TXT record verified, now complete the certificate issuance with --renew
            String cmd = ACME_CMD + " --renew -d " + hostname +
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
                    return new CertificateResult(true, I18n.tr("server.acme.issuedDns01"),
                        output + "\n" + deployResult.output);
                } else {
                    return new CertificateResult(false, I18n.tr("server.acme.issuedDeployFailed", java.util.Map.of("m", String.valueOf(deployResult.message))), output);
                }
            }

            return new CertificateResult(false, I18n.tr("server.acme.verifiedNotIssued"), output);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
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
            // SECURITY: validate hostname (usato per scrivere su disco e per nginx config)
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

            return new CertificateResult(true, I18n.tr("server.acme.manualInstalled"), reloadOutput);

        } catch (Exception e) {
            return new CertificateResult(false, I18n.tr("server.acme.error", java.util.Map.of("m", String.valueOf(e.getMessage()))), null);
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
        return executeCommand(command, null);
    }

    /**
     * Esegue un comando shell, opzionalmente con variabili d'ambiente extra.
     * Le env vengono passate via ProcessBuilder.environment() (NON sulla command line),
     * così segreti come CF_Token non finiscono in argv né nei log di processo.
     */
    private String executeCommand(String command, Map<String, String> extraEnv) throws Exception {
        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        org.mail_panel.util.Shell.applyPath(pb);
        // rc.d non passa HOME. Senza, acme.sh calcola "$HOME/.acme.sh" = "/.acme.sh".
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
