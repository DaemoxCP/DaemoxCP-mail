package org.mail_panel.webserver;

import com.sun.net.httpserver.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.integration.RoundcubeSsoManager;
import org.mail_panel.integration.RspamdManager;
import org.mail_panel.integration.SieveGenerator;
import org.mail_panel.monitoring.LogManager;
import org.mail_panel.monitoring.MailQueueManager;
import org.mail_panel.scripts.*;
import org.mail_panel.security.AcmeManager;
import org.mail_panel.security.DkimManager;
import org.mail_panel.security.DkimRotationScheduler;
import org.mail_panel.security.DnsRecordsGenerator;
import org.mail_panel.security.Fail2banManager;
import org.mail_panel.security.PasskeyManager;
import org.mail_panel.security.TotpManager;
import org.mail_panel.system.UpdateManager;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HTTPS Server for FreeBSD Mail Panel
 * With login system, sessions, and CSRF protection
 *
 * Uses MySQL only (no SQLite)
 */
public class SSLMailServer {

    private final HttpsServer server;
    private final int port;
    private static final Logger LOGGER = Logger.getLogger(SSLMailServer.class.getName());

    // Managers for advanced features
    private DkimManager dkimManager;
    private DkimRotationScheduler dkimRotationScheduler;
    private org.mail_panel.security.CloudflareManager cloudflareManager;
    private RspamdManager rspamdManager;
    private SieveGenerator sieveGenerator;
    private DnsRecordsGenerator dnsGenerator;
    private AcmeManager acmeManager;
    private org.mail_panel.system.RapportoPeriodico rapportoPeriodico;
    private LogManager logManager;
    private MailQueueManager queueManager;
    private RoundcubeSsoManager ssoManager;
    private Fail2banManager fail2banManager;
    private org.mail_panel.security.PfFirewallManager firewallManager;
    private PasskeyManager passkeyManager;

    // SSL certificate content (for constructor with PEM)
    private String sslCertContent;
    private String sslKeyContent;

    public SSLMailServer(int port) throws Exception {
        this.port = port;
        this.server = HttpsServer.create(new InetSocketAddress(port), 0);

        // Setup SSL
        SSLContext sslContext = createSSLContext();
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLParameters sslParams = context.getDefaultSSLParameters();
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error configuring SSL", e);
                }
            }
        });

        // Setup routes
        setupRoutes();
    }

    /**
     * Constructor with SSL certificate and key content from SQLite config
     */
    public SSLMailServer(int port, String certContent, String keyContent) throws Exception {
        this.port = port;
        this.sslCertContent = certContent;
        this.sslKeyContent = keyContent;
        this.server = HttpsServer.create(new InetSocketAddress(port), 0);

        // Setup SSL from provided content
        SSLContext sslContext = createSSLContextFromPEM(certContent, keyContent);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLParameters sslParams = context.getDefaultSSLParameters();
                    params.setSSLParameters(sslParams);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Error configuring SSL", e);
                }
            }
        });

        // Setup routes
        setupRoutes();
    }

    private void setupRoutes() {
        // Public routes (no auth required)
        // I file di Font Awesome viaggiano dentro il jar e li serve il pannello stesso.
        // NON richiede autenticazione di proposito: il foglio di stile serve anche alla
        // pagina di accesso, che per definizione si vede prima di essere autenticati.
        // Rotta PUBBLICA e senza autenticazione, e non puo' essere altrimenti: e' Thunderbird
        // a chiederla, prima ancora che l'utente abbia inserito una password. Restituisce solo
        // nomi di server e numeri di porta, che sono gia' pubblici (stanno nei record DNS), e
        // solo per i domini che questo pannello ospita davvero.
        server.createContext("/autoconfig", this::handleAutoconfigPubblico);
        // Anche questa e' pubblica per forza: la politica MTA-STS la leggono i server mittenti
        // del mondo, che non hanno e non devono avere credenziali. Contiene solo il nome del
        // proprio MX, che sta gia' nei record DNS.
        server.createContext("/mta-sts", this::handleMtaStsPubblico);
        server.createContext("/fa", this::handleStatico);
        server.createContext("/vendor", this::handleStatico);
        server.createContext("/", this::handleRoot);
        server.createContext("/index", this::handleIndex);
        server.createContext("/login_check", this::handleLoginCheck);
        server.createContext("/setup", this::handleSetup);
        server.createContext("/api/setup", this::handleApiSetup);

        // Protected routes (auth required)
        server.createContext("/home", this::handleProtectedPage);
        server.createContext("/domains", this::handleProtectedPage);
        server.createContext("/mailboxes", this::handleProtectedPage);
        server.createContext("/aliases", this::handleProtectedPage);
        server.createContext("/dns", this::handleProtectedPage);
        // /install removed - installation is done via terminal GUI only
        server.createContext("/settings", this::handleProtectedPage);
        server.createContext("/logs", this::handleProtectedPage);
        server.createContext("/ssl", this::handleProtectedPage);
        server.createContext("/queue", this::handleProtectedPage);
        server.createContext("/security", this::handleProtectedPage);
        server.createContext("/firewall", this::handleProtectedPage);
        server.createContext("/cloudflare", this::handleProtectedPage);
        server.createContext("/logout", this::handleLogout);
        server.createContext("/api/logout", this::handleLogout);

        // API endpoints - Core
        server.createContext("/api/status", this::handleApiStatus);
        server.createContext("/api/domains", this::handleApiDomains);
        server.createContext("/api/mailboxes", this::handleApiMailboxes);
        server.createContext("/api/mailconfig", this::handleApiMailConfig);
        server.createContext("/api/aliases", this::handleApiAliases);
        server.createContext("/api/webmail", this::handleApiWebmail);
        server.createContext("/api/service", this::handleApiService);
        // /api/install removed - installation is done via terminal GUI only

        // API endpoints - DKIM & DNS
        server.createContext("/api/dkim", this::handleApiDkim);
        server.createContext("/api/dns", this::handleApiDns);
        server.createContext("/api/cloudflare", this::handleApiCloudflare);
        server.createContext("/api/timezone-diag", this::handleApiTimezoneDiag);
        server.createContext("/api/postfix-aliases-health", this::handleApiPostfixAliases);

        // API endpoints - SSL/Let's Encrypt
        server.createContext("/api/ssl", this::handleApiSsl);

        // API endpoints - Logs & Monitoring
        server.createContext("/api/logs", this::handleApiLogs);
        server.createContext("/api/stats", this::handleApiStats);

        // API endpoints - Mail Queue
        server.createContext("/api/queue", this::handleApiQueue);

        // API endpoints - Roundcube SSO
        server.createContext("/api/sso", this::handleApiSso);
        server.createContext("/api/webmail/open", this::handleApiWebmailOpen);

        // API endpoints - Fail2ban
        server.createContext("/api/fail2ban", this::handleApiFail2ban);
        server.createContext("/api/fail2ban_health", this::handleApiFail2banHealth);
        server.createContext("/api/system_paths", this::handleApiSystemPaths);
        server.createContext("/api/clamav_health", this::handleApiClamavHealth);
        server.createContext("/api/blacklist_check", this::handleApiBlacklistCheck);
        server.createContext("/api/unbound_health", this::handleApiUnboundHealth);
        server.createContext("/api/firewall", this::handleApiFirewall);
        server.createContext("/paths", this::handleProtectedPage);

        // Aggiornamenti, protezione pacchetti e vulnerabilita'
        server.createContext("/updates", this::handleProtectedPage);
        server.createContext("/api/updates", this::handleApiUpdates);

        // New feature pages
        server.createContext("/admins", this::handleProtectedPage);
        server.createContext("/statistics", this::handleProtectedPage);
        server.createContext("/ratelimits", this::handleProtectedPage);

        // API endpoints - 2FA
        server.createContext("/api/2fa", this::handleApi2FA);

        // API endpoints - Auth check (for login flow)
        server.createContext("/api/auth/check", this::handleApiAuthCheck);

        // API endpoints - Passkey (WebAuthn)
        server.createContext("/api/passkey/register/start", this::handleApiPasskeyRegisterStart);
        server.createContext("/api/passkey/register/finish", this::handleApiPasskeyRegisterFinish);
        server.createContext("/api/passkey/login/start", this::handleApiPasskeyLoginStart);
        server.createContext("/api/passkey/login/finish", this::handleApiPasskeyLoginFinish);
        server.createContext("/api/passkeys", this::handleApiPasskeys);

        // API endpoints - Admin management
        server.createContext("/api/admins", this::handleApiAdmins);
        server.createContext("/api/report", this::handleApiReport);
        server.createContext("/api/autodns", this::handleApiAutoDns);
        server.createContext("/api/autoconfig", this::handleApiAutoconfig);
        server.createContext("/api/profilo-apple", this::handleApiProfiloApple);
        server.createContext("/profilo-apple", this::handleScaricaProfiloApple);

        // API endpoints - Auto-responder
        server.createContext("/api/autoresponder", this::handleApiAutoResponder);

        // API endpoints - Sieve filters
        server.createContext("/api/sieve", this::handleApiSieve);

        // API endpoints - Forwarding
        server.createContext("/api/forwarding", this::handleApiForwarding);

        // API endpoints - Rate limits
        server.createContext("/api/ratelimits", this::handleApiRateLimits);

        // API endpoints - Rspamd training
        server.createContext("/api/rspamd", this::handleApiRspamd);

        // API endpoints - Email statistics
        server.createContext("/api/statistics", this::handleApiStatistics);
        server.createContext("/api/theme", this::handleApiTheme);

        // API endpoint - Hostname change
        server.createContext("/api/hostname", this::handleApiHostname);

        // API endpoint - Roundcube domain change
        server.createContext("/api/roundcube-domain", this::handleApiRoundcubeDomain);
    }

    private void initializeManagers() {
        if (Main.mailDatabase != null && Main.mysqlAvailable) {
            this.dkimManager = new DkimManager(Main.mailDatabase);
            this.cloudflareManager = new org.mail_panel.security.CloudflareManager(Main.mailDatabase);
            this.dkimManager.setCloudflareManager(this.cloudflareManager);
            this.dnsGenerator = new DnsRecordsGenerator(Main.mailDatabase);
            this.acmeManager = new AcmeManager(Main.mailDatabase);
            this.logManager = new LogManager();
            this.queueManager = new MailQueueManager();
            this.ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
            this.fail2banManager = new Fail2banManager();
            this.firewallManager = new org.mail_panel.security.PfFirewallManager();
            this.rspamdManager = new RspamdManager();
            this.sieveGenerator = new SieveGenerator();

            // Initialize PasskeyManager for WebAuthn
            initializePasskeyManager();

            // Auto-setup Fail2ban: log file + filter + jail + log rotation + reload
            // Idempotente, fail-safe: salta tutto se Fail2ban non è installato.
            org.mail_panel.security.Fail2banAutoSetup.run();

            // Auto-setup Postfix aliases: crea /etc/aliases (o /etc/mail/aliases) se manca
            // + compila il .db. Risolve l'errore comune "open database /etc/aliases.db: No such file".
            // Idempotente: se è tutto OK non fa nulla.
            try {
                new org.mail_panel.security.PostfixAliasesManager().ensureAtBoot();
            } catch (Throwable t) {
                LOGGER.warning("PostfixAliases ensureAtBoot fallito: " + t.getMessage());
            }

            // Start auto-renewal for certificates
            acmeManager.startAutoRenewal();

            // Start DKIM rotation scheduler (polls DNS propagation hourly)
            this.dkimRotationScheduler = new DkimRotationScheduler(Main.mailDatabase, dkimManager);
            this.dkimRotationScheduler.start();

            // Il rapporto periodico: sa leggere il certificato solo se glielo si passa.
            org.mail_panel.system.RapportoPeriodico.collega(this.acmeManager);
            this.rapportoPeriodico = new org.mail_panel.system.RapportoPeriodico();
            this.rapportoPeriodico.start();

            // Auto-install/update Roundcube SSO plugin if Roundcube is installed
            autoInstallSsoPlugin();
        }
    }

    private void initializePasskeyManager() {
        try {
            // Ensure passkeys table exists (for upgrades)
            Main.mailDatabase.ensurePasskeysTable();

            // Ensure receive_enabled column exists in mailboxes (for upgrades)
            Main.mailDatabase.ensureMailboxReceiveEnabledColumn();

            // Ensure password vault columns exist (cifratura password mailbox per recovery dal pannello)
            Main.mailDatabase.ensureMailboxPasswordVaultColumns();

            // Ensure theme column exists in panel_admin (for upgrades)
            Main.mailDatabase.ensureThemeColumn();

            // Ensure DKIM rotation columns exist in domains (for upgrades)
            Main.mailDatabase.ensureDkimRotationColumns();

            // Ensure Cloudflare accounts schema (migra il token legacy se presente)
            Main.mailDatabase.ensureCloudflareAccountsSchema();

            // Ensure DKIM rotation history table
            Main.mailDatabase.ensureDkimRotationHistoryTable();

            // Get the panel hostname from SQLite config
            String panelHost = "";
            try {
                java.sql.ResultSet rs = Main.dbManager.get_data_config();
                if (rs.next()) {
                    panelHost = rs.getString("mail_panel_host");
                }
            } catch (Exception e) {
                LOGGER.warning("Could not read panel host from SQLite: " + e.getMessage());
            }

            if (panelHost == null || panelHost.isEmpty() || panelHost.equals("127.0.0.1")) {
                LOGGER.warning("Panel hostname not set, passkeys will not work until configured");
                return;
            }

            // Use the full panel hostname as RP ID (e.g., "server.example.com")
            // This isolates passkeys per subdomain, allowing multiple panels
            // under the same domain to have independent passkeys
            String rpId = panelHost;

            // Build origins set - panel hostname with and without port
            Set<String> origins = new HashSet<>();
            origins.add("https://" + panelHost);
            origins.add("https://" + panelHost + ":" + port);

            this.passkeyManager = new PasskeyManager(
                    Main.mailDatabase,
                    rpId,
                    "FreeBSD Mail Panel",
                    origins
            );

            LOGGER.info("PasskeyManager initialized with RP ID: " + rpId + ", origins: " + origins);
        } catch (Exception e) {
            LOGGER.warning("Failed to initialize PasskeyManager: " + e.getMessage());
        }
    }

    /**
     * Automatically install or update the Roundcube SSO plugin at startup.
     * This ensures the plugin is always up-to-date with the panel version.
     */
    private void autoInstallSsoPlugin() {
        if (ssoManager == null) return;

        try {
            RoundcubeSsoManager.SsoStatus status = ssoManager.getStatus();

            // If Roundcube is installed, ensure SSO plugin is installed and up-to-date
            if (status.roundcubeInstalled) {
                LOGGER.info("Roundcube detected, checking SSO plugin...");

                // Always reinstall to ensure plugin is up-to-date
                RoundcubeSsoManager.InstallResult result = ssoManager.installPlugin();

                if (result.success) {
                    LOGGER.info("Roundcube SSO plugin installed/updated successfully");
                } else {
                    LOGGER.warning("Failed to install SSO plugin: " + result.error);
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Error during SSO plugin auto-install: " + e.getMessage());
        }
    }

    public void start() {
        // Virtual threads (Java 21+): ogni richiesta gira su un virtual thread
        // leggerissimo invece che su un thread piattaforma da pool fisso a 10.
        // Vantaggi:
        //  - nessun limite pratico sul numero di richieste concorrenti
        //  - quando una richiesta blocca su I/O (es. fail2ban-client, shell command,
        //    query DB), il carrier thread va a servirne un'altra → niente starvation
        //  - memoria: ~200 byte/virtual thread vs ~1MB/thread piattaforma
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        initializeManagers();
        LOGGER.info("Mail Panel server started on port " + port + " (virtual threads enabled)");
    }

    public void stop() {
        LOGGER.info("Stopping Mail Panel server...");

        // Stop ACME auto-renewal scheduler first
        if (acmeManager != null) {
            try {
                acmeManager.stopAutoRenewal();
            } catch (Exception e) {
                // Ignore
            }
        }

        // Stop HTTP server immediately
        try {
            server.stop(0);
        } catch (Exception e) {
            // Ignore
        }

        LOGGER.info("Mail Panel server stopped");

        // Force exit after a short delay if still hanging
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                System.out.println("Forcing exit...");
                System.exit(0);
            } catch (InterruptedException e) {
                // Ignore
            }
        }).start();
    }

    // ============== SSL SETUP ==============

    private SSLContext createSSLContext() throws Exception {
        String jarDir = getJarDirectory();
        Path keystorePath = Paths.get(jarDir, "mailpanel.jks");
        String keystorePassword = "mailpanel";

        if (!Files.exists(keystorePath)) {
            LOGGER.info("Generating self-signed SSL certificate...");
            generateSelfSignedCertificate(keystorePath.toString(), keystorePassword);
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath.toFile())) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keystorePassword.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        return sslContext;
    }

    /**
     * Create SSL context from PEM certificate and key content
     * The certificate (with its chain) and the private key both come as PEM text.
     */
    private SSLContext createSSLContextFromPEM(String certContent, String keyContent) throws Exception {
        System.out.println("\n========== SSL CONTEXT CREATION DEBUG ==========");

        // Normalize certificate content (fix newlines)
        certContent = normalizePEM(certContent);
        keyContent = normalizePEM(keyContent);

        System.out.println("Certificate content length: " + certContent.length());
        System.out.println("Key content length: " + keyContent.length());
        System.out.println("Certificate starts with: " + certContent.substring(0, Math.min(50, certContent.length())));
        System.out.println("Key starts with: " + keyContent.substring(0, Math.min(50, keyContent.length())));

        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");

        // Load all certificates from the cert content (may contain chain)
        List<java.security.cert.X509Certificate> certChain = new ArrayList<>();
        try (java.io.InputStream certStream = new java.io.ByteArrayInputStream(certContent.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            java.util.Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(certStream);
            for (java.security.cert.Certificate c : certs) {
                java.security.cert.X509Certificate x509 = (java.security.cert.X509Certificate) c;
                certChain.add(x509);
                System.out.println("Loaded certificate: " + x509.getSubjectX500Principal().getName());
            }
        } catch (Exception e) {
            System.err.println("ERROR loading certificate: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }

        if (certChain.isEmpty()) {
            throw new IllegalArgumentException("No valid certificates found in certificate content");
        }
        System.out.println("Loaded " + certChain.size() + " certificate(s)");

        // Load private key
        System.out.println("Loading private key...");
        java.security.PrivateKey privateKey = loadPrivateKeyFromString(keyContent);
        System.out.println("Private key loaded successfully. Algorithm: " + privateKey.getAlgorithm());

        // Build certificate chain array
        java.security.cert.Certificate[] chainArray = certChain.toArray(new java.security.cert.Certificate[0]);

        // Create key store with full certificate chain
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, null);

        // Set the private key with the FULL certificate chain
        keystore.setKeyEntry("server-key", privateKey, new char[0], chainArray);

        // Also add certificates to trust store
        for (int i = 0; i < certChain.size(); i++) {
            keystore.setCertificateEntry("cert-" + i, certChain.get(i));
        }

        // Create key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keystore, new char[0]);

        // Create trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keystore);

        // Create SSL context - try TLS 1.3 first, fallback to TLS
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("TLSv1.3");
            System.out.println("Using TLSv1.3");
        } catch (Exception e) {
            sslContext = SSLContext.getInstance("TLS");
            System.out.println("Fallback to TLS (TLSv1.3 not available)");
        }
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        System.out.println("SSL Context created successfully with " + certChain.size() + " certificate(s)");
        System.out.println("================================================\n");

        LOGGER.info("SSL context created from PEM content");
        return sslContext;
    }

    /**
     * Normalizes PEM content by fixing newlines and removing extra whitespace.
     */
    private String normalizePEM(String pem) {
        if (pem == null) return null;

        // Replace various newline formats with standard \n
        pem = pem.replace("\r\n", "\n").replace("\r", "\n");

        // Remove any leading/trailing whitespace from each line
        String[] lines = pem.split("\n");
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * Load private key from PEM string
     */
    private java.security.PrivateKey loadPrivateKeyFromString(String keyContent) throws Exception {
        if (keyContent == null || keyContent.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key content is empty");
        }

        // Detect key format
        boolean isRSAFormat = keyContent.contains("-----BEGIN RSA PRIVATE KEY-----");
        boolean isPKCS8Format = keyContent.contains("-----BEGIN PRIVATE KEY-----");
        boolean isECFormat = keyContent.contains("-----BEGIN EC PRIVATE KEY-----");

        System.out.println("Key format detected - RSA: " + isRSAFormat + ", PKCS8: " + isPKCS8Format + ", EC: " + isECFormat);

        if (!isRSAFormat && !isPKCS8Format && !isECFormat) {
            throw new IllegalArgumentException("Unsupported private key format. Expected PKCS#8, RSA, or EC format.");
        }

        String base64Key;
        java.security.KeyFactory kf;

        if (isPKCS8Format) {
            // PKCS#8 format (most common, works with RSA and EC)
            base64Key = keyContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedKey = java.util.Base64.getDecoder().decode(base64Key);
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(decodedKey);

            // Try RSA first, then EC
            try {
                kf = java.security.KeyFactory.getInstance("RSA");
                return kf.generatePrivate(spec);
            } catch (Exception e) {
                System.out.println("Not an RSA key, trying EC...");
                kf = java.security.KeyFactory.getInstance("EC");
                return kf.generatePrivate(spec);
            }
        } else if (isRSAFormat) {
            // RSA format (traditional OpenSSL PKCS#1)
            base64Key = keyContent
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] pkcs1Bytes = java.util.Base64.getDecoder().decode(base64Key);
            byte[] pkcs8Bytes = convertPKCS1ToPKCS8(pkcs1Bytes);

            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(pkcs8Bytes);
            kf = java.security.KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } else {
            // EC format
            base64Key = keyContent
                    .replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replace("-----END EC PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedKey = java.util.Base64.getDecoder().decode(base64Key);
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(decodedKey);
            kf = java.security.KeyFactory.getInstance("EC");
            return kf.generatePrivate(spec);
        }
    }

    /**
     * Convert PKCS#1 RSA private key to PKCS#8 format
     */
    private byte[] convertPKCS1ToPKCS8(byte[] pkcs1Bytes) {
        // PKCS#8 header for RSA keys
        byte[] pkcs8Header = {
            0x30, (byte) 0x82, 0x00, 0x00, // SEQUENCE, length placeholder
            0x02, 0x01, 0x00,              // INTEGER 0 (version)
            0x30, 0x0d,                    // SEQUENCE
            0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
            0x05, 0x00,                    // NULL
            0x04, (byte) 0x82, 0x00, 0x00  // OCTET STRING, length placeholder
        };

        int totalLen = pkcs8Header.length + pkcs1Bytes.length;
        byte[] pkcs8Bytes = new byte[totalLen];

        System.arraycopy(pkcs8Header, 0, pkcs8Bytes, 0, pkcs8Header.length);
        System.arraycopy(pkcs1Bytes, 0, pkcs8Bytes, pkcs8Header.length, pkcs1Bytes.length);

        // Fix lengths in header
        int seqLen = totalLen - 4;
        pkcs8Bytes[2] = (byte) ((seqLen >> 8) & 0xff);
        pkcs8Bytes[3] = (byte) (seqLen & 0xff);

        int octetLen = pkcs1Bytes.length;
        pkcs8Bytes[pkcs8Header.length - 2] = (byte) ((octetLen >> 8) & 0xff);
        pkcs8Bytes[pkcs8Header.length - 1] = (byte) (octetLen & 0xff);

        return pkcs8Bytes;
    }

    private void generateSelfSignedCertificate(String keystorePath, String password) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", "mailpanel",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "3650",
                "-keystore", keystorePath,
                "-storepass", password,
                "-keypass", password,
                "-dname", "CN=FreeBSD Mail Panel, OU=Mail, O=FreeBSD, L=Unknown, ST=Unknown, C=US"
            );
            org.mail_panel.util.Shell.applicaPath(pb);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.inheritIO();
            Process p = pb.start();
            p.waitFor();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate certificate", e);
        }
    }

    // ============== AUTH HELPERS ==============

    private boolean isAuthenticated(HttpExchange exchange) {
        // If MySQL not available or setup required, only setup pages are accessible
        if (!Main.mysqlAvailable || Main.setupRequired) {
            System.out.println("[AUTH] MySQL not available or setup required");
            return false;
        }

        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) {
            System.out.println("[AUTH] No cookie found");
            return false;
        }

        String sessionCode = extractSessionCode(cookie);
        if (sessionCode == null) {
            System.out.println("[AUTH] No session code in cookie: " + cookie.substring(0, Math.min(50, cookie.length())));
            return false;
        }

        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        String ip = getClientIp(exchange);  // Use CF-Connecting-IP if available

        boolean result = Main.sessions.checkExistingSession(sessionCode, userAgent, ip);
        System.out.println("[AUTH] Session check result: " + result + " (sessions count: " + Main.sessions.sessions.size() + ")");
        return result;
    }

    private String extractSessionCode(String cookie) {
        if (cookie == null) return null;
        for (String part : cookie.split(";")) {
            part = part.trim();
            if (part.startsWith("__Host-MailPanel=")) {
                return part.substring("__Host-MailPanel=".length());
            }
        }
        return null;
    }

    private String getCsrfToken(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionCode = extractSessionCode(cookie);
        return Main.sessions.getCsrfToken(sessionCode);
    }

    // ============== PAGE HANDLERS ==============

    /**
     * Cosa mostrare quando il pannello non puo' funzionare ma l'installazione NON va rifatta.
     *
     * Prima, in questa situazione, si veniva mandati alla procedura di installazione: era il
     * modo in cui il cancello si apriva da solo. Ora la procedura e' chiusa, e mandare li'
     * chiunque produrrebbe soltanto un rimbalzo infinito fra /index e /setup. Si dice invece
     * cosa sta succedendo davvero, che e' anche l'unica cosa utile a chi deve rimediare.
     */
    private void paginaNonDisponibile(HttpExchange exchange, String motivo, String rimedio)
            throws IOException {
        String html = "<!doctype html><html lang=\"it\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>Pannello non disponibile</title><style>"
                + "body{background:#16213e;color:#e6e6e6;font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
                + "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:1.5rem}"
                + ".c{max-width:38rem;background:#1a1a2e;border:1px solid #2b2b45;border-radius:12px;padding:2rem}"
                + "h1{font-size:1.3rem;margin:0 0 1rem;color:#e94560}"
                + "p{line-height:1.6;margin:0 0 1rem}code{background:#0f3460;padding:.15rem .4rem;border-radius:4px}"
                + "</style></head><body><div class=\"c\">"
                + "<h1>Il pannello non puo' rispondere</h1>"
                + "<p>" + escapeHtmlServer(motivo) + "</p>"
                + "<p>" + escapeHtmlServer(rimedio) + "</p>"
                + "<p style=\"opacity:.7;font-size:.9rem\">La procedura di installazione non viene "
                + "riaperta: risulta gia' completata, e riaprirla quando un componente cade sarebbe un "
                + "modo di perdere il server, non di recuperarlo.</p>"
                + "</div></body></html>";
        byte[] dati = html.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(503, dati.length);
        try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(dati); }
        exchange.close();
    }

    /** Neutralizza il testo prima di metterlo in una pagina costruita a mano. */
    private static String escapeHtmlServer(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /** Il motivo per cui il pannello non e' utilizzabile, quando il setup e' chiuso. */
    private String motivoIndisponibilita() {
        if (!Main.mysqlAvailable)
            return "Il database MySQL non risponde, quindi il pannello non puo' leggere domini, "
                 + "caselle e amministratori.";
        return "Il database risponde, ma non risulta configurato nessun amministratore.";
    }

    private String rimedioIndisponibilita() {
        if (!Main.mysqlAvailable)
            return "Va rimesso in funzione MySQL sul server: di solito basta riavviare il servizio "
                 + "e controllare lo spazio libero sul disco. Appena risponde, questa pagina torna "
                 + "a essere la schermata di accesso.";
        return "Va ricreato un amministratore. Se serve rieseguire l'installazione, crea sul server "
             + "il file /var/db/mailpanel/consenti-setup e riprova entro quindici minuti.";
    }

    private void handleRoot(HttpExchange exchange) throws IOException {
        try {
            // Redirect based on system state
            if (!Main.mysqlAvailable || Main.setupRequired) {
                if (org.mail_panel.security.CancelloSetup.consentito()) {
                    redirect(exchange, "/setup");
                } else {
                    paginaNonDisponibile(exchange, motivoIndisponibilita(), rimedioIndisponibilita());
                }
            } else if (isAuthenticated(exchange)) {
                redirect(exchange, "/home");
            } else {
                redirect(exchange, "/index");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleRoot", e);
            redirect(exchange, "/index");
        }
    }

    private void handleIndex(HttpExchange exchange) throws IOException {
        try {
            // Se l'installazione e' gia' stata fatta non si rimbalza verso /setup — che ora
            // rimanda indietro — ma si dice cosa non va.
            if (!Main.mysqlAvailable || Main.setupRequired) {
                if (org.mail_panel.security.CancelloSetup.consentito()) redirect(exchange, "/setup");
                else paginaNonDisponibile(exchange, motivoIndisponibilita(), rimedioIndisponibilita());
                return;
            }

            if (isAuthenticated(exchange)) {
                redirect(exchange, "/home");
                return;
            }

            // Generate CSRF token for login form
            Object[] sessionData = Main.sessions.Add_Session(
                exchange.getRequestHeaders().getFirst("User-Agent"),
                getClientIp(exchange)  // Use CF-Connecting-IP if available
            );
            String csrfToken = Main.sessions.getCsrfToken((String) sessionData[1]);

            // Read and serve login page
            String html = readHtmlFile("index.html");
            html = html.replace("{{CSRF_TOKEN}}", csrfToken);
            sendHtml(exchange, html);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleIndex", e);
            sendJsonError(exchange, 500, "Errore interno del server");
        }
    }

    private void handleSetup(HttpExchange exchange) throws IOException {
        // Stessa regola dell'endpoint: se l'installazione risulta fatta, qui non si arriva —
        // nemmeno con MySQL giu'. Mostrare il modulo e poi rifiutare le richieste sarebbe
        // un invito a insistere, e direbbe a un estraneo che il pannello e' in difficolta'.
        if (!org.mail_panel.security.CancelloSetup.consentito()) {
            redirect(exchange, "/index");
            return;
        }

        // Generate CSRF token
        Object[] sessionData = Main.sessions.Add_Session(
            exchange.getRequestHeaders().getFirst("User-Agent"),
            getClientIp(exchange)  // Use CF-Connecting-IP if available
        );
        String csrfToken = Main.sessions.getCsrfToken((String) sessionData[1]);

        // Get saved hostname from SQLite
        String savedHostname = Main.dbManager.getMailHostname();
        if (savedHostname == null) savedHostname = "";

        String html = readHtmlFile("setup.html");
        html = html.replace("{{CSRF_TOKEN}}", csrfToken);
        html = html.replace("{{MYSQL_INSTALLED}}", String.valueOf(Main.mysqlAvailable));
        html = html.replace("{{MAIL_HOSTNAME}}", savedHostname);
        sendHtml(exchange, html);
    }

    private void handleProtectedPage(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            System.out.println("[DEBUG] handleProtectedPage: " + path);

            if (!isAuthenticated(exchange)) {
                System.out.println("[DEBUG] NOT authenticated, redirecting to /index");
                redirect(exchange, "/index");
                return;
            }

            System.out.println("[DEBUG] Authenticated OK, serving page");
            String pageName = path.equals("/") ? "home" : path.substring(1);
            String csrfToken = getCsrfToken(exchange);

            String html = readHtmlFile(pageName + ".html");
            if (html == null) {
                System.out.println("[DEBUG] Page not found: " + pageName + ".html, using home.html");
                html = readHtmlFile("home.html");
            }
            html = html.replace("{{CSRF_TOKEN}}", csrfToken != null ? csrfToken : "");
            // Replace system info placeholders
            html = html.replace("{{JAVA_VERSION}}", "Java " + System.getProperty("java.version") + " (OpenJDK)");
            html = html.replace("{{PLATFORM}}", System.getProperty("os.name") + " " + System.getProperty("os.version"));
            html = html.replace("{{DATABASE}}", Main.mysqlAvailable ? "MySQL" : "Non connesso");
            // Replace mail hostname (read-only, configured during installation)
            String mailHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "Non configurato";
            html = html.replace("{{MAIL_HOSTNAME}}", mailHostname != null && !mailHostname.isEmpty() ? mailHostname : "Non configurato");
            // Replace Roundcube domain
            String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
            html = html.replace("{{ROUNDCUBE_DOMAIN}}", rcDomain != null && !rcDomain.isEmpty() ? rcDomain : "Non configurato");
            sendHtml(exchange, html);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in handleProtectedPage", e);
            sendJsonError(exchange, 500, "Errore interno del server");
        }
    }

    private void handleLoginCheck(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        // Il messaggio non manda piu' a /setup quando l'installazione c'e' gia': sarebbe un
        // consiglio sbagliato e un invito a insistere su una porta che deve restare chiusa.
        if (!Main.mysqlAvailable || Main.setupRequired) {
            sendJsonResponse(exchange, new JSONObject()
                .put("success", false)
                .put("Message", org.mail_panel.security.CancelloSetup.consentito()
                        ? "Installazione non ancora completata. Vai a /setup"
                        : motivoIndisponibilita() + " " + rimedioIndisponibilita()));
            return;
        }

        String clientIp = getClientIp(exchange);

        // Check if IP is locked out (rate limiting)
        if (isLoginRateLimited(clientIp)) {
            long remainingSeconds = getRemainingLockoutTime(clientIp);
            logAudit("LOGIN_BLOCKED", clientIp, "IP locked out, remaining: " + remainingSeconds + "s");
            sendJsonResponse(exchange, new JSONObject()
                .put("success", false)
                .put("locked", true)
                .put("remaining_seconds", remainingSeconds)
                .put("Message", "Troppi tentativi falliti. Riprova tra " + remainingSeconds + " secondi"));
            return;
        }

        // Read body with size limit
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }

        JSONObject request = new JSONObject(body);

        String username = request.optString("username", "");
        String password = request.optString("password", "");

        // Validate input format
        if (!SecurityUtils.isValidUsername(username) || !SecurityUtils.isValidPassword(password)) {
            recordLoginFailure(clientIp);
            logAudit("LOGIN_INVALID_INPUT", clientIp, "Invalid username/password format for: " + username);
            sendJsonResponse(exchange, new JSONObject()
                .put("success", false)
                .put("Message", "Credenziali non valide"));
            return;
        }

        // Check credentials from database (BCrypt hashed)
        int adminId = Main.mailDatabase.getAdminIdIfValidLogin(username, password);
        if (adminId > 0) {
            // Successful password - reset rate limiter
            resetLoginAttempts(clientIp);

            // Check if 2FA is enabled
            boolean has2FA = Main.mailDatabase.is2FAEnabled(adminId);
            String totpCode = request.optString("totp_code", "");

            if (has2FA) {
                // 2FA is enabled - check if code was provided
                if (totpCode.isEmpty()) {
                    // First step - password OK, need TOTP
                    sendJsonResponse(exchange, new JSONObject()
                        .put("success", false)
                        .put("requires_2fa", true)
                        .put("Message", "Inserisci il codice 2FA"));
                    return;
                }

                // Verify TOTP code
                String secret = Main.mailDatabase.getTotpSecret(adminId);
                if (secret == null || !TotpManager.verifyCode(secret, totpCode)) {
                    // Check backup codes
                    if (!Main.mailDatabase.useBackupCode(adminId, totpCode)) {
                        logAudit("LOGIN_2FA_FAILURE", clientIp, "Invalid 2FA code for: " + username);
                        sendJsonResponse(exchange, new JSONObject()
                            .put("success", false)
                            .put("requires_2fa", true)
                            .put("Message", "Codice 2FA non valido"));
                        return;
                    }
                }
            }

            // Create session
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            Object[] sessionData = Main.sessions.Add_Session(userAgent, clientIp);
            String sessionCode = (String) sessionData[1];
            String csrfToken = Main.sessions.getCsrfToken(sessionCode);

            System.out.println("[LOGIN] Success! Creating session for user: " + username);
            System.out.println("[LOGIN] UserAgent: " + (userAgent != null ? userAgent.substring(0, Math.min(60, userAgent.length())) : "null"));
            System.out.println("[LOGIN] Session code (first 20 chars): " + sessionCode.substring(0, 20) + "...");
            System.out.println("[LOGIN] Total sessions: " + Main.sessions.sessions.size());

            // Save admin info in session
            Main.sessions.setSessionAdmin(sessionCode, adminId, username);

            // Set cookie (SameSite=Lax for Cloudflare proxy compatibility)
            exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-MailPanel=" + sessionCode + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600");
            // Cleanup: cancella eventuale cookie residuo col vecchio nome (pre-fix __Host-)
            exchange.getResponseHeaders().add("Set-Cookie",
                "MailPanel=; Path=/; HttpOnly; Secure; Max-Age=0");

            logAudit("LOGIN_SUCCESS", clientIp, "User logged in: " + username + (has2FA ? " (with 2FA)" : ""));

            sendJsonResponse(exchange, new JSONObject()
                .put("success", true)
                .put("csrf_token", csrfToken));
        } else {
            // Failed login - record attempt and apply progressive delay
            recordLoginFailure(clientIp);
            int delayMs = getLoginDelay(clientIp);

            logAudit("LOGIN_FAILURE", clientIp, "Failed login attempt for: " + username);

            // Progressive delay (exponential backoff)
            try { Thread.sleep(delayMs); } catch (InterruptedException ignored) {}

            // Check if now locked out after this attempt
            if (isLoginRateLimited(clientIp)) {
                long remainingSeconds = getRemainingLockoutTime(clientIp);
                sendJsonResponse(exchange, new JSONObject()
                    .put("success", false)
                    .put("locked", true)
                    .put("remaining_seconds", remainingSeconds)
                    .put("Message", "Account bloccato per troppi tentativi. Riprova tra " + remainingSeconds + " secondi"));
            } else {
                sendJsonResponse(exchange, new JSONObject()
                    .put("success", false)
                    .put("Message", "Username o password non corretti"));
            }
        }
    }

    private void handleLogout(HttpExchange exchange) throws IOException {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionCode = extractSessionCode(cookie);
        if (sessionCode != null) {
            Main.sessions.deleteCookie(sessionCode);
        }

        exchange.getResponseHeaders().add("Set-Cookie",
            "__Host-MailPanel=; Path=/; HttpOnly; Secure; Max-Age=0");
        // Cleanup: cancella anche eventuale cookie residuo col vecchio nome
        exchange.getResponseHeaders().add("Set-Cookie",
            "MailPanel=; Path=/; HttpOnly; Secure; Max-Age=0");

        sendJsonResponse(exchange, new JSONObject().put("success", true));
    }

    // ============== SETUP API ==============

    private void handleApiSetup(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        // Il cancello non dipende piu' dalla raggiungibilita' di MySQL: con la vecchia
        // condizione bastava che il database non rispondesse perche' questa procedura —
        // che esegue script di installazione — tornasse aperta a chiunque, senza credenziali.
        org.mail_panel.security.CancelloSetup.Esito cancello =
                org.mail_panel.security.CancelloSetup.valuta();
        if (cancello == org.mail_panel.security.CancelloSetup.Esito.CHIUSO) {
            // Ogni tentativo respinto viene registrato: un attacco che non lascia traccia
            // e' un attacco che nessuno scopre.
            logAudit("SETUP_RIFIUTATO", getClientIp(exchange),
                    "tentativo di eseguire la procedura di installazione a installazione gia' completata");
            sendJsonError(exchange, 403, org.mail_panel.security.CancelloSetup.motivoRifiuto());
            return;
        }
        if (cancello == org.mail_panel.security.CancelloSetup.Esito.APERTO_PER_RECUPERO)
            logAudit("SETUP_RECUPERO", getClientIp(exchange),
                    org.mail_panel.security.CancelloSetup.notaRecupero());

        String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
        JSONObject req = new JSONObject(body);
        String action = req.optString("action", "");

        JSONObject response = new JSONObject();

        switch (action) {
            case "install_mysql" -> {
                // Install MySQL: lo script toglie e rimette pacchetti, quindi aspetta il turno.
                JSONObject esito = sulTurnoPacchetti("installazione di MySQL", () -> {
                    JSONObject r = new JSONObject();
                    try {
                        String scriptContent = new MySQLMailScript().getScriptContent();
                        r.put("success", true).put("output", executeScript(scriptContent, "mysql"));
                    } catch (Exception e) {
                        r.put("success", false).put("error", e.getMessage());
                    }
                    return r;
                });
                for (String k : esito.keySet()) response.put(k, esito.get(k));
            }
            case "auto_setup" -> {
                // Automatic setup - only requires admin credentials
                // Hostname is taken from SQLite (set during terminal installation)
                String adminUsername = req.optString("admin_username", "").trim();
                String adminPassword = req.optString("admin_password", "");

                // Get hostname from SQLite (already set during Install/Reinstall Mail Server)
                String mailHostname = Main.dbManager.getMailHostname();
                if (mailHostname == null) mailHostname = "";
                mailHostname = mailHostname.trim().toLowerCase();

                // Validate
                if (!SecurityUtils.isValidUsername(adminUsername)) {
                    response.put("success", false);
                    response.put("error", "Username non valido (3-50 caratteri alfanumerici)");
                } else if (!SecurityUtils.isValidPassword(adminPassword)) {
                    response.put("success", false);
                    response.put("error", "Password non valida (minimo 4 caratteri)");
                } else if (mailHostname.isEmpty() || !mailHostname.contains(".")) {
                    response.put("success", false);
                    response.put("error", "Hostname non configurato. Esegui 'Install/Reinstall Mail Server' dal terminale.");
                } else {
                    // Perform automatic setup
                    boolean success = Main.autoSetupDatabase(adminUsername, adminPassword, mailHostname);
                    response.put("success", success);
                    if (!success) {
                        response.put("error", "Setup automatico fallito. Verifica che MySQL sia in esecuzione.");
                    }
                }
            }
            case "setup_database" -> {
                // Legacy: Setup database with explicit passwords (kept for backward compatibility)
                String rootPassword = req.optString("root_password", "");
                String panelPassword = req.optString("panel_password", "");
                String adminUsername = req.optString("admin_username", "");
                String adminPassword = req.optString("admin_password", "");

                // Validate
                if (!SecurityUtils.isValidUsername(adminUsername)) {
                    response.put("success", false);
                    response.put("error", "Username non valido (3-50 caratteri alfanumerici)");
                } else if (!SecurityUtils.isValidPassword(adminPassword)) {
                    response.put("success", false);
                    response.put("error", "Password non valida (4-128 caratteri)");
                } else if (panelPassword.length() < 8) {
                    response.put("success", false);
                    response.put("error", "Password database deve essere almeno 8 caratteri");
                } else {
                    boolean success = Main.setupDatabase(rootPassword, panelPassword, adminUsername, adminPassword);
                    response.put("success", success);
                    if (!success) {
                        response.put("error", "Impossibile configurare il database. Verifica la password root.");
                    }
                }
            }
            case "check_mysql" -> {
                // Check if MySQL is running
                boolean running = checkServiceRunning("mysql-server");
                response.put("success", true);
                response.put("mysql_running", running);
            }
            default -> {
                response.put("success", false);
                response.put("error", "Azione sconosciuta");
            }
        }

        sendJsonResponse(exchange, response);
    }

    // ============== API HANDLERS ==============

    private void handleApiStatus(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        // Sync installed components based on actual package presence
        syncInstalledComponents();

        JSONObject status = new JSONObject();

        // Service status (check if running)
        status.put("postfix", checkServiceRunning("postfix"));
        status.put("dovecot", checkServiceRunning("dovecot"));
        status.put("rspamd", checkServiceRunning("rspamd"));
        status.put("clamav", checkServiceRunning("clamav_clamd"));
        status.put("mysql", checkServiceRunning("mysql-server"));
        status.put("redis", checkServiceRunning("redis"));
        status.put("roundcube", checkServiceRunning("nginx") && checkServiceRunning("php_fpm"));

        // Installed components from database (now synced)
        if (Main.mysqlAvailable) {
            status.put("installed_postfix", Main.mailDatabase.isComponentInstalled("postfix"));
            status.put("installed_dovecot", Main.mailDatabase.isComponentInstalled("dovecot"));
            status.put("installed_rspamd", Main.mailDatabase.isComponentInstalled("rspamd"));
            status.put("installed_roundcube", Main.mailDatabase.isComponentInstalled("roundcube"));
            status.put("installed_clamav", Main.mailDatabase.isComponentInstalled("clamav"));
            status.put("installed_redis", Main.mailDatabase.isComponentInstalled("redis"));

            // Stats
            status.put("domains", Main.mailDatabase.getDomainCount());
            status.put("mailboxes", Main.mailDatabase.getMailboxCount());
            status.put("aliases", Main.mailDatabase.getAliasCount());

            // Mail server hostname and IP for DNS warning on home page
            String mailHostname = Main.mailDatabase.getSetting("mail_hostname", "");
            status.put("mail_hostname", mailHostname);

            // Get server IP
            String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
            status.put("server_ip", serverIp);

            // SSL certificate mismatch check
            if (acmeManager != null && !mailHostname.isEmpty()) {
                AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                if (certInfo != null && certInfo.installed) {
                    String certCn = certInfo.commonName != null ? certInfo.commonName : "";
                    boolean sslMatch = certCn.equalsIgnoreCase(mailHostname);
                    // Also check SAN (Subject Alternative Names)
                    if (!sslMatch && certInfo.subjectAltNames != null) {
                        for (String san : certInfo.subjectAltNames) {
                            if (san.equalsIgnoreCase(mailHostname)) {
                                sslMatch = true;
                                break;
                            }
                        }
                    }
                    status.put("ssl_cn", certCn);
                    status.put("ssl_match", sslMatch);
                    status.put("ssl_self_signed", acmeManager.isSelfSigned());
                } else {
                    status.put("ssl_cn", "");
                    status.put("ssl_match", false);
                    status.put("ssl_self_signed", true);
                }
            }
        }

        sendJsonResponse(exchange, status);
    }

    private void handleApiDomains(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    JSONArray domains = new JSONArray();
                    for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                        JSONObject domainJson = new JSONObject();
                        domainJson.put("id", d.id);
                        domainJson.put("domain", d.domain);
                        domainJson.put("description", d.description != null ? d.description : "");
                        domainJson.put("active", d.active);
                        domainJson.put("mailbox_count", d.mailboxCount);
                        domainJson.put("alias_count", d.aliasCount);
                        domainJson.put("has_dkim", d.hasDkim);
                        domainJson.put("created_at", d.createdAt != null ? d.createdAt.toString() : "");
                        domains.put(domainJson);
                    }
                    response.put("success", true);
                    response.put("domains", domains);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Richiesta troppo grande");
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    String domain = req.optString("domain", "").toLowerCase().trim();
                    String description = req.optString("description", "");

                    if (!SecurityUtils.isValidDomain(domain)) {
                        response.put("success", false);
                        response.put("error", "Dominio non valido");
                    } else {
                        int id = Main.mailDatabase.addDomain(domain, description);
                        if (id > 0) {
                            response.put("success", true);
                            response.put("id", id);
                            logAudit("DOMAIN_CREATED", getClientIp(exchange), "Domain: " + domain);
                            // Regenerate configs
                            regenerateMailConfigs();
                        } else {
                            response.put("success", false);
                            response.put("error", "Dominio gia' esistente");
                        }
                    }
                }
                case "PUT" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Richiesta troppo grande");
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    int id = req.optInt("id", 0);
                    String description = req.optString("description", "");

                    if (id > 0) {
                        boolean updated = Main.mailDatabase.updateDomainDescription(id, description);
                        response.put("success", updated);
                        if (updated) {
                            logAudit("DOMAIN_UPDATED", getClientIp(exchange), "Domain ID: " + id);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "ID non valido");
                    }
                }
                case "DELETE" -> {
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        boolean deleted = Main.mailDatabase.deleteDomain(id);
                        response.put("success", deleted);
                        if (deleted) {
                            logAudit("DOMAIN_DELETED", getClientIp(exchange), "Domain ID: " + id);
                            regenerateMailConfigs();
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "ID non valido");
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiMailboxes(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    // Check if requesting a single mailbox by ID
                    String query = exchange.getRequestURI().getQuery();
                    int singleId = extractIdFromQuery(query);

                    if (singleId > 0) {
                        // Return single mailbox for editing
                        MailDatabase.Mailbox m = Main.mailDatabase.getMailbox(singleId);
                        if (m != null) {
                            JSONObject mbox = new JSONObject();
                            mbox.put("id", m.id);
                            mbox.put("email", m.email);
                            mbox.put("name", m.name != null ? m.name : "");
                            mbox.put("domain", m.domainName);
                            mbox.put("quota_mb", m.quotaMb);
                            mbox.put("active", m.active);
                            mbox.put("receive_enabled", m.receiveEnabled);
                            mbox.put("last_login", m.lastLogin != null ? m.lastLogin.toString() : "Mai");
                            // Flag: la casella ha una password archiviata nel vault?
                            // Usato dalla UI per mostrare/nascondere l'icona "rivela password".
                            try {
                                mbox.put("has_encrypted_password",
                                    Main.mailDatabase.mailboxHasEncryptedPassword(m.id));
                            } catch (Exception ignore) {
                                mbox.put("has_encrypted_password", false);
                            }
                            response.put("success", true);
                            response.put("mailbox", mbox);
                        } else {
                            response.put("success", false);
                            response.put("error", "Mailbox non trovata");
                        }
                    } else {
                        // Return all mailboxes
                        JSONArray mailboxes = new JSONArray();
                        for (MailDatabase.Mailbox m : Main.mailDatabase.getAllMailboxes()) {
                            JSONObject mbox = new JSONObject();
                            mbox.put("id", m.id);
                            mbox.put("email", m.email);
                            mbox.put("name", m.name != null ? m.name : "");
                            mbox.put("domain", m.domainName);
                            mbox.put("quota_mb", m.quotaMb);
                            mbox.put("active", m.active);
                            mbox.put("receive_enabled", m.receiveEnabled);
                            mbox.put("last_login", m.lastLogin != null ? m.lastLogin.toString() : "Mai");
                            mbox.put("autoresponder_enabled", m.autoresponderEnabled);
                            mbox.put("forwarding_count", m.forwardingCount);
                            mbox.put("filters_count", m.filtersCount);
                            mailboxes.put(mbox);
                        }
                        response.put("success", true);
                        response.put("mailboxes", mailboxes);
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Richiesta troppo grande");
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    // Sub-routing per action specifiche (no email/password richieste)
                    String action = req.optString("action", "");

                    if ("bulk_rotate_passwords".equals(action)) {
                        // Genera + aggiorna in massa le password di N caselle.
                        // Le password in chiaro tornano UNA SOLA volta nella response
                        // (perché poi vengono cifrate nel vault con la chiave master attuale).
                        //
                        // INPUT:
                        //   mailbox_ids: array di INT (oppure "all" come stringa per "tutte")
                        //   length:      lunghezza password (default 20)
                        //
                        // OUTPUT:
                        //   results: array di {id, email, password, success, error?}
                        //   summary: {total, succeeded, failed}
                        Object ids = req.opt("mailbox_ids");
                        java.util.List<Integer> idList = new java.util.ArrayList<>();
                        // Pattern matching for instanceof (Java 16+): la variabile 'idsArr'
                        // e' tipata e in scope solo nel branch dove serve.
                        if ("all".equals(ids)) {
                            for (MailDatabase.Mailbox m : Main.mailDatabase.getAllMailboxes()) idList.add(m.id);
                        } else if (ids instanceof org.json.JSONArray idsArr) {
                            for (int i = 0; i < idsArr.length(); i++) idList.add(idsArr.getInt(i));
                        }
                        if (idList.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Nessuna casella specificata (passa mailbox_ids: array o \"all\")");
                            sendJsonResponse(exchange, response);
                            return;
                        }
                        int length = req.optInt("length", 20);
                        // Opzioni avanzate (stesso schema di generate_password)
                        String type = req.optString("type", "easy_to_read");
                        boolean inclLo = req.optBoolean("include_lowercase", true);
                        boolean inclUp = req.optBoolean("include_uppercase", true);
                        boolean inclNu = req.optBoolean("include_numbers", true);
                        boolean inclSy = req.optBoolean("include_symbols", true);
                        org.mail_panel.security.PasswordVault vault = org.mail_panel.security.PasswordVault.getInstance();
                        org.json.JSONArray results = new org.json.JSONArray();
                        int succeeded = 0, failed = 0;
                        for (int mid : idList) {
                            org.json.JSONObject r = new org.json.JSONObject();
                            r.put("id", mid);
                            try {
                                MailDatabase.Mailbox mb = Main.mailDatabase.getMailbox(mid);
                                if (mb == null) {
                                    r.put("success", false);
                                    r.put("error", "non trovata");
                                    results.put(r);
                                    failed++;
                                    continue;
                                }
                                r.put("email", mb.email);
                                String pw = vault.generatePassword(length, type, inclLo, inclUp, inclNu, inclSy);
                                boolean ok = Main.mailDatabase.updateMailboxPassword(mid, pw);
                                if (ok) {
                                    r.put("success", true);
                                    r.put("password", pw);
                                    succeeded++;
                                    logAudit("MAILBOX_PASSWORD_BULK_ROTATED", getClientIp(exchange),
                                        "mailbox_id=" + mid + " email=" + mb.email);
                                } else {
                                    r.put("success", false);
                                    r.put("error", "update fallito");
                                    failed++;
                                }
                            } catch (Exception ex) {
                                r.put("success", false);
                                r.put("error", ex.getMessage());
                                failed++;
                            }
                            results.put(r);
                        }
                        try { regenerateMailConfigs(); } catch (Exception ignore) {}
                        response.put("success", true);
                        response.put("results", results);
                        org.json.JSONObject summary = new org.json.JSONObject();
                        summary.put("total", idList.size());
                        summary.put("succeeded", succeeded);
                        summary.put("failed", failed);
                        response.put("summary", summary);
                        response.put("warning",
                            "Le password in chiaro sono mostrate UNA SOLA volta — copia e inoltra agli utenti subito. " +
                            "Poi resteranno solo nel vault cifrato (se la chiave master è valida).");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    if ("generate_password".equals(action)) {
                        // Genera una password sicura random — non la salva, solo la ritorna alla UI.
                        // Accetta opzioni avanzate (type, include lower/upper/numbers/symbols).
                        int len = req.optInt("length", 20);
                        String type = req.optString("type", "easy_to_read"); // easy_to_say / easy_to_read / all_chars
                        boolean lo = req.optBoolean("include_lowercase", true);
                        boolean up = req.optBoolean("include_uppercase", true);
                        boolean nu = req.optBoolean("include_numbers", true);
                        boolean sy = req.optBoolean("include_symbols", true);
                        String pw = org.mail_panel.security.PasswordVault.getInstance()
                            .generatePassword(len, type, lo, up, nu, sy);
                        response.put("success", true);
                        response.put("password", pw);
                        response.put("length", pw.length());
                        response.put("type", type);
                        // Stima entropia approssimata (per UI: "strong/very strong/weak")
                        int poolSize = 0;
                        if ("easy_to_say".equals(type)) {
                            if (lo) poolSize += 26;
                            if (up) poolSize += 26;
                        } else if ("all_chars".equals(type)) {
                            if (lo) poolSize += 26;
                            if (up) poolSize += 26;
                            if (nu) poolSize += 10;
                            if (sy) poolSize += 30; // approx
                        } else { // easy_to_read
                            if (lo) poolSize += 24; // no l, o
                            if (up) poolSize += 24; // no I, O
                            if (nu) poolSize += 8;  // no 0, 1
                            if (sy) poolSize += 18; // safe set
                        }
                        double entropy = org.mail_panel.security.PasswordVault.estimateEntropy(pw.length(), poolSize);
                        response.put("entropy_bits", Math.round(entropy * 10.0) / 10.0);
                        String strengthLabel;
                        if (entropy < 50) strengthLabel = "Debole";
                        else if (entropy < 75) strengthLabel = "Discreta";
                        else if (entropy < 100) strengthLabel = "Forte";
                        else strengthLabel = "Molto forte";
                        response.put("strength_label", strengthLabel);
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    if ("reveal_password".equals(action)) {
                        // Decifra la password archiviata per la casella specificata.
                        // Audit log: tracciamo SEMPRE chi e quando rivela una password.
                        int mid = req.optInt("id", 0);
                        if (mid <= 0) {
                            response.put("success", false);
                            response.put("error", "ID casella mancante");
                            sendJsonResponse(exchange, response);
                            return;
                        }
                        MailDatabase.Mailbox mbox = Main.mailDatabase.getMailbox(mid);
                        if (mbox == null) {
                            response.put("success", false);
                            response.put("error", "Casella non trovata");
                            sendJsonResponse(exchange, response);
                            return;
                        }
                        String encrypted = Main.mailDatabase.getMailboxPasswordEncrypted(mid);
                        if (encrypted == null || encrypted.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Nessuna password archiviata per questa casella. " +
                                "Il vault delle password si popola solo a partire dalla prossima modifica/creazione. " +
                                "Genera una nuova password per attivare la feature.");
                            logAudit("MAILBOX_PASSWORD_REVEAL_NOT_AVAILABLE",
                                getClientIp(exchange), "mailbox_id=" + mid + " email=" + mbox.email);
                            sendJsonResponse(exchange, response);
                            return;
                        }
                        try {
                            String plain = org.mail_panel.security.PasswordVault.getInstance().decrypt(encrypted);
                            response.put("success", true);
                            response.put("password", plain);
                            logAudit("MAILBOX_PASSWORD_REVEALED",
                                getClientIp(exchange), "mailbox_id=" + mid + " email=" + mbox.email);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", "Errore decifratura: " + e.getMessage()
                                + ". Probabile chiave master cambiata o blob corrotto.");
                            logAudit("MAILBOX_PASSWORD_REVEAL_FAILED",
                                getClientIp(exchange), "mailbox_id=" + mid + " email=" + mbox.email
                                + " error=" + e.getMessage());
                        }
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Default: creazione casella (codice esistente)
                    String email = req.optString("email", "").toLowerCase().trim();
                    String password = req.optString("password", "");
                    String name = req.optString("name", "");
                    int quotaMb = req.optInt("quota_mb", 1024);
                    boolean receiveEnabled = req.optBoolean("receive_enabled", true);

                    if (!SecurityUtils.isValidEmail(email)) {
                        response.put("success", false);
                        response.put("error", "Email non valida");
                    } else if (!SecurityUtils.isValidPassword(password)) {
                        response.put("success", false);
                        response.put("error", "Password non valida");
                    } else {
                        // Extract domain from email
                        String domainName = email.substring(email.indexOf("@") + 1);
                        MailDatabase.Domain domain = Main.mailDatabase.getDomainByName(domainName);

                        if (domain == null) {
                            response.put("success", false);
                            response.put("error", "Dominio non esistente: " + domainName);
                        } else {
                            int id = Main.mailDatabase.addMailbox(domain.id, email, password, name, quotaMb, receiveEnabled);
                            if (id > 0) {
                                response.put("success", true);
                                response.put("id", id);
                                regenerateMailConfigs();
                            } else {
                                response.put("success", false);
                                response.put("error", "Mailbox gia' esistente");
                            }
                        }
                    }
                }
                case "PUT" -> {
                    // Update existing mailbox
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Richiesta troppo grande");
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    int id = req.optInt("id", 0);
                    if (id <= 0) {
                        response.put("success", false);
                        response.put("error", "ID mailbox non valido");
                    } else {
                        String name = req.optString("name", "");
                        int quotaMb = req.optInt("quota_mb", 1024);  // 0 = unlimited
                        boolean active = req.optBoolean("active", true);
                        boolean receiveEnabled = req.optBoolean("receive_enabled", true);
                        String newPassword = req.optString("password", "");

                        // Update mailbox
                        boolean updated = Main.mailDatabase.updateMailbox(id, name, quotaMb, active, receiveEnabled);

                        // If password provided, update it too
                        if (updated && !newPassword.isEmpty()) {
                            if (SecurityUtils.isValidPassword(newPassword)) {
                                Main.mailDatabase.updateMailboxPassword(id, newPassword);
                            } else {
                                response.put("warning", "Password non valida, non aggiornata");
                            }
                        }

                        if (updated) {
                            response.put("success", true);
                            response.put("message", "Mailbox aggiornata");
                            regenerateMailConfigs();
                        } else {
                            response.put("success", false);
                            response.put("error", "Errore aggiornamento mailbox");
                        }
                    }
                }
                case "DELETE" -> {
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        boolean deleted = Main.mailDatabase.deleteMailbox(id);
                        response.put("success", deleted);
                        if (deleted) regenerateMailConfigs();
                    } else {
                        response.put("success", false);
                        response.put("error", "ID non valido");
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * API endpoint for mail client configuration info
     * Returns IMAP/SMTP/POP3 settings for configuring email clients
     */
    private void handleApiMailConfig(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        JSONObject response = new JSONObject();

        try {
            // Get mail server hostname from SQLite config
            String mailServer = Main.dbManager.getMailHostname();
            if (mailServer == null || mailServer.isEmpty()) {
                mailServer = "mail.example.com";
            }

            response.put("success", true);
            response.put("server", mailServer);

            // IMAP Configuration
            JSONObject imap = new JSONObject();
            imap.put("server", mailServer);
            imap.put("port_ssl", 993);
            imap.put("port_starttls", 143);
            imap.put("security", "SSL/TLS");
            imap.put("auth_method", "Password normale");
            response.put("imap", imap);

            // POP3 Configuration
            JSONObject pop3 = new JSONObject();
            pop3.put("server", mailServer);
            pop3.put("port_ssl", 995);
            pop3.put("port_starttls", 110);
            pop3.put("security", "SSL/TLS");
            pop3.put("auth_method", "Password normale");
            response.put("pop3", pop3);

            // SMTP Configuration
            JSONObject smtp = new JSONObject();
            smtp.put("server", mailServer);
            smtp.put("port_ssl", 465);
            smtp.put("port_starttls", 587);
            smtp.put("security", "STARTTLS");
            smtp.put("auth_method", "Password normale");
            response.put("smtp", smtp);

            // General info
            response.put("username_format", "email completa (es: utente@dominio.it)");
            response.put("password_info", "La password dell'account email");

            // Client-specific instructions
            JSONObject clients = new JSONObject();

            // Outlook
            JSONObject outlook = new JSONObject();
            outlook.put("name", "Microsoft Outlook");
            outlook.put("imap_port", 993);
            outlook.put("smtp_port", 587);
            outlook.put("security", "SSL/TLS per IMAP, STARTTLS per SMTP");
            clients.put("outlook", outlook);

            // Thunderbird
            JSONObject thunderbird = new JSONObject();
            thunderbird.put("name", "Mozilla Thunderbird");
            thunderbird.put("imap_port", 993);
            thunderbird.put("smtp_port", 587);
            thunderbird.put("security", "SSL/TLS per IMAP, STARTTLS per SMTP");
            thunderbird.put("note", "Thunderbird auto-rileva le impostazioni");
            clients.put("thunderbird", thunderbird);

            // Apple Mail
            JSONObject appleMail = new JSONObject();
            appleMail.put("name", "Apple Mail (macOS/iOS)");
            appleMail.put("imap_port", 993);
            appleMail.put("smtp_port", 587);
            appleMail.put("security", "SSL per IMAP, STARTTLS per SMTP");
            clients.put("apple", appleMail);

            // Android
            JSONObject android = new JSONObject();
            android.put("name", "Gmail App / Android");
            android.put("imap_port", 993);
            android.put("smtp_port", 587);
            android.put("security", "SSL/TLS");
            android.put("note", "Seleziona 'Altro' quando aggiungi account");
            clients.put("android", android);

            response.put("clients", clients);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiAliases(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    JSONArray aliases = new JSONArray();
                    for (MailDatabase.Alias a : Main.mailDatabase.getAllAliases()) {
                        JSONObject alias = new JSONObject();
                        alias.put("id", a.id);
                        alias.put("source", a.source);
                        alias.put("destination", a.destination);
                        alias.put("domain", a.domainName);
                        alias.put("active", a.active);
                        aliases.put(alias);
                    }
                    response.put("success", true);
                    response.put("aliases", aliases);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Richiesta troppo grande");
                        return;
                    }
                    JSONObject req = new JSONObject(body);

                    // Validate CSRF token
                    if (!validateCsrfForRequest(exchange, req)) {
                        sendCsrfError(exchange);
                        return;
                    }

                    String source = req.optString("source", "").toLowerCase().trim();
                    String destination = req.optString("destination", "").toLowerCase().trim();

                    if (!SecurityUtils.isValidEmail(source) || !SecurityUtils.isValidEmail(destination)) {
                        response.put("success", false);
                        response.put("error", "Email non valida");
                    } else {
                        String domainName = source.substring(source.indexOf("@") + 1);
                        MailDatabase.Domain domain = Main.mailDatabase.getDomainByName(domainName);

                        if (domain == null) {
                            response.put("success", false);
                            response.put("error", "Dominio non esistente: " + domainName);
                        } else {
                            int id = Main.mailDatabase.addAlias(domain.id, source, destination);
                            if (id > 0) {
                                response.put("success", true);
                                response.put("id", id);
                                logAudit("ALIAS_CREATED", getClientIp(exchange), source + " -> " + destination);
                                regenerateMailConfigs();
                            } else {
                                response.put("success", false);
                                response.put("error", "Alias gia' esistente");
                            }
                        }
                    }
                }
                case "DELETE" -> {
                    String query = exchange.getRequestURI().getQuery();
                    int id = extractIdFromQuery(query);
                    if (id > 0) {
                        boolean deleted = Main.mailDatabase.deleteAlias(id);
                        response.put("success", deleted);
                        if (deleted) {
                            logAudit("ALIAS_DELETED", getClientIp(exchange), "Alias ID: " + id);
                            regenerateMailConfigs();
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "ID non valido");
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiWebmail(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
        JSONObject req = new JSONObject(body);
        int mailboxId = req.optInt("mailbox_id", 0);

        JSONObject response = new JSONObject();

        try {
            if (mailboxId > 0) {
                String token = Main.mailDatabase.createAutoLoginToken(mailboxId);
                response.put("success", true);
                response.put("url", "/roundcube/?_autologin=" + token);
            } else {
                response.put("success", false);
                response.put("error", "ID mailbox non valido");
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiService(HttpExchange exchange) throws IOException {
        try {
            if (!isAuthenticated(exchange)) {
                sendJsonError(exchange, 401, "Unauthorized");
                return;
            }

            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Richiesta troppo grande");
                return;
            }
            JSONObject req = new JSONObject(body);
            String service = req.optString("service", "");
            String action = req.optString("action", "");

            System.out.println("[SERVICE] Request: " + action + " " + service);

            // Validate service name and normalize
            // Accept both "clamav" and "clamav_clamd" for ClamAV
            if (service.equals("clamav")) {
                service = "clamav_clamd";
            }
            if (!Set.of("postfix", "dovecot", "rspamd", "clamav_clamd", "redis", "mysql-server", "roundcube").contains(service)) {
                System.out.println("[SERVICE] Invalid service: " + service);
                sendJsonError(exchange, 400, "Servizio non valido: " + service);
                return;
            }

            // Validate action
            if (!Set.of("start", "stop", "restart").contains(action)) {
                System.out.println("[SERVICE] Invalid action: " + action);
                sendJsonError(exchange, 400, "Azione non valida: " + action);
                return;
            }

            boolean success;
            // Roundcube uses nginx + php_fpm, handle specially
            if (service.equals("roundcube")) {
                boolean phpSuccess = executeServiceCommand("php_fpm", action);
                boolean nginxSuccess = executeServiceCommand("nginx", action);
                success = phpSuccess && nginxSuccess;
            } else {
                success = executeServiceCommand(service, action);
            }
            System.out.println("[SERVICE] Result: " + (success ? "OK" : "FAILED"));

            JSONObject response = new JSONObject();
            response.put("success", success);
            if (!success) {
                response.put("error", "Comando fallito: service " + service + " " + action);
            }
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            System.err.println("[SERVICE] Exception: " + e.getMessage());
            e.printStackTrace();
            sendJsonError(exchange, 500, "Errore interno: " + e.getMessage());
        }
    }

    /**
     * Esegue un'installazione di pacchetti sul turno dei lavori sui pacchetti (vedi
     * TurnoPacchetti): uno alla volta. Se un altro lavoro sta cambiando i pacchetti, o c'e'
     * l'elenco di uno che non si e' chiuso, non parte e la risposta dice perche'.
     */
    private static JSONObject sulTurnoPacchetti(String descrizione, java.util.function.Supplier<JSONObject> lavoro) {
        String id = "installa-" + System.nanoTime();
        String rifiuto = org.mail_panel.system.TurnoPacchetti.prendi(id, descrizione);
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto).put("message", rifiuto);
        try { return lavoro.get(); }
        finally { org.mail_panel.system.TurnoPacchetti.rilascia(id); }
    }

    private void handleApiInstall(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
        JSONObject req = new JSONObject(body);
        String component = req.optString("component", "");

        String scriptContent = switch (component) {
            // System configuration (run first)
            case "timezone" -> new SetTimeOnSystem().getScriptContent();
            // Mail components
            case "postfix" -> new PostfixScript().getScriptContent();
            case "dovecot" -> new DovecotScript().getScriptContent();
            case "roundcube" -> new RoundcubeScript().getScriptContent();
            case "rspamd" -> new RspamdScript().getScriptContent();
            case "clamav" -> new ClamAVScript().getScriptContent();
            case "redis" -> new RedisScript().getScriptContent();
            case "all" -> new FullMailStackScript().getScriptContent();
            default -> null;
        };

        JSONObject response = new JSONObject();
        if (scriptContent == null) {
            response.put("success", false);
            response.put("error", "Componente sconosciuto");
        } else {
            // Gli script dei componenti tolgono e rimettono pacchetti: aspettano il turno dei
            // lavori sui pacchetti. Il fuso orario no.
            final String script = scriptContent;
            java.util.function.Supplier<JSONObject> installa = () -> {
                JSONObject r = new JSONObject();
                try {
                    String output = executeScript(script, component);
                    Main.mailDatabase.markComponentInstalled(component, "latest");
                    r.put("success", true).put("output", output);
                } catch (Exception e) {
                    r.put("success", false).put("error", e.getMessage());
                }
                return r;
            };
            response = "timezone".equals(component) ? installa.get()
                     : sulTurnoPacchetti("installazione di " + component, installa);
        }

        sendJsonResponse(exchange, response);
    }

    // ============== HELPER METHODS ==============

    private int extractIdFromQuery(String query) {
        if (query == null) return -1;
        for (String param : query.split("&")) {
            if (param.startsWith("id=")) {
                try {
                    return Integer.parseInt(param.substring(3));
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        }
        return -1;
    }

    private void regenerateMailConfigs() {
        try {
            if (Main.mailDatabase != null && Main.mysqlAvailable) {
                String script = new ConfigRegeneratorScript(Main.mailDatabase).getScriptContent();
                executeScript(script, "config_regen");
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to regenerate mail configs", e);
        }
    }

    private boolean checkServiceRunning(String serviceName) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", serviceName, "status");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // Read output
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // Timeout of 5 seconds to prevent hanging
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                System.out.println("[STATUS] " + serviceName + ": TIMEOUT");
                return false;
            }

            int exitCode = p.exitValue();
            String out = output.toString().trim();
            System.out.println("[STATUS] " + serviceName + ": exit=" + exitCode + ", output=" + out);

            // Some services return non-zero but are running (check output for "running")
            if (exitCode == 0) {
                return true;
            }
            // Fallback: check if output contains "running" or "is running"
            return out.toLowerCase().contains("running");
        } catch (Exception e) {
            System.out.println("[STATUS] " + serviceName + ": exception=" + e.getMessage());
            return false;
        }
    }

    /**
     * Check if a package is installed on FreeBSD using pkg info
     */
    private boolean checkPackageInstalled(String packageName) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("pkg", "info", "-e", packageName);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if any package matching a pattern is installed (for flavored packages like roundcube-php*)
     */
    private boolean checkPackageInstalledByPattern(String pattern) {
        try {
            // SECURITY: pattern arriva da chiamate interne con costanti, ma defense-in-depth:
            // accetta solo lettere, numeri, dash, underscore, dot, asterisco e percent
            // (caratteri tipici dei nomi pacchetti pkg). Blocca apici, ;, |, &, $, backtick.
            if (pattern == null || !pattern.matches("^[a-zA-Z0-9._%*-]+$")) {
                return false;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "pkg info | grep -q '^" + pattern + "'");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Sync installed components based on actual package presence on the system.
     * This ensures the database reflects reality when installation was done via terminal.
     *
     * IMPORTANT: For Postfix, we also check postfix-mysql because without it,
     * Postfix cannot use MySQL for virtual mailboxes and will fail with
     * "unsupported dictionary type: mysql"
     */
    private void syncInstalledComponents() {
        if (!Main.mysqlAvailable) return;

        // Standard packages (exact name match)
        // Format: {componentName, packageName}
        String[][] components = {
            {"rspamd", "rspamd"},
            {"clamav", "clamav"},
            {"redis", "redis"}
        };

        for (String[] comp : components) {
            String componentName = comp[0];
            String packageName = comp[1];

            boolean isInstalled = checkPackageInstalled(packageName);
            boolean markedInstalled = Main.mailDatabase.isComponentInstalled(componentName);

            if (isInstalled && !markedInstalled) {
                Main.mailDatabase.markComponentInstalled(componentName, "auto-detected");
                System.out.println("[SYNC] Marked " + componentName + " as installed (detected via pkg)");
            }
        }

        // Dovecot: check for dovecot-mysql (required for SQL auth) or base dovecot
        // On FreeBSD, dovecot-mysql REPLACES dovecot package
        boolean dovecotInstalled = checkPackageInstalled("dovecot");
        boolean dovecotMysqlInstalled = checkPackageInstalled("dovecot-mysql");
        boolean dovecotMarked = Main.mailDatabase.isComponentInstalled("dovecot");

        // dovecot-mysql is preferred as it includes SQL authentication support
        if (dovecotMysqlInstalled && !dovecotMarked) {
            Main.mailDatabase.markComponentInstalled("dovecot", "auto-detected");
            System.out.println("[SYNC] Marked dovecot as installed (dovecot-mysql detected)");
        } else if (dovecotInstalled && !dovecotMysqlInstalled) {
            // Plain dovecot without MySQL support - SQL auth won't work!
            System.out.println("[SYNC] WARNING: dovecot installed but dovecot-mysql is MISSING!");
            System.out.println("[SYNC] SQL authentication will fail. Run: pkg install dovecot-mysql");
            if (dovecotMarked) {
                Main.mailDatabase.markComponentUninstalled("dovecot");
                System.out.println("[SYNC] Unmarked dovecot as installed (dovecot-mysql missing)");
            }
        }

        // Special handling for Postfix:
        // On FreeBSD, postfix-mysql REPLACES postfix package, so we need to check for either.
        // If only postfix is installed (without mysql), virtual mailbox lookups will fail.
        boolean postfixInstalled = checkPackageInstalled("postfix");
        boolean postfixMysqlInstalled = checkPackageInstalled("postfix-mysql");
        boolean postfixMarked = Main.mailDatabase.isComponentInstalled("postfix");

        // postfix-mysql includes full postfix functionality + MySQL support
        if (postfixMysqlInstalled && !postfixMarked) {
            Main.mailDatabase.markComponentInstalled("postfix", "auto-detected");
            System.out.println("[SYNC] Marked postfix as installed (postfix-mysql detected)");
        } else if (postfixInstalled && !postfixMysqlInstalled) {
            // Plain postfix without MySQL support - this won't work for virtual mailboxes!
            System.out.println("[SYNC] WARNING: postfix installed but postfix-mysql is MISSING!");
            System.out.println("[SYNC] Virtual mailbox lookups will fail. Run: pkg install postfix-mysql");
            // Do NOT mark as installed since it's incomplete for our use case
            if (postfixMarked) {
                Main.mailDatabase.markComponentUninstalled("postfix");
                System.out.println("[SYNC] Unmarked postfix as installed (postfix-mysql missing)");
            }
        }

        // Roundcube is a flavored package (roundcube-php81, roundcube-php82, roundcube-php83, etc.)
        boolean roundcubeInstalled = checkPackageInstalledByPattern("roundcube-php");
        boolean roundcubeMarked = Main.mailDatabase.isComponentInstalled("roundcube");
        if (roundcubeInstalled && !roundcubeMarked) {
            Main.mailDatabase.markComponentInstalled("roundcube", "auto-detected");
            System.out.println("[SYNC] Marked roundcube as installed (detected via pkg pattern)");
        }
    }

    private boolean executeServiceCommand(String service, String action) {
        try {
            System.out.println("[EXEC] Running: service " + service + " " + action);
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", service, action);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            // Read output
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            // Timeout of 30 seconds for service commands
            boolean finished = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                System.out.println("[EXEC] Timeout! Killing process");
                p.destroyForcibly();
                return false;
            }

            int exitCode = p.exitValue();
            System.out.println("[EXEC] Exit code: " + exitCode);
            if (output.length() > 0) {
                System.out.println("[EXEC] Output: " + output.toString().trim());
            }
            return exitCode == 0;
        } catch (Exception e) {
            System.err.println("[EXEC] Exception: " + e.getMessage());
            return false;
        }
    }

    private String executeScript(String scriptContent, String scriptName) throws Exception {
        String jarDir = getJarDirectory();
        Path scriptPath = Paths.get(jarDir, "install_scripts", "install_" + scriptName + ".sh");
        Files.createDirectories(scriptPath.getParent());
        Files.writeString(scriptPath, scriptContent);
        scriptPath.toFile().setExecutable(true);

        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", scriptPath.toString());
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

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Script failed with exit code " + exitCode + "\n" + output);
        }

        return output.toString();
    }

    private String readHtmlFile(String filename) {
        try {
            String jarDir = getJarDirectory();
            Path filePath = Paths.get(jarDir, "admin", filename);
            if (Files.exists(filePath)) {
                return Files.readString(filePath);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not read HTML file: " + filename, e);
        }
        return "<html><body><h1>Page not found</h1></body></html>";
    }

    /**
     * Serve i file statici dalle risorse del jar: Font Awesome sotto /fa, Bootstrap e
     * Chart.js sotto /vendor.
     *
     * Prima arrivavano da un CDN, fermi alla 6.0.0-beta3, dove due delle icone usate non
     * esistevano affatto. Ora viaggiano dentro il jar (356 KB in tutto): il pannello non
     * dipende piu' da un sito esterno, e la versione e' quella scelta, non quella che
     * l'indirizzo del CDN si porta dietro.
     *
     * Il percorso richiesto viene ripulito prima di essere usato: e' l'unico punto del
     * pannello in cui una stringa che arriva dalla rete diventa il nome di una risorsa da
     * leggere, quindi "../" e i nomi strani non devono passare.
     */
    /**
     * Il file che Thunderbird cerca da solo. Nessuna autenticazione: e' il client a chiederlo
     * prima di sapere qualsiasi cosa dell'utente.
     *
     * Il dominio si ricava dal parametro emailaddress, e in mancanza dall'intestazione Host
     * che nginx passa avanti. In entrambi i casi viene confrontato con l'elenco dei domini
     * gestiti: se non e' uno di quelli, 404. Cosi' il valore che arriva da fuori non finisce
     * mai dentro il file: quello che si scrive e' sempre il nome preso dal database.
     */
    private void handleAutoconfigPubblico(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            if (!"/autoconfig/mail/config-v1.1.xml".equals(path)) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            String indirizzo = parametro(exchange.getRequestURI().getRawQuery(), "emailaddress");
            String candidato = org.mail_panel.system.Autoconfig.dominioDaIndirizzo(indirizzo);
            if (candidato == null) {
                java.util.List<String> host = exchange.getRequestHeaders().get("Host");
                if (host != null && !host.isEmpty()) candidato = host.get(0);
            }

            String dominio = org.mail_panel.system.Autoconfig.dominioGestito(candidato);
            String hostPosta = org.mail_panel.system.Autoconfig.hostDiPosta();
            if (dominio == null || hostPosta == null || hostPosta.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }

            byte[] dati = org.mail_panel.system.Autoconfig.xml(dominio, hostPosta)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/xml; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
            exchange.sendResponseHeaders(200, dati.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(dati); }
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    /** Un parametro dalla query, senza portarsi dietro una libreria per farlo. */
    private static String parametro(String query, String nome) {
        if (query == null || query.isEmpty()) return null;
        for (String coppia : query.split("&")) {
            int i = coppia.indexOf('=');
            if (i <= 0) continue;
            if (!java.net.URLDecoder.decode(coppia.substring(0, i),
                    java.nio.charset.StandardCharsets.UTF_8).equals(nome)) continue;
            return java.net.URLDecoder.decode(coppia.substring(i + 1),
                    java.nio.charset.StandardCharsets.UTF_8);
        }
        return null;
    }

    /**
     * La politica MTA-STS, come la chiede un server mittente. Il dominio si ricava
     * dall'intestazione Host che nginx passa avanti, e viene confrontato con l'elenco dei
     * domini gestiti: se non e' uno di quelli, 404.
     */
    private void handleMtaStsPubblico(HttpExchange exchange) throws IOException {
        try {
            if (!"/mta-sts/policy".equals(exchange.getRequestURI().getPath())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            java.util.List<String> host = exchange.getRequestHeaders().get("Host");
            String dominio = org.mail_panel.system.MtaSts.dominioGestito(
                    host == null || host.isEmpty() ? null : host.get(0));
            String mail = org.mail_panel.system.MtaSts.hostDiPosta();
            if (dominio == null || mail == null || mail.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            String modo = org.mail_panel.system.MtaSts.modoCorrente();
            byte[] dati = org.mail_panel.system.MtaSts
                    .politica(mail, modo, org.mail_panel.system.MtaSts.maxAgeConsigliato(modo))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "public, max-age=3600");
            exchange.sendResponseHeaders(200, dati.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(dati); }
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    private void handleApiAutoconfig(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, "Method not allowed"); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, "JSON non valido"); return; }

        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = org.mail_panel.system.Autoconfig.stato();
            case "preview" -> response = org.mail_panel.system.Autoconfig.anteprima();
            case "install" -> {
                if (!"INSTALLA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = org.mail_panel.system.Autoconfig.installa();
                logAudit("AUTOCONFIG_INSTALL", ip, response.optBoolean("success")
                        ? "nginx configurato" : "NON configurato: " + response.optString("error", "?"));
            }
            default -> response = new JSONObject().put("success", false).put("error", "azione sconosciuta");
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Scarica il profilo di configurazione per Apple Mail. E' una GET perche' deve essere un
     * link che il browser scarica, ma richiede la sessione: il profilo contiene il nome di
     * una casella, e non ha motivo di essere pubblico. Non contiene la password.
     */
    private void handleScaricaProfiloApple(HttpExchange exchange) throws IOException {
        try {
            if (!isAuthenticated(exchange)) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            String email = parametro(exchange.getRequestURI().getRawQuery(), "email");
            var casella = org.mail_panel.system.ProfiloApple.casella(email);
            String host = org.mail_panel.system.ProfiloApple.hostDiPosta();
            if (casella == null || host == null || host.isBlank()) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            String profilo = org.mail_panel.system.ProfiloApple
                    .mobileconfig(casella.email(), casella.nome(), host, host);
            if (!org.mail_panel.system.ProfiloApple.benFormato(profilo)) {
                // Non si consegna un file rotto: Mail lo rifiuterebbe senza spiegare perche'.
                exchange.sendResponseHeaders(500, -1);
                return;
            }
            byte[] dati = profilo.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            String nome = org.mail_panel.system.ProfiloApple.nomeFile(casella.email());
            exchange.getResponseHeaders().set("Content-Type", "application/x-apple-aspen-config");
            exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + nome + "\"");
            exchange.sendResponseHeaders(200, dati.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) { os.write(dati); }
            logAudit("PROFILO_APPLE", getClientIp(exchange), "scaricato per " + casella.email());
        } catch (Exception e) {
            try { exchange.sendResponseHeaders(500, -1); } catch (Exception ignore) {}
        } finally {
            exchange.close();
        }
    }

    private void handleApiProfiloApple(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, "Method not allowed"); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, "JSON non valido"); return; }

        JSONObject response = switch (req.optString("action", "")) {
            case "status" -> org.mail_panel.system.ProfiloApple.stato();
            case "preview" -> org.mail_panel.system.ProfiloApple.anteprima(req.optString("email", ""));
            default -> new JSONObject().put("success", false).put("error", "azione sconosciuta");
        };
        sendJsonResponse(exchange, response);
    }

    private void handleStatico(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String risorsa = null;
        if (path.startsWith("/fa/")) {
            String rel = path.substring(4);                        // css/... oppure webfonts/...
            if (rel.matches("(css|webfonts)/[A-Za-z0-9._-]{1,64}")) risorsa = "/fa/" + rel;
        } else if (path.startsWith("/vendor/")) {
            String rel = path.substring(8);                        // un solo livello, nessuna cartella
            if (rel.matches("[A-Za-z0-9._-]{1,64}")) risorsa = "/vendor/" + rel;
        }
        if (risorsa == null) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        String tipo = risorsa.endsWith(".css") ? "text/css; charset=UTF-8"
                    : risorsa.endsWith(".js") ? "application/javascript; charset=UTF-8"
                    : risorsa.endsWith(".woff2") ? "font/woff2"
                    : risorsa.endsWith(".woff") ? "font/woff"
                    : risorsa.endsWith(".ttf") ? "font/ttf"
                    : "application/octet-stream";
        byte[] dati;
        try (java.io.InputStream in = getClass().getResourceAsStream(risorsa)) {
            if (in == null) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            dati = in.readAllBytes();
        }
        exchange.getResponseHeaders().add("Content-Type", tipo);
        exchange.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
        // Il contenuto cambia solo quando cambia il jar: si puo' tenere in cache a lungo.
        exchange.getResponseHeaders().add("Cache-Control", "public, max-age=604800");
        exchange.sendResponseHeaders(200, dati.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(dati);
        }
    }

    private void sendHtml(HttpExchange exchange, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, JSONObject json) throws IOException {
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonError(HttpExchange exchange, int code, String message) throws IOException {
        JSONObject error = new JSONObject().put("error", message);
        byte[] bytes = error.toString().getBytes(StandardCharsets.UTF_8);
        addSecurityHeaders(exchange);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        exchange.sendResponseHeaders(302, -1);
    }

    private void addSecurityHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("X-XSS-Protection", "1; mode=block");
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
        headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
        // HSTS: un anno di solo-HTTPS per questo nome, sottodomini compresi.
        //
        // Il token "preload" c'era ed e' stato tolto il 02/09/2026. Non faceva niente: la lista
        // di preload e' compilata dentro il browser, e servire il token e' solo un REQUISITO per
        // candidarsi — la candidatura va presentata a hstspreload.org. Verificato quel giorno:
        // ne' domain-b.test ne' mail.domain-b.test risultano nella lista ("status": "unknown").
        // Era quindi una dichiarazione pubblica mai presentata: la stessa forma del record TXT
        // MTA-STS pubblicato senza una politica che risponde.
        //
        // E toglierlo protegge dal caso peggiore: che un domani qualcuno candidi il dominio
        // vedendo il token gia' li'. Da quel momento la regola vive dentro il binario dei
        // browser, e rimuoverla richiede mesi — mentre qui basta che il certificato del
        // pannello si rompa una volta per restare fuori proprio quando serve entrare a
        // ripararlo (HSTS toglie il "prosegui comunque" sugli avvisi di certificato).
        //
        // Cosa resta, e perche': max-age si rinnova a ogni visita e includeSubDomains vale per
        // i sottodomini di QUESTO nome. Si tengono perche' il certificato si rinnova da solo e
        // il pannello ne sorveglia la scadenza. Nota: la regola e' per NOME, non per porta
        // (RFC 6797 §8.1), quindi servita dalla 2096 vale per quel nome ovunque.
        headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        // Content Security Policy - Restrict resource loading
        headers.set("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "style-src-elem 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'");
        // Permissions Policy - Disable unnecessary features
        headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    }

    /** Converte ISO LocalDateTime in formato leggibile italiano, ritorna "Mai" se vuoto */
    private static String humanizeDateTime(String iso) {
        if (iso == null || iso.isEmpty()) return "Mai";
        try {
            java.time.LocalDateTime dt = java.time.LocalDateTime.parse(iso);
            java.time.Duration diff = java.time.Duration.between(dt, java.time.LocalDateTime.now());
            String formatted = dt.format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"));
            long minutes = diff.toMinutes();
            if (minutes < 1)        return formatted + " (poco fa)";
            else if (minutes < 60)  return formatted + " (" + minutes + " min fa)";
            else if (minutes < 1440) return formatted + " (" + (minutes/60) + "h fa)";
            else                    return formatted + " (" + (minutes/1440) + "g fa)";
        } catch (Exception e) {
            return iso;
        }
    }

    private static String escapeHtmlSimple(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String getJarDirectory() {
        try {
            String jarPath = SSLMailServer.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            return new File(jarPath).getParent();
        } catch (Exception e) {
            return System.getProperty("user.dir");
        }
    }

    // ============== DKIM API ==============

    /**
     * Serializza un {@link java.sql.Timestamp} in ISO 8601 UTC ("2026-05-15T21:00:00Z").
     * Costruito dall'epoch milliseconds, bypassando completamente la timezone del JVM.
     */
    private static String tsIso(java.sql.Timestamp ts) {
        return ts == null ? null : java.time.Instant.ofEpochMilli(ts.getTime()).toString();
    }

    /**
     * Helper per scrivere un timestamp in JSON con DUE campi:
     *   key       → ISO 8601 UTC ("2026-05-15T21:00:00Z")
     *   key + "_ms" → epoch milliseconds (long, unambiguo)
     * Il browser preferisce _ms se presente, altrimenti il fallback ISO.
     */
    private static void putTs(org.json.JSONObject obj, String key, java.sql.Timestamp ts) {
        if (ts == null) return;
        obj.put(key, tsIso(ts));
        obj.put(key + "_ms", ts.getTime());
    }

    private void handleApiDkim(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (dkimManager == null) {
            sendJsonError(exchange, 503, "DKIM manager not initialized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Get DKIM info for a domain
                String query = exchange.getRequestURI().getQuery();
                int domainId = extractIdFromQuery(query);

                if (domainId > 0) {
                    DkimManager.DkimInfo info = dkimManager.getDkimInfo(domainId);
                    if (info != null) {
                        response.put("success", true);
                        response.put("domain", info.domain);
                        response.put("selector", info.selector);
                        response.put("configured", info.configured);
                        if (info.configured) {
                            response.put("dns_record_name", info.dnsRecordName);
                            response.put("dns_record_value", info.dnsRecordValue);
                            response.put("key_file_exists", info.keyFileExists);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "Dominio non trovato");
                    }
                } else {
                    response.put("success", false);
                    response.put("error", "ID dominio richiesto");
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "generate");

                if ("generate".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    String selector = req.optString("selector", "mail");

                    MailDatabase.Domain domain = Main.mailDatabase.getDomain(domainId);
                    if (domain == null) {
                        response.put("success", false);
                        response.put("error", "Dominio non trovato");
                    } else if (domain.hasDkim) {
                        // SAFETY: 'generate' è solo per il SETUP INIZIALE. Se DKIM è già configurato,
                        // sovrascrivere la chiave senza rotazione causerebbe DKIM-fail su mail in transito.
                        // L'utente DEVE usare 'rotate_start' per cambiare la chiave su un dominio già attivo.
                        response.put("success", false);
                        response.put("error",
                            "DKIM è già configurato per questo dominio (selector: " + domain.dkimSelector + "). " +
                            "Per generare una nuova chiave, usa il workflow di rotazione (\"Avvia rotazione chiave\"): " +
                            "rispetta il grace period di 7 giorni evitando DKIM-fail su mail in transito. " +
                            "L'azione 'generate' è riservata al setup iniziale.");
                    } else {
                        DkimManager.DkimResult result = dkimManager.generateDkimKeys(domainId, domain.domain, selector);
                        response.put("success", result.success);
                        if (result.success) {
                            response.put("selector", result.selector);
                            response.put("dns_record", result.dnsRecord);
                            response.put("message", "Chiavi DKIM generate. Aggiungi il record DNS per completare la configurazione.");
                        } else {
                            response.put("error", result.error);
                        }
                    }

                } else if ("verify".equals(action)) {
                    String domain = req.optString("domain", "");
                    String selector = req.optString("selector", "mail");

                    DkimManager.DkimVerifyResult result = dkimManager.verifyDkimDns(domain, selector);
                    response.put("success", true);
                    response.put("valid", result.valid);
                    response.put("message", result.message);

                } else if ("delete".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    boolean deleted = dkimManager.deleteDkim(domainId);
                    response.put("success", deleted);

                } else if ("rotate_start".equals(action)) {
                    // FASE 1: genera nuova chiave pending, restituisce record DNS da pubblicare.
                    // Se "auto"=true e Cloudflare configurato, il record viene creato via API.
                    int domainId = req.optInt("domain_id", 0);
                    boolean auto = req.optBoolean("auto", false);
                    DkimManager.RotationStartResult r = dkimManager.startRotation(domainId, auto);
                    response.put("success", r.success);
                    if (r.success) {
                        response.put("pending_selector", r.pendingSelector);
                        response.put("dns_record_name", r.dnsRecordName);
                        response.put("dns_record_value", r.dnsRecordValue);
                        // r.error qui è usato come "warning" non bloccante (es. CF non trovata)
                        if (r.error != null && !r.error.isEmpty()) {
                            response.put("warning", r.error);
                            response.put("message", "Chiave generata (con avviso): " + r.error);
                        } else if (auto && cloudflareManager != null && cloudflareManager.hasAccountForDomain(domainId)) {
                            response.put("message", "Chiave generata e record DNS pubblicato via Cloudflare. Pronto per l'attivazione.");
                        } else {
                            response.put("message", "Nuova chiave generata. Aggiungi il record DNS, poi avvia la verifica.");
                        }
                    } else {
                        response.put("error", r.error);
                    }

                } else if ("rotate_check".equals(action)) {
                    // FASE 2: verifica propagazione DNS della chiave pending
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.PropagationCheckResult r = dkimManager.checkPropagation(domainId);
                    response.put("success", r.success);
                    response.put("propagated", r.propagated);
                    response.put("message", r.message);
                    if (r.rawDigOutput != null && !r.rawDigOutput.isEmpty()) {
                        response.put("raw_output", r.rawDigOutput);
                    }

                } else if ("rotate_activate".equals(action)) {
                    // FASE 3: pending → active, active → previous, reload Rspamd
                    int domainId = req.optInt("domain_id", 0);
                    boolean force = req.optBoolean("force", false);
                    DkimManager.RotationActionResult r = dkimManager.activatePending(domainId, force);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_complete".equals(action)) {
                    // FASE 4: rimuove la previous key (fine grace period)
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationActionResult r = dkimManager.completeRotation(domainId);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_cancel".equals(action)) {
                    // Annulla rotazione pre-attivazione
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationActionResult r = dkimManager.cancelRotation(domainId);
                    response.put("success", r.success);
                    response.put("message", r.message);

                } else if ("rotate_status".equals(action)) {
                    // Stato corrente della rotazione (per la UI)
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.RotationInfo info = dkimManager.getRotationInfo(domainId);
                    if (info == null) {
                        response.put("success", false);
                        response.put("error", "Dominio non trovato");
                    } else {
                        response.put("success", true);
                        response.put("domain", info.domain);
                        response.put("has_dkim", info.hasDkim);
                        // Schedule corrente (per il banner "prossima rotazione")
                        DkimManager.ScheduleResult sched = dkimManager.getRotationSchedule(domainId);
                        if (sched != null && sched.success) {
                            response.put("schedule_interval_days", sched.intervalDays);
                            putTs(response, "schedule_last_rotation_at", sched.lastRotationAt);
                            putTs(response, "schedule_next_rotation_at", sched.nextRotationAt);
                        }
                        // Account Cloudflare assegnato a questo dominio (se c'è)
                        if (cloudflareManager != null) {
                            MailDatabase.CloudflareAccount acct = cloudflareManager.getAccountForDomain(domainId);
                            response.put("cloudflare_configured", acct != null);
                            if (acct != null) {
                                response.put("cloudflare_account_label", acct.label);
                                if (acct.email != null && !acct.email.isEmpty())
                                    response.put("cloudflare_account_email", acct.email);
                            }
                        } else {
                            response.put("cloudflare_configured", false);
                        }
                        response.put("current_selector", info.currentSelector);
                        response.put("rotation_state", info.rotationState == null ? "" : info.rotationState);
                        // Le due durate arrivano SEMPRE, non solo nel ramo del grace period:
                        // la scheda le mostra gia' allo stato "propagated" per dire quando
                        // scatta l'attivazione automatica. Senza, ripiegherebbe su 24 e 7
                        // scritti nella pagina — numeri giusti oggi e silenziosamente falsi
                        // il giorno in cui qualcuno cambia le costanti.
                        response.put("auto_activate_after_hours",
                            org.mail_panel.security.DkimRotationScheduler.AUTO_ACTIVATE_AFTER_HOURS);
                        response.put("grace_period_days",
                            org.mail_panel.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                        // Lo scheduler vive dentro questo server web: se il pannello non
                        // riparte da solo dopo un riavvio, i passi 3 e 4 restano fermi. La
                        // scheda deve poterlo DIRE, non lasciarlo scoprire.
                        response.put("avvio_automatico",
                            UpdateManager.avvioAutomatico().optBoolean("attivo", false));
                        putTs(response, "started_at", info.startedAt);
                        if (info.activatedAt != null) {
                            putTs(response, "activated_at", info.activatedAt);
                            response.put("grace_period_days", org.mail_panel.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                            response.put("grace_period_over",
                                org.mail_panel.security.DkimRotationScheduler.isGracePeriodOver(info.activatedAt));
                        }
                        if (info.pendingSelector != null) {
                            response.put("pending_selector", info.pendingSelector);
                            response.put("pending_dns_name", info.pendingDnsName);
                            response.put("pending_dns_value", info.pendingDnsValue);
                        }
                        if (info.previousSelector != null) {
                            response.put("previous_selector", info.previousSelector);
                            response.put("previous_dns_name", info.previousDnsName);
                            // La scheda dichiarava "la vecchia chiave deve restare nel DNS per
                            // 7 giorni" senza guardare se ci fosse. Su domain-b.test non c'era
                            // gia' prima della rotazione — il pannello lo aveva verificato tre
                            // volte e scritto nel registro — e lo dichiarava lo stesso.
                            // Un'istruzione da seguire su una cosa che non esiste fa cercare
                            // un guasto dove non c'e', e nasconde quello vero: che quella
                            // chiave non e' mai stata pubblicata.
                            try {
                                DkimManager.DkimVerifyResult pv =
                                    dkimManager.verifyDkimDns(info.domain, info.previousSelector);
                                response.put("previous_in_dns", pv != null && pv.valid);
                            } catch (Exception e) {
                                // Non sapere non e' ne' si' ne' no: si omette il campo e la
                                // scheda torna a dire la cosa prudente.
                            }
                        }
                    }

                } else if ("orphans_scan".equals(action)) {
                    // Scansiona Cloudflare per trovare TUTTI i record _domainkey del dominio,
                    // distinguendo tra current/pending/previous (attivi) e orphan (da pulire).
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.OrphanScanResult r = dkimManager.scanDkimRecords(domainId);
                    response.put("success", r.success);
                    if (!r.success) {
                        response.put("error", r.message);
                    } else {
                        response.put("domain", r.domain);
                        if (r.cloudflareAccountLabel != null) response.put("cloudflare_account_label", r.cloudflareAccountLabel);
                        if (r.currentSelector != null)  response.put("current_selector",  r.currentSelector);
                        if (r.pendingSelector != null)  response.put("pending_selector",  r.pendingSelector);
                        if (r.previousSelector != null) response.put("previous_selector", r.previousSelector);
                        JSONArray arr = new JSONArray();
                        for (DkimManager.DkimRecordEntry e : r.records) {
                            JSONObject o = new JSONObject();
                            o.put("record_id", e.recordId);
                            o.put("name", e.name);
                            o.put("selector", e.selector);
                            o.put("content_preview", e.contentPreview);
                            if (e.comment != null) o.put("comment", e.comment);
                            o.put("is_current",  e.isCurrent);
                            o.put("is_pending",  e.isPending);
                            o.put("is_previous", e.isPrevious);
                            o.put("is_orphan",   e.isOrphan);
                            o.put("in_grace_period", e.inGracePeriod);
                            putTs(o, "deactivated_at",       e.deactivatedAt);
                            putTs(o, "grace_period_ends_at", e.gracePeriodEndsAt);
                            arr.put(o);
                        }
                        response.put("records", arr);
                        response.put("grace_period_days", org.mail_panel.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                    }

                } else if ("orphans_delete".equals(action)) {
                    // Cancella un singolo record (per record_id) via Cloudflare API.
                    int domainId = req.optInt("domain_id", 0);
                    String recordId = req.optString("record_id", "");
                    if (domainId <= 0 || recordId.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "domain_id e record_id richiesti");
                    } else {
                        DkimManager.RotationActionResult r = dkimManager.deleteDkimRecordById(domainId, recordId);
                        response.put("success", r.success);
                        response.put("message", r.message);
                    }

                } else if ("last_rotation_reset".equals(action)) {
                    // Sovrascrive dkim_last_rotation_at con NOW (Java JVM clock).
                    // Usare per pulire valori "fossili" memorizzati con tz sbagliata.
                    int domainId = req.optInt("domain_id", 0);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", "domain_id richiesto");
                    } else {
                        Main.mailDatabase.markDkimRotationActivated(domainId);
                        response.put("success", true);
                        response.put("message", "Timestamp 'ultima rotazione' reimpostato a ora.");
                    }

                } else if ("last_rotation_clear".equals(action)) {
                    // Resetta a NULL — l'UI mostrerà "Mai effettuata"
                    int domainId = req.optInt("domain_id", 0);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", "domain_id richiesto");
                    } else {
                        Main.mailDatabase.clearDkimLastRotation(domainId);
                        response.put("success", true);
                        response.put("message", "Timestamp 'ultima rotazione' cancellato (NULL).");
                    }

                } else if ("schedule_get".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.ScheduleResult s = dkimManager.getRotationSchedule(domainId);
                    response.put("success", s.success);
                    if (!s.success) {
                        response.put("error", s.message);
                    } else {
                        response.put("interval_days", s.intervalDays);
                        putTs(response, "last_rotation_at", s.lastRotationAt);
                        putTs(response, "next_rotation_at", s.nextRotationAt);
                        // Clock del server in epoch ms (per diagnosi disallineamenti vs browser)
                        response.put("server_now_ms", System.currentTimeMillis());
                        // Se una rotazione e' GIA' in corso, il riquadro "Prossima rotazione"
                        // deve saperlo: senza questo campo continuava a scrivere "Dovuta, parte
                        // al prossimo controllo" mentre la chiave nuova era gia' stata generata
                        // e pubblicata. Una promessa al futuro su una cosa gia' accaduta.
                        try {
                            DkimManager.RotationInfo ri = dkimManager.getRotationInfo(domainId);
                            if (ri != null && ri.rotationState != null && !ri.rotationState.isBlank()) {
                                response.put("rotation_state", ri.rotationState);
                                if (ri.pendingSelector != null)
                                    response.put("rotation_pending_selector", ri.pendingSelector);
                            }
                        } catch (Exception ignora) {
                            // Nessuno stato: il riquadro torna a dire la cosa prudente.
                        }
                        response.put("auto_activate_after_hours", org.mail_panel.security.DkimRotationScheduler.AUTO_ACTIVATE_AFTER_HOURS);
                        response.put("grace_period_days", org.mail_panel.security.DkimRotationScheduler.GRACE_PERIOD_DAYS);
                        // Se il dominio ha un account Cloudflare, lo dice QUESTA risposta.
                        //
                        // La scheda lo leggeva da una variabile globale che veniva impostata da
                        // un ALTRO caricatore, quello dello stato rotazione. Se questo arrivava
                        // prima, la globale valeva ancora false e compariva l'avviso "senza CF
                        // lo schedule resta inattivo" — proprio sotto al riquadro che diceva
                        // "account collegato: Pietro". Un dato che si legge dall'aria dipende
                        // dall'ordine di due richieste, e prima o poi quell'ordine cambia.
                        response.put("avvio_automatico",
                            UpdateManager.avvioAutomatico().optBoolean("attivo", false));
                        try {
                            response.put("cloudflare_configured",
                                dkimManager.getRotationInfo(domainId) != null
                                && Main.mailDatabase.getDomain(domainId) != null
                                && Main.mailDatabase.getDomain(domainId).cloudflareAccountId > 0);
                        } catch (Exception ignora) { }
                        // Preset consigliati (per la UI)
                        JSONArray presets = new JSONArray();
                        presets.put(new JSONObject().put("days", 0).put("label", "Disattivato"));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_AGGRESSIVE).put("label", "Mensile (massima sicurezza)"));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_RECOMMENDED).put("label", "Trimestrale — consigliato"));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_BALANCED).put("label", "Semestrale (equilibrato)"));
                        presets.put(new JSONObject().put("days", DkimManager.PRESET_MINIMAL).put("label", "Annuale (minimo)"));
                        response.put("presets", presets);
                    }

                } else if ("schedule_set".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    int days = req.optInt("interval_days", 0);
                    DkimManager.ScheduleResult s = dkimManager.setRotationSchedule(domainId, days);
                    response.put("success", s.success);
                    response.put("message", s.success
                        ? (days == 0 ? "Rotazione programmata disattivata."
                                     : "Rotazione programmata ogni " + days + " giorni.")
                        : s.message);
                    response.put("interval_days", s.intervalDays);
                    putTs(response, "last_rotation_at", s.lastRotationAt);
                    putTs(response, "next_rotation_at", s.nextRotationAt);

                } else if ("rotate_history".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    int limit = req.optInt("limit", 50);
                    if (domainId <= 0) {
                        response.put("success", false);
                        response.put("error", "domain_id richiesto");
                    } else {
                        java.util.List<MailDatabase.DkimRotationEvent> events =
                            Main.mailDatabase.getDkimRotationHistory(domainId, limit);
                        JSONArray arr = new JSONArray();
                        for (MailDatabase.DkimRotationEvent ev : events) {
                            JSONObject o = new JSONObject();
                            o.put("id", ev.id);
                            o.put("event_type", ev.eventType);
                            if (ev.selector != null) o.put("selector", ev.selector);
                            if (ev.mode != null) o.put("mode", ev.mode);
                            if (ev.triggeredBy != null) o.put("triggered_by", ev.triggeredBy);
                            if (ev.cloudflareAccountLabel != null) o.put("cloudflare_account_label", ev.cloudflareAccountLabel);
                            o.put("success", ev.success);
                            if (ev.message != null) o.put("message", ev.message);
                            putTs(o, "occurred_at", ev.occurredAt);
                            arr.put(o);
                        }
                        response.put("success", true);
                        response.put("events", arr);
                    }

                } else if ("riepilogo_domini".equals(action)) {
                    // Interroga il DNS una volta per dominio: e' lento come una verifica
                    // singola moltiplicata per il numero di domini, ed e' il prezzo di una
                    // risposta vera invece di una lettura del database.
                    response = dkimManager.riepilogoTuttiIDomini();

                } else if ("verify_active_dns".equals(action)) {
                    int domainId = req.optInt("domain_id", 0);
                    DkimManager.ActiveKeyVerifyResult vr = dkimManager.verifyActiveKeyInDns(domainId);
                    response.put("success", vr.success);
                    response.put("match", vr.match);
                    if (vr.domain != null) response.put("domain", vr.domain);
                    if (vr.selector != null) response.put("selector", vr.selector);
                    if (vr.dnsRecordName != null) response.put("dns_record_name", vr.dnsRecordName);
                    if (vr.message != null) response.put("message", vr.message);
                    if (vr.expectedPublicKey != null) response.put("expected_public_key", vr.expectedPublicKey);
                    if (vr.actualPublicKey != null) response.put("actual_public_key", vr.actualPublicKey);
                    if (vr.rawDigOutput != null && !vr.rawDigOutput.isEmpty()) response.put("raw_output", vr.rawDigOutput);

                } else {
                    response.put("success", false);
                    response.put("error", "Azione non valida");
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== DNS API ==============

    private void handleApiDns(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (dnsGenerator == null) {
            sendJsonError(exchange, 503, "DNS generator not initialized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String query = exchange.getRequestURI().getQuery();
                String domain = extractParamFromQuery(query, "domain");

                if (domain == null || domain.isEmpty()) {
                    response.put("success", false);
                    response.put("error", "Dominio richiesto");
                } else {
                    // Get server IP and hostname
                    String serverIp = dnsGenerator.detectServerIp();
                    String mailHostname = Main.mailDatabase.getSetting("mail_hostname", "mail." + domain);

                    DnsRecordsGenerator.DnsRecordSet records = dnsGenerator.generateAllRecords(domain, mailHostname, serverIp);

                    response.put("success", true);
                    response.put("domain", records.domain);
                    response.put("server_ip", records.serverIp);
                    response.put("mail_hostname", records.mailServerHostname);

                    JSONArray recordsArray = new JSONArray();
                    for (DnsRecordsGenerator.DnsRecord record : records.records) {
                        JSONObject recordJson = new JSONObject();
                        recordJson.put("type", record.type);
                        recordJson.put("name", record.name);
                        recordJson.put("value", record.value);
                        recordJson.put("ttl", record.ttl);
                        recordJson.put("description", record.description);
                        recordJson.put("required", record.required);
                        if (record.checkType != null) recordJson.put("checkType", record.checkType);
                        if (record.valoreCompleto != null) recordJson.put("valoreCompleto", record.valoreCompleto);
                        if (record.dnsZone != null) {
                            recordJson.put("dnsZone", record.dnsZone);
                        }
                        if (record.explanation != null) {
                            recordJson.put("explanation", record.explanation);
                        }
                        recordsArray.put(recordJson);
                    }
                    response.put("records", recordsArray);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "verify");

                if ("verify".equals(action)) {
                    String domain = req.optString("domain", "");

                    DnsRecordsGenerator.DnsVerificationResult result = dnsGenerator.verifyAllRecords(domain);

                    response.put("success", true);
                    response.put("domain", result.domain);
                    response.put("all_passed", result.allPassed);
                    response.put("score", result.score);

                    JSONArray checksArray = new JSONArray();
                    for (DnsRecordsGenerator.DnsCheck check : result.checks) {
                        JSONObject checkJson = new JSONObject();
                        checkJson.put("type", check.recordType);
                        checkJson.put("name", check.recordName);
                        checkJson.put("passed", check.passed);
                        checkJson.put("informativo", check.informativo);
                        checkJson.put("message", check.message);
                        if (check.currentValue != null) {
                            checkJson.put("current_value", check.currentValue);
                        }
                        if (check.expectedValue != null) {
                            checkJson.put("expected_value", check.expectedValue);
                        }
                        checksArray.put(checkJson);
                    }
                    response.put("checks", checksArray);

                } else if ("set_hostname".equals(action)) {
                    String hostname = req.optString("hostname", "");
                    if (!hostname.isEmpty()) {
                        Main.mailDatabase.setSetting("mail_hostname", hostname);
                        // Keep SQLite in sync
                        if (Main.dbManager != null) {
                            Main.dbManager.setMailHostname(hostname);
                        }
                        response.put("success", true);
                    } else {
                        response.put("success", false);
                        response.put("error", "Hostname richiesto");
                    }

                } else {
                    response.put("success", false);
                    response.put("error", "Azione non valida");
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== Cloudflare API integration ==============

    /**
     * Endpoint /api/cloudflare — multi-account.
     *
     * GET                                 -> lista account + assegnazione domini
     * POST { action: "test", token }      -> verifica token (no save)
     * POST { action: "add", label, email, token } -> aggiunge account (verifica e salva)
     * POST { action: "update", account_id, label, email, token? } -> aggiorna account
     * POST { action: "delete", account_id } -> elimina account (disassocia i domini)
     * POST { action: "assign", domain_id, account_id } -> lega un dominio a un account (account_id=0 = manuale)
     */
    private void handleApiCloudflare(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }
        if (cloudflareManager == null) {
            sendJsonError(exchange, 503, "Cloudflare manager not initialized");
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();

        try {
            if ("GET".equals(method)) {
                org.json.JSONArray accounts = new org.json.JSONArray();
                for (MailDatabase.CloudflareAccount a : cloudflareManager.listAccounts()) {
                    org.json.JSONObject obj = new org.json.JSONObject();
                    obj.put("id", a.id);
                    obj.put("label", a.label == null ? "" : a.label);
                    obj.put("email", a.email == null ? "" : a.email);
                    obj.put("token_masked", org.mail_panel.security.CloudflareManager.maskToken(a.apiToken));
                    if (a.verifiedAt != null) obj.put("verified_at", a.verifiedAt.toString());
                    if (a.createdAt != null)  obj.put("created_at", a.createdAt.toString());
                    accounts.put(obj);
                }
                response.put("success", true);
                response.put("accounts", accounts);

                // Lista domini con assegnazione corrente
                org.json.JSONArray domains = new org.json.JSONArray();
                for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                    org.json.JSONObject obj = new org.json.JSONObject();
                    obj.put("id", d.id);
                    obj.put("domain", d.domain);
                    obj.put("cloudflare_account_id", d.cloudflareAccountId);
                    domains.put(obj);
                }
                response.put("domains", domains);

                // Server mail (Mail Hostname): il certificato SSL è emesso per questo
                // hostname, il cui dominio base può NON essere tra i domini mail.
                org.json.JSONObject mailServer = new org.json.JSONObject();
                String mailHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : null;
                mailServer.put("hostname", mailHostname == null ? "" : mailHostname);
                // Riporta l'id solo se l'account esiste davvero: così badge/select restano
                // coerenti con la logica di rinnovo (che ignora id orfani).
                int msAccId = acmeManager != null ? acmeManager.getMailCertCloudflareAccountId() : 0;
                if (msAccId > 0 && Main.mailDatabase.getCloudflareAccount(msAccId) == null) {
                    msAccId = 0;
                }
                mailServer.put("cloudflare_account_id", msAccId);
                response.put("mail_server", mailServer);

                sendJsonResponse(exchange, response);
                return;
            }

            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Richiesta troppo grande");
                return;
            }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("test".equals(action)) {
                String token = req.optString("token", "").trim();
                if (token.isEmpty()) {
                    response.put("success", false);
                    response.put("error", "Token non fornito");
                } else {
                    org.mail_panel.security.CloudflareManager.TokenCheck tc = cloudflareManager.verifyToken(token);
                    response.put("success", tc.valid);
                    response.put("message", tc.message);
                    if (tc.status != null) response.put("status", tc.status);
                }

            } else if ("add".equals(action)) {
                String label = req.optString("label", "").trim();
                String email = req.optString("email", "").trim();
                String token = req.optString("token", "").trim();
                org.mail_panel.security.CloudflareManager.AddAccountResult r =
                    cloudflareManager.addAccount(label, email, token);
                response.put("success", r.success);
                response.put("message", r.message);
                if (r.success) response.put("account_id", r.accountId);

            } else if ("update".equals(action)) {
                int id = req.optInt("account_id", 0);
                String label = req.optString("label", null);
                String email = req.optString("email", null);
                String token = req.has("token") ? req.optString("token", "").trim() : null;
                org.mail_panel.security.CloudflareManager.AddAccountResult r =
                    cloudflareManager.updateAccount(id, label, email, token);
                response.put("success", r.success);
                response.put("message", r.message);

            } else if ("delete".equals(action)) {
                int id = req.optInt("account_id", 0);
                if (id <= 0) {
                    response.put("success", false);
                    response.put("error", "account_id richiesto");
                } else {
                    boolean ok = cloudflareManager.deleteAccount(id);
                    response.put("success", ok);
                    response.put("message", ok ? "Account rimosso. Domini assegnati: torno a modalità manuale." : "Account non trovato");
                }

            } else if ("assign".equals(action)) {
                int domainId = req.optInt("domain_id", 0);
                int accountId = req.optInt("account_id", 0); // 0 = manuale
                if (domainId <= 0) {
                    response.put("success", false);
                    response.put("error", "domain_id richiesto");
                } else {
                    boolean ok = cloudflareManager.assignDomain(domainId, accountId);
                    response.put("success", ok);
                    response.put("message", ok
                        ? (accountId > 0 ? "Dominio assegnato all'account." : "Dominio impostato su modalità manuale.")
                        : "Operazione fallita");
                }

            } else if ("test_mailserver".equals(action)) {
                // Verifica che l'account scelto: (1) abbia un token valido e (2) gestisca
                // la zona DNS del Mail Hostname (così il rinnovo dns_cf funzionerà davvero).
                int accountId = req.optInt("account_id", 0);
                String mh = Main.dbManager != null ? Main.dbManager.getMailHostname() : null;
                if (mh == null || mh.isBlank()) {
                    response.put("success", false);
                    response.put("error", "Mail Hostname non configurato");
                } else if (accountId <= 0) {
                    response.put("success", false);
                    response.put("error", "Seleziona un account Cloudflare da testare");
                } else {
                    MailDatabase.CloudflareAccount acct = Main.mailDatabase.getCloudflareAccount(accountId);
                    if (acct == null || acct.apiToken == null || acct.apiToken.isBlank()) {
                        response.put("success", false);
                        response.put("error", "Account o token non trovato");
                    } else {
                        org.mail_panel.security.CloudflareManager.TokenCheck tc =
                            cloudflareManager.verifyToken(acct.apiToken);
                        if (!tc.valid) {
                            response.put("success", false);
                            response.put("error", "Token non valido: " + tc.message);
                        } else {
                            org.mail_panel.security.CloudflareManager.ZoneLookup zl =
                                cloudflareManager.findZone(acct.apiToken, mh);
                            if (zl.found) {
                                response.put("success", true);
                                response.put("zone", zl.zoneName);
                                response.put("message", "Token valido e zona DNS '" + zl.zoneName
                                    + "' raggiungibile per " + mh + ". Il rinnovo automatico funzionerà.");
                            } else {
                                response.put("success", false);
                                response.put("error", "Token valido, ma non trova la zona DNS per " + mh
                                    + ": " + zl.error + " — aggiungi questa zona ai permessi del token.");
                            }
                        }
                    }
                }

            } else if ("test_domain".equals(action)) {
                // Verifica che l'account assegnato a un dominio caselle abbia un token
                // valido e gestisca la zona DNS di quel dominio.
                int domainId = req.optInt("domain_id", 0);
                if (domainId <= 0) {
                    response.put("success", false);
                    response.put("error", "domain_id richiesto");
                } else {
                    MailDatabase.Domain dom = Main.mailDatabase.getDomain(domainId);
                    MailDatabase.CloudflareAccount acct = cloudflareManager.getAccountForDomain(domainId);
                    if (dom == null) {
                        response.put("success", false);
                        response.put("error", "Dominio non trovato");
                    } else if (acct == null || acct.apiToken == null || acct.apiToken.isBlank()) {
                        response.put("success", false);
                        response.put("error", "Nessun account Cloudflare assegnato a questo dominio (modalità manuale)");
                    } else {
                        org.mail_panel.security.CloudflareManager.TokenCheck tc =
                            cloudflareManager.verifyToken(acct.apiToken);
                        if (!tc.valid) {
                            response.put("success", false);
                            response.put("error", "Token non valido: " + tc.message);
                        } else {
                            org.mail_panel.security.CloudflareManager.ZoneLookup zl =
                                cloudflareManager.findZone(acct.apiToken, dom.domain);
                            if (zl.found) {
                                response.put("success", true);
                                response.put("zone", zl.zoneName);
                                response.put("message", "Token valido e zona DNS '" + zl.zoneName
                                    + "' raggiungibile per " + dom.domain + ".");
                            } else {
                                response.put("success", false);
                                response.put("error", "Token valido, ma non trova la zona DNS per " + dom.domain
                                    + ": " + zl.error + " — aggiungi questa zona ai permessi del token.");
                            }
                        }
                    }
                }

            } else if ("assign_mailserver".equals(action)) {
                // Account Cloudflare per il certificato del server mail (Mail Hostname)
                int accountId = req.optInt("account_id", 0); // 0 = manuale
                if (acmeManager == null) {
                    response.put("success", false);
                    response.put("error", "ACME manager non inizializzato");
                } else if (accountId > 0 && Main.mailDatabase.getCloudflareAccount(accountId) == null) {
                    response.put("success", false);
                    response.put("error", "Account non trovato");
                } else {
                    acmeManager.setMailCertCloudflareAccountId(accountId);
                    response.put("success", true);
                    response.put("message", accountId > 0
                        ? "Account Cloudflare collegato al certificato del server mail. Il rinnovo automatico è ora attivo."
                        : "Certificato del server mail impostato su modalità manuale.");
                }

            } else {
                response.put("success", false);
                response.put("error", "Azione non valida");
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== Timezone diagnostics & fix ==============

    /**
     * Endpoint /api/timezone-diag — strumento diagnostico per allineare timezone.
     *
     * GET → restituisce stato attuale:
     *   - server OS time (epoch ms) e tz JVM
     *   - MySQL @@global.time_zone, @@session.time_zone, NOW(), UTC_TIMESTAMP()
     *   - "alignment": OK se mysql NOW() ≈ jvm now (delta < 60s), MISMATCH altrimenti
     *
     * POST { action: "sync_to_system" } → imposta MySQL global+session time_zone
     *   all'offset corrente del JVM (es. "+02:00"). Richiede privilegio SUPER su MySQL.
     *
     * POST { action: "set", value: "+02:00" | "SYSTEM" | "Europe/Rome" } → manuale.
     */
    private void handleApiTimezoneDiag(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();

        try {
            if ("GET".equals(method)) {
                fillTimezoneDiagnostics(response);
                sendJsonResponse(exchange, response);
                return;
            }
            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("sync_to_system".equals(action) || "set".equals(action)) {
                String desired;
                if ("set".equals(action)) {
                    desired = req.optString("value", "").trim();
                    if (desired.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Valore richiesto (es. '+02:00', 'SYSTEM', 'Europe/Rome')");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                } else {
                    // Calcola l'offset attuale del JVM rispetto a UTC in formato "+HH:MM"
                    java.time.ZoneOffset off = java.time.ZonedDateTime.now().getOffset();
                    int sec = off.getTotalSeconds();
                    String sign = sec >= 0 ? "+" : "-";
                    int abs = Math.abs(sec);
                    desired = String.format("%s%02d:%02d", sign, abs / 3600, (abs % 3600) / 60);
                }

                StringBuilder log = new StringBuilder();
                boolean ok = true;
                String errMsg = null;
                try (java.sql.Statement stmt = Main.mailDatabase.getConnection().createStatement()) {
                    // Prova global (richiede SUPER), poi session
                    try {
                        stmt.executeUpdate("SET GLOBAL time_zone = '" + desired.replace("'", "") + "'");
                        log.append("✓ Global time_zone impostata a '").append(desired).append("'\n");
                    } catch (Exception ex) {
                        log.append("✗ Impossibile impostare GLOBAL time_zone (manca privilegio SUPER?): ").append(ex.getMessage()).append("\n");
                        // Continua comunque a impostare session per la connessione corrente
                    }
                    try {
                        stmt.executeUpdate("SET SESSION time_zone = '" + desired.replace("'", "") + "'");
                        log.append("✓ Session time_zone impostata a '").append(desired).append("'\n");
                    } catch (Exception ex) {
                        log.append("✗ Errore session: ").append(ex.getMessage()).append("\n");
                        ok = false;
                        errMsg = ex.getMessage();
                    }
                } catch (Exception e) {
                    ok = false;
                    errMsg = e.getMessage();
                }

                response.put("success", ok);
                if (errMsg != null) response.put("error", errMsg);
                response.put("log", log.toString());
                response.put("desired_value", desired);
                fillTimezoneDiagnostics(response);
                sendJsonResponse(exchange, response);
                return;
            }

            response.put("success", false);
            response.put("error", "Azione non valida");
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            sendJsonError(exchange, 500, "Errore: " + e.getMessage());
        }
    }

    /** Riempie response con i campi di diagnostica timezone. */
    private void fillTimezoneDiagnostics(org.json.JSONObject response) {
        response.put("success", true);

        // 1) JVM / OS Java
        long jvmNowMs = System.currentTimeMillis();
        response.put("jvm_now_ms", jvmNowMs);
        response.put("jvm_now_iso", java.time.Instant.ofEpochMilli(jvmNowMs).toString());
        response.put("jvm_default_zone", java.util.TimeZone.getDefault().getID());
        java.time.ZoneOffset off = java.time.ZonedDateTime.now().getOffset();
        response.put("jvm_offset", off.getId().equals("Z") ? "+00:00" : off.getId());

        // 2) OS clock via comando "date" (FreeBSD/Linux): più affidabile in caso di JVM
        //    settata a tz diversa dall'OS
        try {
            // TODO: migrate to Shell.run when touched
            Process p = new ProcessBuilder("date", "+%s|%z|%Z").redirectErrorStream(true).start();
            try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()))) {
                String line = r.readLine();
                if (line != null) {
                    String[] parts = line.trim().split("\\|");
                    if (parts.length >= 1) response.put("os_now_ms", Long.parseLong(parts[0]) * 1000L);
                    if (parts.length >= 2) response.put("os_offset", parts[1]);
                    if (parts.length >= 3) response.put("os_tz", parts[2]);
                }
            }
            p.waitFor();
        } catch (Exception ignore) {}

        // 3) MySQL: @@global.time_zone, @@session.time_zone, NOW(), UTC_TIMESTAMP()
        try (java.sql.Statement stmt = Main.mailDatabase.getConnection().createStatement();
             java.sql.ResultSet rs = stmt.executeQuery(
                 "SELECT @@global.time_zone, @@session.time_zone, " +
                 "NOW(), UTC_TIMESTAMP(), @@system_time_zone, " +
                 "UNIX_TIMESTAMP() AS unix_ts")) {
            if (rs.next()) {
                response.put("mysql_global_tz", rs.getString(1));
                response.put("mysql_session_tz", rs.getString(2));
                response.put("mysql_now", rs.getString(3));
                response.put("mysql_utc_now", rs.getString(4));
                response.put("mysql_system_tz", rs.getString(5));
                long unixTs = rs.getLong(6);
                response.put("mysql_now_ms", unixTs * 1000L);

                // Skew = mysql_now_ms - jvm_now_ms
                long skewMs = (unixTs * 1000L) - jvmNowMs;
                response.put("skew_mysql_vs_jvm_ms", skewMs);
                response.put("alignment", Math.abs(skewMs) < 60_000 ? "OK" : "MISMATCH");
            }
        } catch (Exception e) {
            response.put("mysql_error", e.getMessage());
        }
    }

    // ============== Postfix Aliases Health / Fix ==============

    /**
     * Endpoint /api/postfix-aliases-health.
     *   GET                       -> diagnose
     *   POST { action: "fix" }    -> auto-fix (crea sorgente + postalias + reload)
     *   POST { action: "set_root_forward", forward_to: "..." } -> aggiorna root forward
     */
    private void handleApiPostfixAliases(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }
        String method = exchange.getRequestMethod();
        org.json.JSONObject response = new org.json.JSONObject();
        try {
            org.mail_panel.security.PostfixAliasesManager mgr = new org.mail_panel.security.PostfixAliasesManager();

            if ("GET".equals(method)) {
                org.mail_panel.security.PostfixAliasesManager.AliasesStatus s = mgr.diagnose();
                fillAliasesStatus(response, s);
                sendJsonResponse(exchange, response);
                return;
            }
            if (!"POST".equals(method)) {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
            org.json.JSONObject req = new org.json.JSONObject(body);
            String action = req.optString("action", "");

            if ("fix".equals(action)) {
                org.mail_panel.security.PostfixAliasesManager.FixResult r = mgr.fix();
                response.put("success", r.success);
                response.put("message", r.message);
                response.put("log", r.log.toString());
                if (r.aliasFile != null)   response.put("alias_file",    r.aliasFile);
                if (r.aliasDbFile != null) response.put("alias_db_file", r.aliasDbFile);
                logAudit(r.success ? "POSTFIX_ALIASES_FIXED" : "POSTFIX_ALIASES_FIX_FAILED",
                    getClientIp(exchange), "msg=" + r.message);
                // Includi anche lo status aggiornato
                fillAliasesStatus(response, mgr.diagnose());
                sendJsonResponse(exchange, response);
                return;
            }

            if ("set_root_forward".equals(action)) {
                String forwardTo = req.optString("forward_to", "").trim();
                org.mail_panel.security.PostfixAliasesManager.FixResult r = mgr.setRootForward(forwardTo);
                response.put("success", r.success);
                response.put("message", r.message);
                response.put("log", r.log.toString());
                logAudit(r.success ? "POSTFIX_ROOT_FORWARD_SET" : "POSTFIX_ROOT_FORWARD_FAILED",
                    getClientIp(exchange), "forward_to=" + forwardTo + " msg=" + r.message);
                fillAliasesStatus(response, mgr.diagnose());
                sendJsonResponse(exchange, response);
                return;
            }

            response.put("success", false);
            response.put("error", "Azione non valida (usa: fix, set_root_forward)");
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            sendJsonResponse(exchange, response);
        }
    }

    private void fillAliasesStatus(org.json.JSONObject obj,
                                    org.mail_panel.security.PostfixAliasesManager.AliasesStatus s) {
        if (s == null) return;
        obj.put("success", s.success);
        if (s.error != null) obj.put("error", s.error);
        if (s.overall != null) obj.put("overall", s.overall);
        if (s.summary != null) obj.put("summary", s.summary);
        if (s.aliasFile != null) obj.put("alias_file", s.aliasFile);
        if (s.aliasDbFile != null) obj.put("alias_db_file", s.aliasDbFile);
        if (s.aliasMapsRaw != null) obj.put("alias_maps_raw", s.aliasMapsRaw);
        if (s.aliasDatabaseRaw != null) obj.put("alias_database_raw", s.aliasDatabaseRaw);
        obj.put("source_exists", s.sourceExists);
        obj.put("db_exists", s.dbExists);
        obj.put("db_stale_vs_source", s.dbStaleVsSource);
        if (s.rootForward != null) obj.put("root_forward", s.rootForward);
        if (s.sourceContent != null) obj.put("source_content", s.sourceContent);
    }

    /**
     * Helper: popola un JSONObject con l'output strutturato di un JailLiveState.
     */
    private void fillJailLiveStateJson(org.json.JSONObject obj, Fail2banManager.JailLiveState s) {
        if (s == null) return;
        obj.put("name", s.name == null ? "" : s.name);
        if (s.error != null) obj.put("error", s.error);
        // Raw output dei comandi "get"
        obj.put("maxretry", s.maxretry == null ? "" : s.maxretry);
        obj.put("findtime", s.findtime == null ? "" : s.findtime);
        obj.put("bantime", s.bantime == null ? "" : s.bantime);
        obj.put("logpath", s.logpath == null ? "" : s.logpath);
        obj.put("ignoreip", s.ignoreip == null ? "" : s.ignoreip);
        obj.put("filter", s.filter == null ? "" : s.filter);
        // Output completo "fail2ban-client status <jail>"
        obj.put("status_raw", s.statusRaw == null ? "" : s.statusRaw);
        // Campi parsati
        obj.put("currently_failed", s.currentlyFailed);
        obj.put("total_failed", s.totalFailed);
        obj.put("currently_banned", s.currentlyBanned);
        obj.put("total_banned", s.totalBanned);
        if (s.bannedIpsRaw != null) obj.put("banned_ips_raw", s.bannedIpsRaw);
        if (s.fileListRaw != null) obj.put("file_list_raw", s.fileListRaw);
    }

    // ============== SSL/Let's Encrypt API ==============

    private void handleApiSsl(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (acmeManager == null) {
            sendJsonError(exchange, 503, "ACME manager not initialized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Get certificate status
                response.put("success", true);
                response.put("acme_installed", acmeManager.isAcmeInstalled());

                AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                if (certInfo != null && certInfo.installed) {
                    response.put("certificate_installed", true);
                    response.put("common_name", certInfo.commonName);
                    response.put("issuer", certInfo.issuer);
                    response.put("lets_encrypt", certInfo.letsEncrypt);
                    response.put("self_signed", acmeManager.isSelfSigned());
                    response.put("days_until_expiry", certInfo.daysUntilExpiry);
                    response.put("expired", certInfo.expired);
                    response.put("expiring_soon", certInfo.expiringSoon);
                    if (certInfo.issuedAt != null) {
                        response.put("issued_at", certInfo.issuedAt.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        response.put("valid_from", certInfo.issuedAt.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                    }
                    if (certInfo.expiresAt != null) {
                        response.put("expires_at", certInfo.expiresAt.format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                    }
                    if (certInfo.subjectAltNames != null) {
                        response.put("san", new JSONArray(certInfo.subjectAltNames));
                    }
                    if (certInfo.algorithm != null) {
                        response.put("algorithm", certInfo.algorithm);
                    }
                    if (certInfo.serial != null) {
                        response.put("serial", certInfo.serial);
                    }
                } else {
                    response.put("certificate_installed", false);
                    response.put("self_signed", false);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "");

                switch (action) {
                    case "install_acme" -> {
                        String email = req.optString("email", "");
                        if (email.isEmpty() || !email.contains("@")) {
                            response.put("success", false);
                            response.put("error", "Email valida richiesta");
                        } else {
                            // installAcme fa "pkg install curl socat": aspetta il turno dei lavori sui pacchetti.
                            JSONObject esito = sulTurnoPacchetti("installazione di acme.sh", () -> {
                                AcmeManager.InstallResult result = acmeManager.installAcme(email);
                                JSONObject r = new JSONObject().put("success", result.success).put("message", result.message);
                                if (result.output != null) r.put("output", result.output);
                                return r;
                            });
                            for (String k : esito.keySet()) response.put(k, esito.get(k));
                        }
                    }
                    case "issue" -> {
                        String domain = req.optString("domain", "");
                        String mailHostname = req.optString("mail_hostname", "mail." + domain);
                        String challengeType = req.optString("challenge_type", "http");
                        String webroot = req.optString("webroot", "");

                        if (domain.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Dominio richiesto");
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.issueCertificate(domain, mailHostname, challengeType, webroot);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                        }
                    }
                    case "renew" -> {
                        String mailHostname = req.optString("mail_hostname", "");
                        if (mailHostname.isEmpty()) {
                            // Get from certificate
                            AcmeManager.CertificateInfo info = acmeManager.getCertificateInfo();
                            if (info != null) {
                                mailHostname = info.commonName;
                            }
                        }

                        if (mailHostname == null || mailHostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Hostname richiesto");
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.renewCertificate(mailHostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_RENEWED" : "SSL_CERT_RENEW_FAILED",
                                getClientIp(exchange), "hostname=" + mailHostname + " msg=" + result.message);
                        }
                    }

                    // ============== AUTO-RENEWAL ==============

                    case "get_auto_renewal_settings" -> {
                        try {
                            response.put("success", true);
                            response.put("enabled", acmeManager.isAutoRenewalEnabled());
                            response.put("threshold_days", acmeManager.getRenewalThresholdDays());

                            String lastCheck = acmeManager.getLastCheckTime();
                            String lastResult = acmeManager.getLastCheckResult();
                            String lastRenewal = acmeManager.getLastRenewalTime();

                            response.put("last_check", lastCheck);
                            response.put("last_check_human", humanizeDateTime(lastCheck));
                            response.put("last_renewal", lastRenewal);
                            response.put("last_renewal_human", humanizeDateTime(lastRenewal));

                            // Format last result as colored badge
                            if (lastResult != null && !lastResult.isEmpty()) {
                                int sep = lastResult.indexOf('|');
                                String code = sep > 0 ? lastResult.substring(0, sep) : "";
                                String msg  = sep > 0 ? lastResult.substring(sep + 1) : lastResult;
                                String cls  = switch (code) {
                                    case "OK"   -> "bg-success";
                                    case "FAIL" -> "bg-danger";
                                    case "SKIP" -> "bg-secondary";
                                    case "INFO" -> "bg-info text-dark";
                                    default     -> "bg-secondary";
                                };
                                response.put("last_result_html", "<span class=\"badge " + cls + "\">" + code + "</span> " + escapeHtmlSimple(msg));
                            } else {
                                response.put("last_result_html", "<span class=\"text-muted\">-</span>");
                            }

                            // Calcola prossimo check (se enabled): 24h dopo l'ultimo
                            if (acmeManager.isAutoRenewalEnabled() && lastCheck != null && !lastCheck.isEmpty()) {
                                try {
                                    java.time.LocalDateTime last = java.time.LocalDateTime.parse(lastCheck);
                                    java.time.LocalDateTime next = last.plusHours(24);
                                    response.put("next_check_human", next.format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
                                } catch (Exception ignored) {
                                    response.put("next_check_human", "Entro 24h");
                                }
                            } else if (acmeManager.isAutoRenewalEnabled()) {
                                response.put("next_check_human", "Entro 24h");
                            } else {
                                response.put("next_check_human", "Disattivato");
                            }
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", e.getMessage());
                        }
                    }

                    case "set_auto_renewal_settings" -> {
                        try {
                            boolean enabled = req.optBoolean("enabled", true);
                            int thresholdDays = req.optInt("threshold_days", 30);
                            acmeManager.setAutoRenewalEnabled(enabled);
                            acmeManager.setRenewalThresholdDays(thresholdDays);
                            response.put("success", true);
                            response.put("message", "Impostazioni salvate");
                            logAudit("SSL_AUTO_RENEWAL_SETTINGS_CHANGED", getClientIp(exchange),
                                "enabled=" + enabled + " threshold=" + thresholdDays);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", e.getMessage());
                        }
                    }

                    case "trigger_manual_check" -> {
                        try {
                            AcmeManager.CertificateResult res = acmeManager.checkAndRenewCertificates(true);
                            response.put("success", res.success);
                            response.put("message", res.message);
                            logAudit("SSL_MANUAL_CHECK_TRIGGERED", getClientIp(exchange),
                                "success=" + res.success + " msg=" + res.message);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("error", e.getMessage());
                        }
                    }

                    // ============== NEW SSL OPTIONS ==============

                    case "issue_http01" -> {
                        // Let's Encrypt HTTP-01 (standalone, requires port 80)
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Hostname richiesto (es. mail.example.com)");
                        } else {
                            // Extract domain from hostname
                            String domain = hostname.replaceFirst("^[^.]+\\.", "");
                            AcmeManager.CertificateResult result = acmeManager.issueCertificate(domain, hostname, "http", "");
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_ISSUED_HTTP01" : "SSL_CERT_ISSUE_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "generate_dns_challenge" -> {
                        // Let's Encrypt DNS-01 Step 1: Generate TXT record
                        String hostname = req.optString("hostname", "");
                        boolean forceRegenerate = req.optBoolean("force", false);
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Hostname richiesto (es. mail.example.com)");
                        } else {
                            AcmeManager.DnsChallengeResult result = acmeManager.generateDnsChallenge(hostname, forceRegenerate);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.txtDomain != null) {
                                response.put("txt_domain", result.txtDomain);
                            }
                            if (result.txtValue != null) {
                                response.put("txt_value", result.txtValue);
                            }
                        }
                    }

                    case "deploy_existing_cert" -> {
                        // Deploy existing certificate without regenerating
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Hostname richiesto");
                        } else {
                            AcmeManager.DeployResult result = acmeManager.deployCertificate(hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_DEPLOYED" : "SSL_CERT_DEPLOY_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "verify_dns_and_issue" -> {
                        // Let's Encrypt DNS-01 Step 2: Verify TXT and issue certificate
                        String hostname = req.optString("hostname", "");
                        if (hostname.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Hostname richiesto (es. mail.example.com)");
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.verifyDnsAndIssue(hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_ISSUED_DNS01" : "SSL_CERT_ISSUE_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "upload_manual" -> {
                        // Manual certificate upload
                        String cert = req.optString("certificate", "");
                        String key = req.optString("private_key", "");
                        String hostname = req.optString("hostname", "");

                        if (cert.isEmpty() || key.isEmpty()) {
                            response.put("success", false);
                            response.put("error", "Certificato e chiave privata richiesti");
                        } else {
                            AcmeManager.CertificateResult result = acmeManager.installManualCertificate(cert, key, hostname);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
                            logAudit(result.success ? "SSL_CERT_INSTALLED_MANUAL" : "SSL_CERT_MANUAL_FAILED",
                                getClientIp(exchange), "hostname=" + hostname + " msg=" + result.message);
                        }
                    }

                    case "check_self_signed" -> {
                        // Check if current certificate is self-signed
                        boolean selfSigned = acmeManager.isSelfSigned();
                        response.put("success", true);
                        response.put("self_signed", selfSigned);
                    }

                    default -> {
                        response.put("success", false);
                        response.put("error", "Azione non valida");
                    }
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== LOGS API ==============

    private void handleApiLogs(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (logManager == null) {
            logManager = new LogManager();
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String query = exchange.getRequestURI().getQuery();
                String logId = extractParamFromQuery(query, "log");
                String filter = extractParamFromQuery(query, "filter");
                String linesStr = extractParamFromQuery(query, "lines");
                int lines = 100;
                try {
                    if (linesStr != null) lines = Integer.parseInt(linesStr);
                } catch (NumberFormatException e) {
                    // use default
                }

                if (logId == null || logId.isEmpty()) {
                    // Return list of available logs
                    response.put("success", true);
                    JSONArray logsArray = new JSONArray();
                    for (LogManager.LogFile logFile : logManager.getAvailableLogFiles()) {
                        JSONObject logJson = new JSONObject();
                        logJson.put("id", logFile.id);
                        logJson.put("path", logFile.path);
                        logJson.put("description", logFile.description);
                        logJson.put("type", logFile.type.toString());
                        logJson.put("exists", logFile.exists);
                        logsArray.put(logJson);
                    }
                    response.put("logs", logsArray);

                } else {
                    // Return log entries
                    List<LogManager.LogEntry> entries = logManager.readLog(logId, lines, filter);

                    response.put("success", true);
                    response.put("log_id", logId);
                    response.put("count", entries.size());

                    JSONArray entriesArray = new JSONArray();
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
                    for (LogManager.LogEntry entry : entries) {
                        JSONObject entryJson = new JSONObject();
                        if (entry.timestamp != null) {
                            entryJson.put("timestamp", entry.timestamp.format(formatter));
                        }
                        entryJson.put("level", entry.level != null ? entry.level.toString() : "INFO");
                        entryJson.put("message", entry.message);
                        if (entry.process != null) {
                            entryJson.put("process", entry.process);
                        }
                        if (entry.eventType != null) {
                            entryJson.put("event_type", entry.eventType);
                        }
                        if (entry.from != null) {
                            entryJson.put("from", entry.from);
                        }
                        if (entry.to != null) {
                            entryJson.put("to", entry.to);
                        }
                        entriesArray.put(entryJson);
                    }
                    response.put("entries", entriesArray);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "search");

                if ("search".equals(action)) {
                    String logId = req.optString("log_id", "maillog");
                    String pattern = req.optString("pattern", "");
                    int maxResults = req.optInt("max_results", 100);

                    List<LogManager.LogEntry> results = logManager.searchLogs(logId, pattern, maxResults, null, null);

                    response.put("success", true);
                    response.put("count", results.size());

                    JSONArray resultsArray = new JSONArray();
                    for (LogManager.LogEntry entry : results) {
                        JSONObject entryJson = new JSONObject();
                        entryJson.put("raw", entry.raw);
                        if (entry.timestamp != null) {
                            entryJson.put("timestamp", entry.timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        }
                        entryJson.put("level", entry.level != null ? entry.level.toString() : "INFO");
                        resultsArray.put(entryJson);
                    }
                    response.put("results", resultsArray);

                } else {
                    response.put("success", false);
                    response.put("error", "Azione non valida");
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== STATS API ==============

    // Cache stats per evitare di parsare maillog ad ogni request (TTL 60s)
    private static volatile JSONObject CACHED_STATS = null;
    private static volatile long CACHED_STATS_AT = 0;
    private static final long STATS_CACHE_TTL_MS = 60_000;

    private void handleApiStats(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        // Cache hit?
        long now = System.currentTimeMillis();
        if (CACHED_STATS != null && (now - CACHED_STATS_AT) < STATS_CACHE_TTL_MS) {
            sendJsonResponse(exchange, CACHED_STATS);
            return;
        }

        JSONObject response = new JSONObject();

        try {
            // Get stats from Rspamd (accurate spam counting)
            RspamdManager.RspamdStats rspamdStats = null;
            if (rspamdManager != null) {
                rspamdStats = rspamdManager.getStatistics();
            }

            // Get active users count from database
            int activeMailboxes = Main.mailDatabase.getMailboxCount();

            response.put("success", true);
            response.put("generated_at", java.time.LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            response.put("period", "total");

            // SMTP stats — solo conteggi base da Rspamd (no parsing log)
            JSONObject smtp = new JSONObject();
            smtp.put("rejected", rspamdStats != null ? rspamdStats.spamCount : 0);
            smtp.put("source", "rspamd");
            response.put("smtp", smtp);

            // IMAP stats
            JSONObject imap = new JSONObject();
            imap.put("logins", 0);
            imap.put("active_users", activeMailboxes);
            imap.put("auth_failures", 0);
            response.put("imap", imap);

            // Security stats from Rspamd
            JSONObject security = new JSONObject();
            if (rspamdStats != null) {
                security.put("spam_detected", rspamdStats.spamCount);
                security.put("viruses_found", 0);
                security.put("spam_percentage", Math.round(rspamdStats.spamPercent * 100) / 100.0);
            } else {
                security.put("spam_detected", 0);
                security.put("viruses_found", 0);
                security.put("spam_percentage", 0);
            }
            response.put("security", security);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        // Cache aggiornato
        CACHED_STATS = response;
        CACHED_STATS_AT = System.currentTimeMillis();

        sendJsonResponse(exchange, response);
    }

    // ============== MAIL QUEUE API ==============

    private void handleApiQueue(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (queueManager == null) {
            queueManager = new MailQueueManager();
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("stats".equals(action)) {
                    // Get queue statistics (Postfix)
                    MailQueueManager.QueueStats stats = queueManager.getStats();
                    response.put("success", true);
                    response.put("total", stats.totalMessages);
                    response.put("total_size", stats.totalSize);
                    response.put("active", stats.active);
                    response.put("deferred", stats.deferred);
                    response.put("hold", stats.hold);
                    response.put("incoming", stats.incoming);
                    response.put("paused", stats.paused);

                    if (stats.oldestMessage != null) {
                        response.put("oldest_message", stats.oldestMessage.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                    }

                    // Top senders
                    JSONObject senders = new JSONObject();
                    stats.topSenders.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(5)
                        .forEach(e -> senders.put(e.getKey(), e.getValue()));
                    response.put("top_senders", senders);

                    // Top destinations
                    JSONObject destinations = new JSONObject();
                    stats.topDestinations.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(5)
                        .forEach(e -> destinations.put(e.getKey(), e.getValue()));
                    response.put("top_destinations", destinations);

                } else if ("envelope".equals(action) || "message".equals(action)) {
                    // Get message content
                    String messageId = extractParamFromQuery(query, "id");
                    if (messageId == null) {
                        response.put("success", false);
                        response.put("error", "Message ID required");
                    } else {
                        MailQueueManager.MessageContent content = queueManager.getMessage(messageId);
                        response.put("success", content.found);
                        if (content.found) {
                            response.put("from", content.fromHeader);
                            response.put("to", content.toHeader);
                            response.put("subject", content.subject);
                            response.put("date", content.dateHeader);
                            response.put("headers", content.headers);
                            response.put("body_preview", content.bodyPreview);
                        } else {
                            response.put("error", content.error);
                        }
                    }

                } else {
                    // List queue
                    java.util.List<MailQueueManager.QueuedMessage> messages = queueManager.getQueue();
                    response.put("success", true);
                    response.put("count", messages.size());

                    JSONArray messagesArray = new JSONArray();
                    for (MailQueueManager.QueuedMessage msg : messages) {
                        JSONObject msgJson = new JSONObject();
                        msgJson.put("message_id", msg.messageId);
                        msgJson.put("envelope_id", msg.envelopeId);
                        msgJson.put("state", msg.state.name());
                        msgJson.put("sender", msg.sender);
                        msgJson.put("recipient", msg.recipient);
                        msgJson.put("size", msg.size);
                        if (msg.created != null) {
                            msgJson.put("created", msg.created.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        }
                        msgJson.put("error_reason", msg.errorReason);
                        messagesArray.put(msgJson);
                    }
                    response.put("messages", messagesArray);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject json = new JSONObject(body);
                String action = json.optString("action", "");

                switch (action) {
                    case "remove" -> {
                        String envelopeId = json.getString("envelope_id");
                        MailQueueManager.QueueAction result = queueManager.removeMessage(envelopeId);
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "schedule" -> {
                        String envelopeId = json.getString("envelope_id");
                        MailQueueManager.QueueAction result = queueManager.scheduleMessage(envelopeId);
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "flush" -> {
                        MailQueueManager.QueueAction result = queueManager.flushQueue();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "pause" -> {
                        MailQueueManager.QueueAction result = queueManager.pauseQueue();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "resume" -> {
                        MailQueueManager.QueueAction result = queueManager.resumeQueue();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "purge_permfails" -> {
                        // Prima si mostra COSA verrebbe eliminato, poi si elimina. Cancellare
                        // posta e' irreversibile: una finestra di conferma che non dice quanti
                        // e quali messaggi tocca non e' una conferma, e' un pulsante.
                        java.util.List<MailQueueManager.QueuedMessage> perm =
                                queueManager.permanentFailures();
                        if (!"ELIMINA".equals(json.optString("confirm", ""))) {
                            JSONArray elenco = new JSONArray();
                            for (MailQueueManager.QueuedMessage m : perm)
                                elenco.put(new JSONObject()
                                        .put("id", m.envelopeId == null ? "" : m.envelopeId)
                                        .put("mittente", m.sender == null ? "" : m.sender)
                                        .put("destinatario", m.recipient == null ? "" : m.recipient)
                                        .put("errore", m.errorReason == null ? "" : m.errorReason));
                            response.put("success", true).put("anteprima", true)
                                    .put("quanti", perm.size()).put("messaggi", elenco)
                                    .put("message", perm.isEmpty()
                                            ? "Nessun messaggio con errore permanente."
                                            : perm.size() + " messaggi hanno ricevuto un rifiuto definitivo "
                                              + "(5xx) e non partiranno mai. I messaggi con errore "
                                              + "temporaneo non vengono toccati.");
                            break;
                        }
                        MailQueueManager.QueueAction result = queueManager.purgePermanentFailures();
                        response.put("success", result.success).put("message", result.message)
                                .put("output", result.output == null ? "" : result.output);
                        logAudit("QUEUE_PURGE_PERMFAILS", getClientIp(exchange),
                                perm.size() + " messaggi - " + result.message);
                    }
                    case "purge_deferred" -> {
                        MailQueueManager.QueueAction result = queueManager.purgeDeferred();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Unknown action: " + action);
                    }
                }
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== ROUNDCUBE SSO API ==============

    private void handleApiSso(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (ssoManager == null && Main.mailDatabase != null) {
            ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("status".equals(action)) {
                    // Get SSO status
                    RoundcubeSsoManager.SsoStatus status = ssoManager.getStatus();
                    response.put("success", true);
                    response.put("configured", status.configured);
                    response.put("roundcube_installed", status.roundcubeInstalled);
                    response.put("roundcube_path", status.roundcubePath);
                    response.put("plugin_installed", status.pluginInstalled);
                    response.put("plugin_path", status.pluginPath);
                    response.put("secret_configured", status.secretConfigured);
                    response.put("plugin_enabled", status.pluginEnabled);
                    response.put("roundcube_url", status.roundcubeUrl);
                    if (status.error != null) {
                        response.put("error", status.error);
                    }
                } else {
                    response.put("success", false);
                    response.put("error", "Unknown action");
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject json = new JSONObject(body);
                String action = json.optString("action", "");

                switch (action) {
                    case "install" -> {
                        RoundcubeSsoManager.InstallResult result = ssoManager.installPlugin();
                        response.put("success", result.success);
                        response.put("message", result.message);
                        if (result.pluginPath != null) {
                            response.put("plugin_path", result.pluginPath);
                        }
                        if (result.error != null) {
                            response.put("error", result.error);
                        }
                    }
                    case "uninstall" -> {
                        boolean success = ssoManager.uninstallPlugin();
                        response.put("success", success);
                        response.put("message", success ? "SSO plugin uninstalled" : "Failed to uninstall plugin");
                    }
                    case "set_url" -> {
                        String url = json.getString("url");
                        ssoManager.setRoundcubeUrl(url);
                        response.put("success", true);
                        response.put("message", "Roundcube URL updated");
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Unknown action: " + action);
                    }
                }
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void handleApiWebmailOpen(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (ssoManager == null && Main.mailDatabase != null) {
            ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
        }

        JSONObject response = new JSONObject();

        try {
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Richiesta troppo grande");
                return;
            }
            JSONObject json = new JSONObject(body);
            String email = json.getString("email");

            // Get client IP for token binding (use CF-Connecting-IP if available)
            String clientIp = getClientIp(exchange);

            // Generate SSO token using master user (no password needed)
            RoundcubeSsoManager.SsoToken token = ssoManager.generateToken(email, clientIp);

            response.put("success", token.success);
            response.put("sso", token.success);
            if (token.success) {
                response.put("redirect_url", token.redirectUrl);
                response.put("expires_at", token.expiresAt);
            } else {
                response.put("error", token.error);
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== FAIL2BAN API ==============

    private void handleApiFail2ban(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (fail2banManager == null) {
            fail2banManager = new Fail2banManager();
        }

        String method = exchange.getRequestMethod();
        String query = exchange.getRequestURI().getQuery();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String action = extractParamFromQuery(query, "action");

                if ("status".equals(action)) {
                    // Get overall status
                    Fail2banManager.Fail2banStatus status = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", status.installed);
                    response.put("running", status.running);
                    response.put("total_banned", status.totalBanned);
                    response.put("total_banned_total", status.totalBannedTotal);

                    // Active jails
                    JSONArray jailsArray = new JSONArray();
                    for (String jail : status.activeJails) {
                        jailsArray.put(jail);
                    }
                    response.put("active_jails", jailsArray);

                    // Jail details
                    JSONArray jailDetails = new JSONArray();
                    for (Fail2banManager.JailStatus jail : status.jails) {
                        JSONObject jailJson = new JSONObject();
                        jailJson.put("name", jail.name);
                        jailJson.put("enabled", jail.enabled);
                        jailJson.put("currently_banned", jail.currentlyBanned);
                        jailJson.put("total_banned", jail.totalBanned);
                        jailJson.put("currently_failed", jail.currentlyFailed);
                        jailJson.put("total_failed", jail.totalFailed);
                        jailJson.put("porte", jail.porte);
                        jailJson.put("porta_dichiarata", jail.portaDichiarata);
                        jailJson.put("ban_usa_la_porta", jail.banUsaLaPorta);
                        jailJson.put("comando_ban", jail.comandoBan);
                        if (jail.logFile != null) jailJson.put("log", jail.logFile);

                        JSONArray bannedIps = new JSONArray();
                        for (String ip : jail.bannedIps) {
                            bannedIps.put(ip);
                        }
                        jailJson.put("banned_ips", bannedIps);
                        jailDetails.put(jailJson);
                    }
                    response.put("jails", jailDetails);

                    // Recent bans
                    JSONArray recentBans = new JSONArray();
                    for (Fail2banManager.BanEvent event : status.recentBans) {
                        JSONObject eventJson = new JSONObject();
                        eventJson.put("action", event.action());
                        eventJson.put("jail", event.jail());
                        eventJson.put("ip", event.ip());
                        if (event.timestamp() != null) {
                            eventJson.put("timestamp", event.timestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                        }
                        recentBans.put(eventJson);
                    }
                    response.put("recent_bans", recentBans);

                    if (status.error != null) {
                        response.put("error", status.error);
                    }

                } else if ("jail".equals(action)) {
                    // Get specific jail status
                    String jailName = extractParamFromQuery(query, "name");
                    if (jailName == null) {
                        response.put("success", false);
                        response.put("error", "Jail name required");
                    } else if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                        response.put("success", false);
                        response.put("error", "Nome jail non valido");
                    } else {
                        Fail2banManager.JailStatus jail = fail2banManager.getJailStatus(jailName);
                        response.put("success", jail.exists);
                        response.put("name", jail.name);
                        response.put("enabled", jail.enabled);
                        response.put("currently_banned", jail.currentlyBanned);
                        response.put("total_banned", jail.totalBanned);
                        response.put("currently_failed", jail.currentlyFailed);
                        response.put("total_failed", jail.totalFailed);

                        JSONArray bannedIps = new JSONArray();
                        for (String ip : jail.bannedIps) {
                            bannedIps.put(ip);
                        }
                        response.put("banned_ips", bannedIps);
                    }

                } else if ("live_state".equals(action)) {
                    // Per UNA singola jail: output di fail2ban-client get maxretry/findtime/bantime/...
                    // + fail2ban-client status <jail>. Restituiamo sia il raw sia i campi parsati.
                    String jailName = extractParamFromQuery(query, "name");
                    if (jailName == null || !org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                        response.put("success", false);
                        response.put("error", "Nome jail non valido");
                    } else {
                        Fail2banManager.JailLiveState s = fail2banManager.getJailLiveState(jailName);
                        response.put("success", s.success);
                        if (s.error != null) response.put("error", s.error);
                        fillJailLiveStateJson(response, s);
                    }

                } else if ("live_state_all".equals(action)) {
                    // Per TUTTE le jail attive: live state di ognuna IN PARALLELO.
                    // Con N jail, prima ci voleva N * ~1s. Ora ~1s totale perche'
                    // tutte le jail vengono interrogate in parallelo via virtual
                    // threads, e dentro ciascuna anche i 6 fail2ban-client get
                    // sono paralleli.
                    Fail2banManager.Fail2banStatus overall = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", overall.installed);
                    response.put("running", overall.running);
                    JSONArray arr = new JSONArray();
                    try (var exec = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
                        java.util.List<java.util.concurrent.CompletableFuture<Fail2banManager.JailLiveState>> futures
                            = new java.util.ArrayList<>();
                        for (String jail : overall.activeJails) {
                            futures.add(java.util.concurrent.CompletableFuture.supplyAsync(
                                () -> fail2banManager.getJailLiveState(jail), exec));
                        }
                        for (var f : futures) {
                            Fail2banManager.JailLiveState s = f.get(20, java.util.concurrent.TimeUnit.SECONDS);
                            JSONObject one = new JSONObject();
                            fillJailLiveStateJson(one, s);
                            arr.put(one);
                        }
                    }
                    response.put("jails", arr);

                } else if ("banned".equals(action)) {
                    // Get all banned IPs
                    java.util.List<Fail2banManager.BannedIp> banned = fail2banManager.getAllBannedIps();
                    response.put("success", true);
                    response.put("count", banned.size());

                    JSONArray bannedArray = new JSONArray();
                    for (Fail2banManager.BannedIp ban : banned) {
                        JSONObject banJson = new JSONObject();
                        banJson.put("ip", ban.ip());
                        banJson.put("jail", ban.jail());
                        banJson.put("active", ban.active());
                        bannedArray.put(banJson);
                    }
                    response.put("banned", bannedArray);

                } else if ("permaban_list".equals(action)) {
                    // Get permaban list (read-only, GET-friendly)
                    java.util.List<String> fileList = fail2banManager.listPermabans();
                    java.util.Set<String> runtimeSet = fail2banManager.listPermabanRuntime();
                    JSONArray arr = new JSONArray();
                    for (String ip : fileList) {
                        arr.put(new JSONObject()
                            .put("ip", ip)
                            .put("in_runtime", runtimeSet.contains(ip)));
                    }
                    response.put("success", true);
                    response.put("permabans", arr);
                    response.put("count", fileList.size());
                    response.put("runtime_count", runtimeSet.size());
                } else if ("ip_info".equals(action)) {
                    // Get IP whois info
                    String ip = extractParamFromQuery(query, "ip");
                    if (ip == null) {
                        response.put("success", false);
                        response.put("error", "IP address required");
                    } else if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                        response.put("success", false);
                        response.put("error", "IP non valido");
                    } else {
                        Fail2banManager.IpInfo info = fail2banManager.getIpInfo(ip);
                        response.put("success", info.found);
                        response.put("ip", info.ip);
                        response.put("country", info.country);
                        if (info.countryName != null) response.put("country_name", info.countryName);
                        if (info.region != null) response.put("region", info.region);
                        if (info.city != null) response.put("city", info.city);
                        response.put("organization", info.organization);
                        if (info.isp != null) response.put("isp", info.isp);
                        if (info.asn != null) response.put("asn", info.asn);
                        response.put("net_range", info.netRange);
                        if (info.latitude != null) response.put("latitude", info.latitude);
                        if (info.longitude != null) response.put("longitude", info.longitude);
                        if (info.geoSource != null) response.put("geo_source", info.geoSource);
                    }

                } else {
                    // Default: return status
                    Fail2banManager.Fail2banStatus status = fail2banManager.getStatus();
                    response.put("success", true);
                    response.put("installed", status.installed);
                    response.put("running", status.running);
                    response.put("total_banned", status.totalBanned);
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                JSONObject json = new JSONObject(body);
                String action = json.optString("action", "");

                switch (action) {
                    // Legge e basta: fa girare fail2ban-regex sul log della jail e dice se il
                    // filtro aggancia qualcosa. Serve a distinguere "nessuno ha attaccato" da
                    // "la jail non vede niente", che a schermo sono lo stesso zero.
                    case "verifica_filtro" -> {
                        String jail = json.optString("jail", "");
                        Fail2banManager.FiltroCheck c = fail2banManager.verificaFiltro(jail);
                        response.put("success", true)
                                .put("jail", c.jail).put("log", c.log)
                                .put("verificato", c.verificato).put("agganci", c.agganci)
                                .put("righe_log", c.righeLog).put("messaggio", c.messaggio)
                                .put("uscita", c.uscita);
                    }
                    // Legge e basta: mette a confronto gli indirizzi che Fail2ban crede
                    // bannati con quelli che pf blocca davvero. "Currently banned" dice che il
                    // comando di ban e' stato eseguito, non che l'indirizzo sia bloccato.
                    case "confronto_pf" -> {
                        Fail2banManager.ConfrontoPf c = fail2banManager.confrontaBanConPf();
                        JSONArray jj = new JSONArray();
                        for (Fail2banManager.JailPf j : c.jails) {
                            jj.put(new JSONObject()
                                .put("jail", j.jail).put("ancora", j.ancora).put("tabella", j.tabella)
                                .put("letta", j.letta).put("tabella_mancante", j.tabellaMancante)
                                .put("regola_presente", j.regolaPresente)
                                .put("nota", j.nota)
                                .put("creduti_bannati", new JSONArray(j.credutiBannati))
                                .put("nel_firewall", new JSONArray(j.nelFirewall))
                                .put("solo_in_fail2ban", new JSONArray(j.soloInFail2ban))
                                .put("solo_in_pf", new JSONArray(j.soloInPf))
                                .put("comandi_ban", new JSONArray(j.comandiBan))
                                .put("uscita_azioni", j.uscitaAzioni)
                                .put("log", j.logFail2ban)
                                .put("sezioni", j.sezioni)
                                .put("dump", j.dump));
                        }
                        response.put("success", true).put("jails", jj)
                                .put("non_applicati", c.totaleNonApplicati())
                                .put("non_misurate", c.totaleNonMisurate())
                                .put("ban_non_verificati", c.banNonVerificati())
                                .put("senza_regola", c.totaleSenzaRegola());
                    }
                    case "ban" -> {
                        String ip = json.getString("ip");
                        String jail = json.getString("jail");
                        // SECURITY: validare prima di passarli a shell
                        if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", "IP non valido");
                            break;
                        }
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jail)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.BanAction result = fail2banManager.banIp(ip, jail);
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_IP_BANNED" : "FAIL2BAN_BAN_FAILED",
                            getClientIp(exchange), "target_ip=" + ip + " jail=" + jail);
                    }
                    case "unban" -> {
                        String ip = json.getString("ip");
                        String jail = json.optString("jail", null);
                        if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", "IP non valido");
                            break;
                        }
                        if (jail != null && !jail.isEmpty() && !org.mail_panel.security.InputValidator.isValidJailName(jail)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.BanAction result;
                        if (jail != null && !jail.isEmpty()) {
                            result = fail2banManager.unbanIp(ip, jail);
                        } else {
                            result = fail2banManager.unbanIpFromAll(ip);
                        }
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_IP_UNBANNED" : "FAIL2BAN_UNBAN_FAILED",
                            getClientIp(exchange), "target_ip=" + ip + " jail=" + (jail != null ? jail : "ALL"));
                    }
                    case "reload" -> {
                        Fail2banManager.BanAction result = fail2banManager.reload();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "start" -> {
                        Fail2banManager.BanAction result = fail2banManager.start();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "stop" -> {
                        Fail2banManager.BanAction result = fail2banManager.stop();
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "install_mail_jails" -> {
                        Fail2banManager.InstallResult result = fail2banManager.installMailJails();
                        response.put("success", result.success);
                        response.put("message", result.message);
                        if (result.configPath != null) {
                            response.put("config_path", result.configPath);
                        }
                        if (result.error != null) {
                            response.put("error", result.error);
                        }
                    }
                    case "update_jail_config" -> {
                        String jailName = json.getString("jail");
                        // SECURITY: validate jail name (concatenato in shell)
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        int maxRetry = json.optInt("max_retry", 5);
                        int findTime = json.optInt("find_time", 600);
                        int banTime = json.optInt("ban_time", 3600);
                        // Range sani per evitare config nonsense
                        if (maxRetry < 1 || maxRetry > 100 ||
                            findTime < 30 || findTime > 86400 ||
                            banTime  < 60 || banTime  > 31_536_000) {
                            response.put("success", false);
                            response.put("message", "Valori fuori range (maxRetry 1-100, findTime 30-86400s, banTime 60-31536000s)");
                            break;
                        }
                        Fail2banManager.BanAction result = fail2banManager.updateJailConfig(jailName, maxRetry, findTime, banTime);
                        response.put("success", result.success);
                        response.put("message", result.message);
                        logAudit(result.success ? "FAIL2BAN_JAIL_UPDATED" : "FAIL2BAN_JAIL_UPDATE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " maxRetry=" + maxRetry + " findTime=" + findTime + " banTime=" + banTime);
                    }
                    case "update_all_jails_config" -> {
                        int maxRetry = json.optInt("max_retry", 5);
                        int findTime = json.optInt("find_time", 600);
                        int banTime  = json.optInt("ban_time", 3600);
                        if (maxRetry < 1 || maxRetry > 100 ||
                            findTime < 30 || findTime > 86400 ||
                            banTime  < 60 || banTime  > 31_536_000) {
                            response.put("success", false);
                            response.put("message", "Valori fuori range (maxRetry 1-100, findTime 30-86400s, banTime 60-31536000s)");
                            break;
                        }
                        Fail2banManager.BulkJailConfigResult bulk =
                            fail2banManager.updateAllJailsConfig(maxRetry, findTime, banTime);
                        response.put("success", bulk.success);
                        response.put("success_count", bulk.successCount);
                        response.put("fail_count", bulk.failCount);
                        if (bulk.error != null) response.put("error", bulk.error);
                        JSONArray jarr = new JSONArray();
                        for (Fail2banManager.JailConfigOutcome o : bulk.results) {
                            JSONObject jo = new JSONObject();
                            jo.put("jail", o.jail());
                            jo.put("success", o.success());
                            jo.put("message", o.message());
                            jarr.put(jo);
                        }
                        response.put("results", jarr);
                        response.put("message", bulk.error != null
                            ? bulk.error
                            : ("Configurazione applicata a " + bulk.successCount + " jail"
                               + (bulk.failCount > 0 ? " (" + bulk.failCount + " errori)" : "")));
                        logAudit(bulk.success ? "FAIL2BAN_ALL_JAILS_UPDATED" : "FAIL2BAN_ALL_JAILS_UPDATE_PARTIAL",
                            getClientIp(exchange),
                            "maxRetry=" + maxRetry + " findTime=" + findTime + " banTime=" + banTime
                            + " ok=" + bulk.successCount + " fail=" + bulk.failCount);
                    }
                    case "permaban_add" -> {
                        String ip = json.optString("ip", "");
                        if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", "IP non valido");
                            break;
                        }
                        try {
                            boolean added = fail2banManager.addPermaban(ip);
                            response.put("success", true);
                            response.put("added", added);
                            response.put("message", added ? "IP aggiunto al permaban" : "IP già nella lista permaban");
                            logAudit(added ? "PERMABAN_ADDED" : "PERMABAN_ALREADY_PRESENT",
                                getClientIp(exchange), "target_ip=" + ip);
                            // Sbanna anche da tutte le jail Fail2ban (l'utente potrebbe essere già bannato temporaneamente)
                            try { fail2banManager.unbanIpFromAll(ip); } catch (Exception ignored) {}
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("message", e.getMessage());
                        }
                    }
                    case "permaban_remove" -> {
                        String ip = json.optString("ip", "");
                        if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                            response.put("success", false);
                            response.put("message", "IP non valido");
                            break;
                        }
                        try {
                            boolean removed = fail2banManager.removePermaban(ip);
                            response.put("success", true);
                            response.put("removed", removed);
                            response.put("message", removed ? "IP rimosso dal permaban" : "IP non era in permaban");
                            logAudit(removed ? "PERMABAN_REMOVED" : "PERMABAN_NOT_FOUND",
                                getClientIp(exchange), "target_ip=" + ip);
                        } catch (Exception e) {
                            response.put("success", false);
                            response.put("message", e.getMessage());
                        }
                    }
                    case "permaban_list" -> {
                        java.util.List<String> fileList = fail2banManager.listPermabans();
                        java.util.Set<String> runtimeSet = fail2banManager.listPermabanRuntime();
                        JSONArray arr = new JSONArray();
                        for (String ip : fileList) {
                            arr.put(new JSONObject()
                                .put("ip", ip)
                                .put("in_runtime", runtimeSet.contains(ip)));
                        }
                        response.put("success", true);
                        response.put("permabans", arr);
                        response.put("count", fileList.size());
                        response.put("runtime_count", runtimeSet.size());
                    }
                    case "permaban_reload" -> {
                        boolean ok = fail2banManager.reloadPermabanFromFile();
                        response.put("success", ok);
                        response.put("message", ok
                            ? "Tabella pf <permaban> ricaricata da file"
                            : "Reload fallito (pf attivo?)");
                        logAudit(ok ? "PERMABAN_RELOADED" : "PERMABAN_RELOAD_FAILED",
                            getClientIp(exchange), "");
                    }
                    case "get_jail_config" -> {
                        String jailName = json.getString("jail");
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.JailConfig cfg = fail2banManager.getJailConfig(jailName);
                        if (cfg == null || !cfg.found) {
                            response.put("success", false);
                            response.put("message", "Jail non trovata in jail.local");
                        } else {
                            response.put("success", true);
                            response.put("jail", cfg.name);
                            response.put("max_retry", cfg.maxRetry);
                            response.put("find_time", cfg.findTime);
                            response.put("ban_time", cfg.banTime);
                            response.put("enabled", cfg.enabled);
                            response.put("filter", cfg.filter == null ? "" : cfg.filter);
                            response.put("logpath", cfg.logpath == null ? "" : cfg.logpath);
                            // Lista degli ignoreip a runtime (piu' affidabile che da file)
                            JSONArray ignArr = new JSONArray();
                            for (String s : fail2banManager.getIgnoreIps(jailName)) ignArr.put(s);
                            response.put("ignoreip", ignArr);
                        }
                    }
                    case "set_jail_filter" -> {
                        String jailName = json.getString("jail");
                        String filter = json.optString("filter", "");
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.setJailFilter(jailName, filter);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_FILTER_CHANGED" : "FAIL2BAN_FILTER_CHANGE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " filter=" + filter);
                    }
                    case "add_jail_ignoreip" -> {
                        String jailName = json.getString("jail");
                        String ip = json.optString("ip", "").trim();
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.addIgnoreIp(jailName, ip);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_IGNOREIP_ADDED" : "FAIL2BAN_IGNOREIP_ADD_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " ip=" + ip);
                    }
                    case "remove_jail_ignoreip" -> {
                        String jailName = json.getString("jail");
                        String ip = json.optString("ip", "").trim();
                        if (!org.mail_panel.security.InputValidator.isValidJailName(jailName)) {
                            response.put("success", false);
                            response.put("message", "Nome jail non valido");
                            break;
                        }
                        Fail2banManager.BanAction r = fail2banManager.removeIgnoreIp(jailName, ip);
                        response.put("success", r.success);
                        response.put("message", r.message);
                        logAudit(r.success ? "FAIL2BAN_IGNOREIP_REMOVED" : "FAIL2BAN_IGNOREIP_REMOVE_FAILED",
                            getClientIp(exchange),
                            "jail=" + jailName + " ip=" + ip);
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Unknown action: " + action);
                    }
                }
            }

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== FAIL2BAN HEALTH CHECK ==============

    /** Endpoint per diagnosi e setup automatico di Fail2ban. */
    // ============== UNBOUND HEALTH CHECK (Resolver DNS locale) ==============
    // ============== FIREWALL API ==============

    /**
     * Endpoint /api/firewall — gestione firewall pf con CIDR + GeoIP.
     *
     * GET  /api/firewall                → ritorna stato corrente (mode, liste, country selezionati,
     *                                     dimensione tabelle pf a runtime, catalogo paesi)
     * POST /api/firewall  action=...    → mutazioni
     *      Azioni supportate:
     *        - set_mode           {mode: DISABLED|CIDR_ONLY|GEO_WHITELIST|GEO_BLACKLIST}
     *        - set_port25_geo     {value: true|false}    (applica geo anche a porta 25)
     *        - add_cidr_wl        {cidr: "..."}
     *        - remove_cidr_wl     {cidr: "..."}
     *        - add_cidr_bl        {cidr: "..."}
     *        - remove_cidr_bl     {cidr: "..."}
     *        - add_country        {country: "it"}
     *        - remove_country     {country: "it"}
     *        - sync_geo           {country: "it"}        (scarica zone file da ipdeny)
     *        - sync_geo_all       (scarica zone files per tutti i paesi selezionati)
     *        - apply              (rigenera anchor + syntax check + carica nel kernel)
     */
    private void handleApiFirewall(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (firewallManager == null) {
            firewallManager = new org.mail_panel.security.PfFirewallManager();
        }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildFirewallStatusJson();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, "Body troppo grande"); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);

                switch (action) {
                    case "set_mode" -> {
                        String modeStr = req.optString("mode", "CIDR_ONLY");
                        try {
                            org.mail_panel.security.PfFirewallManager.Mode m =
                                org.mail_panel.security.PfFirewallManager.Mode.valueOf(modeStr);
                            firewallManager.setMode(m);
                            response.put("success", true);
                            response.put("message", "Modalita' impostata: " + m);
                            logAudit("FW_MODE_CHANGED", clientIp, "mode=" + m);
                        } catch (IllegalArgumentException e) {
                            response.put("success", false);
                            response.put("error", "Modalita' non valida: " + modeStr);
                        }
                    }
                    case "set_port25_geo" -> {
                        boolean v = req.optBoolean("value", false);
                        firewallManager.setApplyGeoToPort25(v);
                        response.put("success", true);
                        response.put("message", "Geo su port 25: " + (v ? "ATTIVO" : "INATTIVO"));
                        logAudit("FW_PORT25_GEO_TOGGLED", clientIp, "value=" + v);
                    }
                    case "add_cidr_wl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.addCidrWhitelist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? "Aggiunto a whitelist: " + cidr
                                                   : "CIDR non valido o gia' presente");
                        if (ok) logAudit("FW_CIDR_WL_ADD", clientIp, "cidr=" + cidr);
                    }
                    case "remove_cidr_wl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.removeCidrWhitelist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? "Rimosso da whitelist: " + cidr : "Non presente");
                        if (ok) logAudit("FW_CIDR_WL_REMOVE", clientIp, "cidr=" + cidr);
                    }
                    case "add_cidr_bl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.addCidrBlacklist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? "Aggiunto a blacklist: " + cidr
                                                   : "CIDR non valido o gia' presente");
                        if (ok) logAudit("FW_CIDR_BL_ADD", clientIp, "cidr=" + cidr);
                    }
                    case "remove_cidr_bl" -> {
                        String cidr = req.optString("cidr", "").trim();
                        boolean ok = firewallManager.removeCidrBlacklist(cidr);
                        response.put("success", ok);
                        response.put("message", ok ? "Rimosso da blacklist: " + cidr : "Non presente");
                        if (ok) logAudit("FW_CIDR_BL_REMOVE", clientIp, "cidr=" + cidr);
                    }
                    case "add_country" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        boolean ok = firewallManager.addGeoCountry(cc);
                        response.put("success", ok);
                        response.put("message", ok ? "Paese aggiunto: " + cc : "Codice non valido o gia' presente");
                        if (ok) logAudit("FW_COUNTRY_ADD", clientIp, "cc=" + cc);
                    }
                    case "remove_country" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        boolean ok = firewallManager.removeGeoCountry(cc);
                        response.put("success", ok);
                        response.put("message", ok ? "Paese rimosso: " + cc : "Non presente");
                        if (ok) logAudit("FW_COUNTRY_REMOVE", clientIp, "cc=" + cc);
                    }
                    case "bulk_add_countries" -> {
                        JSONArray arr = req.optJSONArray("countries");
                        java.util.List<String> codes = new java.util.ArrayList<>();
                        if (arr != null) for (int i = 0; i < arr.length(); i++) codes.add(arr.getString(i));
                        int added = firewallManager.bulkAddCountries(codes);
                        response.put("success", true);
                        response.put("added", added);
                        response.put("total_requested", codes.size());
                        response.put("message", "Aggiunti " + added + " paesi (su " + codes.size() + " richiesti)");
                        logAudit("FW_BULK_COUNTRY_ADD", clientIp, "added=" + added + " requested=" + codes.size());
                    }
                    case "bulk_remove_countries" -> {
                        JSONArray arr = req.optJSONArray("countries");
                        java.util.List<String> codes = new java.util.ArrayList<>();
                        if (arr != null) for (int i = 0; i < arr.length(); i++) codes.add(arr.getString(i));
                        int removed = firewallManager.bulkRemoveCountries(codes);
                        response.put("success", true);
                        response.put("removed", removed);
                        response.put("message", "Rimossi " + removed + " paesi");
                        logAudit("FW_BULK_COUNTRY_REMOVE", clientIp, "removed=" + removed);
                    }
                    case "clear_countries" -> {
                        int n = firewallManager.clearCountries();
                        response.put("success", true);
                        response.put("removed", n);
                        response.put("message", "Lista paesi svuotata (" + n + " rimossi)");
                        logAudit("FW_CLEAR_COUNTRIES", clientIp, "removed=" + n);
                    }
                    case "set_auto_sync" -> {
                        boolean enabled = req.optBoolean("enabled", false);
                        int interval = Math.max(1, Math.min(req.optInt("interval_days", 7), 365));
                        firewallManager.setAutoSync(enabled, interval);
                        response.put("success", true);
                        response.put("message", "Auto-sync " + (enabled ? "ATTIVO" : "INATTIVO") + " — intervallo " + interval + " giorni");
                        logAudit("FW_AUTOSYNC_SET", clientIp, "enabled=" + enabled + " interval=" + interval);
                    }
                    case "apply_preset_group" -> {
                        String groupId = req.optString("group_id", "");
                        org.mail_panel.security.CountryCatalog.CountryGroup grp = null;
                        for (var g : org.mail_panel.security.CountryCatalog.getGroups()) {
                            if (g.id().equals(groupId)) { grp = g; break; }
                        }
                        if (grp == null) {
                            response.put("success", false);
                            response.put("error", "Gruppo preset non riconosciuto: " + groupId);
                        } else {
                            // Sostituisce completamente la selezione corrente con quella del gruppo
                            firewallManager.clearCountries();
                            int added = firewallManager.bulkAddCountries(grp.codes());
                            response.put("success", true);
                            response.put("group", groupId);
                            response.put("added", added);
                            response.put("message", "Preset '" + grp.label() + "' applicato: " + added + " paesi selezionati");
                            logAudit("FW_PRESET_APPLIED", clientIp, "group=" + groupId + " added=" + added);
                        }
                    }
                    case "sync_geo" -> {
                        String cc = req.optString("country", "").trim().toLowerCase();
                        org.mail_panel.security.PfFirewallManager.SyncResult sr = firewallManager.syncCountry(cc);
                        response.put("success", sr.success);
                        response.put("message", sr.success ? sr.message : ("Errore: " + sr.error));
                        response.put("country", sr.country);
                        response.put("cidr_count", sr.cidrCount);
                        logAudit(sr.success ? "FW_GEO_SYNC_OK" : "FW_GEO_SYNC_FAIL", clientIp,
                            "cc=" + cc + " count=" + sr.cidrCount);
                    }
                    case "sync_geo_all" -> {
                        java.util.List<org.mail_panel.security.PfFirewallManager.SyncResult> results =
                            firewallManager.syncAllSelectedCountries();
                        JSONArray arr = new JSONArray();
                        int ok = 0;
                        for (var sr : results) {
                            arr.put(new JSONObject()
                                .put("country", sr.country)
                                .put("success", sr.success)
                                .put("cidr_count", sr.cidrCount)
                                .put("message", sr.success ? sr.message : sr.error));
                            if (sr.success) ok++;
                        }
                        response.put("success", ok == results.size());
                        response.put("results", arr);
                        response.put("message", ok + "/" + results.size() + " paesi sincronizzati");
                        logAudit("FW_GEO_SYNC_ALL", clientIp, "ok=" + ok + "/" + results.size());
                    }
                    case "apply" -> {
                        org.mail_panel.security.PfFirewallManager.ApplyResult ar =
                            firewallManager.applyConfiguration();
                        response.put("success", ar.success);
                        response.put("message", ar.message);
                        if (ar.backupPath != null) response.put("backup_path", ar.backupPath);
                        if (ar.anchorContent != null) response.put("anchor_content", ar.anchorContent);
                        logAudit(ar.success ? "FW_APPLY_OK" : "FW_APPLY_FAIL", clientIp, ar.message);
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Azione non riconosciuta: " + action);
                    }
                }
            }
            sendJsonResponse(exchange, response);
        } catch (Exception e) {
            sendJsonError(exchange, 500, "Errore interno: " + e.getMessage());
        }
    }

    /** Costruisce il JSON di stato per /api/firewall GET. */
    private JSONObject buildFirewallStatusJson() {
        JSONObject out = new JSONObject();
        org.mail_panel.security.PfFirewallManager.FirewallState s = firewallManager.getState();
        out.put("success", true);
        out.put("mode", s.mode.name());
        out.put("enabled", s.enabled);
        out.put("apply_geo_to_port25", s.applyGeoToPort25);
        out.put("whitelist_cidrs", new JSONArray(s.whitelistCidrs));
        out.put("blacklist_cidrs", new JSONArray(s.blacklistCidrs));
        out.put("geo_countries", new JSONArray(s.geoCountries));

        // Per ogni paese selezionato: ultimo sync + numero CIDR + freshness
        JSONArray geoDetail = new JSONArray();
        for (String cc : s.geoCountries) {
            JSONObject c = new JSONObject();
            c.put("code", cc);
            c.put("cidr_count", firewallManager.getCountryCidrCount(cc));
            Long last = s.geoLastSync.get(cc);
            long lastMs = last == null ? 0L : last;
            c.put("last_sync_ms", lastMs);
            org.mail_panel.security.PfFirewallManager.Freshness fresh =
                org.mail_panel.security.PfFirewallManager.computeFreshness(lastMs, s.autoSyncIntervalDays);
            c.put("freshness", fresh.name());
            // ago_seconds: utile per UI ("3 giorni fa")
            c.put("ago_seconds", lastMs > 0 ? (System.currentTimeMillis() - lastMs) / 1000 : 0);
            org.mail_panel.security.CountryCatalog.Country meta =
                org.mail_panel.security.CountryCatalog.byCode(cc);
            if (meta != null) {
                c.put("name", meta.name());
                c.put("flag", meta.flag());
            }
            geoDetail.put(c);
        }
        out.put("geo_detail", geoDetail);

        // Auto-sync settings + statistiche
        JSONObject autoSync = new JSONObject();
        autoSync.put("enabled", s.autoSyncEnabled);
        autoSync.put("interval_days", s.autoSyncIntervalDays);
        autoSync.put("last_check_ms", s.lastAutoSyncCheck);
        autoSync.put("last_run_ms", s.lastAutoSyncRun);
        // Conta paesi stale (necessari di update)
        int staleCount = 0;
        for (String cc : s.geoCountries) {
            long lm = s.geoLastSync.getOrDefault(cc, 0L);
            org.mail_panel.security.PfFirewallManager.Freshness f =
                org.mail_panel.security.PfFirewallManager.computeFreshness(lm, s.autoSyncIntervalDays);
            if (f != org.mail_panel.security.PfFirewallManager.Freshness.FRESH) staleCount++;
        }
        autoSync.put("stale_countries_count", staleCount);
        out.put("auto_sync", autoSync);

        // Tabelle pf a runtime
        java.util.Map<String, Integer> sizes = firewallManager.getTableSizes();
        JSONObject tableSizes = new JSONObject();
        sizes.forEach(tableSizes::put);
        out.put("table_sizes", tableSizes);

        // Catalogo paesi (per UI)
        out.put("country_catalog", org.mail_panel.security.CountryCatalog.toJsonArray());

        // Gruppi preset (UE, G7, NATO, ecc.) per la UI
        out.put("preset_groups", org.mail_panel.security.CountryCatalog.groupsToJsonArray());

        return out;
    }

    private void handleApiUnboundHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildUnboundHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, "Body troppo grande"); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_unbound" -> {
                        JSONObject r = installUnbound();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_INSTALLED" : "UNBOUND_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "configure_unbound" -> {
                        JSONObject r = writeUnboundConfig();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_CONFIGURED" : "UNBOUND_CONFIGURE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_unbound_at_boot" -> {
                        JSONObject r = sysrcSet("unbound_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_ENABLED_AT_BOOT" : "UNBOUND_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_unbound" -> {
                        JSONObject r = serviceCommand("unbound", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_STARTED" : "UNBOUND_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_local_unbound_at_boot" -> {
                        JSONObject r = sysrcSet("local_unbound_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "LOCAL_UNBOUND_ENABLED_AT_BOOT" : "LOCAL_UNBOUND_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_local_unbound" -> {
                        JSONObject r = serviceCommand("local_unbound", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "LOCAL_UNBOUND_STARTED" : "LOCAL_UNBOUND_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "switch_resolv_conf" -> {
                        JSONObject r = switchResolvConfToUnbound();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RESOLV_CONF_SWITCHED" : "RESOLV_CONF_SWITCH_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "test_query" -> {
                        JSONObject r = testUnboundQuery();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_TEST_OK" : "UNBOUND_TEST_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runUnboundFixAll();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_FIX_ALL_OK" : "UNBOUND_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    case "disable_forwarder" -> {
                        JSONObject r = disableUnboundForwarder();
                        response = r;
                        logAudit(r.optBoolean("success") ? "UNBOUND_FORWARDER_DISABLED" : "UNBOUND_FORWARDER_DISABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "rollback_resolv_conf" -> {
                        JSONObject r = rollbackResolvConf();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RESOLV_CONF_ROLLBACK_OK" : "RESOLV_CONF_ROLLBACK_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Azione non valida: " + action);
                    }
                }
            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    private static final String UNBOUND_CONF_PATH = "/usr/local/etc/unbound/unbound.conf";

    private static final String UNBOUND_CONF_CONTENT = ""
        + "# /usr/local/etc/unbound/unbound.conf\n"
        + "# Generato dal mail panel — Resolver DNS LOCALE per il server\n"
        + "# Ascolta SOLO su 127.0.0.1, non raggiungibile da internet\n"
        + "\n"
        + "server:\n"
        + "    # Bind solo loopback (sicurezza: invisibile da fuori)\n"
        + "    interface: 127.0.0.1\n"
        + "    interface: ::1\n"
        + "    port: 53\n"
        + "    do-ip4: yes\n"
        + "    do-ip6: yes\n"
        + "    do-udp: yes\n"
        + "    do-tcp: yes\n"
        + "\n"
        + "    # Solo localhost può fare query\n"
        + "    access-control: 127.0.0.0/8 allow\n"
        + "    access-control: ::1 allow\n"
        + "    access-control: 0.0.0.0/0 refuse\n"
        + "    access-control: ::/0 refuse\n"
        + "\n"
        + "    # Privacy e sicurezza\n"
        + "    hide-identity: yes\n"
        + "    hide-version: yes\n"
        + "    harden-glue: yes\n"
        + "    harden-dnssec-stripped: yes\n"
        + "    use-caps-for-id: yes\n"
        + "\n"
        + "    # Performance\n"
        + "    num-threads: 2\n"
        + "    cache-min-ttl: 300\n"
        + "    cache-max-ttl: 86400\n"
        + "    prefetch: yes\n"
        + "    prefetch-key: yes\n"
        + "\n"
        + "    # Logging\n"
        + "    use-syslog: yes\n"
        + "    verbosity: 1\n"
        + "\n"
        + "    # Permetti private addresses nelle risposte (necessario per alcuni DNSBL)\n"
        + "    private-address: 192.168.0.0/16\n"
        + "    private-address: 10.0.0.0/8\n"
        + "    private-address: 172.16.0.0/12\n"
        + "    private-address: 169.254.0.0/16\n"
        + "    private-address: fd00::/8\n"
        + "    private-address: fe80::/10\n";

    private JSONObject buildUnboundHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();

        // 1. Resolver locale disponibile (unbound pkg OPPURE local_unbound base system)
        //    Su FreeBSD c'è 'local_unbound' nel base system: stesso effetto, già installato di default.
        boolean pkgInstalled;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "unbound");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            pkgInstalled = p.exitValue() == 0;
        } catch (Exception e) { pkgInstalled = false; }

        boolean baseUnboundAvailable = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/sbin/local-unbound"));
        boolean baseUnboundRunning = isServiceRunning("local_unbound");
        boolean installed = pkgInstalled || baseUnboundAvailable;

        String installedStatus;
        if (pkgInstalled && baseUnboundRunning) installedStatus = "Pacchetto 'unbound' installato + 'local_unbound' base attivo";
        else if (pkgInstalled) installedStatus = "Pacchetto unbound (pkg) presente";
        else if (baseUnboundRunning) installedStatus = "local_unbound (base system FreeBSD) attivo — non serve pacchetto pkg";
        else if (baseUnboundAvailable) installedStatus = "local_unbound (base system) disponibile ma fermo";
        else installedStatus = "Nessun resolver locale disponibile";

        checks.put(makeCheck("unbound-installed", "Resolver locale disponibile", installed,
            installedStatus,
            installed ? null : "Senza un resolver locale non puoi fare check DNSBL affidabili (Spamhaus rifiuta query da DNS pubblici).",
            installed ? null : "install_unbound",
            "Installa pacchetto unbound (alternativa: usa local_unbound del base system)"));

        // 2. Config file: solo se usi il pacchetto pkg, non serve per local_unbound (config in /var/unbound/)
        boolean confPresent = java.nio.file.Files.exists(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
        boolean baseConfPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/var/unbound/unbound.conf"));
        boolean confValid = false;
        if (confPresent) {
            try {
                String c = java.nio.file.Files.readString(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
                confValid = c.contains("interface: 127.0.0.1") && c.contains("access-control");
            } catch (Exception ignored) {}
        }
        // Se local_unbound è già attivo, considera la config "OK" anche senza il file pkg
        boolean configOk = confValid || baseConfPresent || baseUnboundRunning;
        String configStatus;
        if (confValid) configStatus = UNBOUND_CONF_PATH + " (pkg unbound)";
        else if (baseConfPresent) configStatus = "/var/unbound/unbound.conf (local_unbound base system)";
        else if (baseUnboundRunning) configStatus = "local_unbound attivo (config auto-gestita)";
        else if (confPresent) configStatus = "Config pkg esiste ma non è valida";
        else configStatus = "Nessuna config trovata";
        checks.put(makeCheck("unbound-config", "Config resolver presente",
            configOk,
            configStatus,
            configOk ? null : "Senza config, il resolver non parte.",
            (configOk || !installed || baseUnboundAvailable) ? null : "configure_unbound",
            "Scrive config minimal+sicura su " + UNBOUND_CONF_PATH));

        // 3. Abilitato al boot — verifica sia unbound_enable che local_unbound_enable
        boolean unboundEnabledBoot = isSysrcYes("unbound_enable");
        boolean localUnboundEnabledBoot = isSysrcYes("local_unbound_enable");
        boolean enabledBoot = unboundEnabledBoot || localUnboundEnabledBoot;
        String bootStatus;
        if (unboundEnabledBoot && localUnboundEnabledBoot) bootStatus = "unbound_enable + local_unbound_enable=YES";
        else if (unboundEnabledBoot) bootStatus = "unbound_enable=YES (pkg)";
        else if (localUnboundEnabledBoot) bootStatus = "local_unbound_enable=YES (base system)";
        else bootStatus = "Nessun resolver locale abilitato al boot";
        // Fix appropriato: se base system esiste, abilita quello, altrimenti pkg
        String bootFixAction = enabledBoot ? null : (baseUnboundAvailable && !pkgInstalled ? "enable_local_unbound_at_boot" : "enable_unbound_at_boot");
        String bootFixDesc = baseUnboundAvailable && !pkgInstalled
            ? "sysrc local_unbound_enable=YES (usa il resolver del base system)"
            : "sysrc unbound_enable=YES";
        checks.put(makeCheck("unbound-enabled-boot", "Resolver locale abilitato al boot",
            enabledBoot,
            bootStatus,
            enabledBoot ? null : "Dopo un reboot, il server non avrà resolver locale e tornerai ai problemi con DNSBL.",
            (enabledBoot || !installed) ? null : bootFixAction,
            bootFixDesc));

        // 4. In esecuzione (pkg unbound OPPURE local_unbound)
        boolean pkgRunning = isServiceRunning("unbound");
        boolean running = pkgRunning || baseUnboundRunning;
        String runningStatus;
        if (pkgRunning && baseUnboundRunning) runningStatus = "Entrambi attivi (pkg + base)";
        else if (pkgRunning) runningStatus = "unbound (pkg) in esecuzione";
        else if (baseUnboundRunning) runningStatus = "local_unbound (base system) in esecuzione";
        else runningStatus = "Nessun resolver in esecuzione";
        String runningFixAction = running ? null : (baseUnboundAvailable && !pkgInstalled ? "start_local_unbound" : "start_unbound");
        String runningFixDesc = baseUnboundAvailable && !pkgInstalled
            ? "service local_unbound start"
            : "service unbound start";
        checks.put(makeCheck("unbound-running", "Resolver locale attivo",
            running,
            runningStatus,
            running ? null : "Nessuna query DNS verrà servita localmente.",
            (running || !installed) ? null : runningFixAction,
            runningFixDesc));

        // 5. Ascolta su 127.0.0.1:53
        boolean listening53 = isPortListeningOnLocalhost(53);
        checks.put(makeCheck("unbound-listening", "Ascolta su 127.0.0.1:53",
            listening53,
            listening53 ? "Port 53 (DNS) attivo su loopback" : "Niente in ascolto su 127.0.0.1:53",
            listening53 ? null : "Il resolver gira ma non risponde sulla porta giusta.",
            null, null));

        // 6. /etc/resolv.conf punta a 127.0.0.1
        boolean resolvOk = false;
        try {
            String resolv = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/resolv.conf"));
            // Prima riga nameserver utile deve essere 127.0.0.1
            for (String line : resolv.split("\n")) {
                String t = line.trim();
                if (t.startsWith("#")) continue;
                if (t.startsWith("nameserver")) {
                    String ns = t.replaceFirst("nameserver\\s+", "").trim();
                    if (ns.equals("127.0.0.1") || ns.equals("::1")) resolvOk = true;
                    break;
                }
            }
        } catch (Exception ignored) {}
        checks.put(makeCheck("resolv-conf", "/etc/resolv.conf usa unbound (127.0.0.1)",
            resolvOk,
            resolvOk ? "Sistema usa unbound come primary resolver" : "Sistema NON usa unbound — query passano ancora per DNS esterni",
            resolvOk ? null : "Se non lo cambi, tutte le query continuano ad andare via 1.1.1.1 e i check DNSBL falliscono.",
            (resolvOk || !running || !listening53) ? null : "switch_resolv_conf",
            "Backup /etc/resolv.conf + scrive 'nameserver 127.0.0.1' + fallback. Pre-flight test prima di applicare."));

        // 7. Query di test funziona
        boolean queryOk = testUnboundQuerySimple();
        checks.put(makeCheck("unbound-query-works", "Query di test risolve correttamente",
            queryOk,
            queryOk ? "dig @127.0.0.1 freebsd.org → risolto"
                    : (listening53 ? "Query test fallita — unbound non risolve" : "Skip: unbound non in ascolto"),
            queryOk ? null : "Anche se attivo, unbound non sta riuscendo a risolvere domini reali (problema upstream?).",
            null, null));

        // 8. Modalità RICORSIVA (no forwarder) — fondamentale per Spamhaus/SURBL
        //    Se local_unbound usa forward-zone verso 1.1.1.1, Spamhaus vede ancora le query
        //    arrivare da resolver pubblico → 127.255.255.254 (blocked).
        boolean isForwarding = isUnboundUsingForwarder();
        boolean dnsblWorking = testDnsblQuery();
        checks.put(makeCheck("unbound-recursive", "Resolution ricorsiva diretta (no forwarder)",
            !isForwarding && dnsblWorking,
            !isForwarding
                ? (dnsblWorking ? "Risolve ricorsivamente dai root server — Spamhaus funziona"
                                : "Config OK ma query DNSBL non risponde, verifica connettività")
                : "local_unbound usa FORWARDER (es. 1.1.1.1) — Spamhaus blocca queste query",
            (!isForwarding && dnsblWorking) ? null
                : "Spamhaus/SURBL non rispondono perché local_unbound gira le query a Cloudflare/Google che sono resolver pubblici bloccati.",
            (!isForwarding || !running) ? null : "disable_forwarder",
            "Svuota /var/unbound/forward.conf (backup automatico) e ricarica local_unbound. Il resolver passa a modalità ricorsiva diretta."));

        boolean allOk = installed && configOk && enabledBoot && running && listening53 && resolvOk && queryOk
            && !isForwarding && dnsblWorking;
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("can_fix_all", !allOk);
        r.put("checks", checks);
        return r;
    }

    private boolean isPortListeningOnLocalhost(int port) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/bin/sockstat", "-l", "-4", "-6");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
            String line;
            // FreeBSD sockstat usa "IP.PORT" (con punto), Linux usa "IP:PORT"
            String[] patterns = {
                "127.0.0.1:" + port, "127.0.0.1." + port,
                "*:" + port, "*." + port,
                "::1:" + port, "::1." + port
            };
            while ((line = reader.readLine()) != null) {
                // Cerchiamo che termini con il pattern o sia seguito da spazio (parte del campo address)
                for (String pat : patterns) {
                    if (line.contains(pat + " ") || line.endsWith(pat) || line.contains(pat + "\t")) {
                        p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
                        return true;
                    }
                }
            }
            p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            return false;
        } catch (Exception e) { return false; }
    }

    /**
     * Verifica se local_unbound è configurato come FORWARDER (forward-zone definito).
     * Se sì, le query DNSBL passano per i forwarder pubblici e Spamhaus le blocca.
     */
    private boolean isUnboundUsingForwarder() {
        try {
            // Cerca forward-zone in tutti i possibili file di config di local_unbound
            String[] confFiles = {
                "/var/unbound/forward.conf",
                "/var/unbound/unbound.conf",
                "/usr/local/etc/unbound/unbound.conf",
                "/usr/local/etc/unbound/forward.conf"
            };
            for (String path : confFiles) {
                java.nio.file.Path p = java.nio.file.Paths.get(path);
                if (!java.nio.file.Files.exists(p)) continue;
                String content = java.nio.file.Files.readString(p);
                // Cerca direttiva 'forward-zone:' non commentata
                for (String line : content.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("#")) continue;
                    if (t.startsWith("forward-zone:")) return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false; // Default: assume NOT forwarding se non riusciamo a leggere
        }
    }

    /**
     * Esegue una query DNSBL di test contro Spamhaus.
     * 2.0.0.127.zen.spamhaus.org è un IP "sempre listato" usato per test.
     * Se la risposta è 127.0.0.X (escluso 127.255.X) → il resolver funziona bene per DNSBL.
     * Se è 127.255.255.254 → Spamhaus ci blocca (forwarder/public resolver).
     * Se è vuoto → query fallita.
     */
    private boolean testDnsblQuery() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "+tries=1",
                "A", "2.0.0.127.zen.spamhaus.org");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); return false; }
            if (p.exitValue() != 0) return false;
            for (String line : out.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                // 127.0.0.X (escluso 127.255.255.X) = LISTED davvero = query funziona
                if (t.matches("^127\\.0\\.0\\.\\d{1,3}$")) return true;
                // 127.255.255.X = blocco di Spamhaus = NON funziona
                if (t.startsWith("127.255.255.")) return false;
            }
            return false;
        } catch (Exception e) { return false; }
    }

    private boolean testUnboundQuerySimple() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "+tries=1", "A", "freebsd.org");
            org.mail_panel.util.Shell.applicaPath(pb);
            // NIENTE redirectErrorStream: stderr di dig (es. "communications error") va separato
            // così non lo confondiamo con una risposta valida.
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); return false; }
            // dig +short stampa SOLO il valore (es. "1.2.3.4") in stdout se ha successo,
            // niente se non c'è risposta. Errori vanno in stderr (scartati sopra).
            // Inoltre: dig exit code != 0 quando fallisce.
            if (p.exitValue() != 0) return false;
            // Verifica che la PRIMA riga utile sia un IPv4 valido (non un messaggio strano)
            for (String line : out.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                // Deve essere un IPv4 puro (eventualmente CNAME → IP nelle righe successive)
                if (t.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) return true;
                // Se la prima riga utile è un CNAME, controlla la successiva
                if (t.endsWith(".") && t.matches("^[a-zA-Z0-9.-]+\\.$")) continue;
                // Altrimenti è qualcosa di strano, fallisci
                return false;
            }
            return false;
        } catch (Exception e) { return false; }
    }

    private JSONObject installUnbound() {
        return sulTurnoPacchetti("installazione di unbound", this::eseguiInstallUnbound);
    }

    private JSONObject eseguiInstallUnbound() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", "unbound");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(180, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", "Timeout installazione (>3min)"); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "unbound installato" : "pkg install exit=" + p.exitValue());
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject writeUnboundConfig() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path confPath = java.nio.file.Paths.get(UNBOUND_CONF_PATH);
            java.nio.file.Path parent = confPath.getParent();
            if (parent != null && !java.nio.file.Files.exists(parent)) {
                java.nio.file.Files.createDirectories(parent);
            }
            // Backup se esiste
            if (java.nio.file.Files.exists(confPath)) {
                java.nio.file.Files.copy(confPath, java.nio.file.Paths.get(UNBOUND_CONF_PATH + ".bak." + System.currentTimeMillis()));
            }
            java.nio.file.Files.writeString(confPath, UNBOUND_CONF_CONTENT, java.nio.charset.StandardCharsets.UTF_8);
            try { java.nio.file.Files.setPosixFilePermissions(confPath,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}

            // Test sintassi con unbound-checkconf se disponibile
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/local/sbin/unbound-checkconf", UNBOUND_CONF_PATH);
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (p.exitValue() != 0) {
                    r.put("success", false);
                    r.put("message", "unbound-checkconf ha rilevato errori: " + out);
                    return r;
                }
            } catch (Exception ignored) {}

            r.put("success", true);
            r.put("message", "Config scritta: " + UNBOUND_CONF_PATH);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    /**
     * Sostituisce /etc/resolv.conf in modo SAFE:
     *  - backup automatico con timestamp
     *  - pre-flight test: prima verifica che dig @127.0.0.1 risolva, SOLO se OK procede
     *  - scrive 127.0.0.1 come primary + 1.1.1.1 come fallback
     *  - post-flight test: dopo scrittura ri-verifica che il sistema risolva ancora
     *  - rollback automatico se post-flight fail
     */
    private JSONObject switchResolvConfToUnbound() {
        JSONObject r = new JSONObject();
        java.nio.file.Path resolvPath = java.nio.file.Paths.get("/etc/resolv.conf");
        try {
            // 1. Pre-flight: unbound deve rispondere
            if (!testUnboundQuerySimple()) {
                r.put("success", false);
                r.put("message", "PRE-FLIGHT FAIL: dig @127.0.0.1 non risolve. NON modifico resolv.conf — rischio lockout.");
                return r;
            }
            // 2. Backup
            String bakPath = "/etc/resolv.conf.bak." + System.currentTimeMillis();
            if (java.nio.file.Files.exists(resolvPath)) {
                java.nio.file.Files.copy(resolvPath, java.nio.file.Paths.get(bakPath));
            }
            // 3. Scrivi nuovo
            String content = ""
                + "# Configurato dal mail panel\n"
                + "# Resolver primario: unbound locale\n"
                + "# Fallback: DNS pubblici se unbound non risponde\n"
                + "nameserver 127.0.0.1\n"
                + "nameserver 1.1.1.1\n"
                + "nameserver 9.9.9.9\n"
                + "options timeout:2 attempts:3\n";
            java.nio.file.Files.writeString(resolvPath, content, java.nio.charset.StandardCharsets.UTF_8);

            // 4. Post-flight test (risolvi con il sistema, non più @127.0.0.1)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", "+short", "+time=3", "+tries=2", "A", "freebsd.org");
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                p.waitFor(8, java.util.concurrent.TimeUnit.SECONDS);
                boolean ok = out.matches("(?s).*\\b\\d+\\.\\d+\\.\\d+\\.\\d+\\b.*");
                if (!ok) {
                    // Rollback
                    java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), resolvPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    r.put("success", false);
                    r.put("message", "POST-FLIGHT FAIL: la risoluzione DNS non funziona dopo lo switch. Rollback eseguito, /etc/resolv.conf ripristinato.");
                    return r;
                }
            } catch (Exception e) {
                // Rollback su exception
                try { java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), resolvPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING); } catch (Exception ignored) {}
                r.put("success", false);
                r.put("message", "Errore post-flight: " + e.getMessage() + " — rollback tentato");
                return r;
            }

            r.put("success", true);
            r.put("message", "/etc/resolv.conf aggiornato. Backup: " + bakPath);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    /**
     * Trasforma local_unbound da forwarder a resolver ricorsivo:
     *  1. Backup di /var/unbound/forward.conf (e /var/unbound/unbound.conf se contiene forward-zone)
     *  2. Svuota forward.conf
     *  3. Reload local_unbound
     *
     * Dopo questa operazione, local_unbound chiede direttamente ai root server
     * invece di girare le query a forwarder esterni (1.1.1.1, ecc). Spamhaus vede
     * la query arrivare dal tuo IP server → risponde correttamente.
     */
    private JSONObject disableUnboundForwarder() {
        JSONObject r = new JSONObject();
        StringBuilder log = new StringBuilder();
        try {
            int touched = 0;
            String[] paths = { "/var/unbound/forward.conf", "/var/unbound/unbound.conf" };
            for (String path : paths) {
                java.nio.file.Path p = java.nio.file.Paths.get(path);
                if (!java.nio.file.Files.exists(p)) continue;
                String content = java.nio.file.Files.readString(p);
                // Rileva se c'è effettivamente forward-zone (anche commentati: skippiamo solo i veri)
                boolean hasForwardZone = false;
                StringBuilder cleaned = new StringBuilder();
                boolean inForwardZone = false;
                for (String line : content.split("\n", -1)) {
                    String t = line.trim();
                    if (!inForwardZone) {
                        if (!t.startsWith("#") && t.startsWith("forward-zone:")) {
                            hasForwardZone = true;
                            inForwardZone = true;
                            cleaned.append("# Disabilitato dal mail panel (forwarder bloccava Spamhaus)\n");
                            cleaned.append("# ").append(line).append("\n");
                        } else {
                            cleaned.append(line).append("\n");
                        }
                    } else {
                        // Siamo dentro un blocco forward-zone — commentiamo tutto fino al prossimo blocco
                        if (t.isEmpty() || (!t.startsWith("forward-") && !t.startsWith("name:") && !t.startsWith("#"))) {
                            // Fine del blocco
                            inForwardZone = false;
                            cleaned.append(line).append("\n");
                        } else {
                            cleaned.append("# ").append(line).append("\n");
                        }
                    }
                }
                if (hasForwardZone) {
                    java.nio.file.Files.copy(p, java.nio.file.Paths.get(path + ".bak." + System.currentTimeMillis()));
                    String result = cleaned.toString();
                    java.nio.file.Files.writeString(p, result, java.nio.charset.StandardCharsets.UTF_8);
                    touched++;
                    log.append("✓ Commentato forward-zone in ").append(path).append("\n");
                }
            }

            // === FIX PERSISTENZA AL REBOOT ===
            // FreeBSD rigenera /var/unbound/forward.conf a vari trigger (pkg upgrade,
            // local-unbound-setup, dhclient newresolv hook) leggendo dueriferimenti:
            //   1. local_unbound_forwarders in /etc/rc.conf
            //   2. /etc/resolv.conf  (nameserver != 127.0.0.1 vengono presi come forwarder)
            // Se non li sistemiamo entrambi, dopo un reboot torniamo in modalita' forwarder.

            // 1) Svuota local_unbound_forwarders in rc.conf (se presente)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pbGet = new ProcessBuilder("/usr/sbin/sysrc", "-n", "local_unbound_forwarders");
                org.mail_panel.util.Shell.applicaPath(pbGet);
                pbGet.redirectErrorStream(true);
                Process pg = pbGet.start();
                String currentVal = new String(pg.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                pg.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (!currentVal.isEmpty()) {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pbDel = new ProcessBuilder("/usr/sbin/sysrc", "-x", "local_unbound_forwarders");
                    org.mail_panel.util.Shell.applicaPath(pbDel);
                    pbDel.redirectErrorStream(true);
                    Process pd = pbDel.start();
                    pd.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    log.append("✓ Rimosso local_unbound_forwarders da rc.conf (era: \"").append(currentVal).append("\")\n");
                } else {
                    log.append("• local_unbound_forwarders gia' vuoto in rc.conf\n");
                }
            } catch (Exception e) {
                log.append("⚠ Impossibile sistemare rc.conf: ").append(e.getMessage()).append("\n");
            }

            // 2) Assicurati che /etc/resolv.conf abbia 127.0.0.1 come PRIMO nameserver
            try {
                java.nio.file.Path resolv = java.nio.file.Paths.get("/etc/resolv.conf");
                if (java.nio.file.Files.exists(resolv)) {
                    String rc = java.nio.file.Files.readString(resolv);
                    String firstNs = null;
                    for (String line : rc.split("\n")) {
                        String t = line.trim();
                        if (t.startsWith("#") || t.isEmpty()) continue;
                        if (t.startsWith("nameserver")) {
                            firstNs = t.replaceFirst("nameserver\\s+", "").trim();
                            break;
                        }
                    }
                    if (firstNs == null || (!firstNs.equals("127.0.0.1") && !firstNs.equals("::1"))) {
                        java.nio.file.Files.copy(resolv,
                            java.nio.file.Paths.get("/etc/resolv.conf.bak." + System.currentTimeMillis()));
                        String newContent = "# Generato dal mail panel\n# Loopback come PRIMO nameserver per local_unbound\nnameserver 127.0.0.1\noptions edns0\n";
                        java.nio.file.Files.writeString(resolv, newContent, java.nio.charset.StandardCharsets.UTF_8);
                        log.append("✓ /etc/resolv.conf riscritto con 127.0.0.1 come unico nameserver (backup creato)\n");
                    } else {
                        log.append("• /etc/resolv.conf gia' OK (127.0.0.1 primo)\n");
                    }
                }
            } catch (Exception e) {
                log.append("⚠ Impossibile sistemare /etc/resolv.conf: ").append(e.getMessage()).append("\n");
            }

            // 3) Disabilita resolvconf se attivo (altrimenti DHCP riscrive resolv.conf al reboot)
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pbGet = new ProcessBuilder("/usr/sbin/sysrc", "-n", "resolvconf_enable");
                org.mail_panel.util.Shell.applicaPath(pbGet);
                pbGet.redirectErrorStream(true);
                Process pg = pbGet.start();
                String currentVal = new String(pg.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                pg.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (currentVal.equalsIgnoreCase("YES")) {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pbSet = new ProcessBuilder("/usr/sbin/sysrc", "resolvconf_enable=NO");
                    org.mail_panel.util.Shell.applicaPath(pbSet);
                    pbSet.redirectErrorStream(true);
                    Process ps = pbSet.start();
                    ps.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    log.append("✓ Disabilitato resolvconf_enable (DHCP non riscrivera' piu' resolv.conf al boot)\n");
                }
            } catch (Exception e) {
                log.append("⚠ Impossibile disabilitare resolvconf: ").append(e.getMessage()).append("\n");
            }

            // 4) FIX DEFINITIVO: rimuovi 'include: forward.conf' da unbound.conf.
            //    Anche se forward.conf venisse rigenerato da local-unbound-setup
            //    (pkg upgrade, hook DHCP, ecc), non verrebbe piu' caricato.
            try {
                java.nio.file.Path ucPath = java.nio.file.Paths.get("/var/unbound/unbound.conf");
                if (java.nio.file.Files.exists(ucPath)) {
                    String uc = java.nio.file.Files.readString(ucPath);
                    String[] lines = uc.split("\n", -1);
                    boolean changed = false;
                    StringBuilder sb = new StringBuilder();
                    for (String line : lines) {
                        String trimmed = line.trim();
                        // Cattura "include: ..forward.conf" anche con virgolette o spazi
                        if (!trimmed.startsWith("#") && trimmed.toLowerCase().startsWith("include:")
                                && trimmed.toLowerCase().contains("forward.conf")) {
                            sb.append("# Disabilitato dal mail panel (forward-zone bloccava Spamhaus): ").append(line).append("\n");
                            changed = true;
                        } else {
                            sb.append(line).append("\n");
                        }
                    }
                    if (changed) {
                        java.nio.file.Files.copy(ucPath,
                            java.nio.file.Paths.get("/var/unbound/unbound.conf.bak." + System.currentTimeMillis()));
                        // toString aggiunge un \n extra alla fine — lo togliamo se serve
                        String newContent = sb.toString();
                        if (newContent.endsWith("\n\n")) newContent = newContent.substring(0, newContent.length() - 1);
                        java.nio.file.Files.writeString(ucPath, newContent, java.nio.charset.StandardCharsets.UTF_8);
                        log.append("✓ Commentato 'include: forward.conf' in /var/unbound/unbound.conf (backup creato)\n");
                    } else {
                        log.append("• unbound.conf: nessun 'include: forward.conf' attivo\n");
                    }
                }
            } catch (Exception e) {
                log.append("⚠ Impossibile modificare unbound.conf: ").append(e.getMessage()).append("\n");
            }

            // 5) Svuota forward.conf (anche se non e' piu' incluso, per pulizia)
            try {
                java.nio.file.Path fcPath = java.nio.file.Paths.get("/var/unbound/forward.conf");
                if (java.nio.file.Files.exists(fcPath)) {
                    // Rimuovi flag immutabile se gia' presente (per poter sovrascrivere)
                    try {
                        // TODO: migrate to Shell.run when touched
                        new ProcessBuilder("/bin/chflags", "noschg", "/var/unbound/forward.conf")
                            .redirectErrorStream(true).start().waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (Exception ignored) {}
                    java.nio.file.Files.copy(fcPath,
                        java.nio.file.Paths.get("/var/unbound/forward.conf.bak." + System.currentTimeMillis()));
                    java.nio.file.Files.writeString(fcPath,
                        "# Mail panel: modalita' ricorsiva diretta — forward-zone DISABILITATE\n",
                        java.nio.charset.StandardCharsets.UTF_8);
                    log.append("✓ /var/unbound/forward.conf svuotato (backup creato)\n");
                }
            } catch (Exception e) {
                log.append("⚠ Impossibile svuotare forward.conf: ").append(e.getMessage()).append("\n");
            }

            // 6) Rendi forward.conf IMMUTABILE — local-unbound-setup non puo' piu' sovrascriverlo
            try {
                // TODO: migrate to Shell.run when touched
                Process pCh = new ProcessBuilder("/bin/chflags", "schg", "/var/unbound/forward.conf")
                    .redirectErrorStream(true).start();
                pCh.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (pCh.exitValue() == 0) {
                    log.append("✓ chflags schg applicato a forward.conf (file IMMUTABILE)\n");
                } else {
                    log.append("⚠ chflags schg fallito (richiede securelevel <= 0); il file resta scrivibile ma 'include' e' gia' commentato\n");
                }
            } catch (Exception e) {
                log.append("⚠ chflags non eseguibile: ").append(e.getMessage()).append("\n");
            }

            // 7) RESTART (non reload) — il reload non ricarica forward.conf se l'include e' cambiato
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "local_unbound", "restart");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String reloadOut = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS);
            log.append("✓ service local_unbound restart eseguito\n");
            if (!reloadOut.isEmpty()) log.append("  output: ").append(reloadOut.trim()).append("\n");

            try { Thread.sleep(1500); } catch (Exception ignored) {}
            boolean stillForwarding = isUnboundUsingForwarder();
            boolean dnsblWorks = testDnsblQuery();
            r.put("success", !stillForwarding);
            r.put("message", "Modalita' ricorsiva attivata e RESA PERSISTENTE al reboot."
                + (touched == 0 ? " (forward.conf gia' pulito) " : " (commentati " + touched + " file) ")
                + (dnsblWorks ? "Test Spamhaus: OK ✓" : "Test Spamhaus: ancora non OK (attendi qualche secondo e ricontrolla)"));
            r.put("output", log.toString());
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            r.put("output", log.toString());
        }
        return r;
    }

    /** Ripristina l'ultimo backup di /etc/resolv.conf creato dal pannello. */
    private JSONObject rollbackResolvConf() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path etc = java.nio.file.Paths.get("/etc");
            String latest = null;
            long latestMtime = 0;
            try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(etc)) {
                for (java.nio.file.Path p : s.toArray(java.nio.file.Path[]::new)) {
                    if (p.getFileName().toString().startsWith("resolv.conf.bak.")) {
                        long m = java.nio.file.Files.getLastModifiedTime(p).toMillis();
                        if (m > latestMtime) { latestMtime = m; latest = p.toString(); }
                    }
                }
            }
            if (latest == null) {
                r.put("success", false);
                r.put("message", "Nessun backup trovato in /etc/resolv.conf.bak.*");
                return r;
            }
            java.nio.file.Files.copy(java.nio.file.Paths.get(latest), java.nio.file.Paths.get("/etc/resolv.conf"),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            r.put("success", true);
            r.put("message", "Ripristinato da " + latest);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject testUnboundQuery() {
        JSONObject r = new JSONObject();
        try {
            // Test 1: query semplice
            boolean basic = testUnboundQuerySimple();
            // Test 2: query DNSBL Spamhaus con un IP standard (1.0.0.127.zen.spamhaus.org sempre TRUE)
            //         "127.0.0.2" reverse = "2.0.0.127.zen.spamhaus.org" → sempre listed (test address)
            String dnsblOut = "";
            boolean dnsblOk = false;
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", "@127.0.0.1", "+short", "+time=3", "A", "2.0.0.127.zen.spamhaus.org");
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                dnsblOut = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                // Se la risposta inizia con 127.0.0.* (escluso 127.255.*) → query Spamhaus funziona
                if (!dnsblOut.isEmpty()) {
                    String first = dnsblOut.split("\n")[0].trim();
                    dnsblOk = first.startsWith("127.0.0.") || first.startsWith("127.0.0.2");
                }
            } catch (Exception ignored) {}

            r.put("success", basic);
            StringBuilder msg = new StringBuilder();
            msg.append("Test query base (freebsd.org): ").append(basic ? "OK" : "FAIL").append("\n");
            msg.append("Test Spamhaus (2.0.0.127.zen.spamhaus.org → atteso 127.0.0.X): ");
            if (dnsblOk) msg.append("OK ✓ — Spamhaus risponde, le query DNSBL funzionano via unbound!");
            else if (dnsblOut.startsWith("127.255.255.")) msg.append("ANCORA BLOCCATO (resolver pubblico?). Verifica resolv.conf");
            else msg.append("nessuna risposta: ").append(dnsblOut.isEmpty() ? "(vuota)" : dnsblOut);
            r.put("message", msg.toString());
            r.put("basic_ok", basic);
            r.put("dnsbl_ok", dnsblOk);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject runUnboundFixAll() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        boolean anyFailed = false;

        // Strategia: preferisci local_unbound (base system, già installato)
        //            se non è disponibile, usa pkg unbound
        boolean baseAvailable = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/sbin/local-unbound"));
        boolean pkgInstalled;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "unbound");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            pkgInstalled = p.exitValue() == 0;
        } catch (Exception e) { pkgInstalled = false; }

        // Se local_unbound è disponibile, lo usiamo (zero install, già nel base)
        String svcName;
        String sysrcKey;
        if (baseAvailable) {
            svcName = "local_unbound";
            sysrcKey = "local_unbound_enable";
            steps.put(buildSkipStep("install_unbound", "local_unbound (base system FreeBSD) disponibile — niente da installare"));
        } else if (pkgInstalled) {
            svcName = "unbound";
            sysrcKey = "unbound_enable";
            steps.put(buildSkipStep("install_unbound", "Pacchetto unbound già installato"));
        } else {
            // Niente di disponibile: installa pkg
            JSONObject res = installUnbound();
            steps.put(buildStep("install_unbound", "Installa pacchetto unbound (no base system trovato)", res));
            if (!res.optBoolean("success")) {
                anyFailed = true;
                r.put("success", false); r.put("steps", steps); r.put("message", "Installazione fallita");
                return r;
            }
            svcName = "unbound";
            sysrcKey = "unbound_enable";
        }

        // 2. Config — solo per pkg unbound (local_unbound ha config in /var/unbound gestita dal base)
        if ("unbound".equals(svcName)) {
            boolean confValid = false;
            if (java.nio.file.Files.exists(java.nio.file.Paths.get(UNBOUND_CONF_PATH))) {
                try {
                    String c = java.nio.file.Files.readString(java.nio.file.Paths.get(UNBOUND_CONF_PATH));
                    confValid = c.contains("interface: 127.0.0.1") && c.contains("access-control");
                } catch (Exception ignored) {}
            }
            if (!confValid) {
                JSONObject res = writeUnboundConfig();
                steps.put(buildStep("configure_unbound", "Scrive config (loopback, restrittiva)", res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("configure_unbound", "Config pkg unbound già valida"));
            }
        } else {
            steps.put(buildSkipStep("configure_unbound", "local_unbound usa /var/unbound/unbound.conf (config auto-gestita dal base system)"));
        }

        // 3. Enable at boot
        if (!isSysrcYes(sysrcKey)) {
            JSONObject res = sysrcSet(sysrcKey, "YES");
            steps.put(buildStep("enable_at_boot", "Abilita " + svcName + " al boot (" + sysrcKey + "=YES)", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_at_boot", svcName + " già abilitato al boot"));
        }

        // 4. Start
        if (!isServiceRunning(svcName)) {
            JSONObject res = serviceCommand(svcName, "start", 30);
            steps.put(buildStep("start_resolver", "Avvia " + svcName, res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_resolver", svcName + " già in esecuzione"));
        }

        // 5. Aspetta un attimo che unbound sia pronto
        try { Thread.sleep(1500); } catch (Exception ignored) {}

        // 6. Switch /etc/resolv.conf (con safety)
        // Verifica preventiva
        boolean unboundReady = testUnboundQuerySimple();
        if (!unboundReady) {
            steps.put(buildErrorStep("switch_resolv_conf", "unbound non risponde a dig @127.0.0.1 — NON modifico resolv.conf per non rischiare lockout"));
            anyFailed = true;
        } else {
            boolean resolvOk = false;
            try {
                String resolv = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/resolv.conf"));
                for (String line : resolv.split("\n")) {
                    String t = line.trim();
                    if (t.startsWith("#")) continue;
                    if (t.startsWith("nameserver")) {
                        String ns = t.replaceFirst("nameserver\\s+", "").trim();
                        if (ns.equals("127.0.0.1") || ns.equals("::1")) resolvOk = true;
                        break;
                    }
                }
            } catch (Exception ignored) {}
            if (!resolvOk) {
                JSONObject res = switchResolvConfToUnbound();
                steps.put(buildStep("switch_resolv_conf", "Switcha /etc/resolv.conf su 127.0.0.1 (con pre/post-flight + auto-rollback)", res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("switch_resolv_conf", "/etc/resolv.conf già configurato su unbound"));
            }
        }

        // 7. Disabilita forwarder (forward-zone in unbound.conf) — necessario per DNSBL
        if (isUnboundUsingForwarder()) {
            JSONObject res = disableUnboundForwarder();
            steps.put(buildStep("disable_forwarder", "Disabilita forwarder (modalità ricorsiva diretta per Spamhaus/SURBL)", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("disable_forwarder", "Modalità ricorsiva già attiva"));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", anyFailed ? "Alcuni passaggi falliti — verifica dettagli" : "unbound operativo, sistema usa resolver locale, check DNSBL ora affidabili");
        return r;
    }

    // ============== BLACKLIST CHECK (DNSBL + RHSBL) ==============
    private void handleApiBlacklistCheck(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed"); return;
        }
        JSONObject response = new JSONObject();
        try {
            String query = exchange.getRequestURI().getQuery();
            String ip = extractParamFromQuery(query, "ip");
            String domain = extractParamFromQuery(query, "domain");

            org.mail_panel.security.BlacklistChecker checker = new org.mail_panel.security.BlacklistChecker();
            JSONArray reports = new JSONArray();

            // Se non specificato, usa IP del server + tutti i domini del DB
            if ((ip == null || ip.isEmpty()) && (domain == null || domain.isEmpty())) {
                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : null;
                if (serverIp != null && !serverIp.isEmpty()) {
                    reports.put(reportToJson(checker.checkIp(serverIp)));
                }
                // Domini configurati nel pannello
                try {
                    java.util.List<MailDatabase.Domain> domains = Main.mailDatabase.getDomains();
                    for (MailDatabase.Domain d : domains) {
                        if (d.domain != null && !d.domain.isEmpty()) {
                            reports.put(reportToJson(checker.checkDomain(d.domain)));
                        }
                    }
                } catch (Exception ignored) {}
            } else {
                if (ip != null && !ip.isEmpty()) {
                    if (!org.mail_panel.security.InputValidator.isValidIp(ip)) {
                        response.put("success", false);
                        response.put("error", "IP non valido");
                        sendJsonResponse(exchange, response); return;
                    }
                    reports.put(reportToJson(checker.checkIp(ip)));
                }
                if (domain != null && !domain.isEmpty()) {
                    if (!org.mail_panel.security.InputValidator.isValidDomain(domain)) {
                        response.put("success", false);
                        response.put("error", "Dominio non valido");
                        sendJsonResponse(exchange, response); return;
                    }
                    reports.put(reportToJson(checker.checkDomain(domain)));
                }
            }

            response.put("success", true);
            response.put("reports", reports);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    private JSONObject reportToJson(org.mail_panel.security.BlacklistChecker.BlacklistReport rep) {
        JSONObject jo = new JSONObject();
        jo.put("target", rep.target);
        jo.put("type", rep.type);
        jo.put("listed_count", rep.listedCount);
        jo.put("clean_count", rep.cleanCount);
        jo.put("error_count", rep.errorCount);
        jo.put("web_only_count", rep.webOnlyCount);
        jo.put("elapsed_ms", rep.elapsedMs);
        JSONArray arr = new JSONArray();
        for (org.mail_panel.security.BlacklistChecker.CheckResult cr : rep.results) {
            JSONObject e = new JSONObject();
            e.put("blacklist", cr.blacklistName);
            e.put("zone", cr.blacklistZone);
            e.put("lookup_url", cr.lookupUrl);
            e.put("listed", cr.listed);
            e.put("error", cr.error);
            e.put("web_only", cr.webOnly);
            if (cr.responseCode != null) e.put("response_code", cr.responseCode);
            e.put("message", cr.message);
            arr.put(e);
        }
        jo.put("results", arr);
        return jo;
    }

    // ============== CLAMAV HEALTH CHECK ==============
    /**
     * Protezione dei pacchetti, aggiornamenti e vulnerabilita'.
     *
     * GET restituisce lo stato dei pacchetti, che e' la lettura piu' leggera. Tutto il resto
     * passa da POST con token CSRF: anche le sole letture, perche' interrogano la rete e
     * durano decine di secondi, e perche' le azioni vere (sblocco, aggiornamento) non devono
     * poter essere innescate da una richiesta preparata altrove.
     */
    private void handleApiUpdates(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, UpdateManager.packagesStatus());
                return;
            }
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) { sendJsonError(exchange, 413, "Body troppo grande"); return; }
            JSONObject req = new JSONObject(body);
            if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
            String action = req.optString("action", "");
            String ip = getClientIp(exchange);
            JSONObject response;

            switch (action) {
                case "packages_status" -> response = UpdateManager.packagesStatus();
                case "updates_status" -> response = UpdateManager.updatesStatus();
                case "compatibility" -> response = UpdateManager.compatibilityReport();
                case "dovecot_config_dump" -> response = UpdateManager.dumpConfigDovecot();
                case "dovecot_config_regen" -> {
                    // Riscrive la sola configurazione, senza toccare i pacchetti. La conferma
                    // scritta a mano c'e' perche' l'operazione ricarica un servizio vivo.
                    if (!"RIGENERA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaRigenerazioneDovecot();
                    logAudit("DOVECOT_CONFIG_REGEN", ip, response.optString("jobId", ""));
                }
                case "maintenance_preview" -> {
                    String adesso = org.mail_panel.system.TurnoPacchetti.pianoNonAdesso();
                    response = adesso != null ? new JSONObject().put("success", false).put("error", adesso)
                             : UpdateManager.maintenancePreview();
                }
                case "plan" -> response = UpdateManager.pianoManutenzione();
                case "mysql84_preflight" -> response = UpdateManager.mysql84Preflight();
                case "broken_libs" -> response = UpdateManager.pacchettiConLibrerieMancanti();
                case "mysql_client_diag" -> response = UpdateManager.diagnosiClientMysql();
                case "defaults_check" -> response = UpdateManager.coerenzaPredefiniti();
                case "system_report" -> response = UpdateManager.rapportoSistema();
                case "os_status" -> response = UpdateManager.sistemaOperativo();
                case "reboot_preview" -> response = UpdateManager.riavviaServer(false, 1);
                case "reboot_cancel" -> {
                    response = UpdateManager.annullaRiavvio();
                    logAudit("SERVER_REBOOT_CANCEL", ip, response.optString("pid", ""));
                }
                case "reboot_now" -> {
                    if (!"RIAVVIA IL SERVER".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    logAudit("SERVER_REBOOT", ip, "richiesto dal pannello");
                    response = UpdateManager.riavviaServer(true, req.optInt("minuti", 1));
                }
                case "rc_stato" -> response = UpdateManager.avvioAutomatico();
                case "riepilogo_sistema" -> response = UpdateManager.riepilogoSistema();
                case "cf_intervalli" -> response = UpdateManager.intervalliCloudflare();
                case "rc_remove_preview" -> response = UpdateManager.rimuoviScriptRcPannello(false);
                case "rc_remove" -> {
                    if (!"RIMUOVI RC".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.rimuoviScriptRcPannello(true);
                    logAudit("RC_REMOVE", ip, response.optBoolean("success")
                            ? "avvio automatico rimosso" : "NON rimosso: " + response.optString("error", "?"));
                }
                case "rc_preview" -> response = UpdateManager.scriptRcPannello(false);
                case "rc_install" -> {
                    if (!"INSTALLA RC".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.scriptRcPannello(true);
                    logAudit("RC_SCRIPT_INSTALL", ip, response.optString("percorso", ""));
                }
                case "os_upgrade_targets" -> response = UpdateManager.versioniDiArrivo();
                case "os_upgrade_preflight" -> response = UpdateManager.aggiornamentoSistemaPreflight(
                        req.optString("target", "15.1"));
                case "os_upgrade_instructions" -> response = UpdateManager.istruzioniAggiornamentoSistema(
                        req.optString("target", "15.1"));
                case "os_upgrade_verify" -> response = UpdateManager.verificaDopoAggiornamento();
                case "salto_stato" -> response = UpdateManager.statoSalto();
                case "be_list" -> response = UpdateManager.ambientiDiAvvio();
                case "ssl_uso" -> response = UpdateManager.usoOpenssl();
                case "removal_candidates" -> response = UpdateManager.candidatiRimozione();
                case "panel_uses" -> response = UpdateManager.usoDalPannello(req.optString("nome", ""));
                case "deep_scan" -> response = UpdateManager.analisiProfonda(req.optString("nome", ""));
                case "panel_env" -> response = UpdateManager.ambienteDelPannello();
                case "dovecot24_preview" -> response = UpdateManager.anteprimaDovecot24();
                case "rspamd_timeout" -> response = UpdateManager.diagnosiTimeoutRspamd();
                case "web_diagnosi" -> response = org.mail_panel.system.DiagnosiWeb.stato();
                case "web443_status" -> response = org.mail_panel.system.ProtezioneWeb.stato();
                case "web443_config" -> response = new JSONObject().put("success", true)
                        .put("configurazione", org.mail_panel.system.ProtezioneWeb.configurazione(
                                "/usr/local/etc/ssl/mail/fullchain.pem",
                                "/usr/local/etc/ssl/mail/privkey.pem"))
                        .put("filtro", org.mail_panel.system.ProtezioneWeb.filtro())
                        .put("jail", org.mail_panel.system.ProtezioneWeb.jail());
                case "mtasts_piano" -> response = org.mail_panel.system.AttivaMtaSts.piano();
                case "mtasts_attiva" -> {
                    if (!"ATTIVA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaAttivazioneMtaSts();
                    logAudit("MTASTS_ATTIVA", ip, "avviata come lavoro " + response.optString("jobId", ""));
                }
                case "web443_include" -> {
                    if (!"AGGIUNGI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = org.mail_panel.system.ProtezioneWeb.aggiungiInclude();
                    logAudit("NGINX_INCLUDE", ip, response.optBoolean("success")
                            ? "include aggiunto" : "NON aggiunto: " + response.optString("error", "?"));
                }
                case "web443_install" -> {
                    if (!"APRI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = org.mail_panel.system.ProtezioneWeb.installa("", "");
                    logAudit("WEB443_INSTALL", ip, response.optBoolean("success")
                            ? "443 aperta con superficie minima" : "NON aperta: " + response.optString("error", "?"));
                }
                case "web443_jail" -> {
                    if (!"ATTIVA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = org.mail_panel.system.ProtezioneWeb.installaJail();
                    logAudit("WEB443_JAIL", ip, response.optBoolean("success")
                            ? "jail attiva" : "NON attiva: " + response.optString("error", "?"));
                }
                case "sorveglianza" -> response = org.mail_panel.system.Sorveglianza.controlla();
                case "sorveglianza_cambi" -> response = org.mail_panel.system.Sorveglianza.cosaECambiato(
                        req.optString("rfc", ""),
                        // Per un aggiornamento il documento nuovo e la specifica del pannello
                        // sono due numeri diversi: gli identificatori da incrociare sono quelli
                        // della specifica, non del documento che la aggiorna.
                        req.optString("riferimento", req.optString("rfc", "")));
                case "openssl_scadenza" -> response = org.mail_panel.system.ScadenzaOpenssl.stato();
                case "porta465_status" -> response = org.mail_panel.system.PortaSottomissione.stato();
                case "porta465_apply" -> {
                    if (!"APPLICA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = org.mail_panel.system.PortaSottomissione.applica();
                    logAudit("PORTA_465", ip, response.optBoolean("success")
                            ? "restrizione applicata" : "NON applicata: " + response.optString("error", "?"));
                }
                case "postfix_level" -> {
                    if (!"ALZA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.alzaLivelloPostfix(req.optString("livello", ""));
                    logAudit("POSTFIX_LEVEL", ip, req.optString("livello", "")
                            + (response.optBoolean("success") ? " - fatto" : " - NON fatto: "
                               + response.optString("error", "?")));
                }
                case "pkg_remove" -> {
                    if (!"RIMUOVI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.rimuoviPacchetto(req.optString("nome", ""));
                    logAudit("PKG_REMOVE", ip, req.optString("nome", "")
                            + (response.optBoolean("success") ? " - rimosso" : " - NON rimosso: "
                               + response.optString("error", "?")));
                }
                case "be_destroy" -> {
                    if (!"ELIMINA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.eliminaAmbienteDiAvvio(req.optString("nome", ""));
                    logAudit("BE_DESTROY", ip, req.optString("nome", "")
                            + (response.optBoolean("success") ? " - eliminato"
                               : " - NON eliminato: " + response.optString("error", "?")));
                }
                case "salto_prosegui" -> {
                    if (!"PROSEGUI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaProseguiSalto(req.optString("target", ""));
                    logAudit("RELEASE_JUMP_CONTINUE", ip, response.optString("jobId", ""));
                }
                case "os_upgrade_prepare" -> {
                    if (!"PREPARA AGGIORNAMENTO".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaPreparazioneSistema(req.optString("target", "15.1"));
                    logAudit("OS_UPGRADE_PREPARE", ip, req.optString("target", ""));
                }
                case "os_fetch" -> {
                    if (!"CERCA AGGIORNAMENTI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaCercaAggiornamentiSistema();
                    logAudit("OS_UPDATE_FETCH", ip, response.optString("jobId", ""));
                }
                case "python_preflight" -> response = UpdateManager.pythonPreflight();
                case "python_leftovers" -> response = UpdateManager.restiPython(false);
                case "python_leftovers_clean" -> {
                    if (!"PULISCI PYTHON".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.restiPython(true);
                    logAudit("PYTHON_LEFTOVERS_CLEAN", ip, response.optString("tolti", ""));
                }
                case "python_move" -> {
                    if (!"SPOSTA PYTHON".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaPassaggioPython();
                    logAudit("PYTHON_MOVE_STARTED", ip, response.optString("jobId", ""));
                }
                case "java_preflight" -> response = UpdateManager.javaPreflight();
                case "java_status" -> response = UpdateManager.statoAggiornamentoJava();
                case "java_update" -> {
                    if (!"AGGIORNA JAVA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    logAudit("JAVA_UPDATE_STARTED", ip, "il pannello si spegnera'");
                    response = UpdateManager.avviaAggiornamentoJava();
                }
                case "roundcube_preflight" -> response = UpdateManager.roundcubePreflight();
                case "roundcube_diag" -> response = UpdateManager.roundcubeDiagnosi();
                case "roundcube_nginx_preview" -> response = UpdateManager.riparaNginxPathInfo(false);
                case "roundcube_nginx_fix" -> {
                    if (!"RIPARA NGINX".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.riparaNginxPathInfo(true);
                    logAudit("ROUNDCUBE_NGINX_FIX", ip, response.optString("backup", ""));
                }
                case "roundcube_update" -> {
                    if (!"AGGIORNA ROUNDCUBE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaAggiornamentoRoundcube();
                    logAudit("ROUNDCUBE_UPDATE_STARTED", ip, response.optString("jobId", ""));
                }
                case "clean_client" -> {
                    if (!"RIMUOVI".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaPuliziaClientEstraneo(
                            req.optString("estraneo", ""), req.optString("corretto", ""));
                    logAudit("MYSQL_CLIENT_CLEANUP", ip, req.optString("estraneo", ""));
                }
                case "relink" -> {
                    if (!"RICOLLEGA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaRicollegamento();
                    logAudit("RELINK_STARTED", ip, response.optString("jobId", ""));
                }
                case "rspamd_clean_cache" -> {
                    // E' una cancellazione: la conferma si scrive a mano, e il percorso non
                    // arriva dalla richiesta ma e' fissato nel codice.
                    if (!"ELIMINA CACHE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaPuliziaCacheRspamd();
                    logAudit("RSPAMD_CACHE_CLEANED", ip, response.optString("jobId", ""));
                }
                case "mysql84_migrate" -> {
                    if (!"MIGRA A 8.4".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaMigrazione84();
                    logAudit("MYSQL84_MIGRATION_STARTED", ip, response.optString("jobId", ""));
                }
                case "package_preflight" -> {
                    String adesso = org.mail_panel.system.TurnoPacchetti.pianoNonAdesso();
                    response = adesso != null ? new JSONObject().put("success", false).put("error", adesso)
                             : UpdateManager.preflightPacchetto(req.optString("package", ""));
                }
                case "package_update" -> {
                    // La conferma e' il NOME DEL PACCHETTO scritto a mano: cosi' non si puo'
                    // aggiornare per sbaglio quello sbagliato dopo aver letto il referto di
                    // un altro. Un "sei sicuro?" non lo impedirebbe.
                    String pk = req.optString("package", "");
                    if (!pk.equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false)
                                .put("error", "Per confermare scrivi esattamente il nome del pacchetto.");
                        break;
                    }
                    response = UpdateManager.avviaAggiornamentoGuidato(pk, req.optString("firma", ""));
                    logAudit("GUIDED_UPDATE_STARTED", ip, pk + " -> " + response.optString("jobId", ""));
                }
                case "packages_lock" -> {
                    boolean lock = req.optBoolean("lock", true);
                    String only = req.optString("package", "");
                    response = UpdateManager.packagesLock(lock, only);
                    logAudit(lock ? "PACKAGES_LOCKED" : "PACKAGES_UNLOCKED", ip,
                            (only.isEmpty() ? "tutti" : only) + " -> " + response.optInt("changed", 0) + " modificati");
                }
                case "updates_apply" -> {
                    // La conferma scritta a mano non e' burocrazia: distingue un click di
                    // riflesso da una decisione. Qui si modifica un server di posta vivo.
                    if (!"AGGIORNA".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaAggiornamentoNonProtetti();
                    logAudit("UPDATES_APPLY_STARTED", ip, response.optString("jobId", ""));
                }
                case "maintenance_run" -> {
                    if (!"MANUTENZIONE".equals(req.optString("confirm", ""))) {
                        response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                        break;
                    }
                    response = UpdateManager.avviaManutenzione(req.optString("firma", ""));
                    logAudit("MAINTENANCE_STARTED", ip, response.optString("jobId", ""));
                }
                case "job_status" -> response = UpdateManager.jobStatus(req.optString("jobId", ""));
                default -> response = new JSONObject().put("success", false).put("error", "Azione sconosciuta");
            }
            sendJsonResponse(exchange, response);
        } catch (java.io.IOException e) {
            // "Broken pipe" non e' un guasto del server: e' il browser che ha chiuso prima che
            // la risposta fosse scritta, tipicamente perche' l'operazione durava. Il lavoro e'
            // stato fatto, si e' persa la risposta. Registrarlo come SEVERE con tutta la traccia
            // fa credere che sia crollato qualcosa, ed e' esattamente cio' che e' successo il
            // 31/08/2026: un messaggio allarmante per un cliente che se n'era andato.
            String m = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
            if (m.contains("broken pipe") || m.contains("insufficient bytes")
                    || m.contains("connection reset")) {
                LOGGER.info("/api/updates: il client ha chiuso la connessione prima della risposta "
                        + "(l'operazione era gia' stata eseguita). " + e.getMessage());
            } else {
                LOGGER.log(Level.SEVERE, "Errore di I/O in /api/updates", e);
                try { sendJsonError(exchange, 500, "Errore interno del server"); } catch (Exception ignored) { }
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Errore in /api/updates", e);
            sendJsonError(exchange, 500, "Errore interno del server");
        }
    }

    private void handleApiClamavHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildClamavHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, "Body troppo grande"); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_clamav" -> {
                        JSONObject r = installClamav();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_INSTALLED" : "CLAMAV_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_freshclam_at_boot" -> {
                        JSONObject r = sysrcSet("clamav_freshclam_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FRESHCLAM_ENABLED" : "CLAMAV_FRESHCLAM_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_clamd_at_boot" -> {
                        JSONObject r = sysrcSet("clamav_clamd_enable", "YES");
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_CLAMD_ENABLED" : "CLAMAV_CLAMD_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "update_db" -> {
                        JSONObject r = runFreshclam();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_DB_UPDATED" : "CLAMAV_DB_UPDATE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_clamd" -> {
                        JSONObject r = serviceCommand("clamav_clamd", "start", 60);
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_CLAMD_STARTED" : "CLAMAV_CLAMD_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_freshclam" -> {
                        JSONObject r = serviceCommand("clamav_freshclam", "start", 30);
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FRESHCLAM_STARTED" : "CLAMAV_FRESHCLAM_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "ensure_rspamd_antivirus" -> {
                        JSONObject r = ensureRspamdAntivirusConfig();
                        response = r;
                        logAudit(r.optBoolean("success") ? "RSPAMD_ANTIVIRUS_CONFIGURED" : "RSPAMD_ANTIVIRUS_CONFIG_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runClamavFixAll();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_FIX_ALL_OK" : "CLAMAV_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    case "test_eicar" -> {
                        JSONObject r = runEicarTest();
                        response = r;
                        logAudit(r.optBoolean("success") ? "CLAMAV_EICAR_TEST_OK" : "CLAMAV_EICAR_TEST_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Azione non valida: " + action);
                    }
                }
            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    private JSONObject buildClamavHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();

        // 1. ClamAV installato
        boolean installed;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "clamav");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            installed = p.exitValue() == 0;
        } catch (Exception e) { installed = false; }
        checks.put(makeCheck("clamav-installed", "ClamAV installato", installed,
            installed ? "Pacchetto clamav presente" : "Pacchetto clamav NON installato",
            installed ? null : "Senza ClamAV non c'è scansione antivirus delle email.",
            installed ? null : "install_clamav",
            "Esegue: pkg install -y clamav"));

        // 2. freshclam abilitato al boot
        boolean freshclamEnabledBoot = isSysrcYes("clamav_freshclam_enable");
        checks.put(makeCheck("freshclam-enabled-boot", "freshclam abilitato al boot",
            freshclamEnabledBoot,
            freshclamEnabledBoot ? "clamav_freshclam_enable=YES" : "freshclam non si avvia al boot",
            freshclamEnabledBoot ? null : "I database virus non verranno aggiornati automaticamente dopo un riavvio.",
            (freshclamEnabledBoot || !installed) ? null : "enable_freshclam_at_boot",
            "sysrc clamav_freshclam_enable=YES"));

        // 3. clamd abilitato al boot
        boolean clamdEnabledBoot = isSysrcYes("clamav_clamd_enable");
        checks.put(makeCheck("clamd-enabled-boot", "clamd abilitato al boot",
            clamdEnabledBoot,
            clamdEnabledBoot ? "clamav_clamd_enable=YES" : "clamd non si avvia al boot",
            clamdEnabledBoot ? null : "Dopo un reboot clamd non torna su e nessuna email viene scansionata.",
            (clamdEnabledBoot || !installed) ? null : "enable_clamd_at_boot",
            "sysrc clamav_clamd_enable=YES"));

        // 4. Database virus presenti (cerca .cvd, .cld, .cud — tutti i formati ClamAV)
        boolean dbPresent = false;
        long dbAgeDays = -1;
        try {
            java.nio.file.Path dbDir = java.nio.file.Paths.get("/var/db/clamav");
            if (java.nio.file.Files.isDirectory(dbDir)) {
                try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.walk(dbDir, 2)) {
                    java.util.List<java.nio.file.Path> dbFiles = s
                        .filter(p -> {
                            String n = p.getFileName().toString().toLowerCase();
                            // Formati signature di ClamAV: .cvd (compressed), .cld (downloaded),
                            // .cud (compressed updates), .hdb, .ndb, .ldb, .fp
                            return (n.endsWith(".cvd") || n.endsWith(".cld") || n.endsWith(".cud"))
                                && (n.startsWith("main") || n.startsWith("daily") || n.startsWith("bytecode"));
                        }).collect(java.util.stream.Collectors.toList());
                    if (!dbFiles.isEmpty()) {
                        dbPresent = true;
                        java.time.Instant newest = dbFiles.stream()
                            .map(p -> { try { return java.nio.file.Files.getLastModifiedTime(p).toInstant(); } catch (Exception e) { return java.time.Instant.EPOCH; } })
                            .max(java.time.Instant::compareTo).orElse(java.time.Instant.EPOCH);
                        dbAgeDays = java.time.Duration.between(newest, java.time.Instant.now()).toDays();
                    }
                }
            }
        } catch (Exception ignored) {}
        // Fallback: se clamd risponde a clamdscan, il DB c'è anche se non ne riconosciamo i file
        if (!dbPresent) {
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/clamdscan", "--version");
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                // clamdscan --version ritorna info su clamd inclusa la versione del database
                // es: "ClamAV 1.5.1/27582/Wed May 14 ..."
                if (out.contains("/") && out.matches("(?s).*\\d+/.*")) {
                    dbPresent = true;
                    // età stimata 0 perché clamd risponde correttamente
                    if (dbAgeDays < 0) dbAgeDays = 0;
                }
            } catch (Exception ignored) {}
        }
        String dbStatus = dbPresent
            ? "Database trovati (più recente: " + dbAgeDays + " giorni fa)"
            : "Nessun database .cvd/.cld in /var/db/clamav";
        boolean dbOk = dbPresent && dbAgeDays <= 7;
        checks.put(makeCheck("clamav-db", "Database virus aggiornato",
            dbOk,
            dbPresent
                ? (dbAgeDays > 7 ? "OBSOLETO: " + dbStatus : dbStatus)
                : dbStatus,
            dbOk ? null
                : (dbPresent ? "I database hanno più di 7 giorni — nuovi malware non vengono rilevati."
                             : "Senza database, clamd non può partire. Va scaricato con freshclam (primo download ~200MB)."),
            (dbOk || !installed) ? null : "update_db",
            "Esegue: freshclam --foreground --stdout (download iniziale richiede 2-5 min)"));

        // 5. clamd in esecuzione
        boolean clamdRunning = isServiceRunning("clamav_clamd");
        checks.put(makeCheck("clamd-running", "clamd attivo",
            clamdRunning,
            clamdRunning ? "Servizio attivo, scansione operativa"
                         : (dbPresent ? "Servizio fermo" : "Non può partire senza database"),
            clamdRunning ? null
                : "Mentre è fermo, Rspamd tenta di chiamarlo ma fallisce: le email NON vengono scansionate da ClamAV.",
            (clamdRunning || !installed || !dbPresent) ? null : "start_clamd",
            "service clamav_clamd start (richiede database già scaricati)"));

        // 6. freshclam in esecuzione (auto-update) — check rigoroso
        boolean freshclamRunning = isServiceRunning("clamav_freshclam");
        // Analisi log: cerca "is up to date" o "downloading" nelle ultime 48h
        FreshclamLogStatus fcLog = analyzeFreshclamLog();
        boolean autoUpdateOk = freshclamRunning && fcLog.lastUpdateAgeHours >= 0 && fcLog.lastUpdateAgeHours <= 48;
        String fcStatusText;
        if (!freshclamRunning) {
            fcStatusText = "Servizio fermo";
        } else if (fcLog.lastUpdateAgeHours < 0) {
            fcStatusText = "Daemon attivo ma NESSUN update registrato nel log (mirror irraggiungibile?)";
        } else if (fcLog.lastUpdateAgeHours <= 2) {
            fcStatusText = "Ultimo check " + fcLog.lastUpdateAgeHours + "h fa — funziona correttamente";
        } else if (fcLog.lastUpdateAgeHours <= 48) {
            fcStatusText = "Ultimo check " + fcLog.lastUpdateAgeHours + "h fa";
        } else {
            fcStatusText = "DATATO: ultimo update " + (fcLog.lastUpdateAgeHours / 24) + " giorni fa";
        }
        if (fcLog.lastErrorMessage != null) {
            fcStatusText += " | Ultimo errore: " + fcLog.lastErrorMessage;
        }
        checks.put(makeCheck("freshclam-running", "freshclam attivo e funzionante",
            autoUpdateOk,
            fcStatusText,
            autoUpdateOk ? null
                : (freshclamRunning
                    ? "Il daemon gira ma non sta aggiornando i database. Possibili cause: mirror irraggiungibile, firewall outbound, errore SSL. Verifica /var/log/clamav/freshclam.log"
                    : "I database non vengono aggiornati: dopo qualche giorno saranno obsoleti."),
            (autoUpdateOk || !installed) ? null
                : (freshclamRunning ? "update_db" : "start_freshclam"),
            freshclamRunning ? "Forza un update manuale (freshclam --foreground)" : "service clamav_freshclam start"));

        // 7. Rspamd → ClamAV configurato
        boolean rspamdHasAntivirus = false;
        try {
            java.nio.file.Path conf = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d/antivirus.conf");
            if (java.nio.file.Files.exists(conf)) {
                String c = java.nio.file.Files.readString(conf);
                rspamdHasAntivirus = c.contains("clamav") && c.contains("clamd.sock");
            }
        } catch (Exception ignored) {}
        checks.put(makeCheck("rspamd-antivirus", "Rspamd configurato per usare ClamAV",
            rspamdHasAntivirus,
            rspamdHasAntivirus ? "antivirus.conf con riferimento a clamd.sock"
                               : "antivirus.conf MANCA o non punta a clamd",
            rspamdHasAntivirus ? null
                : "Anche se ClamAV gira, Rspamd non lo chiama e le email passano senza scansione AV.",
            (rspamdHasAntivirus || !installed) ? null : "ensure_rspamd_antivirus",
            "Scrive /usr/local/etc/rspamd/local.d/antivirus.conf e ricarica Rspamd"));

        boolean allOk = installed && freshclamEnabledBoot && clamdEnabledBoot && dbOk
            && clamdRunning && freshclamRunning && rspamdHasAntivirus;
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("can_fix_all", !allOk);
        r.put("checks", checks);
        return r;
    }

    /** Status di freshclam dal suo log. */
    private static class FreshclamLogStatus {
        /** Età in ore dell'ultima evidenza di update/check. -1 se nessuna. */
        long lastUpdateAgeHours = -1;
        /** Eventuale messaggio di errore recente. */
        String lastErrorMessage = null;
    }

    /**
     * Analizza /var/log/clamav/freshclam.log per stabilire SE freshclam sta
     * davvero aggiornando i database o ha errori. Cerca pattern tipici:
     *   - "Time: ... update completed"
     *   - "main.cvd is up to date"
     *   - "Downloading"
     *   - "ERROR:" / "WARNING:"
     */
    private FreshclamLogStatus analyzeFreshclamLog() {
        FreshclamLogStatus result = new FreshclamLogStatus();
        java.nio.file.Path logPath = java.nio.file.Paths.get("/var/log/clamav/freshclam.log");
        if (!java.nio.file.Files.exists(logPath)) return result;

        try {
            // Leggi le ultime ~200 righe del log
            java.util.List<String> lines = new java.util.ArrayList<>();
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(logPath.toFile(), "r")) {
                long fileSize = raf.length();
                long start = Math.max(0, fileSize - 32 * 1024); // ultimi 32KB
                raf.seek(start);
                if (start > 0) raf.readLine(); // scarta riga parziale
                String line;
                while ((line = raf.readLine()) != null) lines.add(line);
            }

            // Cerca dall'ultima verso la prima la riga indicativa di update o check riuscito
            // Pattern positivi: "up-to-date", "is up to date", "updated", "Downloading", "Time:"
            // Pattern negativi (errore): "ERROR:", "Can't download", "Mirror error"
            java.util.regex.Pattern timestampPat = java.util.regex.Pattern.compile(
                "(?:^|\\s)([A-Z][a-z]{2}\\s+\\w+\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4})"
            );
            String lastErrorLine = null;
            for (int i = lines.size() - 1; i >= 0; i--) {
                String ln = lines.get(i);
                String lower = ln.toLowerCase();
                if (lastErrorLine == null && (lower.contains("error:") || lower.contains("can't download") || lower.contains("mirror error") || lower.contains("warning:"))) {
                    String snippet = ln.length() > 200 ? ln.substring(0, 200) : ln;
                    lastErrorLine = snippet.trim();
                }
                if (lower.contains("up to date") || lower.contains("up-to-date")
                    || lower.contains("updated.") || lower.contains("downloading")
                    || lower.contains("daily.cvd updated") || lower.contains("main.cvd updated")) {
                    // Trova timestamp nella riga (cerca pattern "Mon Day HH:MM:SS YYYY" o ISO)
                    java.util.regex.Matcher m = timestampPat.matcher(ln);
                    if (m.find()) {
                        try {
                            // Pattern: "Wed May 14 18:30:00 2026"
                            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("EEE MMM d HH:mm:ss yyyy", java.util.Locale.US);
                            java.util.Date d = sdf.parse(m.group(1).trim());
                            long diffMs = System.currentTimeMillis() - d.getTime();
                            result.lastUpdateAgeHours = diffMs / (1000L * 60 * 60);
                            break;
                        } catch (Exception ignored) {}
                    }
                    // Se non riesce a parsare il timestamp ma c'è la riga "up to date",
                    // marca comunque come "presente ma età sconosciuta" → 0 (assumiamo recente)
                    if (result.lastUpdateAgeHours < 0) result.lastUpdateAgeHours = 0;
                    break;
                }
            }
            result.lastErrorMessage = lastErrorLine;
        } catch (Exception e) {
            LOGGER.warning("analyzeFreshclamLog: " + e.getMessage());
        }
        return result;
    }

    private boolean isSysrcYes(String key) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", key);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) { return false; }
    }

    private boolean isServiceRunning(String name) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", name, "status");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.toLowerCase().contains("is running");
        } catch (Exception e) { return false; }
    }

    private JSONObject sysrcSet(String key, String value) {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", key + "=" + value);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "OK: " + key + "=" + value : "sysrc exit=" + p.exitValue());
            r.put("output", out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject serviceCommand(String svc, String cmd, int timeoutSeconds) {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", svc, cmd);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0;
            r.put("success", ok);
            r.put("message", ok ? "Servizio " + svc + " " + cmd + " OK" : "service " + svc + " " + cmd + " exit=" + p.exitValue());
            r.put("output", out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject installClamav() {
        return sulTurnoPacchetti("installazione di ClamAV", this::eseguiInstallClamav);
    }

    private JSONObject eseguiInstallClamav() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", "clamav");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(300, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", "Timeout installazione (>5min)"); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "ClamAV installato" : "pkg install exit=" + p.exitValue());
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    private JSONObject runFreshclam() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/freshclam", "--foreground", "--stdout");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(600, java.util.concurrent.TimeUnit.SECONDS); // 10 min
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", "Timeout (>10min)"); return r; }
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "Database virus aggiornato" : "freshclam exit=" + p.exitValue());
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    /**
     * Test EICAR end-to-end:
     *  1. Crea un file temporaneo con il payload EICAR (virus standard innocuo)
     *  2. Esegue clamdscan sul file
     *  3. Verifica che la risposta contenga "FOUND" (clamd ha rilevato il virus)
     *  4. Cleanup file
     *
     * Questo conferma che la pipeline clamd→clamdscan funziona end-to-end.
     * Se passa, ClamAV protegge davvero. Se fallisce, c'è un problema concreto.
     */
    private JSONObject runEicarTest() {
        JSONObject r = new JSONObject();
        java.nio.file.Path tmp = null;
        try {
            // EICAR standard test string — riconosciuta da TUTTI gli antivirus, innocua
            String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            tmp = java.nio.file.Files.createTempFile("eicar-test-", ".txt");
            java.nio.file.Files.writeString(tmp, eicar, java.nio.charset.StandardCharsets.US_ASCII);
            // Perm 644 così clamav user può leggere
            try {
                java.nio.file.Files.setPosixFilePermissions(tmp,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
            } catch (Exception ignored) {}

            // Esegui clamdscan
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/clamdscan", "--no-summary", tmp.toString());
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", "Timeout clamdscan"); return r; }
            int exit = p.exitValue();

            // Interpretazione exit code di clamdscan:
            //   0 = nessun virus
            //   1 = VIRUS TROVATO (è quello che vogliamo!)
            //   2 = errore
            if (exit == 1 && out.contains("FOUND") && (out.contains("EICAR") || out.contains("Eicar"))) {
                r.put("success", true);
                r.put("message", "✅ Test EICAR superato — ClamAV scansiona e rileva i virus correttamente");
                r.put("scan_output", out.trim());
                r.put("detected", true);
            } else if (exit == 2) {
                r.put("success", false);
                r.put("message", "❌ clamdscan ha avuto un errore (clamd irraggiungibile?)");
                r.put("scan_output", out.trim());
            } else if (exit == 0) {
                r.put("success", false);
                r.put("message", "⚠️ clamdscan NON ha rilevato il virus EICAR — database non aggiornato o configurazione anomala");
                r.put("scan_output", out.trim());
            } else {
                r.put("success", false);
                r.put("message", "❓ Risultato inaspettato (exit=" + exit + ")");
                r.put("scan_output", out.trim());
            }
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        } finally {
            if (tmp != null) {
                try { java.nio.file.Files.deleteIfExists(tmp); } catch (Exception ignored) {}
            }
        }
        return r;
    }

    private JSONObject ensureRspamdAntivirusConfig() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path confDir = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d");
            if (!java.nio.file.Files.isDirectory(confDir)) {
                java.nio.file.Files.createDirectories(confDir);
            }
            java.nio.file.Path conf = confDir.resolve("antivirus.conf");
            String content = ""
                + "# Auto-gestito dal mail panel — Rspamd → ClamAV\n"
                + "clamav {\n"
                + "  action = \"reject\";\n"
                + "  symbol = \"CLAM_VIRUS\";\n"
                + "  type = \"clamav\";\n"
                + "  servers = \"/var/run/clamav/clamd.sock\";\n"
                + "  scan_mime_parts = true;\n"
                + "  scan_text_mime = false;\n"
                + "  scan_image_mime = false;\n"
                + "}\n";
            // Backup se esiste
            if (java.nio.file.Files.exists(conf)) {
                java.nio.file.Files.copy(conf, java.nio.file.Paths.get(conf.toString() + ".bak." + System.currentTimeMillis()));
            }
            java.nio.file.Files.writeString(conf, content, java.nio.charset.StandardCharsets.UTF_8);
            // Reload rspamd
            try {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "rspamd", "reload");
                org.mail_panel.util.Shell.applicaPath(pb);
                pb.redirectErrorStream(true);
                Process p = pb.start();
                p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            } catch (Exception ignored) {}
            r.put("success", true);
            r.put("message", "antivirus.conf scritto e Rspamd ricaricato");
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
        }
        return r;
    }

    /** Esegue tutti i fix necessari per ClamAV in ordine corretto. */
    private JSONObject runClamavFixAll() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        boolean anyFailed = false;

        // 1. Install
        boolean installed;
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "info", "-e", "clamav");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            installed = p.exitValue() == 0;
        } catch (Exception e) { installed = false; }
        if (!installed) {
            JSONObject res = installClamav();
            steps.put(buildStep("install_clamav", "Installa ClamAV (pkg install)", res));
            if (!res.optBoolean("success")) anyFailed = true;
            installed = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("install_clamav", "ClamAV già installato"));
        }

        if (!installed) {
            r.put("success", false);
            r.put("steps", steps);
            r.put("message", "Installazione ClamAV fallita");
            return r;
        }

        // 2. Enable freshclam at boot
        if (!isSysrcYes("clamav_freshclam_enable")) {
            JSONObject res = sysrcSet("clamav_freshclam_enable", "YES");
            steps.put(buildStep("enable_freshclam_boot", "Abilita freshclam al boot", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_freshclam_boot", "freshclam già abilitato al boot"));
        }

        // 3. Enable clamd at boot
        if (!isSysrcYes("clamav_clamd_enable")) {
            JSONObject res = sysrcSet("clamav_clamd_enable", "YES");
            steps.put(buildStep("enable_clamd_boot", "Abilita clamd al boot", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("enable_clamd_boot", "clamd già abilitato al boot"));
        }

        // 4. Update database (può richiedere minuti)
        boolean dbPresent = false;
        try {
            java.nio.file.Path dbDir = java.nio.file.Paths.get("/var/db/clamav");
            if (java.nio.file.Files.isDirectory(dbDir)) {
                try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(dbDir)) {
                    dbPresent = s.anyMatch(p -> {
                        String n = p.getFileName().toString();
                        return n.endsWith(".cvd") || n.endsWith(".cld");
                    });
                }
            }
        } catch (Exception ignored) {}
        if (!dbPresent) {
            JSONObject res = runFreshclam();
            steps.put(buildStep("update_db", "Scarica database virus (può richiedere fino a 5 min)", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("update_db", "Database virus già presente"));
        }

        // 5. Start freshclam
        if (!isServiceRunning("clamav_freshclam")) {
            JSONObject res = serviceCommand("clamav_freshclam", "start", 30);
            steps.put(buildStep("start_freshclam", "Avvia freshclam", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_freshclam", "freshclam già in esecuzione"));
        }

        // 6. Start clamd
        if (!isServiceRunning("clamav_clamd")) {
            JSONObject res = serviceCommand("clamav_clamd", "start", 60);
            steps.put(buildStep("start_clamd", "Avvia clamd (scanner)", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("start_clamd", "clamd già in esecuzione"));
        }

        // 7. Configura Rspamd → ClamAV
        boolean rspamdConfigured = false;
        try {
            java.nio.file.Path conf = java.nio.file.Paths.get("/usr/local/etc/rspamd/local.d/antivirus.conf");
            if (java.nio.file.Files.exists(conf)) {
                String c = java.nio.file.Files.readString(conf);
                rspamdConfigured = c.contains("clamav") && c.contains("clamd.sock");
            }
        } catch (Exception ignored) {}
        if (!rspamdConfigured) {
            JSONObject res = ensureRspamdAntivirusConfig();
            steps.put(buildStep("ensure_rspamd_antivirus", "Configura Rspamd per chiamare ClamAV", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else {
            steps.put(buildSkipStep("ensure_rspamd_antivirus", "Rspamd → ClamAV già configurato"));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", anyFailed ? "Alcuni passaggi sono falliti — verifica i dettagli" : "ClamAV operativo e collegato a Rspamd");
        return r;
    }

    private void handleApiFail2banHealth(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }
        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        try {
            if ("GET".equals(method)) {
                response = buildFail2banHealthReport();
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) { sendJsonError(exchange, 413, "Body troppo grande"); return; }
                JSONObject req = new JSONObject(body);
                if (!validateCsrfForRequest(exchange, req)) { sendCsrfError(exchange); return; }
                String action = req.optString("action", "");
                String clientIp = getClientIp(exchange);
                switch (action) {
                    case "install_fail2ban" -> {
                        JSONObject r = installFail2ban();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_INSTALLED" : "FAIL2BAN_INSTALL_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_at_boot" -> {
                        JSONObject r = enableFail2banAtBoot();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_ENABLED_AT_BOOT" : "FAIL2BAN_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "start_service" -> {
                        JSONObject r = startFail2banService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_STARTED" : "FAIL2BAN_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "setup_mail_jail" -> {
                        org.mail_panel.security.Fail2banAutoSetup.run();
                        response.put("success", true);
                        response.put("message", "Setup eseguito (filter, jail, log file, log rotation)");
                        logAudit("FAIL2BAN_AUTOSETUP_TRIGGERED", clientIp, "manual trigger from health page");
                    }
                    case "install_mail_jails" -> {
                        Fail2banManager.InstallResult res = fail2banManager.installMailJails();
                        response.put("success", res.success);
                        response.put("message", res.success ? res.message : (res.error != null ? res.error : "Installation failed"));
                        if (res.configPath != null) response.put("config_path", res.configPath);
                        logAudit(res.success ? "FAIL2BAN_MAIL_JAILS_INSTALLED" : "FAIL2BAN_MAIL_JAILS_FAILED",
                            clientIp, res.success ? res.configPath : (res.error != null ? res.error : ""));
                    }
                    case "ripara_azione_ban" -> {
                        JSONObject rr = org.mail_panel.security.RiparaAzioneBan.ripara();
                        response = rr;
                        logAudit(rr.optBoolean("success", false) ? "FAIL2BAN_BANACTION_RIPARATA"
                                                                 : "FAIL2BAN_BANACTION_RIPARAZIONE_FALLITA",
                            clientIp, rr.optString("message", ""));
                    }
                    case "start_pf" -> {
                        JSONObject r = startPfService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_STARTED" : "PF_START_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "enable_pf_at_boot" -> {
                        JSONObject r = enablePfAtBoot();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_ENABLED_AT_BOOT" : "PF_ENABLE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "add_pf_anchor" -> {
                        JSONObject r = addPfAnchorF2b();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_ANCHOR_ADDED" : "PF_ANCHOR_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "create_pf_conf_minimal" -> {
                        JSONObject r = createPfConfMinimal();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_CONF_CREATED" : "PF_CONF_CREATE_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "load_pf_module" -> {
                        JSONObject r = loadPfModule();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "PF_MODULE_LOADED" : "PF_MODULE_LOAD_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "reload_fail2ban" -> {
                        JSONObject r = reloadFail2banAction();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_RELOADED" : "FAIL2BAN_RELOAD_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "restart_service" -> {
                        JSONObject r = restartFail2banService();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_RESTARTED" : "FAIL2BAN_RESTART_FAILED",
                            clientIp, r.optString("message", ""));
                    }
                    case "fix_all" -> {
                        JSONObject r = runFixAll();
                        response = r;
                        logAudit(r.optBoolean("success", false) ? "FAIL2BAN_FIX_ALL_OK" : "FAIL2BAN_FIX_ALL_PARTIAL",
                            clientIp, r.optString("message", ""));
                    }
                    default -> {
                        response.put("success", false);
                        response.put("error", "Azione non valida: " + action);
                    }
                }
            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Endpoint diagnostico: ritorna tutti i path che il pannello sta usando,
     * raggruppati per categoria, ognuno con status (esiste / dimensione / mtime).
     * Utile per debugging e per copia/incolla rapidi durante troubleshooting.
     */
    private void handleApiSystemPaths(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }
        JSONObject response = new JSONObject();
        try {
            JSONArray categories = new JSONArray();

            // === Roundcube (auto-detect) ===
            JSONArray rcEntries = new JSONArray();
            String rcInstall = fail2banManager.detectRoundcubeInstallPath();
            if (rcInstall != null) {
                rcEntries.put(pathEntry("Installazione", rcInstall, "Directory radice di Roundcube"));
                rcEntries.put(pathEntry("Config file", rcInstall + "/config/config.inc.php", "Configurazione PHP di Roundcube"));
                rcEntries.put(pathEntry("Logs directory", rcInstall + "/logs", "Directory dei log di Roundcube"));
                rcEntries.put(pathEntry("Login log (Fail2ban target)", rcInstall + "/logs/userlogins", "File che Fail2ban monitora per il jail roundcube-auth"));
                rcEntries.put(pathEntry("Errors log (opzionale)", rcInstall + "/logs/errors", "Errori PHP/runtime di Roundcube — creato solo quando si verificano errori"));
            } else {
                rcEntries.put(new JSONObject().put("label", "Roundcube non trovato")
                    .put("path", "(nessuno dei path standard contiene un install plausibile)")
                    .put("exists", false));
            }
            categories.put(new JSONObject().put("name", "Roundcube").put("entries", rcEntries));

            // === Fail2ban ===
            JSONArray f2bEntries = new JSONArray();
            f2bEntries.put(pathEntry("Binario fail2ban-client", "/usr/local/bin/fail2ban-client", "Comando per gestire Fail2ban"));
            f2bEntries.put(pathEntry("Config jail principale", "/usr/local/etc/fail2ban/jail.local", "jail.local: jail di base del pannello"));
            f2bEntries.put(pathEntry("Config jail mail", "/usr/local/etc/fail2ban/jail.d/mail.local", "Jail aggiuntive per Postfix/Dovecot/Roundcube/Rspamd"));
            f2bEntries.put(pathEntry("Directory filter", "/usr/local/etc/fail2ban/filter.d", "Filter regex per ogni jail"));
            f2bEntries.put(pathEntry("Filter mail-panel-auth", "/usr/local/etc/fail2ban/filter.d/mail-panel-auth.conf", "Filter per il login del pannello"));
            f2bEntries.put(pathEntry("Filter roundcube-auth", "/usr/local/etc/fail2ban/filter.d/roundcube-auth.conf", "Filter per i login Roundcube"));
            f2bEntries.put(pathEntry("Log Fail2ban", "/var/log/fail2ban.log", "Log del servizio Fail2ban"));
            categories.put(new JSONObject().put("name", "Fail2ban").put("entries", f2bEntries));

            // === Mail Panel ===
            JSONArray panelEntries = new JSONArray();
            panelEntries.put(pathEntry("Log auth pannello", "/var/log/mail-panel-auth.log", "File monitorato dal jail mail-panel-auth (LOGIN_FAILURE, CSRF_FAILURE, ...)"));
            panelEntries.put(pathEntry("newsyslog conf", "/usr/local/etc/newsyslog.conf.d/mail-panel-auth.conf", "Configurazione di log rotation"));
            categories.put(new JSONObject().put("name", "Mail Panel").put("entries", panelEntries));

            // === pf (firewall) ===
            JSONArray pfEntries = new JSONArray();
            pfEntries.put(pathEntry("Config principale", "/etc/pf.conf", "Regole pf attive"));
            pfEntries.put(pathEntry("Binario pfctl", "/sbin/pfctl", "Strumento di controllo pf"));
            pfEntries.put(pathEntry("rc.conf", "/etc/rc.conf", "Configurazione boot — contiene pf_enable, fail2ban_enable, ecc."));
            pfEntries.put(pathEntry("loader.conf", "/boot/loader.conf", "Caricamento moduli kernel al boot (pf_load)"));
            categories.put(new JSONObject().put("name", "pf (firewall)").put("entries", pfEntries));

            // === Mail services ===
            JSONArray mailEntries = new JSONArray();
            mailEntries.put(pathEntry("Postfix config", "/usr/local/etc/postfix/main.cf", "Config principale Postfix"));
            mailEntries.put(pathEntry("Postfix master", "/usr/local/etc/postfix/master.cf", "Service definition Postfix"));
            mailEntries.put(pathEntry("Dovecot config", "/usr/local/etc/dovecot/dovecot.conf", "Config principale Dovecot"));
            mailEntries.put(pathEntry("Maillog", "/var/log/maillog", "Log condiviso Postfix/Dovecot (input dei jail postfix-auth e dovecot)"));
            mailEntries.put(pathEntry("Rspamd log", "/var/log/rspamd/rspamd.log", "Log di rspamd (input del jail rspamd)"));
            mailEntries.put(pathEntry("Rspamd config", "/usr/local/etc/rspamd/local.d", "Override di rspamd"));
            categories.put(new JSONObject().put("name", "Servizi Mail").put("entries", mailEntries));

            // === SSL ===
            JSONArray sslEntries = new JSONArray();
            sslEntries.put(pathEntry("Certificato + chain", "/usr/local/etc/ssl/mail/fullchain.pem", "Cert + CA chain usati da Postfix/Dovecot"));
            sslEntries.put(pathEntry("Chiave privata", "/usr/local/etc/ssl/mail/privkey.pem", "Private key del certificato"));
            sslEntries.put(pathEntry("ACME home", "/root/.acme.sh", "Home di acme.sh (rinnovi Let's Encrypt)"));
            sslEntries.put(pathEntry("ACME binario", "/root/.acme.sh/acme.sh", "Comando acme.sh"));
            categories.put(new JSONObject().put("name", "SSL/TLS").put("entries", sslEntries));

            // === Web server (nginx) ===
            JSONArray webEntries = new JSONArray();
            webEntries.put(pathEntry("Nginx conf principale", "/usr/local/etc/nginx/nginx.conf", "Config principale Nginx"));
            webEntries.put(pathEntry("Sites-enabled (opzionale)", "/usr/local/etc/nginx/sites-enabled", "Directory vhost separati — usata solo se il vhost Roundcube è in un file dedicato"));
            webEntries.put(pathEntry("Vhost Roundcube (opzionale)", "/usr/local/etc/nginx/sites-enabled/roundcube.conf", "Vhost dedicato Roundcube, se gestito dal pannello"));
            webEntries.put(pathEntry("Nginx access log", "/var/log/nginx/access.log", "Log accessi web"));
            webEntries.put(pathEntry("Nginx error log", "/var/log/nginx/error.log", "Log errori web"));
            categories.put(new JSONObject().put("name", "Nginx / Web").put("entries", webEntries));

            // === Database (panel) ===
            // Path SQLite del pannello: relativo a CWD di esecuzione, di solito /home/panel/
            JSONArray dbEntries = new JSONArray();
            String sqliteDbPath = "./database/mail_panel.db";
            try {
                java.nio.file.Path abs = java.nio.file.Paths.get(sqliteDbPath).toAbsolutePath().normalize();
                sqliteDbPath = abs.toString();
            } catch (Exception ignored) {}
            dbEntries.put(pathEntry("DB SQLite pannello", sqliteDbPath, "Database SQLite del mail panel (settings, sessioni, ecc.)"));
            dbEntries.put(pathEntry("MySQL my.cnf", "/usr/local/etc/mysql/my.cnf", "Config MySQL/MariaDB"));
            dbEntries.put(pathEntry("MySQL var (data)", "/var/db/mysql", "Directory dati MySQL/MariaDB"));
            categories.put(new JSONObject().put("name", "Database").put("entries", dbEntries));

            response.put("success", true);
            response.put("categories", categories);
            // Hostname: tentativi multipli, mai bloccante
            String hostname = "(non disponibile)";
            try {
                hostname = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception ignoredEx) {
                // Fallback 1: variabile d'ambiente HOSTNAME
                String envHost = System.getenv("HOSTNAME");
                if (envHost != null && !envHost.isEmpty()) {
                    hostname = envHost;
                } else {
                    // Fallback 2: comando hostname
                    try {
                        // TODO: migrate to Shell.run when touched
                        ProcessBuilder pb = new ProcessBuilder("/bin/hostname");
                        org.mail_panel.util.Shell.applicaPath(pb);
                        pb.redirectErrorStream(true);
                        Process p = pb.start();
                        String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                        p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
                        if (!out.isEmpty()) hostname = out;
                    } catch (Exception ignored2) {}
                }
            }
            response.put("hostname", hostname);

        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /** Costruisce un entry JSON con metadata del file/directory. */
    private JSONObject pathEntry(String label, String path, String description) {
        JSONObject e = new JSONObject();
        e.put("label", label);
        e.put("path", path);
        e.put("description", description);
        try {
            java.nio.file.Path p = java.nio.file.Paths.get(path);
            boolean exists = java.nio.file.Files.exists(p);
            e.put("exists", exists);
            if (exists) {
                e.put("is_directory", java.nio.file.Files.isDirectory(p));
                e.put("readable", java.nio.file.Files.isReadable(p));
                try {
                    java.nio.file.attribute.BasicFileAttributes attrs =
                        java.nio.file.Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class);
                    if (!attrs.isDirectory()) {
                        e.put("size", attrs.size());
                    }
                    e.put("modified", attrs.lastModifiedTime().toString());
                } catch (Exception ignored) {}
                try {
                    java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                        java.nio.file.Files.getPosixFilePermissions(p);
                    e.put("perms", java.nio.file.attribute.PosixFilePermissions.toString(perms));
                } catch (Exception ignored) {}
            }
        } catch (Exception ex) {
            e.put("exists", false);
            e.put("error", ex.getMessage());
        }
        return e;
    }

    private JSONObject buildFail2banHealthReport() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean f2bInstalled = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/bin/fail2ban-client"));
        checks.put(makeCheck("fail2ban-installed",
            "Fail2ban installato",
            f2bInstalled,
            f2bInstalled ? ("Pacchetto py311-fail2ban presente sul sistema. " + versioneFail2ban())
                         : "Il pacchetto Fail2ban non è installato",
            f2bInstalled ? null : "Senza Fail2ban gli IP che falliscono il login non vengono bannati a livello firewall.",
            f2bInstalled ? null : "install_fail2ban",
            f2bInstalled ? null : "Esegue: pkg install -y py311-fail2ban"));
        boolean enabledAtBoot = isFail2banEnabledAtBoot();
        checks.put(makeCheck("fail2ban-enabled-boot",
            "Avvio automatico al boot",
            enabledAtBoot,
            enabledAtBoot ? "fail2ban_enable=YES in rc.conf" : "fail2ban non si avvia automaticamente al riavvio del server",
            enabledAtBoot ? null : "Se il server riparte (reboot, kernel panic), Fail2ban non si riaccende e gli IP malevoli non sono più bloccati.",
            (enabledAtBoot || !f2bInstalled) ? null : "enable_at_boot",
            "Esegue: sysrc fail2ban_enable=YES"));
        boolean f2bRunning = isFail2banRunning();
        checks.put(makeCheck("fail2ban-running",
            "Fail2ban in esecuzione",
            f2bRunning,
            f2bRunning ? "Servizio attivo" : "Servizio fermo",
            f2bRunning ? null : "Mentre è fermo non vengono effettuati nuovi ban anche se il pannello rileva tentativi sospetti.",
            (f2bRunning || !f2bInstalled) ? null : "start_service",
            "Esegue: service fail2ban start"));
        boolean filterPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/etc/fail2ban/filter.d/mail-panel-auth.conf"));
        boolean logPresent = java.nio.file.Files.exists(java.nio.file.Paths.get("/var/log/mail-panel-auth.log"));
        boolean jailPresent = false;
        try {
            java.nio.file.Path jl = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.local");
            if (java.nio.file.Files.exists(jl)) {
                String c = java.nio.file.Files.readString(jl);
                jailPresent = c.contains("[mail-panel-auth]");
            }
        } catch (Exception ignored) {}
        boolean panelSetupOk = filterPresent && logPresent && jailPresent;
        String missingDetails = "Mancano: " +
            (filterPresent ? "" : "filter ") +
            (jailPresent ? "" : "jail ") +
            (logPresent ? "" : "log-file ");
        checks.put(makeCheck("panel-jail-configured",
            "Jail mail-panel-auth configurata",
            panelSetupOk,
            panelSetupOk ? "Filter + jail + log-file presenti" : missingDetails.trim(),
            panelSetupOk ? null : "I tentativi di login falliti sul pannello vengono loggati ma NON producono ban automatici.",
            (panelSetupOk || !f2bInstalled) ? null : "setup_mail_jail",
            "Crea filter, jail e log file con i default consigliati"));

        // Jail per i servizi mail (Postfix, Dovecot, Roundcube, Rspamd)
        // Verifica DOPPIA: file esiste E le jail sono effettivamente attive nel runtime di Fail2ban
        java.util.List<String> expectedMailJails = java.util.Arrays.asList("dovecot", "postfix-auth", "roundcube-auth", "rspamd");
        boolean mailFileExists = false;
        java.util.Set<String> jailsInFile = new java.util.HashSet<>();
        try {
            java.nio.file.Path mailLocal = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.d/mail.local");
            if (java.nio.file.Files.exists(mailLocal)) {
                mailFileExists = true;
                String c = java.nio.file.Files.readString(mailLocal);
                for (String j : expectedMailJails) {
                    if (c.contains("[" + j + "]")) jailsInFile.add(j);
                }
            }
        } catch (Exception ignored) {}

        // Quali jail sono ATTIVE a runtime?
        // FIX (regression del check precedente): prima parsavamo la riga "Jail list:"
        // dell'output globale `fail2ban-client status`. Quel parsing era fragile —
        // se il formato dell'output cambia (whitespace, tab, encoding), TUTTE le jail
        // venivano marcate come "non attive" anche se in realtà giravano normalmente.
        //
        // Approccio robusto: per ciascuna jail attesa eseguiamo `status <jail>` —
        // se ritorna un output normale (non "does not exist") significa che la jail
        // E' caricata e attiva nel runtime di Fail2ban.
        java.util.Set<String> activeJails = new java.util.HashSet<>();
        if (f2bRunning) {
            for (String jail : expectedMailJails) {
                var statusRes = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(5),
                    "/usr/local/bin/fail2ban-client", "status", jail);
                String statusOut = statusRes.output();
                boolean notExists = statusOut.contains("does not exist") || statusOut.contains("not found")
                                 || statusOut.contains("Sorry, but the jail");
                if (statusRes.success() && !notExists) {
                    activeJails.add(jail);
                }
            }
        }

        // Per ogni jail mancante a runtime, capisci PERCHÉ
        java.util.List<String> missingActive = new java.util.ArrayList<>();
        java.util.List<String> reasons = new java.util.ArrayList<>();
        for (String jail : expectedMailJails) {
            if (!activeJails.contains(jail)) {
                missingActive.add(jail);
                reasons.add(jail + ": " + diagnoseMailJailIssue(jail, jailsInFile.contains(jail)));
            }
        }

        boolean mailJailsActive = mailFileExists && missingActive.isEmpty();
        String detailStatus;
        if (mailJailsActive) {
            detailStatus = "Tutte le 4 jail mail attive a runtime: " + String.join(", ", expectedMailJails);
        } else if (mailFileExists) {
            detailStatus = "File configurato ma " + missingActive.size() + " jail NON attive a runtime: " + String.join(" | ", reasons);
        } else {
            detailStatus = "File mail.local non esiste — nessuna jail mail configurata";
        }
        String impact = mailJailsActive ? null
            : "I mail server sono il bersaglio #1 per attacchi: SMTP AUTH, IMAP login, webmail. Le jail elencate sopra NON stanno bloccando niente.";

        // Fix appropriato:
        //   - file mancante o jail non attive a runtime → install_mail_jails (rigenera mail.local
        //     con path corretti, crea log file mancanti, riscrive filter, reload)
        //   - install_mail_jails è idempotente e gestisce tutti i casi, quindi è sempre la
        //     scelta più safe rispetto al solo reload
        String fixAction = null;
        String fixDesc = null;
        if (f2bInstalled && (!mailFileExists || !missingActive.isEmpty())) {
            fixAction = "install_mail_jails";
            fixDesc = "Rigenera config jail Postfix/Dovecot/Roundcube/Rspamd con path corretti, crea log file mancanti, ricarica Fail2ban";
        }

        checks.put(makeCheck("mail-services-jails",
            "Jail per servizi mail (Postfix/Dovecot/Roundcube/Rspamd) attive a runtime",
            mailJailsActive,
            detailStatus,
            impact,
            fixAction,
            fixDesc));

        // ========== Le jail guardano file capaci di dirgli qualcosa? ==========
        // Il controllo qui sopra chiede "la jail e' caricata". roundcube-auth lo era, e la
        // pagina dava verde mentre sorvegliava "userlogins" invece di "userlogins.log" scritto
        // accanto: non avrebbe bannato nessuno, e proprio perche' la diagnosi non vedeva niente
        // di storto il pulsante "Risolvi tutto" restava nascosto. Questa e' la seconda domanda.
        // Il verde di questo controllo deve dire "ho guardato N jail e stanno bene", mai
        // "non ho trovato problemi" quando il motivo e' che non ho guardato niente: una lista
        // vuota per esito e una lista vuota per fallimento sono indistinguibili, e quella
        // ambiguita' e' esattamente la forma del difetto che questo controllo esiste per
        // scoprire. Quindi si conta, e il conteggio finisce a schermo.
        Fail2banManager.EsameLog esame = null;
        String erroreEsame = null;
        try {
            if (f2bRunning) esame = fail2banManager.esaminaLogSorvegliati();
        } catch (Exception e) { erroreEsame = e.getMessage(); }

        boolean logOk;
        StringBuilder logDettaglio = new StringBuilder();
        if (!f2bRunning) {
            logOk = false;
            logDettaglio.append("Fail2ban non e' in esecuzione: non ho potuto guardare nessuna jail, "
                              + "quindi di questi file non so dire niente");
        } else if (esame == null) {
            logOk = false;
            logDettaglio.append("Non sono riuscito a esaminare i log delle jail")
                        .append(erroreEsame != null ? (": " + erroreEsame) : "")
                        .append(" — questo controllo non ha guardato niente, e il suo silenzio non "
                              + "va letto come un via libera");
        } else if (esame.esaminate.isEmpty()) {
            logOk = false;
            logDettaglio.append("Fail2ban gira ma non sono riuscito a farmi dire quali file sorvegli "
                              + "nessuna jail: questo controllo non ha guardato niente");
        } else if (esame.problemi.isEmpty()) {
            logOk = true;
            logDettaglio.append("Guardate ").append(esame.esaminate.size())
                        .append(" jail (").append(String.join(", ", esame.esaminate))
                        .append("): ognuna sorveglia un file che esiste e viene scritto");
            if (!esame.senzaLog.isEmpty())
                logDettaglio.append(". Senza file di log da sorvegliare, quindi fuori da questo controllo: ")
                            .append(String.join(", ", esame.senzaLog));
        } else {
            logOk = false;
            logDettaglio.append("Su ").append(esame.esaminate.size()).append(" jail guardate, ")
                        .append(esame.problemi.size()).append(" non vedra' mai niente — ");
            boolean primo = true;
            for (Fail2banManager.LogSbagliato sb : esame.problemi) {
                if (!primo) logDettaglio.append(" | ");
                logDettaglio.append(sb.jail).append(": ").append(sb.motivo);
                primo = false;
            }
        }
        // ========== Il comando che banna esiste su questo sistema? ==========
        // La causa vera del guasto piu' grave trovato finora. Cinque jail dichiaravano
        // "action = pf[...]", due no: non dichiarandola ereditavano il valore predefinito di
        // jail.conf, costruito su iptables, che su FreeBSD non esiste. Quelle due rilevavano,
        // contavano i tentativi e incrementavano i ban — 14.370 e 46 su mailpanel-pubblico —
        // senza bloccare niente, e nessuna schermata poteva accorgersene perche' nessuna
        // guardava se il comando di ban fosse un comando. Questo lo guarda.
        JSONObject diagBan = new JSONObject().put("rotte", new JSONArray());
        boolean banEseguibile = true;
        String banDettaglio;
        try {
            if (f2bRunning) diagBan = org.mail_panel.security.RiparaAzioneBan.diagnosi();
        } catch (Exception ignored) { }
        JSONArray rotte = diagBan.optJSONArray("rotte");
        if (rotte == null) rotte = new JSONArray();
        if (!f2bRunning) {
            banEseguibile = false;
            banDettaglio = "Fail2ban non e' in esecuzione: non ho potuto chiedere a nessuna jail "
                         + "quale comando esegua per bannare";
        } else if (rotte.length() == 0) {
            int esaminateBan = diagBan.optInt("esaminate", 0);
            JSONArray nonGiud = diagBan.optJSONArray("non_giudicate");
            if (esaminateBan == 0) {
                banEseguibile = false;
                banDettaglio = "Non sono riuscito a giudicare il comando di nessuna jail: questo "
                             + "controllo non ha guardato niente";
            } else {
                banDettaglio = "Guardate " + esaminateBan + " jail: ognuna banna con un comando che "
                             + "esiste su questo sistema";
                if (nonGiud != null && nonGiud.length() > 0) {
                    // Non giudicata non e' promossa. Se una jail non riporta la propria azione,
                    // il piu' delle volte e' perche' quell'azione non si e' caricata — cioe' non
                    // banna affatto — e lasciare verde il controllo per le altre nasconderebbe
                    // esattamente il caso peggiore dietro la maggioranza sana.
                    banEseguibile = false;
                    StringBuilder ng = new StringBuilder();
                    for (int i = 0; i < nonGiud.length(); i++) {
                        JSONObject x = nonGiud.getJSONObject(i);
                        if (ng.length() > 0) ng.append(" | ");
                        ng.append(x.optString("jail")).append(": ").append(x.optString("perche"));
                        // L'evidenza accanto al verdetto: cosa ha risposto fail2ban, e cosa ha
                        // scritto nel proprio log. Senza, la riga dice solo che non si sa.
                        String u = x.optString("uscita", "");
                        if (!u.isEmpty()) ng.append(" [fail2ban risponde: ").append(u).append("]");
                        String lg = x.optString("log", "");
                        if (!lg.isEmpty()) ng.append(" [fail2ban.log: ").append(lg.replace("\n", " ⏎ ")).append("]");
                    }
                    banDettaglio += ". NON giudicate, e quindi non promosse — " + ng
                                 + ". Una jail che non riporta la propria azione con ogni probabilita' "
                                 + "non l'ha caricata, e quindi non banna";
                }
            }
        } else {
            banEseguibile = false;
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < rotte.length(); i++) {
                JSONObject x = rotte.getJSONObject(i);
                if (b.length() > 0) b.append(" | ");
                b.append(x.optString("jail")).append(": banna con \"")
                 .append(x.optString("eseguibile")).append("\", che su questo sistema non esiste");
            }
            banDettaglio = b.toString();
        }
        checks.put(makeCheck("ban-eseguibile",
            "Il comando di ban esiste su questo sistema",
            banEseguibile,
            banDettaglio,
            banEseguibile ? null
                : "Queste jail rilevano gli attacchi e contano i ban, ma il comando che dovrebbe applicarli fallisce ogni volta: nessun indirizzo viene bloccato davvero. A schermo sono indistinguibili da jail che funzionano.",
            (banEseguibile || !f2bRunning) ? null : "ripara_azione_ban",
            "Dichiara l'azione pf sulle jail del pannello, ricarica, e poi richiede a Fail2ban quale comando esegue per verificare che la correzione abbia preso"));

        // ========== I ban arrivano davvero a pf? ==========
        // E' il controllo piu' profondo che il pannello sappia fare, e finora viveva soltanto
        // nella scheda del confronto: il verdetto in cima diceva "Tutto OK" mentre recidive
        // aveva una tabella che nessuna regola legge. Un riepilogo che non comprende il
        // controllo piu' severo non e' un riepilogo: e' la stessa mezza verita' che ha tenuto
        // nascoste per mesi una jail cieca e due che bannavano nel vuoto.
        boolean banApplicati = true;
        String banApplicatiDettaglio;
        try {
            if (!f2bRunning) {
                banApplicati = false;
                banApplicatiDettaglio = "Fail2ban non e' in esecuzione: non ho potuto confrontare niente";
            } else {
                Fail2banManager.ConfrontoPf cf = fail2banManager.confrontaBanConPf();
                int senzaRegola = cf.totaleSenzaRegola();
                int nonApplicati = cf.totaleNonApplicati();
                int nonMisurate = cf.totaleNonMisurate();
                int ok = 0;
                for (Fail2banManager.JailPf j : cf.jails)
                    if (j.letta && j.regolaVerificata && j.regolaPresente && !j.tabellaMancante) ok++;

                StringBuilder d = new StringBuilder();
                if (senzaRegola == 0 && nonApplicati == 0 && nonMisurate == 0) {
                    d.append("Tutte le ").append(ok).append(" jail hanno tabella e regola pf al loro ")
                     .append("posto, e ogni indirizzo che Fail2ban dichiara bannato risulta nel firewall");
                } else {
                    banApplicati = false;
                    d.append(ok).append(" jail su ").append(cf.jails.size()).append(" verificate a posto");
                    for (Fail2banManager.JailPf j : cf.jails) {
                        if (!j.letta) { d.append(" | ").append(j.jail).append(": non misurata"); continue; }
                        if (j.tabellaMancante) { d.append(" | ").append(j.jail).append(": la tabella pf non esiste"); continue; }
                        if (j.regolaVerificata && !j.regolaPresente) {
                            d.append(" | ").append(j.jail).append(": nessuna regola pf legge ")
                             .append(j.tabella).append(", i ban non bloccano");
                            continue;
                        }
                        if (!j.soloInFail2ban.isEmpty())
                            d.append(" | ").append(j.jail).append(": bannati ma non nel firewall — ")
                             .append(String.join(", ", j.soloInFail2ban));
                    }
                }
                banApplicatiDettaglio = d.toString();
            }
        } catch (Exception e) {
            banApplicati = false;
            banApplicatiDettaglio = "Non sono riuscito a fare il confronto con pf: " + e.getMessage()
                                  + " — quindi di questo non so dire niente";
        }
        checks.put(makeCheck("ban-applicati-in-pf",
            "I ban risultano davvero nel firewall (tabella e regola pf)",
            banApplicati,
            banApplicatiDettaglio,
            banApplicati ? null
                : "Una tabella senza regola, o un indirizzo che Fail2ban dichiara bannato e pf non blocca, valgono zero protezione: il ban risulta eseguito e l'attaccante passa. E' il controllo che fa Fail2ban stesso con pfctl -sr.",
            (banApplicati || !f2bInstalled) ? null : "install_mail_jails",
            "Rigenera le jail di posta con l'azione pf completa di porta, ricarica e ricrea le jail interessate"));

        checks.put(makeCheck("mail-jails-logpath",
            "Le jail sorvegliano i file di log giusti",
            logOk,
            logDettaglio.toString(),
            logOk ? null
                  : "Una jail che guarda il file sbagliato non bannera' mai nessuno e resta a zero tentativi: e' peggio di una jail spenta, perche' la pagina la mostra attiva e nessuno va a controllare.",
            (logOk || !f2bInstalled) ? null : "install_mail_jails",
            "Rigenera le jail rileggendo dai servizi il percorso reale dei log, crea i file mancanti e ricarica Fail2ban"));

        // ========== Verifica pf (firewall FreeBSD) ==========
        boolean pfEnabledAtBoot = isPfEnabledAtBoot();
        boolean pfRunning = isPfRunning();
        boolean pfConfExists = java.nio.file.Files.exists(java.nio.file.Paths.get("/etc/pf.conf"));
        boolean pfAnchorPresent = false;
        try {
            if (pfConfExists) {
                String pfConf = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/pf.conf"));
                pfAnchorPresent = pfConf.contains("anchor \"f2b/*\"") || pfConf.contains("anchor f2b/*");
            }
        } catch (Exception ignored) {}

        // Check del modulo kernel pf (deve venire PRIMA di tutto il resto pf)
        boolean pfModuleLoaded = isPfModuleLoaded();
        boolean inJail = isRunningInsideFreebsdJail();
        checks.put(makeCheck("pf-module-loaded",
            "Modulo kernel pf caricato",
            pfModuleLoaded,
            pfModuleLoaded ? "pf.ko presente in kldstat"
                           : (inJail ? "Il pannello gira dentro una jail FreeBSD: pf NON è gestibile da qui"
                                     : "Modulo pf non caricato — pfctl non funzionerà"),
            pfModuleLoaded ? null
                : (inJail ? "Sei in una jail FreeBSD: i ban via pf non funzioneranno. Devi caricare pf sull'host (non qui dentro) con 'kldload pf' e impostare pf_load=YES in /boot/loader.conf dell'host."
                          : "Senza il modulo pf caricato, l'intero stack firewall non funziona: nessun comando pfctl può girare."),
            (pfModuleLoaded || inJail) ? null : "load_pf_module",
            "Esegue: kldload pf + aggiunge pf_load=\"YES\" a /boot/loader.conf"));

        // ========== L'anchor di Fail2ban viene raggiunta? ==========
        // pf valuta le regole in ordine e "quick" ferma la valutazione alla prima che
        // corrisponde. Le regole di Fail2ban sono "block quick", ma un "pass ... quick" che
        // stia PRIMA dell'anchor f2b vince: da quelle sorgenti non si viene bannati, e i ban
        // risultano eseguiti. Il pannello scrive il proprio anchor panel-fw in fondo a pf.conf,
        // e quell'anchor contiene "pass in quick from <panel_wl_cidrs>" e la lista geografica:
        // se finisce prima di f2b, la whitelist non e' piu' una precedenza voluta ma una
        // esenzione dai ban di cui nessuno sa. Qui si guarda l'ordine reale del file.
        boolean ordineOk = true;
        String ordineDettaglio;
        java.util.List<String> primaDiF2b = new java.util.ArrayList<>();
        int rigaF2b = -1;
        try {
            if (pfConfExists && pfAnchorPresent) {
                String[] righe = java.nio.file.Files.readString(
                    java.nio.file.Paths.get("/etc/pf.conf")).split("\n", -1);
                for (int i = 0; i < righe.length; i++) {
                    String t = righe[i].trim();
                    if (t.isEmpty() || t.startsWith("#")) continue;
                    if (rigaF2b < 0 && (t.contains("anchor \"f2b/*\"") || t.contains("anchor f2b/*"))) {
                        rigaF2b = i;
                        break;
                    }
                    // Solo cio' che puo' davvero far saltare un ban in entrata.
                    // "pass out ... quick" riguarda il traffico in uscita e non c'entra:
                    // segnalarlo farebbe diventare rossa una pf.conf sana, e un controllo che
                    // grida a vuoto smette di essere letto.
                    if (t.startsWith("pass") && t.contains("quick")
                            && !t.matches("^pass\\s+out\\b.*")) {
                        primaDiF2b.add("riga " + (i + 1) + ": " + t);
                        continue;
                    }
                    // Un anchor precedente conta solo se contiene davvero un pass quick: lo si
                    // chiede a pf invece di presumerlo dal nome. Se non si riesce a leggerlo,
                    // lo si dice — non lo si assolve.
                    if (t.startsWith("anchor ")) {
                        String nome = t.substring(7).trim().replace("\"", "");
                        int sp = nome.indexOf(' ');
                        if (sp > 0) nome = nome.substring(0, sp);
                        if (nome.isEmpty() || nome.equals("f2b/*")) continue;
                        var reg = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(10),
                            "/sbin/pfctl", "-a", nome.replace("/*", ""), "-sr");
                        if (!reg.success()) {
                            primaDiF2b.add("riga " + (i + 1) + ": anchor " + nome
                                + " (non sono riuscito a leggerne le regole, quindi non posso "
                                + "escludere che ne contenga una che chiude la valutazione)");
                            continue;
                        }
                        for (String rr : reg.output().split("\n")) {
                            String u = rr.trim();
                            if (u.startsWith("pass") && u.contains("quick")
                                    && !u.matches("^pass\\s+out\\b.*")) {
                                primaDiF2b.add("riga " + (i + 1) + ": anchor " + nome
                                    + " contiene \"" + u + "\"");
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) { }

        if (!pfConfExists || !pfAnchorPresent) {
            ordineDettaglio = "L'anchor f2b non e' in pf.conf: l'ordine si valuta quando c'e'";
            ordineOk = pfAnchorPresent;
        } else if (rigaF2b < 0) {
            ordineOk = false;
            ordineDettaglio = "Non sono riuscito a trovare la riga dell'anchor f2b leggendo pf.conf: "
                            + "non posso dire in che ordine venga valutata";
        } else if (primaDiF2b.isEmpty()) {
            ordineDettaglio = "L'anchor f2b (riga " + (rigaF2b + 1) + ") viene valutata prima di "
                            + "qualunque regola pass quick e di ogni altro anchor: niente puo' "
                            + "chiudere la valutazione prima che i ban vengano applicati";
        } else {
            ordineOk = false;
            ordineDettaglio = "Prima dell'anchor f2b (riga " + (rigaF2b + 1) + ") ci sono "
                            + primaDiF2b.size() + " regole o anchor che possono chiudere la "
                            + "valutazione: " + String.join(" | ", primaDiF2b);
        }
        checks.put(makeCheck("pf-ordine-anchor",
            "L'anchor Fail2ban viene valutata prima delle regole pass quick",
            ordineOk,
            ordineDettaglio,
            ordineOk ? null
                : "pf si ferma alla prima regola quick che corrisponde. Chi rientra in una di queste regole non arrivera' mai alle regole di ban di Fail2ban: i ban su quelle sorgenti risultano eseguiti e non bloccano niente. Riguarda in particolare la whitelist e la lista geografica del firewall del pannello, che sono pass quick.",
            null,
            null));

        // Check separato per esistenza pf.conf (deve venire prima)
        checks.put(makeCheck("pf-conf-exists",
            "pf.conf esiste",
            pfConfExists,
            pfConfExists ? "/etc/pf.conf trovato"
                         : "/etc/pf.conf NON esiste — pf non è mai stato configurato",
            pfConfExists ? null
                : "Senza pf.conf, pf non può essere avviato e Fail2ban non può applicare ban via firewall.",
            pfConfExists ? null : "create_pf_conf_minimal",
            "Crea una pf.conf SICURA (minimal: pass tutto + anchor f2b). Non blocca nulla a parte gli IP banditi da Fail2ban — non rischio lockout."));

        checks.put(makeCheck("pf-running",
            "pf (firewall) attivo",
            pfRunning,
            pfRunning ? "pf è in esecuzione e applica regole"
                      : (pfConfExists ? "pf.conf esiste ma il servizio è fermo"
                                      : "pf.conf manca — non si può avviare pf finché non lo crei"),
            pfRunning ? null
                : "ATTENZIONE: anche se Fail2ban è configurato, senza pf attivo i ban NON vengono applicati. Il pannello pensa di proteggerti ma il firewall non blocca niente.",
            (pfRunning || !pfConfExists) ? null : "start_pf",
            pfConfExists ? "Avvia pf con la configurazione esistente in /etc/pf.conf" : null));

        checks.put(makeCheck("pf-enabled-boot",
            "pf si avvia al boot",
            pfEnabledAtBoot,
            pfEnabledAtBoot ? "pf_enable=YES in rc.conf" : "pf non si avvia automaticamente al riavvio",
            pfEnabledAtBoot ? null : "Se il server riparte (reboot), pf non torna su e Fail2ban non blocca più nulla.",
            (pfEnabledAtBoot || !pfConfExists) ? null : "enable_pf_at_boot",
            "Esegue: sysrc pf_enable=YES"));

        checks.put(makeCheck("pf-anchor-f2b",
            "pf.conf include l'anchor Fail2ban",
            pfAnchorPresent,
            pfAnchorPresent ? "anchor \"f2b/*\" presente in pf.conf"
                            : (pfConfExists ? "pf.conf c'è ma manca anchor \"f2b/*\""
                                            : "pf.conf non esiste"),
            pfAnchorPresent ? null
                : "Senza l'anchor, Fail2ban non può inserire regole nel firewall: i ban vengono \"applicati\" da fail2ban-client ma pf li ignora.",
            (pfAnchorPresent || !pfConfExists) ? null : "add_pf_anchor",
            "Aggiunge una sola riga ad /etc/pf.conf:  anchor \"f2b/*\""));

        // Il verdetto complessivo si legge dai controlli, non da un elenco di booleani scritto
        // a mano. Quell'elenco era una seconda versione della stessa verita', e le due
        // divergevano appena se ne aggiungeva uno: il controllo nuovo compariva rosso nella
        // lista mentre in cima restava "Tutto OK" e il pulsante per rimediare restava nascosto,
        // perche' nessuno si era ricordato di nominarlo anche qui. Contando le righe rosse la
        // dimenticanza non e' piu' possibile.
        boolean allOk = true;
        boolean qualcosaDaRiparare = false;
        for (int i = 0; i < checks.length(); i++) {
            JSONObject c = checks.getJSONObject(i);
            if (c.optBoolean("ok", false)) continue;
            allOk = false;
            if (c.has("fix_action")) qualcosaDaRiparare = true;
        }
        r.put("can_fix_all", qualcosaDaRiparare);
        r.put("success", true);
        r.put("all_ok", allOk);
        r.put("checks", checks);
        // Stato CSRF token per i POST successivi
        try {
            // riusiamo il sessionCode dell'exchange — si ottiene fuori. Qui generichiamo il check.
        } catch (Exception ignored) {}
        return r;
    }

    /**
     * Versione esatta di Fail2ban e del pacchetto, testuali.
     *
     * Serve a leggere la documentazione giusta. Le opzioni di un'azione cambiano fra versioni, e
     * una pagina letta per la versione sbagliata porta a scrivere una configurazione che il
     * sistema rifiuta — con l'aggravante che il rifiuto puo' essere silenzioso, come quando una
     * jail viene caricata senza nessuna azione e continua a contare i tentativi.
     */
    private String versioneFail2ban() {
        StringBuilder b = new StringBuilder();
        try {
            var v = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(10),
                "/usr/local/bin/fail2ban-client", "--version");
            if (v.success() && v.output() != null && !v.output().isBlank())
                b.append("Versione: ").append(v.output().trim().split("\n")[0]);
        } catch (Exception ignored) { }
        try {
            var p2 = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(10),
                "/usr/sbin/pkg", "query", "%n-%v", "py311-fail2ban");
            if (p2.success() && p2.output() != null && !p2.output().isBlank()) {
                if (b.length() > 0) b.append(" — ");
                b.append("Pacchetto: ").append(p2.output().trim().split("\n")[0]);
            }
        } catch (Exception ignored) { }
        return b.length() == 0 ? "(non sono riuscito a leggerne la versione)" : b.toString();
    }

    private JSONObject makeCheck(String id, String label, boolean ok, String statusText,
                                 String impactIfMissing, String fixAction, String fixDescription) {
        JSONObject c = new JSONObject();
        c.put("id", id);
        c.put("label", label);
        c.put("ok", ok);
        c.put("status", statusText);
        if (impactIfMissing != null) c.put("impact", impactIfMissing);
        if (fixAction != null) {
            c.put("fix_action", fixAction);
            c.put("fix_description", fixDescription != null ? fixDescription : "");
        }
        return c;
    }

    private boolean isFail2banEnabledAtBoot() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", "fail2ban_enable");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isFail2banRunning() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "fail2ban", "status");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.toLowerCase().contains("is running");
        } catch (Exception e) {
            return false;
        }
    }

    private JSONObject installFail2ban() {
        return sulTurnoPacchetti("installazione di fail2ban", this::eseguiInstallFail2ban);
    }

    private JSONObject eseguiInstallFail2ban() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/pkg", "install", "-y", "py311-fail2ban");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            boolean done = p.waitFor(180, java.util.concurrent.TimeUnit.SECONDS);
            if (!done) { p.destroyForcibly(); r.put("success", false); r.put("message", "Timeout installazione (>3min)"); return r; }
            int exit = p.exitValue();
            r.put("success", exit == 0);
            r.put("message", exit == 0 ? "Fail2ban installato con successo" : "pkg install exit=" + exit);
            r.put("output", out.length() > 4000 ? out.substring(out.length() - 4000) : out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    private JSONObject enableFail2banAtBoot() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "fail2ban_enable=YES");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "Avvio al boot abilitato" : "sysrc exit=" + p.exitValue());
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    /** Verifica se il modulo kernel pf è caricato (kldstat). */
    private boolean isPfModuleLoaded() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/kldstat");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.contains("pf.ko");
        } catch (Exception e) { return false; }
    }

    /** Verifica se il pannello sta girando dentro una jail FreeBSD (security.jail.jailed). */
    private boolean isRunningInsideFreebsdJail() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/sysctl", "-n", "security.jail.jailed");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equals("1");
        } catch (Exception e) { return false; }
    }

    /** Carica il modulo kernel pf con kldload. */
    private JSONObject loadPfModule() {
        JSONObject r = new JSONObject();
        try {
            if (isRunningInsideFreebsdJail()) {
                r.put("success", false);
                r.put("message", "Il pannello sta girando dentro una jail FreeBSD: il modulo kernel pf NON può essere caricato dall'interno di una jail. Carica pf dall'host con 'kldload pf' e abilita 'pf_load=\"YES\"' in /boot/loader.conf, poi riavvia il pannello.");
                return r;
            }
            if (isPfModuleLoaded()) {
                r.put("success", true);
                r.put("message", "Modulo pf già caricato");
                return r;
            }
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/kldload", "pf");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0 && isPfModuleLoaded();
            r.put("success", ok);
            r.put("message", ok ? "Modulo pf caricato" : "kldload pf fallito (exit=" + p.exitValue() + ")");
            r.put("output", out);

            // Persistenza: aggiungi pf_load=YES a /boot/loader.conf se manca
            if (ok) {
                try {
                    java.nio.file.Path loaderConf = java.nio.file.Paths.get("/boot/loader.conf");
                    String content = java.nio.file.Files.exists(loaderConf)
                        ? java.nio.file.Files.readString(loaderConf) : "";
                    if (!content.contains("pf_load=")) {
                        java.nio.file.Files.writeString(loaderConf,
                            content + (content.endsWith("\n") || content.isEmpty() ? "" : "\n") + "pf_load=\"YES\"\n",
                            java.nio.file.StandardOpenOption.CREATE,
                            java.nio.file.StandardOpenOption.WRITE);
                    }
                } catch (Exception ignored) {}
            }
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    private boolean isPfEnabledAtBoot() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "-n", "pf_enable");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.equalsIgnoreCase("YES");
        } catch (Exception e) { return false; }
    }

    private boolean isPfRunning() {
        try {
            // pfctl -si ritorna info status. Se pf non gira, exit code != 0 o output dice "Disabled".
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-si");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
            return out.contains("Status: Enabled");
        } catch (Exception e) { return false; }
    }

    private JSONObject startPfService() {
        JSONObject r = new JSONObject();
        try {
            // PRE-FLIGHT 1: verifica esistenza pf.conf
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (!java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", "/etc/pf.conf non esiste. Crea prima una configurazione pf prima di avviare il servizio (rischio lockout).");
                return r;
            }

            // PRE-FLIGHT 2: pfctl -nf controlla la sintassi senza caricare le regole.
            // Se la sintassi è invalida, non lanciamo il servizio.
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", "/etc/pf.conf");
            org.mail_panel.util.Shell.applicaPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                r.put("success", false);
                r.put("message", "Sintassi /etc/pf.conf NON valida — non avvio pf per evitare lockout. Errori: " + testOut.trim());
                r.put("output", testOut);
                return r;
            }

            // OK — avvio
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/service", "pf", "start");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
            boolean ok = p.exitValue() == 0;
            // Verifica che ora sia effettivamente in stato "Enabled"
            if (ok && !isPfRunning()) {
                ok = false;
                out += "\n\nATTENZIONE: service pf start exit=0 ma pfctl -si dice ancora Disabled.";
            }
            r.put("success", ok);
            r.put("message", ok ? "pf avviato e attivo" : "Avvio pf fallito (exit=" + p.exitValue() + ")");
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    private JSONObject enablePfAtBoot() {
        JSONObject r = new JSONObject();
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("/usr/sbin/sysrc", "pf_enable=YES");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            r.put("success", p.exitValue() == 0);
            r.put("message", p.exitValue() == 0 ? "pf abilitato al boot" : "sysrc exit=" + p.exitValue());
            r.put("output", out);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    /**
     * Crea /etc/pf.conf da zero con regole MINIME e SICURE:
     *   - skip on lo (loopback non viene filtrato)
     *   - anchor "f2b/*" (Fail2ban può inserire i suoi block-quick qui)
     *   - pass (default permissivo: niente viene bloccato a parte gli IP banditi)
     *
     * Questa configurazione NON blocca SSH, web, mail, niente — l'unico
     * blocco viene da Fail2ban quando rileva brute force. Non c'è rischio lockout.
     *
     * Refused se pf.conf esiste già (per non sovrascrivere config customizzate).
     */
    private JSONObject createPfConfMinimal() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", "/etc/pf.conf esiste già — uso 'add_pf_anchor' per aggiungere solo l'anchor.");
                return r;
            }
            String content = ""
                + "# /etc/pf.conf — generato automaticamente dal mail panel\n"
                + "# Configurazione MINIMA e SICURA per Fail2ban+pf\n"
                + "# - Nessun servizio è bloccato (no rischio lockout)\n"
                + "# - Solo gli IP banditi da Fail2ban vengono bloccati via anchor\n"
                + "#\n"
                + "# Per personalizzare: modifica questo file e poi 'pfctl -f /etc/pf.conf'.\n"
                + "# Backup vecchio file (se esiste) salvato come /etc/pf.conf.bak.<timestamp>\n"
                + "\n"
                + "# Loopback non filtrato\n"
                + "set skip on lo\n"
                + "\n"
                + "# Anchor Fail2ban: contiene i 'block in quick from <bannedIps>'\n"
                + "# inseriti automaticamente da fail2ban-client. Devono essere PRIMA del pass.\n"
                + "anchor \"f2b/*\"\n"
                + "\n"
                + "# Default: pass tutto (niente blocco a parte gli anchor sopra)\n"
                + "pass\n";

            // Test sintassi prima di scrivere su /etc/pf.conf:
            // scriviamo prima in temp, validiamo, poi copiamo.
            java.nio.file.Path tmp = java.nio.file.Files.createTempFile("pf-conf-", ".tmp");
            java.nio.file.Files.writeString(tmp, content, java.nio.charset.StandardCharsets.UTF_8);
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", tmp.toString());
            org.mail_panel.util.Shell.applicaPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                java.nio.file.Files.deleteIfExists(tmp);
                r.put("success", false);
                r.put("message", "Sintassi non valida: " + testOut);
                return r;
            }
            // Tutto OK, scrivi
            java.nio.file.Files.move(tmp, pfConfPath);
            try { java.nio.file.Files.setPosixFilePermissions(pfConfPath,
                java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")); } catch (Exception ignored) {}
            r.put("success", true);
            r.put("message", "/etc/pf.conf creato (minimo permissivo + anchor f2b)");
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    /**
     * Esegue tutti i fix necessari nell'ordine corretto.
     * Ritorna un report passo-passo con cosa è stato fatto e cosa è andato male.
     *
     * Ordine:
     *  1. Install Fail2ban
     *  2. Enable Fail2ban at boot
     *  3. Setup mail-panel-auth jail
     *  4. Install mail jails (Postfix/Dovecot/Roundcube/Rspamd)
     *  5. Create /etc/pf.conf minimo se manca
     *  6. Add anchor "f2b/*" a pf.conf se manca
     *  7. Enable pf at boot
     *  8. Start pf service
     *  9. Start Fail2ban service
     */
    private JSONObject runFixAll() {
        JSONObject r = new JSONObject();
        org.json.JSONArray steps = new org.json.JSONArray();
        boolean anyFailed = false;

        // Step 1: install Fail2ban
        boolean f2bInstalled = java.nio.file.Files.exists(java.nio.file.Paths.get("/usr/local/bin/fail2ban-client"));
        if (!f2bInstalled) {
            JSONObject res = installFail2ban();
            steps.put(buildStep("install_fail2ban", "Installa pacchetto py311-fail2ban", res));
            if (!res.optBoolean("success")) anyFailed = true;
            f2bInstalled = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("install_fail2ban", "Fail2ban già installato"));
        }

        // Step 2: enable at boot
        if (f2bInstalled && !isFail2banEnabledAtBoot()) {
            JSONObject res = enableFail2banAtBoot();
            steps.put(buildStep("enable_fail2ban_at_boot", "Abilita Fail2ban al boot", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (f2bInstalled) {
            steps.put(buildSkipStep("enable_fail2ban_at_boot", "Già abilitato al boot"));
        }

        // Step 3: setup mail-panel-auth jail (filter, log, jail entry)
        org.mail_panel.security.Fail2banAutoSetup.run();
        steps.put(buildStep("setup_mail_panel_jail", "Setup jail mail-panel-auth (filter + jail + log file)",
            new JSONObject().put("success", true).put("message", "Eseguito (idempotente)")));

        // Step 4: install mail jails (verifica file + runtime)
        try {
            java.nio.file.Path mailLocal = java.nio.file.Paths.get("/usr/local/etc/fail2ban/jail.d/mail.local");
            boolean mailFileOk = false;
            if (java.nio.file.Files.exists(mailLocal)) {
                String c = java.nio.file.Files.readString(mailLocal);
                mailFileOk = c.contains("[dovecot]") && c.contains("[postfix-auth]");
            }
            // Check runtime: tutte le 4 jail attive?
            java.util.Set<String> activeJailsNow = new java.util.HashSet<>();
            if (isFail2banRunning()) {
                try {
                    // TODO: migrate to Shell.run when touched
                    ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/fail2ban-client", "status");
                    org.mail_panel.util.Shell.applicaPath(pb);
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("Jail list:\\s*(.*)").matcher(out);
                    if (m.find()) for (String n : m.group(1).split(",")) activeJailsNow.add(n.trim());
                } catch (Exception ignored) {}
            }
            boolean allActive = activeJailsNow.contains("dovecot") && activeJailsNow.contains("postfix-auth");

            // "Il file nomina le jail" e "le jail sono accese" non dicono che stiano guardando
            // qualcosa. Con roundcube-auth erano entrambe vere mentre la jail sorvegliava un
            // file vuoto accanto a quello scritto: qui il passo veniva saltato con la motivazione
            // "gia' configurate e attive", e il percorso sbagliato sarebbe rimasto per sempre.
            boolean logSbagliati = false;
            try {
                logSbagliati = !fail2banManager.esaminaLogSorvegliati(activeJailsNow).problemi.isEmpty();
            } catch (Exception ignored) { }

            // E nemmeno "le jail ci sono e guardano il file giusto" basta: recidive aveva la
            // tabella pf e nessuna regola che la legge, quindi bannava nel vuoto, e questo passo
            // veniva saltato perche' il file la nominava ed era attiva. Ogni volta che il
            // cancello ha guardato una cosa piu' facile di quella che conta, il guasto e' passato.
            boolean senzaRegola = false;
            try {
                senzaRegola = fail2banManager.confrontaBanConPf().totaleSenzaRegola() > 0;
            } catch (Exception ignored) { }

            if (f2bInstalled && (!mailFileOk || !allActive || logSbagliati || senzaRegola)) {
                // File mancante O runtime non allineato → install (rigenera tutto: path
                // corretti dall'auto-detect, log file mancanti, filter aggiornati, reload).
                // install_mail_jails è idempotente: safe da chiamare anche se quasi tutto è OK.
                Fail2banManager.InstallResult res = fail2banManager.installMailJails();
                JSONObject jres = new JSONObject().put("success", res.success)
                    .put("message", res.success ? res.message : (res.error != null ? res.error : "Failed"));
                steps.put(buildStep("install_mail_jails",
                    "Configura jail Postfix/Dovecot/Roundcube/Rspamd (rigenera path corretti, crea log file, reload)", jres));
                if (!res.success) anyFailed = true;
            } else if (mailFileOk) {
                steps.put(buildSkipStep("install_mail_jails",
                    "Jail mail già configurate, attive, ognuna sorveglia un file che viene scritto, "
                    + "e ognuna ha in pf una regola che legge la propria tabella"));
            }
        } catch (Exception e) {
            steps.put(buildErrorStep("install_mail_jails", "Errore: " + e.getMessage()));
            anyFailed = true;
        }

        // Step 4b: le jail bannano con un comando che esiste su questo sistema?
        // Installarle non basta: due di loro ereditavano un'azione basata su iptables, che su
        // FreeBSD non esiste, e bannavano nel vuoto contando i ban come riusciti.
        try {
            JSONObject diag = org.mail_panel.security.RiparaAzioneBan.diagnosi();
            JSONArray rotte = diag.optJSONArray("rotte");
            JSONArray nonGiudicate = diag.optJSONArray("non_giudicate");
            boolean daRiparare = (rotte != null && rotte.length() > 0)
                              || (nonGiudicate != null && nonGiudicate.length() > 0);
            if (daRiparare) {
                JSONObject rr = org.mail_panel.security.RiparaAzioneBan.ripara();
                steps.put(buildStep("ripara_azione_ban",
                    "Dichiara l'azione pf sulle jail che bannavano con un comando inesistente, e verifica dopo il reload", rr));
                if (!rr.optBoolean("success", false)) anyFailed = true;
            } else {
                steps.put(buildSkipStep("ripara_azione_ban",
                    "Ogni jail banna con un comando che esiste su questo sistema"));
            }
        } catch (Exception e) {
            steps.put(buildErrorStep("ripara_azione_ban", "Errore: " + e.getMessage()));
            anyFailed = true;
        }

        // Step 5a: PRE-step — verifica che NON siamo in jail, e carica il modulo pf
        boolean inJail = isRunningInsideFreebsdJail();
        if (inJail) {
            steps.put(buildErrorStep("load_pf_module",
                "Il pannello gira dentro una jail FreeBSD: pf NON è gestibile da qui. Carica pf sull'host con 'kldload pf' e imposta 'pf_load=\"YES\"' in /boot/loader.conf dell'host. I passi pf successivi vengono saltati."));
            // skip tutti i passi pf
            r.put("success", false);
            r.put("steps", steps);
            r.put("message", "Stack pf non configurabile da una jail FreeBSD — risolto solo Fail2ban-side");
            return r;
        }
        boolean pfModuleLoaded = isPfModuleLoaded();
        if (!pfModuleLoaded) {
            JSONObject res = loadPfModule();
            steps.put(buildStep("load_pf_module", "Carica modulo kernel pf + persiste in /boot/loader.conf", res));
            if (!res.optBoolean("success")) {
                anyFailed = true;
                // Senza modulo pf, tutti i passi successivi falliranno: stop qui
                r.put("success", false);
                r.put("steps", steps);
                r.put("message", "Modulo pf non caricato — fix interrotto. Verifica i log del kernel.");
                return r;
            }
            pfModuleLoaded = true;
        } else {
            steps.put(buildSkipStep("load_pf_module", "Modulo pf già caricato"));
        }

        // Step 5b: create /etc/pf.conf if missing
        boolean pfConfExists = java.nio.file.Files.exists(java.nio.file.Paths.get("/etc/pf.conf"));
        if (!pfConfExists) {
            JSONObject res = createPfConfMinimal();
            steps.put(buildStep("create_pf_conf", "Crea /etc/pf.conf (minimal + anchor f2b)", res));
            if (!res.optBoolean("success")) anyFailed = true;
            pfConfExists = res.optBoolean("success");
        } else {
            steps.put(buildSkipStep("create_pf_conf", "/etc/pf.conf esiste già"));
        }

        // Step 6: add anchor f2b if missing
        if (pfConfExists) {
            boolean anchorPresent = false;
            try {
                String c = java.nio.file.Files.readString(java.nio.file.Paths.get("/etc/pf.conf"));
                anchorPresent = c.contains("anchor \"f2b/*\"") || c.contains("anchor f2b/*");
            } catch (Exception ignored) {}
            if (!anchorPresent) {
                JSONObject res = addPfAnchorF2b();
                steps.put(buildStep("add_pf_anchor", "Aggiunge anchor f2b a /etc/pf.conf", res));
                if (!res.optBoolean("success")) anyFailed = true;
            } else {
                steps.put(buildSkipStep("add_pf_anchor", "Anchor f2b già presente"));
            }
        }

        // Step 7: enable pf at boot
        if (pfConfExists && !isPfEnabledAtBoot()) {
            JSONObject res = enablePfAtBoot();
            steps.put(buildStep("enable_pf_at_boot", "Abilita pf al boot", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (pfConfExists) {
            steps.put(buildSkipStep("enable_pf_at_boot", "pf già abilitato al boot"));
        }

        // Step 8: start pf
        if (pfConfExists && !isPfRunning()) {
            JSONObject res = startPfService();
            steps.put(buildStep("start_pf", "Avvia pf (con pre-flight syntax check)", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (pfConfExists) {
            steps.put(buildSkipStep("start_pf", "pf già in esecuzione"));
        }

        // Step 9: start Fail2ban
        if (f2bInstalled && !isFail2banRunning()) {
            JSONObject res = startFail2banService();
            steps.put(buildStep("start_fail2ban", "Avvia Fail2ban", res));
            if (!res.optBoolean("success")) anyFailed = true;
        } else if (f2bInstalled) {
            steps.put(buildSkipStep("start_fail2ban", "Fail2ban già in esecuzione"));
        }

        r.put("success", !anyFailed);
        r.put("steps", steps);
        r.put("message", anyFailed ? "Alcuni passaggi sono falliti — controlla i dettagli" : "Tutto risolto");
        return r;
    }

    private JSONObject buildStep(String id, String label, JSONObject result) {
        return new JSONObject()
            .put("id", id)
            .put("label", label)
            .put("success", result.optBoolean("success", false))
            .put("status", "executed")
            .put("message", result.optString("message", ""))
            .put("output", result.optString("output", ""));
    }
    private JSONObject buildSkipStep(String id, String reason) {
        return new JSONObject()
            .put("id", id)
            .put("label", reason)
            .put("success", true)
            .put("status", "skipped")
            .put("message", "Già OK, niente da fare");
    }
    private JSONObject buildErrorStep(String id, String msg) {
        return new JSONObject()
            .put("id", id)
            .put("label", "Errore inatteso")
            .put("success", false)
            .put("status", "error")
            .put("message", msg);
    }

    /**
     * Aggiunge l'anchor f2b a /etc/pf.conf se manca. Operazione safe:
     *  - non rimuove regole esistenti
     *  - aggiunge una sola riga "anchor \"f2b/*\""
     *  - fa backup del file con timestamp
     *  - se aggiunto, ricarica pf con pfctl -f /etc/pf.conf
     */
    private JSONObject addPfAnchorF2b() {
        JSONObject r = new JSONObject();
        try {
            java.nio.file.Path pfConfPath = java.nio.file.Paths.get("/etc/pf.conf");
            if (!java.nio.file.Files.exists(pfConfPath)) {
                r.put("success", false);
                r.put("message", "/etc/pf.conf non esiste — devi prima creare una pf.conf base.");
                return r;
            }
            String content = java.nio.file.Files.readString(pfConfPath);
            if (content.contains("anchor \"f2b/*\"") || content.contains("anchor f2b/*")) {
                r.put("success", true);
                r.put("message", "Anchor f2b già presente, nessuna modifica.");
                return r;
            }
            // Backup
            String bakPath = "/etc/pf.conf.bak." + System.currentTimeMillis();
            java.nio.file.Files.copy(pfConfPath, java.nio.file.Paths.get(bakPath));
            // L'anchor va messo PRIMA delle regole pass/block. La posizione raccomandata
            // è subito dopo le tabelle, prima delle regole filter. Approccio safe:
            // appendiamo in fondo con un commento — pf valuta gli anchor in ordine,
            // e per fail2ban (che fa block) va in fondo va comunque bene.
            String append = "\n# Fail2ban anchor (auto-aggiunto dal pannello)\nanchor \"f2b/*\"\n";
            java.nio.file.Files.writeString(pfConfPath,
                content + append,
                java.nio.charset.StandardCharsets.UTF_8);

            // Test sintassi prima di ricaricare
            // TODO: migrate to Shell.run when touched
            ProcessBuilder testPb = new ProcessBuilder("/sbin/pfctl", "-nf", "/etc/pf.conf");
            org.mail_panel.util.Shell.applicaPath(testPb);
            testPb.redirectErrorStream(true);
            Process tp = testPb.start();
            String testOut = new String(tp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            tp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (tp.exitValue() != 0) {
                // Rollback
                java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), pfConfPath,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                r.put("success", false);
                r.put("message", "Sintassi pf.conf NON valida dopo l'aggiunta — rollback al backup. Output: " + testOut);
                return r;
            }
            // Ricarica live (solo se pf è in esecuzione, altrimenti l'anchor verrà
            // caricato al prossimo start)
            String loadOut = "";
            if (isPfRunning()) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder loadPb = new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf");
                org.mail_panel.util.Shell.applicaPath(loadPb);
                loadPb.redirectErrorStream(true);
                Process lp = loadPb.start();
                loadOut = new String(lp.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                lp.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                if (lp.exitValue() != 0) {
                    // Rollback se il load fallisce a runtime (config era valida ma rifiuta il reload?)
                    java.nio.file.Files.copy(java.nio.file.Paths.get(bakPath), pfConfPath,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    // Re-load la versione di backup
                    // TODO: migrate to Shell.run when touched
                    new ProcessBuilder("/sbin/pfctl", "-f", "/etc/pf.conf").redirectErrorStream(true).start().waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                    r.put("success", false);
                    r.put("message", "pfctl -f ha fallito il reload — rollback al backup. Output: " + loadOut);
                    return r;
                }
            } else {
                loadOut = "(pf non in esecuzione: l'anchor sarà caricato al prossimo avvio di pf)";
            }

            r.put("success", true);
            r.put("message", "Anchor f2b aggiunto a /etc/pf.conf (backup salvato in " + bakPath + ")");
            r.put("output", loadOut);
            return r;
        } catch (Exception e) {
            r.put("success", false);
            r.put("message", "Errore: " + e.getMessage());
            return r;
        }
    }

    /**
     * Diagnostica perché una jail mail non è attiva a runtime.
     * Controlla in ordine: file, logpath esistente, filter esistente, errori da fail2ban-client.
     */
    private String diagnoseMailJailIssue(String jailName, boolean inFile) {
        if (!inFile) return "non presente in mail.local";

        // Logpath previsto per ogni jail mail (path di roundcube auto-detected)
        String logpath = switch (jailName) {
            case "dovecot", "postfix-auth" -> "/var/log/maillog";
            case "roundcube-auth" -> {
                String detected = fail2banManager.getRoundcubeUserloginsPath();
                yield detected != null ? detected : "/usr/local/www/roundcube/logs/userlogins";
            }
            case "rspamd" -> "/var/log/rspamd/rspamd.log";
            default -> null;
        };
        if (logpath != null && !java.nio.file.Files.exists(java.nio.file.Paths.get(logpath))) {
            return "logpath '" + logpath + "' non esiste (servizio installato?)";
        }

        // Filter file
        String filterName = switch (jailName) {
            case "postfix-auth" -> "postfix-sasl";
            default -> jailName;
        };
        java.nio.file.Path filterPath = java.nio.file.Paths.get("/usr/local/etc/fail2ban/filter.d/" + filterName + ".conf");
        if (!java.nio.file.Files.exists(filterPath)) {
            return "filter " + filterName + ".conf manca in filter.d";
        }

        // Chiedi a fail2ban-client il motivo specifico
        var r = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(5),
            "/usr/local/bin/fail2ban-client", "status", jailName);
        String out = r.output();
        if (out.contains("does not exist") || out.contains("not found")
                || out.contains("Sorry, but the jail")) {
            return "non caricata (serve reload Fail2ban)";
        }
        if (!r.success()) {
            return "exit=" + r.exitCode() + " (" + (out.isBlank() ? "no output" : out.trim().replace('\n', ' ')) + ")";
        }
        // Se siamo qui, lo status command ha risposto normalmente (con i contatori
        // "Currently failed", "Banned IP list", ecc). La jail E' caricata e attiva,
        // ma per qualche motivo il check chiamante non l'ha rilevata. Non e' un errore
        // della jail: ritorniamo una stringa che fa capire che e' un falso allarme.
        return "in realta' attiva (rilevamento check fallito — log f2b OK)";
    }

    /**
     * Reload Fail2ban con fail2ban-client reload.
     * Prima del reload assicura i prerequisiti che potrebbero far fallire
     * il caricamento di alcune jail (es. file userlogins di Roundcube).
     * Se una sola jail fallisce, fail2ban rifiuta TUTTO il reload — quindi
     * conviene sempre essere proattivi.
     */
    /**
     * Helper: converte un {@link org.mail_panel.util.Shell.Result} in JSONObject
     * con campi success/message/output, riducendo boilerplate.
     */
    private JSONObject shellResultToJson(org.mail_panel.util.Shell.Result r, String okMessage, String failPrefix) {
        return new JSONObject()
            .put("success", r.success())
            .put("message", r.success() ? okMessage
                : (r.timedOut() ? "TIMEOUT: " + failPrefix
                                : failPrefix + " exit=" + r.exitCode()))
            .put("output", r.output());
    }

    private JSONObject reloadFail2banAction() {
        // Prereq: log file Roundcube (se manca, roundcube-auth jail fa fallire l'intero reload)
        try { fail2banManager.ensureRoundcubeLoggingEnabled(); } catch (Exception ignored) {}
        var r = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(15),
            "/usr/local/bin/fail2ban-client", "reload");
        return shellResultToJson(r, "Fail2ban reload OK", "Reload");
    }

    private JSONObject startFail2banService() {
        var r = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(20),
            "/usr/sbin/service", "fail2ban", "start");
        return shellResultToJson(r, "Servizio avviato", "service start");
    }

    /**
     * Restart pulito del servizio fail2ban (equivalente di `service fail2ban restart`).
     * A differenza di "reload", questo killa il daemon e lo riavvia da zero — utile per
     * uscire da stati confusi (es. dopo molti reload consecutivi).
     * NB: azzera anche i contatori "Currently failed" e "Total failed" di tutte le jail.
     */
    private JSONObject restartFail2banService() {
        var r = org.mail_panel.util.Shell.run(java.time.Duration.ofSeconds(30),
            "/usr/sbin/service", "fail2ban", "restart");
        return shellResultToJson(r, "Fail2ban riavviato (restart pulito)", "service restart");
    }

    // ============== 2FA API ==============

    private void handleApi2FA(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            int adminId = getSessionAdminId(exchange);

            switch (method) {
                case "GET" -> {
                    // Check for action in query string
                    String query = exchange.getRequestURI().getQuery();
                    String action = "";
                    if (query != null && query.contains("action=")) {
                        for (String param : query.split("&")) {
                            if (param.startsWith("action=")) {
                                action = param.substring(7);
                                break;
                            }
                        }
                    }

                    if ("backup_codes".equals(action)) {
                        // Get backup codes (show hashed, user needs originals)
                        String codesJson = Main.mailDatabase.getBackupCodes(adminId);
                        if (codesJson != null && !codesJson.isEmpty()) {
                            // Note: we can't show original codes, only that they exist
                            // User should have saved them during setup
                            response.put("success", true);
                            response.put("message", "I codici di backup sono stati generati durante l'attivazione della 2FA. Se li hai persi, rigenerali.");
                            response.put("codes", new JSONArray()); // Empty - can't recover hashed codes
                        } else {
                            response.put("success", false);
                            response.put("error", "Nessun codice di backup trovato");
                        }
                    } else {
                        // Get 2FA status
                        boolean enabled = Main.mailDatabase.is2FAEnabled(adminId);
                        response.put("success", true);
                        response.put("enabled", enabled);
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "");

                    switch (action) {
                        case "setup" -> {
                            // Generate new secret and QR code
                            String secret = TotpManager.generateSecret();
                            String qrUrl = TotpManager.getQrCodeImageUrl(secret, "admin", "FreeBSD Mail Panel");
                            response.put("success", true);
                            response.put("secret", secret);
                            response.put("qr_url", qrUrl);
                        }
                        case "enable" -> {
                            // Verify code and enable 2FA
                            String secret = req.optString("secret", "");
                            String code = req.optString("code", "");

                            if (TotpManager.verifyCode(secret, code)) {
                                // Generate backup codes
                                String[] backupCodes = TotpManager.generateBackupCodes(8);
                                JSONArray codesJson = new JSONArray();
                                for (String bc : backupCodes) {
                                    codesJson.put(TotpManager.hashBackupCode(bc));
                                }

                                Main.mailDatabase.enable2FA(adminId, secret, codesJson.toString());
                                response.put("success", true);
                                response.put("backup_codes", new JSONArray(backupCodes));
                                logAudit("2FA_ENABLED", getClientIp(exchange), "admin_id=" + adminId);
                            } else {
                                response.put("success", false);
                                response.put("error", "Codice non valido");
                                logAudit("2FA_ENABLE_FAILED", getClientIp(exchange), "admin_id=" + adminId + " reason=invalid_code");
                            }
                        }
                        case "disable" -> {
                            String code = req.optString("code", "");
                            String secret = Main.mailDatabase.getTotpSecret(adminId);

                            if (secret != null && TotpManager.verifyCode(secret, code)) {
                                Main.mailDatabase.disable2FA(adminId);
                                response.put("success", true);
                                logAudit("2FA_DISABLED", getClientIp(exchange), "admin_id=" + adminId);
                            } else {
                                response.put("success", false);
                                response.put("error", "Codice non valido");
                                logAudit("2FA_DISABLE_FAILED", getClientIp(exchange), "admin_id=" + adminId + " reason=invalid_code");
                            }
                        }
                        case "regenerate_backup" -> {
                            // Generate new backup codes
                            if (!Main.mailDatabase.is2FAEnabled(adminId)) {
                                response.put("success", false);
                                response.put("error", "2FA non attiva");
                            } else {
                                String[] backupCodes = TotpManager.generateBackupCodes(8);
                                JSONArray codesJson = new JSONArray();
                                for (String bc : backupCodes) {
                                    codesJson.put(TotpManager.hashBackupCode(bc));
                                }
                                Main.mailDatabase.updateBackupCodes(adminId, codesJson.toString());
                                response.put("success", true);
                                response.put("codes", new JSONArray(backupCodes));
                                logAudit("2FA_BACKUP_CODES_REGENERATED", getClientIp(exchange), "admin_id=" + adminId);
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== PASSKEY/WEBAUTHN API ==============

    /**
     * Check username and return available auth methods (no auth required)
     */
    private void handleApiAuthCheck(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        JSONObject response = new JSONObject();
        try {
            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Request too large");
                return;
            }
            JSONObject req = new JSONObject(body);
            String username = req.optString("username", "").trim();

            // Whitelist, non lista di cose vietate: si accetta SOLO cio' che un username puo'
            // essere. Controllare che non sia vuoto lasciava passare qualsiasi altra cosa.
            if (!SecurityUtils.isValidUsername(username)) {
                response.put("success", false);
                response.put("error", "Username non valido");
                sendJsonResponse(exchange, response);
                return;
            }

            // Check if user exists and get auth methods
            MailDatabase.AuthMethods authMethods = Main.mailDatabase.getAuthMethods(username);

            response.put("success", true);
            response.put("exists", authMethods.exists);
            response.put("hasPassword", authMethods.hasPassword);
            response.put("hasPasskey", authMethods.hasPasskey);
            response.put("has2FA", authMethods.has2FA);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Start passkey registration (requires auth)
     */
    private void handleApiPasskeyRegisterStart(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        JSONObject response = new JSONObject();
        try {
            if (passkeyManager == null) {
                response.put("success", false);
                response.put("error", "Passkey non configurate. Verificare il mail hostname nelle impostazioni.");
                sendJsonResponse(exchange, response);
                return;
            }

            int adminId = getSessionAdminId(exchange);
            MailDatabase.AdminUser admin = Main.mailDatabase.getAdminUserById(adminId);

            if (admin == null) {
                response.put("success", false);
                response.put("error", "Admin non trovato");
                sendJsonResponse(exchange, response);
                return;
            }

            PasskeyManager.RegistrationStartResponse regStart = passkeyManager.startRegistration(
                    adminId,
                    admin.username,
                    admin.username
            );

            response.put("success", true);
            response.put("challengeId", regStart.challengeId());
            // Convert the options to JSON for JavaScript WebAuthn API
            response.put("options", regStart.options().toCredentialsCreateJson());
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Finish passkey registration (requires auth)
     */
    private void handleApiPasskeyRegisterFinish(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        JSONObject response = new JSONObject();
        try {
            if (passkeyManager == null) {
                response.put("success", false);
                response.put("error", "Passkey non configurate");
                sendJsonResponse(exchange, response);
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Request too large");
                return;
            }
            JSONObject req = new JSONObject(body);

            String challengeId = req.optString("challengeId", "");
            String credential = req.optString("credential", "");
            String passkeyName = req.optString("name", "Passkey");

            if (challengeId.isEmpty() || credential.isEmpty()) {
                response.put("success", false);
                response.put("error", "Dati mancanti");
                sendJsonResponse(exchange, response);
                return;
            }

            PasskeyManager.RegistrationResult result = passkeyManager.finishRegistration(
                    challengeId,
                    credential,
                    passkeyName
            );

            response.put("success", result.success());
            if (result.success()) {
                response.put("message", result.message());
                logAudit("PASSKEY_REGISTERED", getClientIp(exchange), "name=" + passkeyName);
            } else {
                response.put("error", result.message());
                logAudit("PASSKEY_REGISTER_FAILED", getClientIp(exchange), "msg=" + result.message());
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Start passkey login (no auth required)
     */
    private void handleApiPasskeyLoginStart(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        JSONObject response = new JSONObject();
        try {
            if (passkeyManager == null) {
                response.put("success", false);
                response.put("error", "Passkey non configurate");
                sendJsonResponse(exchange, response);
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Request too large");
                return;
            }
            JSONObject req = new JSONObject(body);
            String username = req.optString("username", "").trim();

            // Whitelist, non lista di cose vietate: si accetta SOLO cio' che un username puo'
            // essere. Controllare che non sia vuoto lasciava passare qualsiasi altra cosa.
            if (!SecurityUtils.isValidUsername(username)) {
                response.put("success", false);
                response.put("error", "Username non valido");
                sendJsonResponse(exchange, response);
                return;
            }

            PasskeyManager.AuthenticationStartResponse authStart = passkeyManager.startAuthentication(username);

            if (authStart.error() != null) {
                response.put("success", false);
                response.put("error", authStart.error());
            } else {
                response.put("success", true);
                response.put("challengeId", authStart.challengeId());
                response.put("options", authStart.options().toCredentialsGetJson());
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Finish passkey login (no auth required)
     */
    private void handleApiPasskeyLoginFinish(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        JSONObject response = new JSONObject();
        try {
            if (passkeyManager == null) {
                response.put("success", false);
                response.put("error", "Passkey non configurate");
                sendJsonResponse(exchange, response);
                return;
            }

            String body = readRequestBodyWithLimit(exchange);
            if (body == null) {
                sendJsonError(exchange, 413, "Request too large");
                return;
            }
            JSONObject req = new JSONObject(body);

            String challengeId = req.optString("challengeId", "");
            String credential = req.optString("credential", "");

            if (challengeId.isEmpty() || credential.isEmpty()) {
                response.put("success", false);
                response.put("error", "Dati mancanti");
                sendJsonResponse(exchange, response);
                return;
            }

            PasskeyManager.AuthenticationResult result = passkeyManager.finishAuthentication(challengeId, credential);

            if (result.success()) {
                // Create session for the authenticated admin
                MailDatabase.AdminUser admin = Main.mailDatabase.getAdminUserById(result.adminId());
                if (admin != null && admin.active) {
                    // Create session using existing session manager
                    String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
                    String clientIp = getClientIp(exchange);
                    Object[] sessionData = Main.sessions.Add_Session(userAgent, clientIp);
                    String sessionCode = (String) sessionData[1];

                    // Save admin info in session
                    Main.sessions.setSessionAdmin(sessionCode, result.adminId(), admin.username);

                    // Set session cookie
                    exchange.getResponseHeaders().add("Set-Cookie",
                        "__Host-MailPanel=" + sessionCode + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600");
                    // Cleanup: cancella eventuale cookie residuo col vecchio nome
                    exchange.getResponseHeaders().add("Set-Cookie",
                        "MailPanel=; Path=/; HttpOnly; Secure; Max-Age=0");

                    logAudit("PASSKEY_LOGIN_SUCCESS", clientIp, "User logged in via passkey: " + admin.username);

                    response.put("success", true);
                    response.put("message", "Login con passkey riuscito");
                } else {
                    response.put("success", false);
                    response.put("error", "Account disabilitato");
                }
            } else {
                response.put("success", false);
                response.put("error", result.error());
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    /**
     * Manage passkeys (list, rename, delete) - requires auth
     */
    private void handleApiPasskeys(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();
        int adminId = getSessionAdminId(exchange);

        try {
            switch (method) {
                case "GET" -> {
                    // List passkeys for current user
                    List<MailDatabase.Passkey> passkeys = Main.mailDatabase.getPasskeys(adminId);
                    JSONArray arr = new JSONArray();
                    for (MailDatabase.Passkey pk : passkeys) {
                        JSONObject p = new JSONObject();
                        p.put("id", pk.id);
                        p.put("name", pk.name);
                        p.put("createdAt", pk.createdAt != null ? pk.createdAt.toString() : "");
                        p.put("lastUsed", pk.lastUsed != null ? pk.lastUsed.toString() : "Mai");
                        arr.put(p);
                    }
                    response.put("success", true);
                    response.put("passkeys", arr);
                }
                case "POST" -> {
                    // Rename passkey
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Request too large");
                        return;
                    }
                    JSONObject req = new JSONObject(body);
                    int passkeyId = req.optInt("id", 0);
                    String newName = req.optString("name", "").trim();

                    if (passkeyId <= 0 || newName.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "ID e nome richiesti");
                    } else if (Main.mailDatabase.renamePasskey(passkeyId, adminId, newName)) {
                        response.put("success", true);
                        response.put("message", "Passkey rinominata");
                    } else {
                        response.put("success", false);
                        response.put("error", "Errore durante la rinomina");
                    }
                }
                case "DELETE" -> {
                    // Delete passkey
                    String body = readRequestBodyWithLimit(exchange);
                    if (body == null) {
                        sendJsonError(exchange, 413, "Request too large");
                        return;
                    }
                    JSONObject req = new JSONObject(body);
                    int passkeyId = req.optInt("id", 0);

                    if (passkeyId <= 0) {
                        response.put("success", false);
                        response.put("error", "ID passkey richiesto");
                    } else if (Main.mailDatabase.deletePasskey(passkeyId, adminId)) {
                        response.put("success", true);
                        response.put("message", "Passkey eliminata");
                        logAudit("PASSKEY_DELETED", getClientIp(exchange), "passkey_id=" + passkeyId + " admin_id=" + adminId);
                    } else {
                        response.put("success", false);
                        response.put("error", "Errore durante l'eliminazione");
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }
        sendJsonResponse(exchange, response);
    }

    // ============== ADMIN MANAGEMENT API ==============

    /**
     * Il rapporto periodico appartiene alle IMPOSTAZIONI, non agli aggiornamenti: destinatario,
     * mittente e frequenza sono scelte, non diagnosi. Era finito nella pagina degli
     * aggiornamenti solo perche' li' l'impianto delle chiamate esisteva gia' — comodo per chi
     * scrive, non per chi usa — e per giunta il piede dell'email diceva gia' di cercarlo qui.
     */
    /**
     * Creazione automatica su Cloudflare dei record che finora si aggiungevano a mano.
     * L'automatismo esisteva gia' ma solo dentro la rotazione DKIM: stessi strumenti, non
     * collegati a niente altro.
     */
    private void handleApiAutoDns(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, "Method not allowed"); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, "JSON non valido"); return; }

        org.mail_panel.security.AutoDns auto =
                new org.mail_panel.security.AutoDns(Main.mailDatabase,
                        new org.mail_panel.security.CloudflareManager(Main.mailDatabase));
        int domainId = req.optInt("domain_id", 0);
        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = auto.stato(domainId);
            case "create" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                String quale = req.optString("quale", "");
                // Il predefinito e' "none", non "quarantine": RFC 9989 §5.1.5. Un valore
                // predefinito che blocca posta e' una trappola per chi preme senza scegliere.
                response = auto.crea(domainId, quale, req.optString("politica", "none"));
                logAudit("AUTODNS_CREATE", ip, quale + " su dominio " + domainId
                        + (response.optBoolean("success") ? " - creato" : " - NON creato: "
                           + response.optString("error", "?")));
            }
            case "change_policy" -> {
                response = auto.cambiaPolitica(domainId, req.optString("politica", ""),
                        "CAMBIA".equals(req.optString("confirm", "")));
                if ("CAMBIA".equals(req.optString("confirm", "")))
                    logAudit("AUTODNS_POLITICA", ip, "dominio " + domainId + " -> p="
                            + req.optString("politica", "") + (response.optBoolean("success")
                            ? " - fatto" : " - NON fatto: " + response.optString("error", "?")));
            }
            case "mtasts_status" -> response = org.mail_panel.system.MtaSts.stato();
            case "mtasts_mode" -> response = org.mail_panel.system.MtaSts.impostaModo(req.optString("modo", ""));
            case "mtasts_txt" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = auto.creaTxtMtaSts(domainId);
                logAudit("MTASTS_TXT", ip, "dominio " + domainId
                        + (response.optBoolean("success") ? " - pubblicato" : " - NON pubblicato: "
                           + response.optString("error", "?")));
            }
            case "create_optional" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                String q = req.optString("quale", "");
                response = auto.creaOpzionale(domainId, q);
                logAudit("AUTODNS_OPZIONALE", ip, q + " su dominio " + domainId
                        + (response.optBoolean("success") ? " - creato" : " - NON creato: "
                           + response.optString("error", "?")));
            }
            // La pagina DNS deve poter seguire il lavoro che ha appena avviato: senza questo
            // caso resterebbe con un identificativo e nessun modo di sapere com'e' finito.
            case "job_status" -> response = UpdateManager.jobStatus(req.optString("jobId", ""));
            case "configura_tutto" -> {
                if (!"CONFIGURA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = UpdateManager.avviaConfiguraDominio(domainId);
                logAudit("DOMINIO_CONFIGURA", ip, "dominio " + domainId
                        + " - avviata come lavoro " + response.optString("jobId", ""));
            }
            case "mailboxes" -> response = auto.caselleDisponibili();
            case "mailbox_create" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = auto.creaCasellaRapporti(domainId);
                logAudit("AUTODNS_CASELLA", ip, "casella dmarc@ dominio " + domainId
                        + (response.optBoolean("success") ? " - creata" : " - NON creata: "
                           + response.optString("error", "?")));
            }
            case "alias_create" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                String verso = req.optString("verso", "");
                response = auto.creaAliasRapporti(domainId, verso);
                logAudit("AUTODNS_ALIAS", ip, "alias dmarc@ dominio " + domainId + " verso " + verso
                        + (response.optBoolean("success") ? " - creato" : " - NON creato: "
                           + response.optString("error", "?")));
            }
            default -> response = new JSONObject().put("success", false).put("error", "azione sconosciuta");
        }
        sendJsonResponse(exchange, response);
    }

    private void handleApiReport(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) { sendJsonError(exchange, 401, "Unauthorized"); return; }
        if (!"POST".equals(exchange.getRequestMethod())) { sendJsonError(exchange, 405, "Method not allowed"); return; }
        String body = readRequestBodyWithLimit(exchange);
        if (body == null) { sendJsonError(exchange, 413, "Richiesta troppo grande"); return; }
        String ip = getClientIp(exchange);
        JSONObject req;
        try { req = new JSONObject(body); }
        catch (Exception e) { sendJsonError(exchange, 400, "JSON non valido"); return; }

        JSONObject response;
        switch (req.optString("action", "")) {
            case "status" -> response = org.mail_panel.system.RapportoPeriodico.stato();
            case "identity" -> response = org.mail_panel.system.RapportoPeriodico.statoIdentita();
            case "preview" -> response = org.mail_panel.system.RapportoPeriodico.anteprima();
            case "save" -> response = org.mail_panel.system.RapportoPeriodico.salvaImpostazioni(
                    req.optString("destinatario", ""), req.optString("mittente", ""),
                    req.optString("frequenza", ""), req.optString("ora", ""),
                    req.optBoolean("attivo", false));
            case "identity_create" -> {
                if (!"CREA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = org.mail_panel.system.RapportoPeriodico.creaIdentita(req.optString("indirizzo", ""));
                logAudit("REPORT_IDENTITY", ip, req.optString("indirizzo", "")
                        + (response.optBoolean("success") ? " - creata" : " - NON creata"));
            }
            case "send" -> {
                if (!"INVIA".equals(req.optString("confirm", ""))) {
                    response = new JSONObject().put("success", false).put("error", "Conferma mancante");
                    break;
                }
                response = org.mail_panel.system.RapportoPeriodico.inviaAdesso(req.optString("destinatario", ""));
                logAudit("REPORT_SEND", ip, req.optString("destinatario", "")
                        + (response.optBoolean("success") ? " - inviato" : " - NON inviato"));
            }
            default -> response = new JSONObject().put("success", false).put("error", "azione sconosciuta");
        }
        sendJsonResponse(exchange, response);
    }

    private void handleApiAdmins(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            int currentAdminId = getSessionAdminId(exchange);
            String currentRole = Main.mailDatabase.getAdminRole(currentAdminId);

            // Handle password change first (any authenticated user can change their own password)
            if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, "Richiesta troppo grande");
                    return;
                }
                JSONObject req = new JSONObject(body);
                String action = req.optString("action", "");

                if ("change_password".equals(action)) {
                    String currentPassword = req.optString("current_password", "");
                    String newPassword = req.optString("new_password", "");

                    if (currentPassword.isEmpty() || newPassword.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Password corrente e nuova richieste");
                    } else if (newPassword.length() < 8) {
                        response.put("success", false);
                        response.put("error", "La nuova password deve essere di almeno 8 caratteri");
                    } else if (Main.mailDatabase.verifyAdminPassword(currentAdminId, currentPassword)) {
                        if (Main.mailDatabase.updateAdminPassword(currentAdminId, newPassword)) {
                            response.put("success", true);
                            response.put("message", "Password cambiata con successo");
                            logAudit("ADMIN_PASSWORD_CHANGED", getClientIp(exchange), "admin_id=" + currentAdminId);
                        } else {
                            response.put("success", false);
                            response.put("error", "Errore durante il salvataggio della password");
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "Password corrente non valida");
                        logAudit("ADMIN_PASSWORD_CHANGE_FAILED", getClientIp(exchange), "admin_id=" + currentAdminId + " reason=invalid_current_password");
                    }
                    sendJsonResponse(exchange, response);
                    return;
                }

                if ("vault_backup_key".equals(action)) {
                    // Esporta la master key in base64 per backup.
                    // Richiede la password admin per conferma identità.
                    String currentPassword = req.optString("current_password", "");
                    if (currentPassword.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Password attuale richiesta per esportare la master key");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!Main.mailDatabase.verifyAdminPassword(currentAdminId, currentPassword)) {
                        response.put("success", false);
                        response.put("error", "Password attuale non valida");
                        logAudit("VAULT_KEY_EXPORT_FAILED", getClientIp(exchange),
                            "admin_id=" + currentAdminId + " reason=invalid_password");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    try {
                        org.mail_panel.security.PasswordVault vault =
                            org.mail_panel.security.PasswordVault.getInstance();
                        String b64 = vault.exportKeyBase64();
                        response.put("success", true);
                        response.put("key_base64", b64);
                        response.put("key_file_path", org.mail_panel.security.PasswordVault.getKeyFilePath());
                        response.put("message",
                            "Master key esportata. Salvala in un posto SICURO " +
                            "(password manager, vault hardware, ecc.) — con questo file chiunque " +
                            "può decifrare tutte le password mailbox archiviate.");
                        logAudit("VAULT_KEY_EXPORTED", getClientIp(exchange), "admin_id=" + currentAdminId);
                    } catch (Exception e) {
                        response.put("success", false);
                        response.put("error", "Errore export: " + e.getMessage());
                    }
                    sendJsonResponse(exchange, response);
                    return;
                }

                if ("vault_rotate_key".equals(action)) {
                    // Rotazione master key: genera nuova chiave, ri-cifra TUTTI i blob esistenti
                    // con la nuova, salva la nuova chiave su disco (backup della vecchia).
                    // Operazione sensibile: richiede password admin.
                    String currentPassword = req.optString("current_password", "");
                    if (currentPassword.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Password attuale richiesta per ruotare la master key");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!Main.mailDatabase.verifyAdminPassword(currentAdminId, currentPassword)) {
                        response.put("success", false);
                        response.put("error", "Password attuale non valida");
                        logAudit("VAULT_KEY_ROTATION_FAILED", getClientIp(exchange),
                            "admin_id=" + currentAdminId + " reason=invalid_password");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    try {
                        org.mail_panel.security.PasswordVault vault =
                            org.mail_panel.security.PasswordVault.getInstance();
                        byte[] oldKey = java.util.Base64.getDecoder().decode(vault.exportKeyBase64());
                        byte[] newKey = vault.generateNewKeyBytes();

                        // Re-encrypt tutti i blob: leggi col vecchio, scrivi col nuovo
                        java.util.List<Object[]> rows = Main.mailDatabase.listMailboxesWithEncryptedPasswordAndBlob();
                        int total = rows.size();
                        int reencrypted = 0;
                        int failed = 0;
                        for (Object[] row : rows) {
                            int mid = (int) row[0];
                            String blob = (String) row[1];
                            try {
                                String plain = vault.decryptWithKey(blob, oldKey);
                                String newBlob = vault.encryptWithKey(plain, newKey);
                                Main.mailDatabase.setMailboxEncryptedPasswordOnly(mid, newBlob);
                                reencrypted++;
                            } catch (Exception e) {
                                failed++;
                                System.err.println("[VaultRotate] mailbox_id=" + mid + " re-encrypt failed: " + e.getMessage());
                            }
                        }

                        if (failed > 0 && reencrypted == 0) {
                            // Tutti falliti: probabilmente la vecchia chiave è già non valida.
                            // NON salviamo la nuova chiave (lasciamo lo stato com'è).
                            response.put("success", false);
                            response.put("error",
                                "Tutti i " + total + " blob hanno fallito il re-encrypt. " +
                                "La chiave master attuale non riesce a decifrarli — probabilmente è già rotta. " +
                                "Per recovery: usa 'Cambia password massivo' nella pagina Caselle invece di rotare la chiave.");
                            sendJsonResponse(exchange, response);
                            return;
                        }

                        // Salva la nuova chiave (anche se qualche blob ha fallito: meglio andare avanti)
                        vault.persistNewKey(newKey);

                        org.json.JSONObject summary = new org.json.JSONObject();
                        summary.put("total", total);
                        summary.put("reencrypted", reencrypted);
                        summary.put("failed", failed);
                        response.put("success", true);
                        response.put("summary", summary);
                        response.put("message",
                            "Master key rotata. Re-cifrati " + reencrypted + "/" + total + " blob. " +
                            (failed > 0
                                ? failed + " blob NON re-cifrati (forse cifrati con una chiave ancora più vecchia): " +
                                  "per quelle caselle usa 'Cambia password massivo'. "
                                : "") +
                            "La vecchia chiave è stata salvata come backup in " +
                            org.mail_panel.security.PasswordVault.getKeyFilePath() + ".bak.<timestamp>.");
                        logAudit("VAULT_KEY_ROTATED", getClientIp(exchange),
                            "admin_id=" + currentAdminId + " total=" + total +
                            " reencrypted=" + reencrypted + " failed=" + failed);
                    } catch (Exception e) {
                        response.put("success", false);
                        response.put("error", "Errore rotazione: " + e.getMessage());
                    }
                    sendJsonResponse(exchange, response);
                    return;
                }

                if ("change_username".equals(action)) {
                    String currentPassword = req.optString("current_password", "");
                    String newUsername = req.optString("new_username", "").trim();

                    // Sanity check inputs
                    if (currentPassword.isEmpty() || newUsername.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Password corrente e nuovo username richiesti");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!SecurityUtils.isValidUsername(newUsername)) {
                        response.put("success", false);
                        response.put("error", "Username non valido: deve essere 3-50 caratteri, solo lettere/numeri/underscore/trattino/punto");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Verifica la password corrente (security: prova di identità)
                    if (!Main.mailDatabase.verifyAdminPassword(currentAdminId, currentPassword)) {
                        response.put("success", false);
                        response.put("error", "Password corrente non valida");
                        logAudit("ADMIN_USERNAME_CHANGE_FAILED", getClientIp(exchange),
                            "admin_id=" + currentAdminId + " reason=invalid_password");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Recupera username corrente (per audit log e verifica no-op)
                    String currentUsername = null;
                    for (MailDatabase.AdminUser au : Main.mailDatabase.getAdminUsers()) {
                        if (au.id == currentAdminId) { currentUsername = au.username; break; }
                    }

                    // No-op check: stesso username
                    if (currentUsername != null && currentUsername.equalsIgnoreCase(newUsername)) {
                        response.put("success", false);
                        response.put("error", "Il nuovo username è uguale a quello attuale");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Verifica unicità (case-insensitive)
                    if (Main.mailDatabase.adminUsernameExists(newUsername)) {
                        response.put("success", false);
                        response.put("error", "Username già in uso da un altro admin");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Esegui UPDATE
                    if (!Main.mailDatabase.updateAdminUsername(currentAdminId, newUsername)) {
                        response.put("success", false);
                        response.put("error", "Errore durante il salvataggio del nuovo username");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Aggiorna in-memory la sessione corrente (e tutte le altre dell'admin), così
                    // non serve un re-login e il pannello continua a riconoscere correttamente l'utente.
                    try {
                        String sessionCode = extractSessionCode(exchange.getRequestHeaders().getFirst("Cookie"));
                        if (sessionCode != null) {
                            Main.sessions.setSessionAdmin(sessionCode, currentAdminId, newUsername);
                        }
                        // Aggiorna anche eventuali altre sessioni attive dello stesso admin
                        for (org.mail_panel.webserver.Session s : Main.sessions.sessions) {
                            if (s.adminId == currentAdminId) s.username = newUsername;
                        }
                    } catch (Exception ignore) {}

                    response.put("success", true);
                    response.put("message", "Username cambiato con successo da '" + (currentUsername == null ? "?" : currentUsername) + "' a '" + newUsername + "'. La sessione corrente resta valida — non serve effettuare di nuovo il login.");
                    response.put("new_username", newUsername);
                    logAudit("ADMIN_USERNAME_CHANGED", getClientIp(exchange),
                        "admin_id=" + currentAdminId + " old=" + currentUsername + " new=" + newUsername);
                    sendJsonResponse(exchange, response);
                    return;
                }
            }

            // Only superadmin can manage other admins
            if (!"superadmin".equals(currentRole)) {
                sendJsonError(exchange, 403, "Solo superadmin può gestire gli amministratori");
                return;
            }

            switch (method) {
                case "GET" -> {
                    JSONArray admins = new JSONArray();
                    for (MailDatabase.AdminUser admin : Main.mailDatabase.getAdminUsers()) {
                        JSONObject a = new JSONObject();
                        a.put("id", admin.id);
                        a.put("username", admin.username);
                        a.put("role", admin.role);
                        a.put("active", admin.active);
                        a.put("totp_enabled", admin.totpEnabled);
                        a.put("created_at", admin.createdAt != null ? admin.createdAt.toString() : "");
                        a.put("last_login", admin.lastLogin != null ? admin.lastLogin.toString() : "");
                        admins.put(a);
                    }
                    response.put("success", true);
                    response.put("admins", admins);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "create");

                    switch (action) {
                        case "create" -> {
                            String username = req.optString("username", "").trim();
                            String password = req.optString("password", "");
                            String role = req.optString("role", "admin");

                            // Qui non si validava nulla: un username qualsiasi finiva nel
                            // database, e da li' nell'elenco degli amministratori, che lo
                            // interpola in HTML. La catena si spezza al primo anello.
                            if (!SecurityUtils.isValidUsername(username)) {
                                response.put("success", false);
                                response.put("error", "Username non valido: sono ammessi solo "
                                        + "lettere, cifre, trattino e trattino basso, da 3 a 50 caratteri.");
                                sendJsonResponse(exchange, response);
                                return;
                            }
                            if (!"admin".equals(role) && !"superadmin".equals(role)) {
                                response.put("success", false);
                                response.put("error", "Ruolo non valido");
                                sendJsonResponse(exchange, response);
                                return;
                            }

                            if (Main.mailDatabase.createAdmin(username, password, role)) {
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile creare admin");
                            }
                        }
                        case "update_role" -> {
                            int adminId = req.optInt("admin_id", 0);
                            String role = req.optString("role", "admin");

                            if (Main.mailDatabase.updateAdminRole(adminId, role)) {
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile aggiornare ruolo");
                            }
                        }
                        case "delete" -> {
                            int adminId = req.optInt("admin_id", 0);

                            if (adminId == currentAdminId) {
                                response.put("success", false);
                                response.put("error", "Non puoi eliminare te stesso");
                            } else if (Main.mailDatabase.deleteAdmin(adminId)) {
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile eliminare admin");
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== AUTO-RESPONDER API ==============

    private void handleApiAutoResponder(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String mailboxIdStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "mailbox_id");
                    if (mailboxIdStr != null) {
                        int mailboxId = Integer.parseInt(mailboxIdStr);
                        MailDatabase.AutoResponder ar = Main.mailDatabase.getAutoResponder(mailboxId);

                        response.put("success", true);
                        if (ar != null) {
                            response.put("enabled", ar.enabled);
                            response.put("subject", ar.subject);
                            response.put("body", ar.body);
                            response.put("start_date", ar.startDate != null ? ar.startDate.toString() : "");
                            response.put("end_date", ar.endDate != null ? ar.endDate.toString() : "");
                            response.put("interval_hours", ar.intervalHours);
                        } else {
                            response.put("enabled", false);
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "mailbox_id richiesto");
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "save");

                    if ("reset_tracking".equals(action)) {
                        // Reset vacation tracking files
                        int mailboxId = req.optInt("mailbox_id", 0);
                        MailDatabase.Mailbox mailbox = Main.mailDatabase.getMailboxById(mailboxId);
                        if (mailbox != null) {
                            String[] parts = mailbox.email.split("@");
                            if (parts.length == 2) {
                                String user = parts[0];
                                String domain = parts[1];
                                // Delete vacation tracking files
                                try {
                                    java.nio.file.Path vmailDupes = java.nio.file.Path.of("/var/vmail", domain, user, ".dovecot.lda-dupes");
                                    java.nio.file.Path sieveDb = java.nio.file.Path.of("/var/mail/sieve", domain, user, ".dovecot.sieve.db");
                                    java.nio.file.Files.deleteIfExists(vmailDupes);
                                    java.nio.file.Files.deleteIfExists(sieveDb);
                                    // Also delete any .svbin compiled file to force recompile
                                    java.nio.file.Path svbin = java.nio.file.Path.of("/var/mail/sieve", domain, user, ".dovecot.svbin");
                                    java.nio.file.Files.deleteIfExists(svbin);
                                    // Restart Dovecot to clear in-memory vacation cache
                                    // TODO: migrate to Shell.run when touched
                                    ProcessBuilder pb = new ProcessBuilder("service", "dovecot", "restart");
                                    org.mail_panel.util.Shell.applicaPath(pb);
                                    pb.redirectErrorStream(true);
                                    Process p = pb.start();
                                    p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                                    response.put("success", true);
                                } catch (Exception e) {
                                    response.put("success", false);
                                    response.put("error", "Errore: " + e.getMessage());
                                }
                            } else {
                                response.put("success", false);
                                response.put("error", "Email non valida");
                            }
                        } else {
                            response.put("success", false);
                            response.put("error", "Mailbox non trovata");
                        }
                    } else {
                        // Save auto-responder
                        int mailboxId = req.optInt("mailbox_id", 0);
                        boolean enabled = req.optBoolean("enabled", false);
                        String subject = req.optString("subject", "Out of Office");
                        String bodyText = req.optString("body", "");
                        String startDateStr = req.optString("start_date", "");
                        String endDateStr = req.optString("end_date", "");
                        int intervalHours = req.optInt("interval_hours", 24);

                        java.sql.Date startDate = startDateStr.isEmpty() ? null : java.sql.Date.valueOf(startDateStr);
                        java.sql.Date endDate = endDateStr.isEmpty() ? null : java.sql.Date.valueOf(endDateStr);

                        if (Main.mailDatabase.saveAutoResponder(mailboxId, enabled, subject, bodyText, startDate, endDate, intervalHours)) {
                            // Regenerate Sieve script
                            MailDatabase.Mailbox mailbox = Main.mailDatabase.getMailboxById(mailboxId);
                            if (mailbox != null && sieveGenerator != null) {
                                String sieveScript = sieveGenerator.generateSieveScript(mailboxId, Main.mailDatabase);
                                sieveGenerator.saveSieveScript(mailbox.email, sieveScript);
                            }
                            response.put("success", true);
                        } else {
                            response.put("success", false);
                            response.put("error", "Impossibile salvare auto-responder");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== SIEVE FILTERS API ==============

    private void handleApiSieve(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String mailboxIdStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "mailbox_id");
                    if (mailboxIdStr != null) {
                        int mailboxId = Integer.parseInt(mailboxIdStr);
                        JSONArray filters = new JSONArray();
                        for (MailDatabase.SieveFilter f : Main.mailDatabase.getSieveFilters(mailboxId)) {
                            JSONObject filter = new JSONObject();
                            filter.put("id", f.id);
                            filter.put("name", f.name);
                            filter.put("priority", f.priority);
                            filter.put("enabled", f.enabled);
                            filter.put("conditions", new JSONArray(f.conditions));
                            filter.put("actions", new JSONArray(f.actions));
                            filters.put(filter);
                        }
                        response.put("success", true);
                        response.put("filters", filters);
                    } else {
                        response.put("success", false);
                        response.put("error", "mailbox_id richiesto");
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "create");

                    switch (action) {
                        case "create" -> {
                            int mailboxId = req.optInt("mailbox_id", 0);
                            String name = req.optString("name", "");
                            int priority = req.optInt("priority", 0);
                            String conditions = req.optJSONArray("conditions").toString();
                            String actions = req.optJSONArray("actions").toString();

                            if (Main.mailDatabase.createSieveFilter(mailboxId, name, priority, conditions, actions)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile creare filtro");
                            }
                        }
                        case "update" -> {
                            int filterId = req.optInt("filter_id", 0);
                            int mailboxId = req.optInt("mailbox_id", 0);
                            String name = req.optString("name", "");
                            int priority = req.optInt("priority", 0);
                            boolean enabled = req.optBoolean("enabled", true);
                            String conditions = req.optJSONArray("conditions").toString();
                            String actions = req.optJSONArray("actions").toString();

                            if (Main.mailDatabase.updateSieveFilter(filterId, name, priority, enabled, conditions, actions)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile aggiornare filtro");
                            }
                        }
                        case "delete" -> {
                            int filterId = req.optInt("filter_id", 0);
                            int mailboxId = req.optInt("mailbox_id", 0);

                            if (Main.mailDatabase.deleteSieveFilter(filterId)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile eliminare filtro");
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    private void regenerateSieveScript(int mailboxId) {
        if (sieveGenerator != null) {
            MailDatabase.Mailbox mailbox = Main.mailDatabase.getMailboxById(mailboxId);
            if (mailbox != null) {
                String sieveScript = sieveGenerator.generateSieveScript(mailboxId, Main.mailDatabase);
                sieveGenerator.saveSieveScript(mailbox.email, sieveScript);
            }
        }
    }

    // ============== FORWARDING API ==============

    private void handleApiForwarding(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String mailboxIdStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "mailbox_id");
                    if (mailboxIdStr != null) {
                        int mailboxId = Integer.parseInt(mailboxIdStr);
                        JSONArray rules = new JSONArray();
                        for (MailDatabase.ForwardingRule r : Main.mailDatabase.getForwardingRules(mailboxId)) {
                            JSONObject rule = new JSONObject();
                            rule.put("id", r.id);
                            rule.put("destination", r.destination);
                            rule.put("keep_copy", r.keepCopy);
                            rule.put("enabled", r.enabled);
                            rules.put(rule);
                        }
                        response.put("success", true);
                        response.put("rules", rules);
                    } else {
                        response.put("success", false);
                        response.put("error", "mailbox_id richiesto");
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "create");

                    int mailboxId = req.optInt("mailbox_id", 0);

                    switch (action) {
                        case "create" -> {
                            String destination = req.optString("destination", "");
                            boolean keepCopy = req.optBoolean("keep_copy", true);

                            if (Main.mailDatabase.createForwardingRule(mailboxId, destination, keepCopy)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile creare regola");
                            }
                        }
                        case "update" -> {
                            int ruleId = req.optInt("rule_id", 0);
                            String destination = req.optString("destination", "");
                            boolean keepCopy = req.optBoolean("keep_copy", true);
                            boolean enabled = req.optBoolean("enabled", true);

                            if (Main.mailDatabase.updateForwardingRule(ruleId, destination, keepCopy, enabled)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile aggiornare regola");
                            }
                        }
                        case "delete" -> {
                            int ruleId = req.optInt("rule_id", 0);

                            if (Main.mailDatabase.deleteForwardingRule(ruleId)) {
                                regenerateSieveScript(mailboxId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile eliminare regola");
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== RATE LIMITS API ==============

    private void handleApiRateLimits(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    // La pagina leggeva "limits.hourly" da quello che era un ARRAY, e i campi
                    // delle righe con nomi che il server non ha mai prodotto: la tabella
                    // mostrava "undefined" e il modulo si riempiva di valori predefiniti.
                    // Qui la risposta prende la forma che la pagina legge davvero.
                    JSONArray limits = new JSONArray();
                    JSONObject globale = null;
                    for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits()) {
                        if ("global".equalsIgnoreCase(rl.targetType)) {
                            globale = new JSONObject()
                                    .put("hourly", rl.maxPerHour)
                                    .put("daily", rl.maxPerDay)
                                    .put("max_recipients", rl.maxRecipients);
                            continue;
                        }
                        limits.put(new JSONObject()
                                .put("id", rl.id)
                                .put("email", rl.targetName == null ? "" : rl.targetName)
                                .put("target_id", rl.targetId)
                                .put("hourly_limit", rl.maxPerHour)
                                .put("daily_limit", rl.maxPerDay)
                                .put("max_recipients", rl.maxRecipients)
                                .put("enabled", rl.enabled));
                    }
                    if (globale == null)
                        globale = new JSONObject().put("hourly", 50).put("daily", 500)
                                                 .put("max_recipients", 50).put("nonImpostato", true);
                    // La dimensione massima non sta nel database: e' un parametro di Postfix,
                    // e si legge da li' invece di tenerne una copia che diverge.
                    int mb = org.mail_panel.system.LimiteDimensione.leggiMega();
                    globale.put("max_size_mb", mb < 0 ? JSONObject.NULL : mb);
                    if (mb < 0) globale.put("max_size_nota", "non riesco a leggere message_size_limit da Postfix");

                    response.put("success", true);
                    response.put("limits", limits);
                    response.put("globale", globale);
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "save");

                    switch (action) {
                        case "save" -> {
                            String targetType = req.optString("target_type", "global");
                            Integer targetId = req.has("target_id") ? req.optInt("target_id") : null;
                            int maxPerHour = req.optInt("max_per_hour", 100);
                            int maxPerDay = req.optInt("max_per_day", 1000);
                            int maxRecipients = req.optInt("max_recipients", 50);
                            boolean enabled = req.optBoolean("enabled", true);

                            if (Main.mailDatabase.saveRateLimit(targetType, targetId, maxPerHour, maxPerDay, maxRecipients, enabled)) {
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile salvare limite");
                            }
                        }
                        case "save_global" -> {
                            int hourly = req.optInt("hourly", 0);
                            int daily = req.optInt("daily", 0);
                            int maxSize = req.optInt("max_size_mb", 0);
                            if (hourly < 1 || daily < 1) {
                                response.put("success", false)
                                        .put("error", "I limiti orario e giornaliero devono essere almeno 1. "
                                                + "Zero non vuol dire \"nessun limite\": vuol dire che non "
                                                + "parte piu' niente.");
                                break;
                            }
                            if (daily < hourly) {
                                response.put("success", false)
                                        .put("error", "Il limite giornaliero (" + daily + ") e' piu' basso di "
                                                + "quello orario (" + hourly + "): quello orario non si "
                                                + "raggiungerebbe mai, e il valore piu' basso vincerebbe "
                                                + "sempre. Probabilmente non e' cio' che vuoi.");
                                break;
                            }
                            // Il conteggio dei destinatari per messaggio non e' in questo modulo:
                            // si conserva quello gia' salvato invece di azzerarlo di nascosto.
                            int destinatari = 50;
                            for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits())
                                if ("global".equalsIgnoreCase(rl.targetType)) destinatari = rl.maxRecipients;

                            boolean okDb = Main.mailDatabase.saveRateLimit("global", null, hourly, daily,
                                    destinatari, true);
                            response.put("success", okDb);
                            if (!okDb) {
                                response.put("error", "Impossibile salvare i limiti globali nel database.");
                                break;
                            }
                            StringBuilder nota = new StringBuilder("Limiti globali salvati: " + hourly
                                    + " all'ora, " + daily + " al giorno.");
                            if (maxSize > 0) {
                                JSONObject dim = org.mail_panel.system.LimiteDimensione.imposta(maxSize);
                                response.put("dimensione", dim);
                                if (dim.optBoolean("success", false)) {
                                    nota.append(" ").append(dim.optString("nota", ""));
                                } else {
                                    // I limiti sono salvati, la dimensione no: si dice esattamente
                                    // questo, invece di un "errore" generico che farebbe credere
                                    // che non sia stato salvato niente.
                                    response.put("success", false)
                                            .put("error", nota + " La dimensione massima invece NON e' stata "
                                                    + "cambiata: " + dim.optString("error", "errore sconosciuto"));
                                    break;
                                }
                            }
                            response.put("message", nota.toString());
                            logAudit("RATELIMIT_GLOBAL", getClientIp(exchange), nota.toString());
                        }
                        case "delete" -> {
                            int limitId = req.optInt("limit_id", 0);

                            if (Main.mailDatabase.deleteRateLimit(limitId)) {
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Impossibile eliminare limite");
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== RSPAMD TRAINING API ==============

    private void handleApiRspamd(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            switch (method) {
                case "GET" -> {
                    String action = extractParamFromQuery(exchange.getRequestURI().getQuery(), "action");

                    if ("stats".equals(action)) {
                        RspamdManager.RspamdStats stats = rspamdManager.getStatistics();
                        if (stats != null) {
                            response.put("success", true);
                            response.put("scanned", stats.scanned);
                            response.put("learned", stats.learned);
                            response.put("spam_count", stats.spamCount);
                            response.put("ham_count", stats.hamCount);
                            response.put("spam_percent", stats.spamPercent);
                            response.put("uptime", stats.uptime);
                            response.put("version", stats.version);
                        } else {
                            response.put("success", false);
                            response.put("error", "Rspamd non raggiungibile");
                        }
                    } else if ("quarantine".equals(action)) {
                        JSONArray messages = new JSONArray();
                        for (RspamdManager.QuarantinedMessage msg : rspamdManager.getQuarantinedMessages(100)) {
                            JSONObject m = new JSONObject();
                            m.put("id", msg.id);
                            m.put("from", msg.from);
                            m.put("to", msg.to);
                            m.put("subject", msg.subject);
                            m.put("score", msg.score);
                            m.put("timestamp", msg.timestamp);
                            messages.put(m);
                        }
                        response.put("success", true);
                        response.put("messages", messages);
                    } else {
                        response.put("success", true);
                        response.put("running", rspamdManager.isRunning());
                    }
                }
                case "POST" -> {
                    String body = readRequestBodyWithLimit(exchange);
        if (body == null) {
            sendJsonError(exchange, 413, "Richiesta troppo grande");
            return;
        }
                    JSONObject req = new JSONObject(body);
                    String action = req.optString("action", "");

                    int adminId = getSessionAdminId(exchange);

                    switch (action) {
                        case "train_spam" -> {
                            String content = req.optString("content", "");
                            RspamdManager.TrainingResult result = rspamdManager.trainSpam(content);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.success) {
                                Main.mailDatabase.logRspamdTraining("manual", "spam", adminId);
                            }
                        }
                        case "train_ham" -> {
                            String content = req.optString("content", "");
                            RspamdManager.TrainingResult result = rspamdManager.trainHam(content);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.success) {
                                Main.mailDatabase.logRspamdTraining("manual", "ham", adminId);
                            }
                        }
                        case "release" -> {
                            String messageId = req.optString("message_id", "");
                            boolean released = rspamdManager.releaseFromQuarantine(messageId);
                            response.put("success", released);
                        }
                        case "delete_quarantine" -> {
                            String messageId = req.optString("message_id", "");
                            boolean deleted = rspamdManager.deleteFromQuarantine(messageId);
                            response.put("success", deleted);
                        }
                        case "scan" -> {
                            String content = req.optString("content", "");
                            RspamdManager.ScanResult result = rspamdManager.scanMessage(content);
                            if (result != null) {
                                response.put("success", true);
                                response.put("is_spam", result.isSpam);
                                response.put("score", result.score);
                                response.put("required_score", result.requiredScore);
                                response.put("action", result.action);
                                response.put("symbols", new JSONArray(result.symbols));
                            } else {
                                response.put("success", false);
                                response.put("error", "Scansione fallita");
                            }
                        }
                        default -> {
                            response.put("success", false);
                            response.put("error", "Azione sconosciuta");
                        }
                    }
                }
                default -> {
                    sendJsonError(exchange, 405, "Method not allowed");
                    return;
                }
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== EMAIL STATISTICS API ==============

    private void handleApiStatistics(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                String daysStr = extractParamFromQuery(exchange.getRequestURI().getQuery(), "days");
                int days = daysStr != null ? Integer.parseInt(daysStr) : 30;

                // Get statistics
                JSONArray stats = new JSONArray();
                for (MailDatabase.EmailStat stat : Main.mailDatabase.getEmailStatistics(days)) {
                    JSONObject s = new JSONObject();
                    s.put("date", stat.statDate != null ? stat.statDate.toString() : "");
                    s.put("name", stat.name);
                    s.put("sent", stat.sentCount);
                    s.put("received", stat.receivedCount);
                    s.put("spam", stat.spamCount);
                    s.put("virus", stat.virusCount);
                    s.put("bounced", stat.bouncedCount);
                    s.put("bytes_sent", stat.bytesSent);
                    s.put("bytes_received", stat.bytesReceived);
                    stats.put(s);
                }

                // Get today's summary
                MailDatabase.EmailStat today = Main.mailDatabase.getTodayStats();
                JSONObject todaySummary = new JSONObject();
                if (today != null) {
                    todaySummary.put("sent", today.sentCount);
                    todaySummary.put("received", today.receivedCount);
                    todaySummary.put("spam", today.spamCount);
                    todaySummary.put("virus", today.virusCount);
                    todaySummary.put("bounced", today.bouncedCount);
                }

                // Training stats
                int spamTrained = Main.mailDatabase.getTrainingCount("spam", days);
                int hamTrained = Main.mailDatabase.getTrainingCount("ham", days);

                response.put("success", true);
                response.put("statistics", stats);
                response.put("today", todaySummary);
                response.put("spam_trained", spamTrained);
                response.put("ham_trained", hamTrained);
            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== THEME API ==============

    private void handleApiTheme(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            String username = getSessionUsername(exchange);
            if (username == null || username.isEmpty()) {
                response.put("success", false);
                response.put("error", "Utente non trovato");
                sendJsonResponse(exchange, response);
                return;
            }

            if ("GET".equals(method)) {
                // Get current theme preference
                String theme = Main.mailDatabase.getAdminTheme(username);
                response.put("success", true);
                response.put("theme", theme);
            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, "Richiesta troppo grande");
                    return;
                }
                JSONObject req = new JSONObject(body);

                String theme = req.optString("theme", "auto");
                boolean saved = Main.mailDatabase.setAdminTheme(username, theme);

                response.put("success", saved);
                if (saved) {
                    response.put("theme", theme);
                    response.put("message", "Tema salvato");
                } else {
                    response.put("error", "Errore salvataggio tema");
                }
            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    // ============== HOSTNAME CHANGE API ==============

    /**
     * API endpoint for changing the mail server hostname.
     *
     * GET  /api/hostname           - Returns current hostname state and consistency checks
     * POST /api/hostname           - Performs the hostname change with full orchestration
     *
     * The change process:
     *   1. Validate the new hostname format
     *   2. Read the old hostname from both SQLite and MySQL
     *   3. Update SQLite config.mail_hostname
     *   4. Update MySQL panel_settings.mail_hostname
     *   5. Update Postfix main.cf (myhostname, mydomain)
     *   6. Clean stale SSL/DNS settings in MySQL
     *   7. Reload Postfix, Dovecot, Nginx
     *   8. Return a checklist of what was done and what the user must do manually (DNS, SSL cert)
     */
    private void handleApiHostname(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Return current hostname state and consistency info
                String sqliteHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                if (sqliteHostname == null) sqliteHostname = "";

                String mysqlHostname = "";
                if (Main.mailDatabase != null && Main.mysqlAvailable) {
                    mysqlHostname = Main.mailDatabase.getSetting("mail_hostname", "");
                }

                // Read Postfix myhostname from main.cf
                String postfixHostname = readPostfixHostname();

                // Read current SSL certificate CN
                String sslHostname = "";
                if (Main.mailDatabase != null && Main.mysqlAvailable) {
                    sslHostname = Main.mailDatabase.getSetting("ssl_hostname", "");
                }

                // Detect server IP
                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";

                // Consistency check
                boolean allConsistent = !sqliteHostname.isEmpty()
                        && sqliteHostname.equals(mysqlHostname)
                        && (postfixHostname.isEmpty() || sqliteHostname.equals(postfixHostname));

                response.put("success", true);
                response.put("sqlite_hostname", sqliteHostname);
                response.put("mysql_hostname", mysqlHostname);
                response.put("postfix_hostname", postfixHostname);
                response.put("ssl_hostname", sslHostname);
                response.put("server_ip", serverIp);
                response.put("consistent", allConsistent);

                // Current SSL cert info
                if (acmeManager != null) {
                    AcmeManager.CertificateInfo certInfo = acmeManager.getCertificateInfo();
                    if (certInfo != null && certInfo.installed) {
                        response.put("ssl_cn", certInfo.commonName);
                        response.put("ssl_self_signed", acmeManager.isSelfSigned());
                        response.put("ssl_days_until_expiry", certInfo.daysUntilExpiry);
                    }
                }

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, "Richiesta troppo grande");
                    return;
                }
                JSONObject req = new JSONObject(body);

                // Validate CSRF token
                if (!validateCsrfForRequest(exchange, req)) {
                    sendCsrfError(exchange);
                    return;
                }

                String action = req.optString("action", "");

                if ("change".equals(action)) {
                    // Full hostname change orchestration
                    String newHostname = req.optString("hostname", "").trim().toLowerCase();

                    // Validate hostname format
                    if (newHostname.isEmpty() || !newHostname.contains(".") || newHostname.length() > 253) {
                        response.put("success", false);
                        response.put("error", "Hostname non valido. Deve essere un FQDN (es: mail.esempio.it)");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    // Must match domain pattern (allow subdomain.domain.tld)
                    if (!newHostname.matches("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")) {
                        response.put("success", false);
                        response.put("error", "Hostname contiene caratteri non validi");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Get old hostname
                    String oldHostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                    if (oldHostname == null) oldHostname = "";

                    JSONArray steps = new JSONArray();

                    // Step 1: Update SQLite
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        sqliteOk = Main.dbManager.setMailHostname(newHostname);
                    }
                    steps.put(new JSONObject()
                            .put("step", "SQLite config.mail_hostname")
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? oldHostname + " -> " + newHostname : "Errore aggiornamento SQLite"));

                    // Step 2: Update MySQL
                    boolean mysqlOk = false;
                    if (Main.mailDatabase != null && Main.mysqlAvailable) {
                        try {
                            Main.mailDatabase.setSetting("mail_hostname", newHostname);
                            mysqlOk = true;
                        } catch (Exception e) {
                            // setSetting does not throw, but handle just in case
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", "MySQL panel_settings.mail_hostname")
                            .put("success", mysqlOk)
                            .put("detail", mysqlOk ? oldHostname + " -> " + newHostname : "Errore aggiornamento MySQL"));

                    // Step 3: Update Postfix main.cf
                    boolean postfixOk = updatePostfixHostname(newHostname);
                    steps.put(new JSONObject()
                            .put("step", "Postfix main.cf (myhostname)")
                            .put("success", postfixOk)
                            .put("detail", postfixOk ? "myhostname aggiornato a " + newHostname : "File non trovato o errore scrittura"));

                    // Step 4: Clean stale MySQL settings
                    boolean cleanOk = false;
                    if (Main.mailDatabase != null && Main.mysqlAvailable) {
                        try {
                            Main.mailDatabase.deleteSetting("ssl_hostname");
                            Main.mailDatabase.deleteSetting("ssl_domain");
                            Main.mailDatabase.deleteSetting("dns_challenge_hostname");
                            cleanOk = true;
                        } catch (Exception e) {
                            // best effort
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", "Pulizia metadati SSL/DNS obsoleti")
                            .put("success", cleanOk)
                            .put("detail", cleanOk ? "ssl_hostname, ssl_domain, dns_challenge_hostname rimossi" : "Errore pulizia"));

                    // Step 5: Reload services
                    boolean postfixReload = executeServiceCommand("postfix", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Postfix")
                            .put("success", postfixReload)
                            .put("detail", postfixReload ? "Postfix ricaricato" : "Postfix non in esecuzione o errore reload"));

                    boolean dovecotReload = executeServiceCommand("dovecot", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Dovecot")
                            .put("success", dovecotReload)
                            .put("detail", dovecotReload ? "Dovecot ricaricato" : "Dovecot non in esecuzione o errore reload"));

                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? "Nginx ricaricato" : "Nginx non in esecuzione o errore reload"));

                    // Determine overall success (core steps must succeed)
                    boolean overallSuccess = sqliteOk && mysqlOk;

                    // Build manual actions needed
                    String domain = newHostname.contains(".") ? newHostname.substring(newHostname.indexOf('.') + 1) : newHostname;
                    JSONArray manualActions = new JSONArray();

                    manualActions.put(new JSONObject()
                            .put("action", "Aggiorna record DNS A")
                            .put("detail", "Record A per '" + newHostname + "' deve puntare all'IP del server")
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", "Aggiorna record DNS MX")
                            .put("detail", "Record MX per '" + domain + "' deve puntare a '" + newHostname + "'")
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", "Aggiorna record PTR (Reverse DNS)")
                            .put("detail", "Contatta il provider hosting per aggiornare il PTR all'IP del server con '" + newHostname + "'")
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", "Aggiorna il CNAME autoconfig")
                            .put("detail", "autoconfig." + domain + " deve puntare a '" + newHostname + "'")
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", "Emetti nuovo certificato SSL")
                            .put("detail", "Vai nella sezione SSL del pannello e genera un nuovo certificato per '" + newHostname + "'. Il vecchio certificato"
                                    + (!oldHostname.isEmpty() ? " (per '" + oldHostname + "')" : "") + " non sara' valido per il nuovo hostname.")
                            .put("type", "ssl"));
                    manualActions.put(new JSONObject()
                            .put("action", "Verifica record DNS")
                            .put("detail", "Dopo aver aggiornato i DNS, vai nella sezione DNS del pannello e clicca 'Verifica' per controllare che tutto sia corretto")
                            .put("type", "verify"));

                    // Roundcube domain reminder
                    String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    if (rcDomain != null && !rcDomain.isEmpty()) {
                        manualActions.put(new JSONObject()
                                .put("action", "Verifica dominio Roundcube (Webmail)")
                                .put("detail", "Il dominio Roundcube attuale e' '" + rcDomain + "'. "
                                        + "Se vuoi aggiornarlo, vai nelle Impostazioni e modifica il Dominio Roundcube. "
                                        + "Ricorda di aggiornare anche il record DNS A per il nuovo dominio.")
                                .put("type", "roundcube"));
                    }

                    response.put("success", overallSuccess);
                    response.put("steps", steps);
                    response.put("manual_actions", manualActions);
                    response.put("old_hostname", oldHostname);
                    response.put("new_hostname", newHostname);

                    // Audit log
                    logAudit("HOSTNAME_CHANGED", getClientIp(exchange),
                            "Hostname changed: " + oldHostname + " -> " + newHostname);

                } else if ("check_dns".equals(action)) {
                    // Quick DNS consistency check for the current hostname
                    String hostname = req.optString("hostname", "");
                    if (hostname.isEmpty()) {
                        hostname = Main.dbManager != null ? Main.dbManager.getMailHostname() : "";
                    }
                    if (hostname == null || hostname.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Nessun hostname configurato");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    JSONArray checks = new JSONArray();

                    // Check A record
                    String aResult = digRecord(hostname, "A");
                    String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
                    boolean aOk = !aResult.isEmpty() && aResult.contains(serverIp) && !serverIp.isEmpty();
                    checks.put(new JSONObject()
                            .put("type", "A").put("name", hostname)
                            .put("passed", aOk)
                            .put("current", aResult.isEmpty() ? "Non trovato" : aResult)
                            .put("expected", serverIp.isEmpty() ? "IP del server" : serverIp));

                    // Check MX record
                    String domain = hostname.contains(".") ? hostname.substring(hostname.indexOf('.') + 1) : hostname;
                    String mxResult = digRecord(domain, "MX");
                    boolean mxOk = !mxResult.isEmpty() && mxResult.toLowerCase().contains(hostname.toLowerCase());
                    checks.put(new JSONObject()
                            .put("type", "MX").put("name", domain)
                            .put("passed", mxOk)
                            .put("current", mxResult.isEmpty() ? "Non trovato" : mxResult)
                            .put("expected", "10 " + hostname + "."));

                    // Check PTR record
                    String ptrResult = "";
                    if (!serverIp.isEmpty()) {
                        ptrResult = digPtrRecord(serverIp);
                    }
                    boolean ptrOk = !ptrResult.isEmpty() && ptrResult.toLowerCase().contains(hostname.toLowerCase());
                    checks.put(new JSONObject()
                            .put("type", "PTR").put("name", serverIp.isEmpty() ? "IP server" : serverIp)
                            .put("passed", ptrOk)
                            .put("current", ptrResult.isEmpty() ? "Non trovato" : ptrResult)
                            .put("expected", hostname + "."));

                    response.put("success", true);
                    response.put("hostname", hostname);
                    response.put("checks", checks);
                    response.put("all_passed", aOk && mxOk && ptrOk);

                } else {
                    response.put("success", false);
                    response.put("error", "Azione non valida. Usa 'change' o 'check_dns'.");
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * Handle Roundcube domain GET (read) and POST (change)
     */
    private void handleApiRoundcubeDomain(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        String method = exchange.getRequestMethod();
        JSONObject response = new JSONObject();

        try {
            if ("GET".equals(method)) {
                // Return current Roundcube domain + DNS check
                String rcDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                if (rcDomain == null) rcDomain = "";
                String rcPort = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                if (rcPort == null) rcPort = "8443";

                String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";

                // Check DNS for Roundcube domain
                // For webmail, Cloudflare proxy (orange cloud) is perfectly fine
                boolean dnsOk = false;
                boolean dnsProxied = false;
                String dnsResult = "";
                if (!rcDomain.isEmpty()) {
                    dnsResult = digRecord(rcDomain, "A");
                    if (!dnsResult.isEmpty()) {
                        if (!serverIp.isEmpty() && dnsResult.contains(serverIp)) {
                            dnsOk = true;  // Direct IP match
                        } else {
                            // Check if it resolves to known CDN/proxy IPs (Cloudflare etc.)
                            // If it resolves to ANY IP, the domain is configured (might be proxied)
                            dnsProxied = true;
                            dnsOk = true;
                        }
                    }
                }

                // Read actual SSL paths from nginx.conf
                String[] nginxSslPaths = readNginxRoundcubeSslPaths();
                String certPath = nginxSslPaths[0].isEmpty() ? "/usr/local/etc/ssl/mail/fullchain.pem" : nginxSslPaths[0];
                String keyPath = nginxSslPaths[1].isEmpty() ? "/usr/local/etc/ssl/mail/privkey.pem" : nginxSslPaths[1];

                // Read SSL file contents to show in textarea
                String certContent = "";
                String keyContent = "";
                String chainContent = "";
                try {
                    if (Files.exists(Path.of(certPath))) certContent = Files.readString(Path.of(certPath));
                } catch (Exception ignored) {}
                try {
                    if (Files.exists(Path.of(keyPath))) keyContent = Files.readString(Path.of(keyPath));
                } catch (Exception ignored) {}
                // Chain: check if separate chain file exists in same dir
                String rcSslChain = Main.dbManager != null ? Main.dbManager.getRoundcubeSslChain() : "";
                if (rcSslChain != null && !rcSslChain.isEmpty()) {
                    try {
                        if (Files.exists(Path.of(rcSslChain))) chainContent = Files.readString(Path.of(rcSslChain));
                    } catch (Exception ignored) {}
                }

                response.put("success", true);
                response.put("domain", rcDomain);
                response.put("port", rcPort);
                response.put("server_ip", serverIp);
                response.put("dns_result", dnsResult.isEmpty() ? "Non trovato" : dnsResult);
                response.put("dns_ok", dnsOk);
                response.put("dns_proxied", dnsProxied);
                response.put("nginx_ssl_cert", certPath);
                response.put("nginx_ssl_key", keyPath);
                response.put("ssl_cert_content", certContent);
                response.put("ssl_key_content", keyContent);
                response.put("ssl_chain_content", chainContent);

            } else if ("POST".equals(method)) {
                String body = readRequestBodyWithLimit(exchange);
                if (body == null) {
                    sendJsonError(exchange, 413, "Richiesta troppo grande");
                    return;
                }
                JSONObject req = new JSONObject(body);

                // Validate CSRF token
                if (!validateCsrfForRequest(exchange, req)) {
                    sendCsrfError(exchange);
                    return;
                }

                String action = req.optString("action", "");

                if ("change".equals(action)) {
                    String newDomain = req.optString("domain", "").trim().toLowerCase();

                    // Validate domain format
                    if (newDomain.isEmpty() || !newDomain.contains(".") || newDomain.length() > 253) {
                        response.put("success", false);
                        response.put("error", "Dominio non valido. Deve essere un FQDN (es: webmail.esempio.it)");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!newDomain.matches("^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$")) {
                        response.put("success", false);
                        response.put("error", "Dominio contiene caratteri non validi");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    // Get old domain
                    String oldDomain = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    if (oldDomain == null) oldDomain = "";

                    JSONArray steps = new JSONArray();

                    // Read current settings before updating
                    String currentPort = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                    String currentCert = Main.dbManager != null ? Main.dbManager.getRoundcubeSslCert() : "";
                    String currentKey = Main.dbManager != null ? Main.dbManager.getRoundcubeSslKey() : "";
                    String currentChain = Main.dbManager != null ? Main.dbManager.getRoundcubeSslChain() : "";

                    // Step 1: Update SQLite roundcube_domain
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        sqliteOk = Main.dbManager.updateRoundcubeConfig(
                            newDomain,
                            currentPort != null ? currentPort : "8443",
                            currentCert != null ? currentCert : "",
                            currentKey != null ? currentKey : "",
                            currentChain != null ? currentChain : ""
                        );
                    }
                    steps.put(new JSONObject()
                            .put("step", "SQLite config.roundcube_domain")
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? oldDomain + " -> " + newDomain : "Errore aggiornamento SQLite"));

                    // Step 2: Regenerate entire nginx.conf with new domain
                    String rcCert = currentCert != null && !currentCert.isEmpty() ? currentCert : "/usr/local/etc/ssl/mail/fullchain.pem";
                    String rcKey = currentKey != null && !currentKey.isEmpty() ? currentKey : "/usr/local/etc/ssl/mail/privkey.pem";
                    boolean nginxOk = regenerateNginxRoundcubeConfig(newDomain, currentPort, rcCert, rcKey);
                    steps.put(new JSONObject()
                            .put("step", "Nginx nginx.conf rigenerato")
                            .put("success", nginxOk)
                            .put("detail", nginxOk ? "server_name=" + newDomain + ", risponde SOLO a questo dominio" : "Errore scrittura nginx.conf"));

                    // Step 3: Reload Nginx
                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? "Nginx ricaricato" : "Nginx non in esecuzione o errore reload"));

                    // Step 4: Refresh SSO manager URL
                    boolean ssoOk = false;
                    if (ssoManager != null) {
                        try {
                            String rcPort = currentPort != null ? currentPort : "8443";
                            String newUrl = "https://" + newDomain;
                            if (rcPort != null && !rcPort.isEmpty() && !rcPort.equals("443")) {
                                newUrl += ":" + rcPort;
                            }
                            ssoManager.setRoundcubeUrl(newUrl);
                            ssoOk = true;
                        } catch (Exception e) {
                            // best effort
                        }
                    }
                    steps.put(new JSONObject()
                            .put("step", "SSO Manager URL aggiornato")
                            .put("success", ssoOk)
                            .put("detail", ssoOk ? "URL SSO aggiornato per " + newDomain : "Errore aggiornamento SSO"));

                    boolean overallSuccess = sqliteOk;

                    // Manual actions
                    JSONArray manualActions = new JSONArray();
                    manualActions.put(new JSONObject()
                            .put("action", "Configura record DNS A")
                            .put("detail", "Il record A per '" + newDomain + "' deve puntare all'IP del server")
                            .put("type", "dns"));
                    manualActions.put(new JSONObject()
                            .put("action", "Verifica certificato SSL")
                            .put("detail", "Assicurati che il certificato SSL copra anche '" + newDomain + "'. "
                                    + "Se Roundcube usa un certificato separato, rigeneralo per il nuovo dominio.")
                            .put("type", "ssl"));

                    response.put("success", overallSuccess);
                    response.put("steps", steps);
                    response.put("manual_actions", manualActions);
                    response.put("old_domain", oldDomain);
                    response.put("new_domain", newDomain);

                    // Audit log
                    logAudit("ROUNDCUBE_DOMAIN_CHANGED", getClientIp(exchange),
                            "Roundcube domain changed: " + oldDomain + " -> " + newDomain);

                } else if ("update_ssl".equals(action)) {
                    // Receive PEM content, save to disk, update nginx
                    String certContent = req.optString("ssl_cert", "").trim();
                    String keyContent = req.optString("ssl_key", "").trim();
                    String chainContent = req.optString("ssl_chain", "").trim();

                    // Validate PEM format
                    if (!certContent.isEmpty() && !certContent.contains("BEGIN")) {
                        response.put("success", false);
                        response.put("error", "Il certificato deve essere in formato PEM");
                        sendJsonResponse(exchange, response);
                        return;
                    }
                    if (!keyContent.isEmpty() && !keyContent.contains("BEGIN")) {
                        response.put("success", false);
                        response.put("error", "La chiave deve essere in formato PEM");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    JSONArray steps = new JSONArray();

                    // Determine file paths
                    String sslDir = "/usr/local/etc/ssl/roundcube";
                    String certPath, keyPath, chainPath;

                    if (certContent.isEmpty() && keyContent.isEmpty()) {
                        // Use mail server certs
                        certPath = "/usr/local/etc/ssl/mail/fullchain.pem";
                        keyPath = "/usr/local/etc/ssl/mail/privkey.pem";
                        chainPath = "";
                        steps.put(new JSONObject()
                                .put("step", "Usa certificati del mail server")
                                .put("success", true)
                                .put("detail", "fullchain.pem e privkey.pem da /usr/local/etc/ssl/mail/"));
                    } else {
                        // Save PEM content to /usr/local/etc/ssl/roundcube/
                        certPath = sslDir + "/fullchain.pem";
                        keyPath = sslDir + "/privkey.pem";
                        chainPath = chainContent.isEmpty() ? "" : sslDir + "/chain.pem";

                        try {
                            Files.createDirectories(Path.of(sslDir));

                            // If chain provided, concatenate cert + chain into fullchain.pem
                            // This is how fullchain works: cert first, then intermediate CA(s)
                            String fullchainContent = certContent;
                            if (!chainContent.isEmpty()) {
                                fullchainContent = certContent + "\n" + chainContent;
                                // Also save chain separately for reference
                                Files.writeString(Path.of(chainPath), chainContent);
                            }

                            Files.writeString(Path.of(certPath), fullchainContent);
                            Files.writeString(Path.of(keyPath), keyContent);

                            // Secure permissions
                            // TODO: migrate to Shell.run when touched
                            new ProcessBuilder("chmod", "600", keyPath).start().waitFor();
                            // TODO: migrate to Shell.run when touched
                            new ProcessBuilder("chmod", "644", certPath).start().waitFor();

                            String detail = "Salvati in " + sslDir + "/";
                            if (!chainContent.isEmpty()) {
                                detail += " (chain inclusa nel fullchain.pem)";
                            }

                            steps.put(new JSONObject()
                                    .put("step", "Certificati salvati su disco")
                                    .put("success", true)
                                    .put("detail", detail));
                        } catch (Exception e) {
                            steps.put(new JSONObject()
                                    .put("step", "Salvataggio certificati su disco")
                                    .put("success", false)
                                    .put("detail", "Errore: " + e.getMessage()));
                            response.put("success", false);
                            response.put("steps", steps);
                            sendJsonResponse(exchange, response);
                            return;
                        }
                    }

                    // Step 2: Update SQLite (preserve domain and port, update SSL paths)
                    boolean sqliteOk = false;
                    if (Main.dbManager != null) {
                        String currentDomain = Main.dbManager.getRoundcubeDomain();
                        String currentPort = Main.dbManager.getRoundcubePort();
                        sqliteOk = Main.dbManager.updateRoundcubeConfig(
                            currentDomain != null ? currentDomain : "",
                            currentPort != null ? currentPort : "8443",
                            certPath, keyPath, chainPath
                        );
                    }
                    steps.put(new JSONObject()
                            .put("step", "SQLite aggiornato")
                            .put("success", sqliteOk)
                            .put("detail", sqliteOk ? "Percorsi SSL salvati nel database" : "Errore aggiornamento SQLite"));

                    // Step 3: Regenerate nginx.conf
                    String currentDomainForSsl = Main.dbManager != null ? Main.dbManager.getRoundcubeDomain() : "";
                    String currentPortForSsl = Main.dbManager != null ? Main.dbManager.getRoundcubePort() : "8443";
                    boolean nginxOk = regenerateNginxRoundcubeConfig(
                        currentDomainForSsl != null ? currentDomainForSsl : "",
                        currentPortForSsl != null ? currentPortForSsl : "8443",
                        certPath, keyPath
                    );
                    steps.put(new JSONObject()
                            .put("step", "Nginx rigenerato")
                            .put("success", nginxOk)
                            .put("detail", nginxOk ? "nginx.conf aggiornato con i nuovi certificati" : "Errore scrittura nginx.conf"));

                    // Step 4: Reload Nginx
                    boolean nginxReload = executeServiceCommand("nginx", "reload");
                    steps.put(new JSONObject()
                            .put("step", "Reload Nginx")
                            .put("success", nginxReload)
                            .put("detail", nginxReload ? "Nginx ricaricato" : "Nginx non in esecuzione o errore reload"));

                    response.put("success", sqliteOk && nginxOk);
                    response.put("steps", steps);

                    logAudit("ROUNDCUBE_SSL_UPDATED", getClientIp(exchange),
                            "Roundcube SSL updated: cert=" + certPath + " key=" + keyPath);

                } else if ("check_dns".equals(action)) {
                    String domain = req.optString("domain", "");
                    if (domain.isEmpty() && Main.dbManager != null) {
                        domain = Main.dbManager.getRoundcubeDomain();
                    }
                    if (domain == null || domain.isEmpty()) {
                        response.put("success", false);
                        response.put("error", "Nessun dominio Roundcube configurato");
                        sendJsonResponse(exchange, response);
                        return;
                    }

                    String serverIp = dnsGenerator != null ? dnsGenerator.detectServerIp() : "";
                    String aResult = digRecord(domain, "A");
                    boolean aOk = false;
                    boolean aProxied = false;
                    if (!aResult.isEmpty()) {
                        if (!serverIp.isEmpty() && aResult.contains(serverIp)) {
                            aOk = true;
                        } else {
                            // Resolves to different IP = likely CDN/proxy, fine for web traffic
                            aProxied = true;
                            aOk = true;
                        }
                    }

                    response.put("success", true);
                    response.put("domain", domain);
                    response.put("server_ip", serverIp);
                    response.put("a_record", aResult.isEmpty() ? "Non trovato" : aResult);
                    response.put("a_ok", aOk);
                    response.put("a_proxied", aProxied);

                } else {
                    response.put("success", false);
                    response.put("error", "Azione non valida. Usa 'change' o 'check_dns'.");
                }

            } else {
                sendJsonError(exchange, 405, "Method not allowed");
                return;
            }
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
        }

        sendJsonResponse(exchange, response);
    }

    /**
     * Read current ssl_certificate and ssl_certificate_key from Nginx config.
     * Checks sites-enabled/roundcube.conf first (RoundcubeScript), then nginx.conf (FullMailServerScript).
     */
    private String[] readNginxRoundcubeSslPaths() {
        String[] result = {"", ""};
        Path nginxConf = Path.of("/usr/local/etc/nginx/sites-enabled/roundcube.conf");
        if (!Files.exists(nginxConf)) {
            nginxConf = Path.of("/usr/local/etc/nginx/nginx.conf");
        }
        if (!Files.exists(nginxConf)) return result;

        try {
            List<String> lines = Files.readAllLines(nginxConf);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("ssl_certificate ") && !trimmed.startsWith("ssl_certificate_key")) {
                    result[0] = trimmed.replace("ssl_certificate", "").replace(";", "").trim();
                } else if (trimmed.startsWith("ssl_certificate_key ")) {
                    result[1] = trimmed.replace("ssl_certificate_key", "").replace(";", "").trim();
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Could not read Nginx SSL paths: " + e.getMessage());
        }
        return result;
    }

    /**
     * Regenerate the entire /usr/local/etc/nginx/nginx.conf from current SQLite settings.
     * Produces a config identical to FullMailServerScript but with a default_server block
     * that rejects requests on non-matching hostnames (returns 444 = close connection).
     */
    private boolean regenerateNginxRoundcubeConfig(String domain, String port, String sslCert, String sslKey) {
        try {
            // Defaults
            if (port == null || port.isEmpty()) port = "8443";
            if (sslCert == null || sslCert.isEmpty()) sslCert = "/usr/local/etc/ssl/mail/fullchain.pem";
            if (sslKey == null || sslKey.isEmpty()) sslKey = "/usr/local/etc/ssl/mail/privkey.pem";

            // Dalla 1.7 Roundcube non serve piu' i file dalla radice dell'applicazione ma dalla
            // sottocartella public_html: e' una protezione voluta, e con la radice vecchia la
            // webmail risponde 404 su tutto. La scelta non si fa sul numero di versione ma su
            // cosa c'e' davvero sul disco, cosi' la stessa riga vale prima e dopo il salto.
            String rcRoot = "/usr/local/www/roundcube";
            if (Files.isDirectory(Path.of(rcRoot, "public_html"))) rcRoot = rcRoot + "/public_html";

            String config = """
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 50M;

    # Default server: reject requests on non-matching hostnames
    server {
        listen %s ssl default_server;
        server_name _;

        ssl_certificate %s;
        ssl_certificate_key %s;

        return 444;
    }

    # Roundcube webmail: responds ONLY to the configured domain
    server {
        listen %s ssl;
        server_name %s;
        root %s;
        index index.php;

        ssl_certificate %s;
        ssl_certificate_key %s;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        # Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css: uno script PHP
        # con un percorso attaccato. Un location che chiede .php in fondo all'URI non lo prende,
        # e il foglio di stile torna come pagina HTML: la webmail si apre senza grafica.
        # Configurazione dal wiki ufficiale di Roundcube (pagina Installation). La riga
        location ~ \\.php {
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_split_path_info ^(.+\\.php)(/.+)$;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_pass unix:/var/run/php-fpm.sock;
        }

        location ~ /\\. { deny all; }
    }
}
""".formatted(port, sslCert, sslKey, port, domain, rcRoot, sslCert, sslKey);

            Path nginxConf = Path.of("/usr/local/etc/nginx/nginx.conf");
            Files.writeString(nginxConf, config);
            return true;
        } catch (Exception e) {
            LOGGER.warning("Could not regenerate Nginx roundcube config: " + e.getMessage());
            return false;
        }
    }

    /**
     * Read the current 'myhostname' value from Postfix main.cf
     */
    private String readPostfixHostname() {
        try {
            Path mainCf = Path.of("/usr/local/etc/postfix/main.cf");
            if (!Files.exists(mainCf)) return "";
            List<String> lines = Files.readAllLines(mainCf);
            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("myhostname") && trimmed.contains("=")) {
                    String value = trimmed.substring(trimmed.indexOf('=') + 1).trim();
                    // Remove possible inline comments
                    if (value.contains("#")) {
                        value = value.substring(0, value.indexOf('#')).trim();
                    }
                    return value;
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Could not read Postfix hostname: " + e.getMessage());
        }
        return "";
    }

    /**
     * Update 'myhostname' and 'mydomain' in Postfix main.cf
     */
    private boolean updatePostfixHostname(String newHostname) {
        try {
            Path mainCf = Path.of("/usr/local/etc/postfix/main.cf");
            if (!Files.exists(mainCf)) return false;

            List<String> lines = Files.readAllLines(mainCf);
            List<String> updated = new ArrayList<>();
            boolean foundMyhostname = false;
            boolean foundMydomain = false;

            for (String line : lines) {
                String trimmed = line.trim();
                if (trimmed.startsWith("myhostname") && trimmed.contains("=")) {
                    updated.add("myhostname = " + newHostname);
                    foundMyhostname = true;
                } else if (trimmed.startsWith("mydomain") && trimmed.contains("=") && !trimmed.startsWith("mydestination")) {
                    updated.add("mydomain = " + newHostname);
                    foundMydomain = true;
                } else {
                    updated.add(line);
                }
            }

            // If not found, append them
            if (!foundMyhostname) {
                updated.add("myhostname = " + newHostname);
            }
            if (!foundMydomain) {
                updated.add("mydomain = " + newHostname);
            }

            Files.write(mainCf, updated);
            return true;
        } catch (Exception e) {
            LOGGER.warning("Could not update Postfix hostname: " + e.getMessage());
            return false;
        }
    }

    /**
     * Run dig to resolve a DNS record
     */
    private String digRecord(String name, String type) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name, type);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(" ");
                }
            }
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return output.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Run dig -x to resolve a PTR record
     */
    private String digPtrRecord(String ip) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "-x", ip);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder output = new StringBuilder();
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(" ");
                }
            }
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            return output.toString().trim();
        } catch (Exception e) {
            return "";
        }
    }

    private int getSessionAdminId(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionCode = extractSessionCode(cookie);
        if (sessionCode != null) {
            Session session = Main.sessions.getSession(sessionCode);
            if (session != null) {
                return session.adminId;
            }
        }
        return 0;
    }

    // ============== HELPER FOR QUERY PARAMS ==============

    /**
     * Extract and URL-decode a parameter from query string
     * Prevents URL encoding attacks by properly decoding values
     */
    private String extractParamFromQuery(String query, String param) {
        if (query == null) return null;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(param)) {
                try {
                    // URL decode the value to handle encoded characters
                    return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                } catch (Exception e) {
                    LOGGER.warning("Failed to decode URL parameter: " + param);
                    return null;
                }
            }
        }
        return null;
    }

    // ============== RATE LIMITING ==============

    // Login attempt tracking for rate limiting
    private static final Map<String, LoginAttemptInfo> loginAttempts = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    private static final long ATTEMPT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

    private static class LoginAttemptInfo {
        int attempts;
        long firstAttemptTime;
        long lockoutUntil;

        LoginAttemptInfo() {
            this.attempts = 0;
            this.firstAttemptTime = System.currentTimeMillis();
            this.lockoutUntil = 0;
        }

        boolean isLockedOut() {
            return System.currentTimeMillis() < lockoutUntil;
        }

        long getRemainingLockoutSeconds() {
            return Math.max(0, (lockoutUntil - System.currentTimeMillis()) / 1000);
        }

        void recordFailedAttempt() {
            long now = System.currentTimeMillis();
            // Reset counter if window expired
            if (now - firstAttemptTime > ATTEMPT_WINDOW_MS) {
                attempts = 0;
                firstAttemptTime = now;
            }
            attempts++;
            if (attempts >= MAX_ATTEMPTS) {
                lockoutUntil = now + LOCKOUT_DURATION_MS;
            }
        }

        void reset() {
            attempts = 0;
            lockoutUntil = 0;
            firstAttemptTime = System.currentTimeMillis();
        }

        int getProgressiveDelayMs() {
            // Exponential backoff: 1s, 2s, 4s, 8s, 16s
            return (int) Math.min(16000, Math.pow(2, attempts) * 1000);
        }
    }

    private boolean isLoginRateLimited(String identifier) {
        LoginAttemptInfo info = loginAttempts.get(identifier);
        return info != null && info.isLockedOut();
    }

    private void recordLoginFailure(String identifier) {
        loginAttempts.computeIfAbsent(identifier, k -> new LoginAttemptInfo()).recordFailedAttempt();
    }

    private void resetLoginAttempts(String identifier) {
        LoginAttemptInfo info = loginAttempts.get(identifier);
        if (info != null) {
            info.reset();
        }
    }

    private int getLoginDelay(String identifier) {
        LoginAttemptInfo info = loginAttempts.get(identifier);
        return info != null ? info.getProgressiveDelayMs() : 1000;
    }

    private long getRemainingLockoutTime(String identifier) {
        LoginAttemptInfo info = loginAttempts.get(identifier);
        return info != null ? info.getRemainingLockoutSeconds() : 0;
    }

    // ============== REQUEST SIZE LIMITING ==============

    private static final int MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10 MB max

    /**
     * Read request body with size limit to prevent DoS
     * @return body string or null if too large
     */
    private String readRequestBodyWithLimit(HttpExchange exchange) throws IOException {
        String contentLengthHeader = exchange.getRequestHeaders().getFirst("Content-Length");
        if (contentLengthHeader != null) {
            try {
                long contentLength = Long.parseLong(contentLengthHeader);
                if (contentLength > MAX_REQUEST_SIZE) {
                    return null; // Too large
                }
            } catch (NumberFormatException ignored) {}
        }

        // Read with limit
        InputStream is = exchange.getRequestBody();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[8192];
        int totalRead = 0;
        int bytesRead;
        while ((bytesRead = is.read(data)) != -1) {
            totalRead += bytesRead;
            if (totalRead > MAX_REQUEST_SIZE) {
                return null; // Exceeded limit during read
            }
            buffer.write(data, 0, bytesRead);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    // ============== CSRF VALIDATION ==============

    /**
     * Validate CSRF token for state-changing requests
     * @return true if valid, false if invalid
     */
    private boolean validateCsrfForRequest(HttpExchange exchange, JSONObject request) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionCode = extractSessionCode(cookie);
        if (sessionCode == null) return false;

        String expectedToken = Main.sessions.getCsrfToken(sessionCode);
        String providedToken = request.optString("csrf_token", "");

        return SecurityUtils.validateCsrfToken(expectedToken, providedToken);
    }

    /**
     * Send CSRF error response
     */
    private void sendCsrfError(HttpExchange exchange) throws IOException {
        sendJsonError(exchange, 403, "CSRF token non valido");
        logAudit("CSRF_FAILURE", getClientIp(exchange), "Invalid CSRF token attempt");
    }

    // ============== AUDIT LOGGING ==============

    /**
     * Log an audit event to database AND to a parallel text file
     * for external tooling (Fail2ban, log shippers, ecc.).
     *
     * File path (default): /var/log/mail-panel-auth.log
     * Configurabile via setting "audit_log_file_path" nel DB.
     * Se il file non è scrivibile, l'errore non blocca l'app.
     *
     * Formato di linea (parsabile da Fail2ban con regex semplice):
     *   2026-05-08T12:34:56 [ACTION] ip=1.2.3.4 user=admin details="..."
     */
    private void logAudit(String action, String ipAddress, String details) {
        String username = getSessionUsername();
        // 1) DB
        try {
            if (Main.mailDatabase != null) {
                Main.mailDatabase.logAuditEvent(action, ipAddress, details, username);
            }
        } catch (Exception e) {
            LOGGER.warning("Failed to log audit event to DB: " + e.getMessage());
        }
        // 2) File testuale parallelo per Fail2ban / log shippers
        try {
            writeAuditToFile(action, ipAddress, username, details);
        } catch (Exception e) {
            // Non propagare — il logging non deve mai rompere l'app
        }
    }

    private static volatile String CACHED_AUDIT_LOG_PATH = null;

    private static String getAuditLogPath() {
        if (CACHED_AUDIT_LOG_PATH != null) return CACHED_AUDIT_LOG_PATH;
        String path = "/var/log/mail-panel-auth.log";
        try {
            if (Main.mailDatabase != null) {
                String fromDb = Main.mailDatabase.getSetting("audit_log_file_path", null);
                if (fromDb != null && !fromDb.isEmpty()) path = fromDb;
            }
        } catch (Exception ignored) {}
        CACHED_AUDIT_LOG_PATH = path;
        return path;
    }

    private static void writeAuditToFile(String action, String ip, String username, String details) {
        String path = getAuditLogPath();
        // Sanitizza newline / quote per evitare CRLF injection nei log
        String safeAction = action == null ? "-" : action.replaceAll("[\\r\\n\\t]", " ");
        String safeIp = ip == null ? "-" : ip.replaceAll("[\\r\\n\\t\\s]", "");
        String safeUser = username == null || username.isEmpty() ? "-" : username.replaceAll("[\\r\\n\\t\"]", "_");
        String safeDetails = details == null ? "" : details.replaceAll("[\\r\\n\\t\"]", " ");
        String ts = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String line = ts + " [" + safeAction + "] ip=" + safeIp + " user=" + safeUser + " details=\"" + safeDetails + "\"\n";

        java.nio.file.Path p = java.nio.file.Paths.get(path);
        try {
            // Crea la directory se non esiste (best effort)
            java.nio.file.Path parent = p.getParent();
            if (parent != null && !java.nio.file.Files.exists(parent)) {
                java.nio.file.Files.createDirectories(parent);
            }
            java.nio.file.Files.writeString(
                p,
                line,
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND
            );
        } catch (java.io.IOException e) {
            // Permessi mancanti, disco pieno, ecc. — silenzioso, non bloccare
        }
    }

    private String getClientIp(HttpExchange exchange) {
        // SECURITY: l'IP TCP della connessione è sempre affidabile.
        // Gli header forwarding (CF-Connecting-IP, X-Forwarded-For, X-Real-IP)
        // sono affidabili SOLO se la connessione arriva da un proxy fidato
        // (Cloudflare o reverse proxy locale). Altrimenti un attaccante
        // potrebbe falsificare l'IP nei log e bypassare il rate limit.
        String tcpIp = exchange.getRemoteAddress().getAddress().getHostAddress();

        if (!org.mail_panel.security.TrustedProxy.isTrustedProxy(tcpIp)) {
            // Connessione diretta non da proxy fidato → ignora gli header forwarding
            return tcpIp;
        }

        // Connessione da proxy fidato → ci possiamo fidare degli header
        String cfIp = exchange.getRequestHeaders().getFirst("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isEmpty()) {
            String trimmed = cfIp.trim();
            if (org.mail_panel.security.InputValidator.isValidIp(trimmed)) {
                return trimmed;
            }
        }
        String daXff = ipDaForwardedFor(exchange.getRequestHeaders().getFirst("X-Forwarded-For"));
        if (daXff != null) return daXff;
        String realIp = exchange.getRequestHeaders().getFirst("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            String trimmed = realIp.trim();
            if (org.mail_panel.security.InputValidator.isValidIp(trimmed)) {
                return trimmed;
            }
        }
        // Fallback all'IP TCP se nessun header valido (improbabile passando da CF)
        return tcpIp;
    }

    /**
     * L'indirizzo di chi bussa, letto da X-Forwarded-For DA DESTRA. null se non si ricava.
     *
     * La forma dell'intestazione e' "client, proxy1, proxy2": a sinistra c'e' il client
     * originale, ed e' per questo che prima si prendeva il primo pezzo. Ma quel pezzo e'
     * l'unico che il client puo' SCRIVERSI DA SOLO: chi manda una richiesta con gia' dentro
     * "X-Forwarded-For: 1.2.3.4" se la vede accodare dal proxy, che aggiunge il proprio
     * mittente in coda. Il primo valore e' quindi il piu' facile da falsificare, non il piu'
     * attendibile — e usandolo per il limite dei tentativi bastava cambiarlo a ogni prova per
     * non essere mai bloccati.
     *
     * Si scorre da destra saltando gli indirizzi che sono a loro volta proxy fidati (una
     * catena vera ne ha piu' d'uno) e ci si ferma al primo che non lo e': quello l'ha scritto
     * un proxy di cui ci fidiamo, non chi bussa. Se sono tutti fidati non si inventa niente:
     * si torna null e chi chiama usa l'indirizzo TCP.
     *
     * Sta in un metodo suo per poter essere provato: dentro getClientIp servirebbe un
     * HttpExchange vero, e una logica che nessun test raggiunge e' una logica che nessuno
     * controlla.
     */
    static String ipDaForwardedFor(String intestazione) {
        if (intestazione == null || intestazione.isEmpty()) return null;
        String[] pezzi = intestazione.split(",");
        for (int i = pezzi.length - 1; i >= 0; i--) {
            String cand = pezzi[i].trim();
            if (!org.mail_panel.security.InputValidator.isValidIp(cand)) continue;
            if (org.mail_panel.security.TrustedProxy.isTrustedProxy(cand)) continue;
            return cand;
        }
        return null;
    }

    private String getSessionUsername() {
        // This is a simplified version - ideally pass exchange as parameter
        return "system";
    }

    private String getSessionUsername(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        String sessionCode = extractSessionCode(cookie);
        if (sessionCode != null) {
            Session session = Main.sessions.getSession(sessionCode);
            if (session != null && session.username != null) {
                return session.username;
            }
        }
        return "anonymous";
    }
}
