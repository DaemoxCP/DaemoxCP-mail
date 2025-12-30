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
import org.mail_panel.security.DnsRecordsGenerator;
import org.mail_panel.security.Fail2banManager;
import org.mail_panel.security.PasskeyManager;
import org.mail_panel.security.TotpManager;

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
    private RspamdManager rspamdManager;
    private SieveGenerator sieveGenerator;
    private DnsRecordsGenerator dnsGenerator;
    private AcmeManager acmeManager;
    private LogManager logManager;
    private MailQueueManager queueManager;
    private RoundcubeSsoManager ssoManager;
    private Fail2banManager fail2banManager;
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
    }

    private void initializeManagers() {
        if (Main.mailDatabase != null && Main.mysqlAvailable) {
            this.dkimManager = new DkimManager(Main.mailDatabase);
            this.dnsGenerator = new DnsRecordsGenerator(Main.mailDatabase);
            this.acmeManager = new AcmeManager(Main.mailDatabase);
            this.logManager = new LogManager();
            this.queueManager = new MailQueueManager();
            this.ssoManager = new RoundcubeSsoManager(Main.mailDatabase);
            this.fail2banManager = new Fail2banManager();
            this.rspamdManager = new RspamdManager();
            this.sieveGenerator = new SieveGenerator();

            // Initialize PasskeyManager for WebAuthn
            initializePasskeyManager();

            // Start auto-renewal for certificates
            acmeManager.startAutoRenewal();

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

            // Ensure theme column exists in panel_admin (for upgrades)
            Main.mailDatabase.ensureThemeColumn();

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

            // Extract the base domain for RP ID (e.g., "server.example.com" -> "example.com")
            String rpId = panelHost;
            String[] parts = panelHost.split("\\.");
            if (parts.length >= 2) {
                // Use the last two parts as RP ID (e.g., example.com)
                rpId = parts[parts.length - 2] + "." + parts[parts.length - 1];
            }

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
        // Use a thread pool to handle multiple concurrent requests
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        server.start();
        initializeManagers();
        LOGGER.info("Mail Panel server started on port " + port);
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
            if (part.startsWith("MailPanel=")) {
                return part.substring("MailPanel=".length());
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

    private void handleRoot(HttpExchange exchange) throws IOException {
        try {
            // Redirect based on system state
            if (!Main.mysqlAvailable || Main.setupRequired) {
                redirect(exchange, "/setup");
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
            // If setup required, redirect to setup
            if (!Main.mysqlAvailable || Main.setupRequired) {
                redirect(exchange, "/setup");
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
        // If already configured, redirect to login
        if (Main.mysqlAvailable && !Main.setupRequired) {
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

        // If setup required, reject login
        if (!Main.mysqlAvailable || Main.setupRequired) {
            sendJsonResponse(exchange, new JSONObject()
                .put("success", false)
                .put("Message", "Setup richiesto. Vai a /setup"));
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
                "MailPanel=" + sessionCode + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600");

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
            "MailPanel=; Path=/; HttpOnly; Secure; Max-Age=0");

        sendJsonResponse(exchange, new JSONObject().put("success", true));
    }

    // ============== SETUP API ==============

    private void handleApiSetup(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendJsonError(exchange, 405, "Method not allowed");
            return;
        }

        // Only allow if setup is required
        if (Main.mysqlAvailable && !Main.setupRequired) {
            sendJsonError(exchange, 403, "Setup already completed");
            return;
        }

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
                // Install MySQL
                try {
                    String scriptContent = new MySQLMailScript().getScriptContent();
                    String output = executeScript(scriptContent, "mysql");
                    response.put("success", true);
                    response.put("output", output);
                } catch (Exception e) {
                    response.put("success", false);
                    response.put("error", e.getMessage());
                }
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
            try {
                String output = executeScript(scriptContent, component);
                Main.mailDatabase.markComponentInstalled(component, "latest");
                response.put("success", true);
                response.put("output", output);
            } catch (Exception e) {
                response.put("success", false);
                response.put("error", e.getMessage());
            }
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
            ProcessBuilder pb = new ProcessBuilder("service", serviceName, "status");
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
            ProcessBuilder pb = new ProcessBuilder("pkg", "info", "-e", packageName);
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
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "pkg info | grep -q '^" + pattern + "'");
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
            ProcessBuilder pb = new ProcessBuilder("service", service, action);
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

        ProcessBuilder pb = new ProcessBuilder("/bin/sh", scriptPath.toString());
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
        // HSTS - Force HTTPS for 1 year, include subdomains
        headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
        // Content Security Policy - Restrict resource loading
        headers.set("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' https://cdnjs.cloudflare.com; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'");
        // Permissions Policy - Disable unnecessary features
        headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
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
                            AcmeManager.InstallResult result = acmeManager.installAcme(email);
                            response.put("success", result.success);
                            response.put("message", result.message);
                            if (result.output != null) {
                                response.put("output", result.output);
                            }
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

    private void handleApiStats(HttpExchange exchange) throws IOException {
        if (!isAuthenticated(exchange)) {
            sendJsonError(exchange, 401, "Unauthorized");
            return;
        }

        JSONObject response = new JSONObject();

        try {
            // Get stats from Rspamd (accurate email counting)
            RspamdManager.RspamdStats rspamdStats = null;
            if (rspamdManager != null) {
                rspamdStats = rspamdManager.getStatistics();
            }

            // Get active users count from database
            int activeMailboxes = Main.mailDatabase.getMailboxCount();

            response.put("success", true);
            response.put("generated_at", java.time.LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            response.put("period", "total");

            // SMTP stats from Rspamd
            JSONObject smtp = new JSONObject();
            if (rspamdStats != null) {
                // hamCount = legitimate emails (received + sent that passed)
                // scanned = total processed
                smtp.put("received", rspamdStats.hamCount);
                smtp.put("sent", 0); // Rspamd doesn't distinguish, would need log parsing
                smtp.put("rejected", rspamdStats.spamCount);
                smtp.put("total", rspamdStats.scanned);
            } else {
                smtp.put("received", 0);
                smtp.put("sent", 0);
                smtp.put("rejected", 0);
                smtp.put("total", 0);
            }
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
                        eventJson.put("action", event.action);
                        eventJson.put("jail", event.jail);
                        eventJson.put("ip", event.ip);
                        if (event.timestamp != null) {
                            eventJson.put("timestamp", event.timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
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

                } else if ("banned".equals(action)) {
                    // Get all banned IPs
                    java.util.List<Fail2banManager.BannedIp> banned = fail2banManager.getAllBannedIps();
                    response.put("success", true);
                    response.put("count", banned.size());

                    JSONArray bannedArray = new JSONArray();
                    for (Fail2banManager.BannedIp ban : banned) {
                        JSONObject banJson = new JSONObject();
                        banJson.put("ip", ban.ip);
                        banJson.put("jail", ban.jail);
                        banJson.put("active", ban.active);
                        bannedArray.put(banJson);
                    }
                    response.put("banned", bannedArray);

                } else if ("ip_info".equals(action)) {
                    // Get IP whois info
                    String ip = extractParamFromQuery(query, "ip");
                    if (ip == null) {
                        response.put("success", false);
                        response.put("error", "IP address required");
                    } else {
                        Fail2banManager.IpInfo info = fail2banManager.getIpInfo(ip);
                        response.put("success", info.found);
                        response.put("ip", info.ip);
                        response.put("country", info.country);
                        response.put("organization", info.organization);
                        response.put("net_range", info.netRange);
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
                    case "ban" -> {
                        String ip = json.getString("ip");
                        String jail = json.getString("jail");
                        Fail2banManager.BanAction result = fail2banManager.banIp(ip, jail);
                        response.put("success", result.success);
                        response.put("message", result.message);
                    }
                    case "unban" -> {
                        String ip = json.getString("ip");
                        String jail = json.optString("jail", null);
                        Fail2banManager.BanAction result;
                        if (jail != null && !jail.isEmpty()) {
                            result = fail2banManager.unbanIp(ip, jail);
                        } else {
                            result = fail2banManager.unbanIpFromAll(ip);
                        }
                        response.put("success", result.success);
                        response.put("message", result.message);
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
                        int maxRetry = json.optInt("max_retry", 5);
                        int findTime = json.optInt("find_time", 600);
                        int banTime = json.optInt("ban_time", 3600);
                        Fail2banManager.BanAction result = fail2banManager.updateJailConfig(jailName, maxRetry, findTime, banTime);
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
                            } else {
                                response.put("success", false);
                                response.put("error", "Codice non valido");
                            }
                        }
                        case "disable" -> {
                            String code = req.optString("code", "");
                            String secret = Main.mailDatabase.getTotpSecret(adminId);

                            if (secret != null && TotpManager.verifyCode(secret, code)) {
                                Main.mailDatabase.disable2FA(adminId);
                                response.put("success", true);
                            } else {
                                response.put("success", false);
                                response.put("error", "Codice non valido");
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

            if (username.isEmpty()) {
                response.put("success", false);
                response.put("error", "Username required");
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
            } else {
                response.put("error", result.message());
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

            if (username.isEmpty()) {
                response.put("success", false);
                response.put("error", "Username required");
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
                        "MailPanel=" + sessionCode + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600");

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
                        } else {
                            response.put("success", false);
                            response.put("error", "Errore durante il salvataggio della password");
                        }
                    } else {
                        response.put("success", false);
                        response.put("error", "Password corrente non valida");
                    }
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
                            String username = req.optString("username", "");
                            String password = req.optString("password", "");
                            String role = req.optString("role", "admin");

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
                    JSONArray limits = new JSONArray();
                    for (MailDatabase.RateLimit rl : Main.mailDatabase.getRateLimits()) {
                        JSONObject limit = new JSONObject();
                        limit.put("id", rl.id);
                        limit.put("target_type", rl.targetType);
                        limit.put("target_id", rl.targetId);
                        limit.put("target_name", rl.targetName);
                        limit.put("max_per_hour", rl.maxPerHour);
                        limit.put("max_per_day", rl.maxPerDay);
                        limit.put("max_recipients", rl.maxRecipients);
                        limit.put("enabled", rl.enabled);
                        limits.put(limit);
                    }
                    response.put("success", true);
                    response.put("limits", limits);
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
     * Log an audit event to database
     */
    private void logAudit(String action, String ipAddress, String details) {
        try {
            if (Main.mailDatabase != null) {
                Main.mailDatabase.logAuditEvent(action, ipAddress, details, getSessionUsername());
            }
        } catch (Exception e) {
            LOGGER.warning("Failed to log audit event: " + e.getMessage());
        }
    }

    private String getClientIp(HttpExchange exchange) {
        // Check for Cloudflare header first (most reliable when using CF)
        String cfIp = exchange.getRequestHeaders().getFirst("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isEmpty()) {
            return cfIp.trim();
        }
        // Check for other proxy headers
        String forwarded = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isEmpty()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = exchange.getRequestHeaders().getFirst("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            return realIp;
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
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
