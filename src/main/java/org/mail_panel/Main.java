package org.mail_panel;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

import org.mail_panel.content.MailPanelContent;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.gui.Chooser;
import org.mail_panel.gui.ModifyData;
import org.mail_panel.gui.RoundcubeConfig;
import org.mail_panel.gui.Welcome;
import org.mail_panel.scripts.*;
import org.mail_panel.sqli.dataBaseManager;
import org.mail_panel.webserver.SSLMailServer;
import org.mail_panel.webserver.WebSessions;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.ResultSet;

/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                     FreeBSD Mail Panel - Main Entry Point                     ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  Native mail server control panel for FreeBSD 15+                            ║
 * ║  Similar to Mailcow but WITHOUT Docker - 100% native FreeBSD services        ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                              MAIL SERVER STACK                                ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  SMTP SERVER: Postfix                                                   │ ║
 * ║  │  ─────────────────────────────────────────                              │ ║
 * ║  │  • Port 25   - Incoming mail (STARTTLS)                                 │ ║
 * ║  │  • Port 587  - Submission (STARTTLS + Auth)                             │ ║
 * ║  │  • Port 465  - Submission SSL (SMTPS + Auth)                            │ ║
 * ║  │  • Service name: postfix                                                │ ║
 * ║  │  • Config: /usr/local/etc/postfix/main.cf                               │ ║
 * ║  │  • MySQL tables: mysql-virtual-domains.cf, mysql-virtual-mailboxes.cf   │ ║
 * ║  │                                                                         │ ║
 * ║  │  NOTE: We use Postfix with MySQL virtual users.                         │ ║
 * ║  │        Delivery is via LMTP to Dovecot on port 24.                      │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  IMAP/POP3 SERVER: Dovecot                                              │ ║
 * ║  │  ──────────────────────────────                                         │ ║
 * ║  │  • Port 143  - IMAP (STARTTLS)                                          │ ║
 * ║  │  • Port 993  - IMAPS (SSL)                                              │ ║
 * ║  │  • Port 110  - POP3 (STARTTLS)                                          │ ║
 * ║  │  • Port 995  - POP3S (SSL)                                              │ ║
 * ║  │  • LMTP socket: /var/run/dovecot/lmtp                                   │ ║
 * ║  │  • Config: /usr/local/etc/dovecot/                                      │ ║
 * ║  │  • Mailboxes: /var/vmail/{domain}/{user}                                │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  ANTI-SPAM: Rspamd                                                      │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Port 11332 - Milter protocol (for Postfix milter)                    │ ║
 * ║  │  • Port 11333 - Normal worker                                           │ ║
 * ║  │  • Port 11334 - Controller/Web UI                                       │ ║
 * ║  │  • Config: /usr/local/etc/rspamd/                                       │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  ANTIVIRUS: ClamAV                                                      │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Socket: /var/run/clamav/clamd.sock                                   │ ║
 * ║  │  • Services: clamav_clamd, clamav_freshclam (underscore on FreeBSD)     │ ║
 * ║  │  • Integrated with Rspamd for email scanning                            │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  DATABASE: MySQL 8.0                                                    │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Port 3306                                                            │ ║
 * ║  │  • Database: mailserver (configurable)                                  │ ║
 * ║  │  • Tables: domains, mailboxes, aliases,                                 │ ║
 * ║  │            panel_admins, settings, rate_limits, etc.                    │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  CACHE: Redis                                                           │ ║
 * ║  │  ─────────────────                                                      │ ║
 * ║  │  • Port 6379                                                            │ ║
 * ║  │  • Used by Rspamd for caching                                           │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  SSL CERTIFICATES                                                       │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Path: /usr/local/etc/ssl/mail/                                       │ ║
 * ║  │  • fullchain.pem - Certificate + chain                                  │ ║
 * ║  │  • privkey.pem   - Private key                                          │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                           PANEL CONFIGURATION                                 ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  • SQLite database: ./database/mailpanel.db (panel settings only)            ║
 * ║  • MySQL database: mail data (domains, users, aliases)                        ║
 * ║  • Web panel: HTTPS on port 2096 (configurable)                               ║
 * ║  • Terminal GUI: Lanterna library                                             ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  IMPORTANT: This project uses Postfix with MySQL virtual users.               ║
 * ║  Postfix delivers to Dovecot via LMTP on port 24.                             ║
 * ║                                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 *
 * @author FreeBSD Mail Panel Team
 * @version 1.0
 */
public class Main {

    public static dataBaseManager dbManager;         // SQLite for panel config
    public static MailDatabase mailDatabase;         // MySQL for mail data
    public static WebSessions sessions;

    // Status flags for SSLMailServer compatibility
    public static boolean mysqlAvailable = false;
    public static boolean setupRequired = true;

    // ANSI color codes
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_CYAN = "\u001B[36m";

    private static String getJarDirectory() throws URISyntaxException {
        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        return new File(jarPath).getParent();
    }

    public static void createDirectoryIfNotExists(String directoryPath) throws IOException {
        Path path = Paths.get(directoryPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
        }
    }

    public static String showTextInputDialog(MultiWindowTextGUI gui, String title, String description) {
        return showTextInputDialogWithDefault(gui, title, description, "");
    }

    public static String showTextInputDialogWithDefault(MultiWindowTextGUI gui, String title, String description, String defaultValue) {
        final String[] result = {null};

        BasicWindow window = new BasicWindow(title);
        Panel panel = new Panel();
        panel.setLayoutManager(new GridLayout(2));

        if (description != null && !description.isEmpty()) {
            panel.addComponent(new Label(description));
            panel.addComponent(new EmptySpace());
        }

        TextBox textBox = new TextBox(new TerminalSize(40, 1));
        if (defaultValue != null && !defaultValue.isEmpty()) {
            textBox.setText(defaultValue);
        }
        panel.addComponent(new Label("Input:"));
        panel.addComponent(textBox);

        // Cancel first = pre-selected (safety)
        panel.addComponent(new Button("Cancel", () -> {
            result[0] = null;
            window.close();
        }));
        panel.addComponent(new Button("OK", () -> {
            result[0] = textBox.getText();
            window.close();
        }));

        window.setComponent(panel);
        gui.addWindowAndWait(window);

        return result[0];
    }

    /**
     * Execute a shell script with detailed output
     */
    public static boolean executeScript(String scriptPath, String scriptName, String... args) {
        System.out.println();
        System.out.println(ANSI_CYAN + "═══════════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println(ANSI_CYAN + "  Executing: " + scriptName + ANSI_RESET);
        System.out.println(ANSI_CYAN + "  Script: " + scriptPath + ANSI_RESET);
        if (args.length > 0) {
            System.out.println(ANSI_CYAN + "  Arguments: " + String.join(" ", args) + ANSI_RESET);
        }
        System.out.println(ANSI_CYAN + "═══════════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println();

        File scriptFile = new File(scriptPath);
        if (!scriptFile.exists()) {
            System.out.println(ANSI_RED + "[ERROR] Script file not found: " + scriptPath + ANSI_RESET);
            waitForEnter();
            return false;
        }

        if (!scriptFile.canExecute()) {
            scriptFile.setExecutable(true);
        }

        try {
            String[] command = new String[2 + args.length];
            command[0] = "sh";
            command[1] = scriptPath;
            System.arraycopy(args, 0, command, 2, args.length);

            // TODO: migrate to Shell.run when touched
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            org.mail_panel.util.Shell.applicaPath(processBuilder);
            processBuilder.redirectErrorStream(true);
            processBuilder.directory(new File(System.getProperty("user.dir")));

            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                    System.out.flush();
                }
            }

            int exitCode = process.waitFor();

            System.out.println();
            System.out.println("═══════════════════════════════════════════════════════════════");

            if (exitCode == 0) {
                System.out.println(ANSI_GREEN + "  [SUCCESS] " + scriptName + " completed successfully!" + ANSI_RESET);
            } else {
                System.out.println(ANSI_RED + "  [FAILED] " + scriptName + " failed! Exit code: " + exitCode + ANSI_RESET);
            }

            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println();
            System.out.flush();

            waitForEnter();
            return exitCode == 0;

        } catch (Exception e) {
            System.out.println(ANSI_RED + "[ERROR] Failed to execute script: " + e.getMessage() + ANSI_RESET);
            waitForEnter();
            return false;
        }
    }

    private static void waitForEnter() {
        System.out.println(ANSI_YELLOW + "Press ENTER to continue..." + ANSI_RESET);
        try {
            System.in.read();
            // Clear any remaining input
            while (System.in.available() > 0) {
                System.in.read();
            }
        } catch (IOException e) {
            // Ignore
        }
    }

    public static void main(String[] args) throws InterruptedException, IOException {
        sessions = new WebSessions();
        String directoryPath = "./database/";
        try {
            createDirectoryIfNotExists(directoryPath);
        } catch (IOException e) {
            // Silent
        }
        directoryPath = "./install_scripts/";
        try {
            createDirectoryIfNotExists(directoryPath);
        } catch (IOException e) {
            // Silent
        }

        // Generate all panel HTML content
        MailPanelContent.generateAllContent();

        // Se una manutenzione dei pacchetti non e' arrivata in fondo (pannello ucciso, crash,
        // riavvio a meta'), i pacchetti sono rimasti SBLOCCATI e nessuno se ne accorgerebbe
        // finche' un aggiornamento successivo non porta via un pezzo dello stack di posta.
        // Il ripristino va fatto qui, all'avvio, prima che il pannello torni utilizzabile.
        try {
            String ripristino = org.mail_panel.system.UpdateManager.ripristinaLockDopoCrash();
            if (!ripristino.isEmpty()) System.out.println(ripristino);
        } catch (Exception e) {
            System.out.println("Ripristino protezione pacchetti non riuscito: " + e.getMessage());
        }

        // Initialize database BEFORE screen to avoid warnings during GUI
        dbManager = new dataBaseManager();
        dbManager.ensureMailHostnameColumn();
        dbManager.ensureSslChainColumn();
        dbManager.ensureRoundcubeColumns();
        dbManager.ensurePostfixColumn();

        Integer count = dbManager.check_tables();
        boolean needsTableCreation = (count < 1);
        if (needsTableCreation) {
            dbManager.create_tables();
            dbManager.insert_data_default();
        }

        // Modalita' solo-web: nessun menu a schermo.
        //
        // Serve perche' il pannello deve poter tornare su DA SOLO dopo che si e' spento per
        // aggiornare la propria JVM. L'interfaccia a schermo (Lanterna) pretende un terminale,
        // e uno script staccato non ne ha uno: senza questa modalita' il processo ripartirebbe
        // e morirebbe subito, lasciando il pannello web irraggiungibile.
        // Il server web di suo non ha mai avuto bisogno del terminale: usa solo System.out.
        boolean soloWeb = false;
        for (String a1 : args) if ("--web".equals(a1)) soloWeb = true;
        if (soloWeb) {
            System.out.println("Avvio in modalita' solo-web: nessun menu a schermo.");
            System.out.println("Per rivedere il menu: ferma questo processo e rilancialo senza --web.");
            startWebServer(true);
            return;
        }

        // Comodita', non dipendenza: il pannello non ha bisogno di run.sh per funzionare ne'
        // per riaccendersi da solo (la riga di riavvio la ricostruisce dal processo vivo).
        // Se pero' non c'e', se lo scrive, cosi' esiste un modo breve per avviare --web a mano.
        try {
            String creato = org.mail_panel.system.UpdateManager.creaRunSh();
            if (!creato.isEmpty()) System.out.println(creato);
        } catch (Exception e) {
            // Se non si puo' scrivere accanto al jar non e' un problema: serviva solo a comodita'.
        }

        // NOW start screen (after SQLite native libs are loaded)
        Screen screen = null;
        try {
            screen = new DefaultTerminalFactory().createScreen();
            screen.startScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        MultiWindowTextGUI gui = new MultiWindowTextGUI(screen, new DefaultWindowManager(), new EmptySpace(TextColor.ANSI.BLUE));
        Welcome simpleBox = new Welcome("Information", "Welcome to FreeBSD Mail Panel");
        simpleBox.show(gui);

        if (needsTableCreation) {
            Welcome success = new Welcome("Information", "Database initialized successfully");
            success.show(gui);
        }

        // Generate install scripts
        generateInstallScripts(gui);

        // Main loop
        if (dbManager.check_tables() > 0) {
            while (true) {
                Chooser chooser = new Chooser();
                try {
                    chooser.run(gui);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                switch (chooser.option) {
                    case 0:
                        // Exit
                        screen.stopScreen();
                        System.exit(0);
                        break;

                    case 1:
                        // Set TimeZone and CloudFlare DNS
                        try {
                            screen.stopScreen();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        executeScript("./install_scripts/setup_timezone_and_dns.sh", "Timezone & DNS Configuration");
                        try {
                            screen.startScreen();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        break;

                    case 2:
                        // Edit Panel Configuration
                        ModifyData data = new ModifyData(dbManager);
                        data.show(gui);
                        break;

                    case 3:
                        // Edit Roundcube Configuration
                        RoundcubeConfig rcConfig = new RoundcubeConfig(dbManager);
                        rcConfig.show(gui);
                        break;

                    case 4:
                        // Install/Reinstall Complete Mail Server
                        installMailServer(screen, gui);
                        break;

                    case 100:
                        // Start Mail Panel WebServer
                        try {
                            screen.stopScreen();
                            startWebServer(false);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                        break;

                    default:
                        continue;
                }
            }
        }

        try {
            screen.stopScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void generateInstallScripts(MultiWindowTextGUI gui) {
        // Generate timezone/DNS script
        SetTimeOnSystemScript timezoneScript = new SetTimeOnSystemScript();
        timezoneScript.write_file();
        if (timezoneScript.writed) {
            Welcome msg = new Welcome("Information", "Created setup_timezone_and_dns script");
            msg.show(gui);
        }

        // Generate unified mail server installation script
        FullMailServerScript mailServerScript = new FullMailServerScript();
        mailServerScript.write_file();
        if (mailServerScript.writed) {
            Welcome msg = new Welcome("Information", "Created mail server install script");
            msg.show(gui);
        }
    }

    /**
     * Generate a random password
     */
    private static String generateRandomPassword(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        java.security.SecureRandom random = new java.security.SecureRandom();
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        return password.toString();
    }

    /**
     * Install/Reinstall the complete mail server
     */
    private static void installMailServer(Screen screen, MultiWindowTextGUI gui) {
        // Always ask for hostname (pre-fill with saved value if exists)
        String savedHostname = dbManager.getMailHostname();
        String defaultValue = (savedHostname != null && !savedHostname.trim().isEmpty())
                ? savedHostname : "mail.example.com";

        String mailHostname = showTextInputDialogWithDefault(gui, "Mail Server Hostname",
                "Enter the mail server hostname:", defaultValue);

        if (mailHostname == null || mailHostname.trim().isEmpty()) {
            Welcome cancelled = new Welcome("Cancelled", "Installation cancelled - no hostname provided");
            cancelled.show(gui);
            return;
        }

        // Save hostname
        dbManager.setMailHostname(mailHostname.trim());

        try {
            screen.stopScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Reset all service flags in SQLite (fresh install/reinstall)
        System.out.println(ANSI_YELLOW + "[RESET] Resetting service flags for fresh installation..." + ANSI_RESET);
        dbManager.resetAllServices();

        // Read MySQL config INCLUDING password from SQLite
        String mysqlHost = "127.0.0.1";
        String mysqlPort = "3306";
        String mysqlUser = "mailpanel";
        String mysqlPassword = "";
        String mysqlDatabase = "mailserver";

        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                mysqlHost = result.getString("mysql_host");
                mysqlPort = result.getString("mysql_port");
                mysqlUser = result.getString("mysql_user");
                mysqlPassword = result.getString("mysql_password");
                mysqlDatabase = result.getString("mysql_database");
            }
        } catch (Exception e) {
            System.out.println(ANSI_YELLOW + "[WARNING] Could not read MySQL config: " + e.getMessage() + ANSI_RESET);
        }

        // ALWAYS generate a new password (both install and reinstall)
        // This ensures a fresh secure password every time
        mysqlPassword = generateRandomPassword(24);
        System.out.println(ANSI_GREEN + "[AUTO] Generated MySQL password" + ANSI_RESET);

        // Save to SQLite (replaces old password if reinstalling)
        dbManager.update_mysql_config(mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase);
        System.out.println(ANSI_GREEN + "[AUTO] MySQL password saved to SQLite" + ANSI_RESET);

        // Read Roundcube configuration
        String roundcubeDomain = dbManager.getRoundcubeDomain();
        String roundcubePort = dbManager.getRoundcubePort();
        String roundcubeSslCert = dbManager.getRoundcubeSslCert();
        String roundcubeSslKey = dbManager.getRoundcubeSslKey();
        String roundcubeSslChain = dbManager.getRoundcubeSslChain();

        // If Roundcube SSL is not configured, use Panel's SSL certificates
        if ((roundcubeSslCert == null || roundcubeSslCert.isEmpty()) &&
            (roundcubeSslKey == null || roundcubeSslKey.isEmpty())) {
            try {
                // Read panel's SSL certificates from database
                try (java.sql.ResultSet configResult = dbManager.get_data_config()) {
                    if (configResult.next()) {
                        String panelCert = configResult.getString("mail_panel_ssl_cert");
                        String panelKey = configResult.getString("mail_panel_ssl_cert_key");
                        String panelChain = null;
                        try {
                            panelChain = configResult.getString("mail_panel_ssl_chain");
                        } catch (Exception ignored) {}

                        if (panelCert != null && !panelCert.isEmpty() &&
                            panelKey != null && !panelKey.isEmpty() &&
                            panelCert.contains("-----BEGIN CERTIFICATE-----")) {

                            // Save panel certificates to files for nginx
                            String panelSslDir = "/usr/local/etc/ssl/panel";
                            java.nio.file.Files.createDirectories(java.nio.file.Paths.get(panelSslDir));

                            String panelCertPath = panelSslDir + "/fullchain.pem";
                            String panelKeyPath = panelSslDir + "/privkey.pem";
                            String panelChainPath = panelSslDir + "/chain.pem";

                            java.nio.file.Files.writeString(java.nio.file.Paths.get(panelCertPath), panelCert);
                            java.nio.file.Files.writeString(java.nio.file.Paths.get(panelKeyPath), panelKey);

                            // Set secure permissions on key
                            Runtime.getRuntime().exec(new String[]{"chmod", "600", panelKeyPath}).waitFor();

                            // Use panel's certificate paths for Roundcube
                            roundcubeSslCert = panelCertPath;
                            roundcubeSslKey = panelKeyPath;

                            if (panelChain != null && !panelChain.isEmpty()) {
                                java.nio.file.Files.writeString(java.nio.file.Paths.get(panelChainPath), panelChain);
                                roundcubeSslChain = panelChainPath;
                            }

                            System.out.println(ANSI_GREEN + "[SSL] Using Panel SSL certificates for Roundcube" + ANSI_RESET);
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println(ANSI_YELLOW + "[SSL] Could not load Panel certificates: " + e.getMessage() + ANSI_RESET);
            }
        }

        // Execute the unified mail server installation script
        boolean success = executeScript("./install_scripts/install_mail_server.sh",
                "Complete Mail Server Installation",
                mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase, mailHostname.trim(),
                roundcubeDomain, roundcubePort, roundcubeSslCert, roundcubeSslKey, roundcubeSslChain);

        if (success) {
            // Mark all services as installed
            dbManager.setServiceInstalled("postfix", true);
            dbManager.setServiceInstalled("dovecot", true);
            dbManager.setServiceInstalled("rspamd", true);
            dbManager.setServiceInstalled("clamav", true);

            // Auto-load the generated self-signed certificate ONLY if no certificate is configured
            // This prevents overwriting user-configured Cloudflare certificates
            try {
                // Check if user already has certificates configured
                boolean hasCertConfigured = false;
                try (ResultSet configResult = dbManager.get_data_config()) {
                    if (configResult.next()) {
                        String existingCert = configResult.getString("mail_panel_ssl_cert");
                        if (existingCert != null && !existingCert.trim().isEmpty()
                            && existingCert.contains("-----BEGIN CERTIFICATE-----")) {
                            hasCertConfigured = true;
                            System.out.println(ANSI_GREEN + "[KEEP] Existing SSL certificate preserved (not overwritten)" + ANSI_RESET);
                        }
                    }
                }

                // Only load self-signed if no certificate is configured
                if (!hasCertConfigured) {
                    String certPath = "/usr/local/etc/ssl/mail/fullchain.pem";
                    String keyPath = "/usr/local/etc/ssl/mail/privkey.pem";

                    java.io.File certFile = new java.io.File(certPath);
                    java.io.File keyFile = new java.io.File(keyPath);

                    if (certFile.exists() && keyFile.exists()) {
                        String certContent = new String(java.nio.file.Files.readAllBytes(certFile.toPath()));
                        String keyContent = new String(java.nio.file.Files.readAllBytes(keyFile.toPath()));

                        // Update panel config with the self-signed cert so web panel can start
                        // Use 0.0.0.0 only for first-time setup
                        dbManager.update_panel_config(
                            "0.0.0.0",  // host - listen on all interfaces
                            "2096",      // port
                            certContent,
                            keyContent,
                            "",          // chain (empty for self-signed)
                            "mailpanel-" // session prefix
                        );
                        System.out.println(ANSI_GREEN + "[AUTO] Self-signed certificate loaded into panel configuration" + ANSI_RESET);
                    }
                }
            } catch (Exception e) {
                System.out.println(ANSI_YELLOW + "[WARNING] Could not auto-load certificate: " + e.getMessage() + ANSI_RESET);
            }

            System.out.println(ANSI_GREEN + "Mail server installed successfully!" + ANSI_RESET);
            System.out.println(ANSI_YELLOW + "Remember to configure a real SSL certificate from the web panel!" + ANSI_RESET);
            System.out.flush();
        }

        // Note: waitForEnter() is already called inside executeScript(), no need to call again

        try {
            screen.startScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void startWebServer(boolean senzaTastiera) {
        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                String certContent = result.getString("mail_panel_ssl_cert");
                String keyContent = result.getString("mail_panel_ssl_cert_key");
                int port = Integer.parseInt(result.getString("mail_panel_port"));
                String host = result.getString("mail_panel_host");

                // Validate SSL
                if (certContent == null || certContent.trim().isEmpty()) {
                    System.out.println(ANSI_RED + "ERROR: SSL Certificate is empty!" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Configure SSL in 'Edit Panel Configuration'" + ANSI_RESET);
                    waitForEnter();
                    return;
                }

                if (keyContent == null || keyContent.trim().isEmpty()) {
                    System.out.println(ANSI_RED + "ERROR: SSL Private Key is empty!" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Configure SSL in 'Edit Panel Configuration'" + ANSI_RESET);
                    waitForEnter();
                    return;
                }

                if (!certContent.contains("-----BEGIN CERTIFICATE-----")) {
                    System.out.println(ANSI_RED + "ERROR: Invalid SSL Certificate format!" + ANSI_RESET);
                    waitForEnter();
                    return;
                }

                if (!keyContent.contains("-----BEGIN PRIVATE KEY-----") &&
                    !keyContent.contains("-----BEGIN RSA PRIVATE KEY-----") &&
                    !keyContent.contains("-----BEGIN EC PRIVATE KEY-----")) {
                    System.out.println(ANSI_RED + "ERROR: Invalid SSL Private Key format!" + ANSI_RESET);
                    waitForEnter();
                    return;
                }

                // Connect to MySQL for mail data
                String mysqlHost = result.getString("mysql_host");
                String mysqlPort = result.getString("mysql_port");
                String mysqlUser = result.getString("mysql_user");
                String mysqlPassword = result.getString("mysql_password");
                String mysqlDatabase = result.getString("mysql_database");

                mailDatabase = new MailDatabase();
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mysqlAvailable = true;
                    setupRequired = !mailDatabase.hasAdminUser();
                    System.out.println(ANSI_GREEN + "Connected to MySQL database" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_YELLOW + "[WARNING] Could not connect to MySQL database" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Some features will be unavailable" + ANSI_RESET);
                }

                // La porta gia' occupata quasi sempre vuol dire una cosa sola: il pannello e'
                // gia' acceso. Da quando puo' riaccendersi da solo dopo l'aggiornamento della
                // JVM, capita di lanciarlo credendolo spento — e una traccia di stack Java non
                // e' una risposta a "che e' successo?". Qui si dice chi occupa la porta.
                SSLMailServer server;
                try {
                    server = new SSLMailServer(port, certContent, keyContent);
                } catch (java.net.BindException be) {
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "La porta " + port + " e' gia' occupata: "
                            + "il pannello e' molto probabilmente GIA' IN ESECUZIONE." + ANSI_RESET);
                    String chi = "";
                    try {
                        chi = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(20),
                                "sockstat -46l -p " + port + " 2>/dev/null | grep -v '^USER'").outputTrim();
                    } catch (Exception ignored) { }
                    if (!chi.isEmpty()) {
                        System.out.println("Chi la occupa:");
                        System.out.println(chi);
                        System.out.println();
                        System.out.println("Per fermarlo:  kill <PID>    (il PID e' la terza colonna)");
                    }
                    System.out.println("Oppure aprilo nel browser: https://" + host + ":" + port);
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "Non ho avviato niente: il pannello che gira "
                            + "non e' stato toccato." + ANSI_RESET);
                    waitForEnter();
                    return;
                }
                server.start();

                System.out.println(ANSI_GREEN + "Mail Panel Server started on port " + port + ANSI_RESET);
                System.out.println(ANSI_GREEN + "Open your browser: https://" + host + ":" + port + ANSI_RESET);
                System.out.println();
                System.out.println("Press ENTER to stop the server.");
                System.out.flush();

                // Handle Ctrl+C properly
                final SSLMailServer finalServer = server;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "Shutting down server..." + ANSI_RESET);
                    finalServer.stop();
                }));

                if (senzaTastiera) {
                    // Senza terminale, System.in e' /dev/null: readLine() tornerebbe subito null
                    // e il server si spegnerebbe un istante dopo essersi acceso. Qui si resta
                    // fermi finche' non arriva un segnale, e a quello pensa lo shutdown hook.
                    System.out.println("In ascolto. Per fermarlo: kill " + ProcessHandle.current().pid());
                    System.out.flush();
                    try { new java.util.concurrent.CountDownLatch(1).await(); }
                    catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    return;
                }

                // Wait for ENTER to stop (blocks until input)
                BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
                consoleReader.readLine();

                System.out.println(ANSI_YELLOW + "Stopping server..." + ANSI_RESET);
                server.stop();
                System.out.println(ANSI_GREEN + "Server stopped. Goodbye!" + ANSI_RESET);
                System.exit(0);
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
            waitForEnter();
        }
    }

    private static void setupMySQLDatabase() {
        System.out.println(ANSI_CYAN + "Setting up MySQL database for mail server..." + ANSI_RESET);

        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                String mysqlHost = result.getString("mysql_host");
                String mysqlPort = result.getString("mysql_port");
                String mysqlUser = result.getString("mysql_user");
                String mysqlPassword = result.getString("mysql_password");
                String mysqlDatabase = result.getString("mysql_database");

                mailDatabase = new MailDatabase();
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mailDatabase.createSchema();
                    System.out.println(ANSI_GREEN + "MySQL database setup completed!" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_RED + "Failed to connect to MySQL" + ANSI_RESET);
                }
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
        }

        waitForEnter();
    }

    private static void resetMySQLDatabase() {
        System.out.println(ANSI_RED + "RESETTING MySQL database..." + ANSI_RESET);

        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                String mysqlHost = result.getString("mysql_host");
                String mysqlPort = result.getString("mysql_port");
                String mysqlUser = result.getString("mysql_user");
                String mysqlPassword = result.getString("mysql_password");
                String mysqlDatabase = result.getString("mysql_database");

                mailDatabase = new MailDatabase();
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mailDatabase.dropAllTables();
                    mailDatabase.createSchema();
                    System.out.println(ANSI_GREEN + "Database reset completed!" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_RED + "Failed to connect to MySQL" + ANSI_RESET);
                }
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
        }

        waitForEnter();
    }

    private static void fullReset() {
        System.out.println(ANSI_RED + "════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println(ANSI_RED + "                    FULL RESET                          " + ANSI_RESET);
        System.out.println(ANSI_RED + "════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println();

        // Stop all services (try both ClamAV naming conventions for FreeBSD compatibility)
        System.out.println(ANSI_YELLOW + "Stopping all mail services..." + ANSI_RESET);
        executeCommand("service postfix stop");
        executeCommand("service dovecot stop");
        executeCommand("service rspamd stop");
        executeCommand("service clamav_clamd stop 2>/dev/null || service clamav-clamd stop");
        executeCommand("service clamav_freshclam stop 2>/dev/null || service clamav-freshclam stop");

        // Remove configurations
        System.out.println(ANSI_YELLOW + "Removing configurations..." + ANSI_RESET);
        executeCommand("rm -rf /usr/local/etc/postfix/* /var/spool/postfix/*");
        executeCommand("rm -rf /usr/local/etc/dovecot/*");
        executeCommand("rm -rf /usr/local/etc/rspamd/*");

        // Reset database
        resetMySQLDatabase();

        // Reset service status in SQLite
        dbManager.resetAllServices();

        System.out.println(ANSI_GREEN + "Full reset completed!" + ANSI_RESET);
        System.out.println(ANSI_YELLOW + "You can now reinstall services from the menu." + ANSI_RESET);

        waitForEnter();
    }

    private static void executeCommand(String command) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.inheritIO();
            Process p = pb.start();
            p.waitFor();
        } catch (Exception e) {
            System.out.println(ANSI_YELLOW + "[WARNING] Command failed: " + command + ANSI_RESET);
        }
    }

    /**
     * Automatic database setup for web setup wizard
     */
    public static boolean autoSetupDatabase(String adminUsername, String adminPassword, String mailHostname) {
        try {
            if (mailDatabase == null || !mailDatabase.isConnected()) {
                System.out.println(ANSI_RED + "MySQL not connected" + ANSI_RESET);
                return false;
            }

            // Create schema
            mailDatabase.createSchema();

            // Create admin user
            mailDatabase.createAdminUser(adminUsername, adminPassword);

            // Save mail hostname
            mailDatabase.setSetting("mail_hostname", mailHostname);

            mysqlAvailable = true;
            setupRequired = false;

            System.out.println(ANSI_GREEN + "Database setup completed" + ANSI_RESET);
            return true;
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Database setup failed: " + e.getMessage() + ANSI_RESET);
            return false;
        }
    }

    /**
     * Manual database setup with root password
     */
    public static boolean setupDatabase(String rootPassword, String panelPassword, String adminUsername, String adminPassword) {
        try {
            // Connect as root
            MailDatabase rootDb = new MailDatabase();
            if (!rootDb.connectAsRoot(rootPassword)) {
                System.out.println(ANSI_RED + "Cannot connect as root" + ANSI_RESET);
                return false;
            }

            // Create database and user
            rootDb.createDatabaseAndUser(panelPassword);
            rootDb.close();

            // Connect as panel user
            mailDatabase = new MailDatabase(panelPassword);
            if (!mailDatabase.connect()) {
                System.out.println(ANSI_RED + "Cannot connect as panel user" + ANSI_RESET);
                return false;
            }

            // Create schema
            mailDatabase.createSchema();

            // Create admin user
            mailDatabase.createAdminUser(adminUsername, adminPassword);

            mysqlAvailable = true;
            setupRequired = false;

            System.out.println(ANSI_GREEN + "Database setup completed" + ANSI_RESET);
            return true;
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Database setup failed: " + e.getMessage() + ANSI_RESET);
            return false;
        }
    }
}
