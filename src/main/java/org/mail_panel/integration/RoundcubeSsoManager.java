package org.mail_panel.integration;

import org.mail_panel.database.MailDatabase;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;

/**
 * Roundcube Single Sign-On Manager for FreeBSD Mail Panel
 *
 * Implements secure SSO between the mail panel and Roundcube webmail.
 * Uses encrypted tokens to authenticate users without exposing passwords.
 *
 * Flow:
 * 1. User clicks "Open Webmail" in panel
 * 2. Panel generates encrypted SSO token with user email + timestamp
 * 3. User is redirected to Roundcube with token
 * 4. Roundcube plugin validates token and auto-logs user in
 *
 * Security:
 * - AES-256-GCM encryption for tokens
 * - Tokens expire after 30 seconds (single use)
 * - Shared secret between panel and Roundcube plugin
 * - IP binding to prevent token theft
 */
public class RoundcubeSsoManager {

    // Paths
    private static final String ROUNDCUBE_PATH = "/usr/local/www/roundcube";
    private static final String ROUNDCUBE_CONFIG = ROUNDCUBE_PATH + "/config/config.inc.php";
    private static final String ROUNDCUBE_PLUGINS = ROUNDCUBE_PATH + "/plugins";
    private static final String SSO_PLUGIN_PATH = ROUNDCUBE_PLUGINS + "/mailpanel_sso";
    private static final String SSO_SECRET_FILE = "/var/db/mailpanel/roundcube_sso.key";

    // Token settings
    private static final int TOKEN_EXPIRY_SECONDS = 60;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    // Master user settings. In Roundcube chi entra cosi' e' "casella*admin" (la riga di users e il
    // registro degli accessi lo dicono): RoundcubeDbUser lo usa per scegliere la casella di prova.
    public static final String MASTER_USER = "admin";
    private static final String MASTER_PASSWORD_FILE = "/var/db/mailpanel/dovecot_master.key";

    private final MailDatabase database;
    private SecretKey secretKey;
    private String roundcubeUrl = "https://mail.example.com";
    private String masterPassword = null;
    /** La porta HTTPS del pannello: la webmail ci manda i cambi password e le password di chi entra. */
    private int panelPort = 0;

    public RoundcubeSsoManager(MailDatabase database) {
        this.database = database;
        loadOrGenerateSecret();
        loadRoundcubeUrlFromConfig();
        loadMasterPassword();
    }

    /**
     * Load Dovecot master password for admin SSO
     */
    private void loadMasterPassword() {
        try {
            Path masterPath = Paths.get(MASTER_PASSWORD_FILE);
            if (Files.exists(masterPath)) {
                masterPassword = Files.readString(masterPath).trim();
                System.out.println("Dovecot master password loaded for SSO");
            }
        } catch (Exception e) {
            System.err.println("Failed to load master password: " + e.getMessage());
        }
    }

    /**
     * Load Roundcube URL from database config
     */
    private void loadRoundcubeUrlFromConfig() {
        try {
            // Try to get Roundcube domain and port from dbManager
            if (org.mail_panel.Main.dbManager != null) {
                String domain = org.mail_panel.Main.dbManager.getRoundcubeDomain();
                String port = org.mail_panel.Main.dbManager.getRoundcubePort();

                if (domain != null && !domain.isEmpty()) {
                    // Build URL: https://domain:port
                    StringBuilder url = new StringBuilder("https://");
                    url.append(domain);
                    if (port != null && !port.isEmpty() && !port.equals("443")) {
                        url.append(":").append(port);
                    }
                    // No /webmail - nginx serves Roundcube at root /
                    this.roundcubeUrl = url.toString();
                    System.out.println("Roundcube SSO URL loaded from config: " + this.roundcubeUrl);
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to load Roundcube URL from config: " + e.getMessage());
            // Keep default URL
        }
    }

    /**
     * Set the Roundcube URL
     */
    public void setPanelPort(int port) {
        this.panelPort = port;
    }

    public void setRoundcubeUrl(String url) {
        this.roundcubeUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Load existing secret or generate new one
     */
    private void loadOrGenerateSecret() {
        try {
            Path secretPath = Paths.get(SSO_SECRET_FILE);
            if (Files.exists(secretPath)) {
                byte[] keyBytes = Files.readAllBytes(secretPath);
                secretKey = new SecretKeySpec(keyBytes, "AES");
            } else {
                // Generate new secret
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256, new SecureRandom());
                secretKey = keyGen.generateKey();

                // Save secret
                Files.createDirectories(secretPath.getParent());
                Files.write(secretPath, secretKey.getEncoded());

                // Secure permissions
                executeCommand("chmod 600 " + SSO_SECRET_FILE);
                executeCommand("chown root:wheel " + SSO_SECRET_FILE);
            }
        } catch (Exception e) {
            System.err.println("Failed to load/generate SSO secret: " + e.getMessage());
            // Generate in-memory key as fallback
            try {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256, new SecureRandom());
                secretKey = keyGen.generateKey();
            } catch (Exception ex) {
                throw new RuntimeException("Cannot generate secret key", ex);
            }
        }
    }

    /**
     * Generate SSO token for user using master user (admin access)
     * Uses Dovecot master user to login as any user without knowing their password
     */
    public SsoToken generateToken(String email, String clientIp) {
        // Always try to reload master password in case it was created after panel start
        // (e.g., after reinstalling mail server)
        if (masterPassword == null || masterPassword.isEmpty()) {
            loadMasterPassword();
        }

        // Use master user for admin SSO
        if (masterPassword == null || masterPassword.isEmpty()) {
            SsoToken result = new SsoToken();
            result.success = false;
            result.error = "Master password not configured. Reinstall mail server or restart panel.";
            return result;
        }

        // Refresh URL from config in case it was updated
        loadRoundcubeUrlFromConfig();

        try {
            // Token data: JSON format with master user credentials
            // Roundcube will login as: email*admin with master password
            long timestamp = Instant.now().getEpochSecond();
            String tokenData = String.format(
                "{\"email\":\"%s\",\"password\":\"%s\",\"master_user\":\"%s\",\"timestamp\":%d}",
                escapeJson(email),
                escapeJson(masterPassword),
                escapeJson(MASTER_USER),
                timestamp
            );

            // Encrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encrypted = cipher.doFinal(tokenData.getBytes(StandardCharsets.UTF_8));

            // Combine IV + encrypted data (tag is appended by GCM mode)
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            // Base64 URL-safe encode
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(combined);

            SsoToken result = new SsoToken();
            result.success = true;
            result.token = token;
            result.redirectUrl = roundcubeUrl + "/?_sso=" + token;
            result.expiresAt = timestamp + TOKEN_EXPIRY_SECONDS;

            return result;

        } catch (Exception e) {
            SsoToken result = new SsoToken();
            result.success = false;
            result.error = "Token generation failed: " + e.getMessage();
            return result;
        }
    }

    /**
     * Generate SSO token for user with password
     * Token format: JSON {"email": "...", "password": "...", "timestamp": ...}
     * This matches the PHP plugin expectation in Roundcube
     */
    public SsoToken generateToken(String email, String password, String clientIp) {
        // Refresh URL from config in case it was updated
        loadRoundcubeUrlFromConfig();

        try {
            // Token data: JSON format matching PHP plugin expectations
            long timestamp = Instant.now().getEpochSecond();
            String tokenData = String.format(
                "{\"email\":\"%s\",\"password\":\"%s\",\"timestamp\":%d}",
                escapeJson(email),
                escapeJson(password),
                timestamp
            );

            // Encrypt with AES-256-GCM
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] encrypted = cipher.doFinal(tokenData.getBytes(StandardCharsets.UTF_8));

            // Combine IV + encrypted data (tag is appended by GCM mode)
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            // Base64 URL-safe encode
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(combined);

            SsoToken result = new SsoToken();
            result.success = true;
            result.token = token;
            result.redirectUrl = roundcubeUrl + "/?_sso=" + token;
            result.expiresAt = timestamp + TOKEN_EXPIRY_SECONDS;

            return result;

        } catch (Exception e) {
            SsoToken result = new SsoToken();
            result.success = false;
            result.error = "Token generation failed: " + e.getMessage();
            return result;
        }
    }

    /**
     * Escape special characters for JSON string
     */
    private String escapeJson(String input) {
        if (input == null) return "";
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    /**
     * Validate SSO token (used by Roundcube plugin via shared secret)
     */
    public TokenValidation validateToken(String token, String clientIp) {
        try {
            // Base64 decode
            byte[] combined = Base64.getUrlDecoder().decode(token);

            // Extract IV and encrypted data
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);

            // Decrypt
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            String tokenData = new String(decrypted, StandardCharsets.UTF_8);

            // Parse: email|timestamp|ip|nonce
            String[] parts = tokenData.split("\\|");
            if (parts.length != 4) {
                return TokenValidation.invalid("Invalid token format");
            }

            String email = parts[0];
            long timestamp = Long.parseLong(parts[1]);
            String tokenIp = parts[2];

            // Check expiry
            long now = Instant.now().getEpochSecond();
            if (now - timestamp > TOKEN_EXPIRY_SECONDS) {
                return TokenValidation.invalid("Token expired");
            }

            // Check IP binding
            if (!tokenIp.equals(clientIp)) {
                return TokenValidation.invalid("IP mismatch");
            }

            // Verify user exists using getMailboxByEmail
            try {
                MailDatabase.Mailbox mailbox = database.getMailboxByEmail(email);
                if (mailbox == null) {
                    return TokenValidation.invalid("User not found");
                }
            } catch (Exception e) {
                return TokenValidation.invalid("Database error: " + e.getMessage());
            }

            // For SSO, we don't pass the password - Roundcube will use master password or dovecot passdb
            TokenValidation result = new TokenValidation();
            result.valid = true;
            result.email = email;
            result.password = ""; // SSO uses token-based auth, not password
            return result;

        } catch (Exception e) {
            return TokenValidation.invalid("Token validation failed: " + e.getMessage());
        }
    }

    /**
     * Install SSO plugin in Roundcube
     * Always overwrites existing plugin to ensure it's up-to-date
     */
    public InstallResult installPlugin() {
        InstallResult result = new InstallResult();

        try {
            // Check Roundcube exists
            if (!Files.exists(Paths.get(ROUNDCUBE_PATH))) {
                result.success = false;
                result.error = "Roundcube not found at " + ROUNDCUBE_PATH;
                return result;
            }

            System.out.println("[SSO] Installing Roundcube SSO plugin...");

            // Create plugin directory (using shell to ensure proper permissions)
            executeCommand("mkdir -p " + SSO_PLUGIN_PATH);

            // Generate plugin files
            String pluginPhp = generatePluginPhp();
            String configPhp = generatePluginConfig();

            // Write files using shell commands to handle permissions properly
            // This ensures the files are written even if they exist with different ownership
            Path pluginFile = Paths.get(SSO_PLUGIN_PATH, "mailpanel_sso.php");
            Path configFile = Paths.get(SSO_PLUGIN_PATH, "config.inc.php");

            // Remove old files first
            executeCommand("rm -f " + pluginFile + " " + configFile);

            // Write new files
            Files.writeString(pluginFile, pluginPhp);
            Files.writeString(configFile, configPhp);

            System.out.println("[SSO] Plugin files written");

            // Enable plugin in Roundcube config
            enablePluginInConfig();
            System.out.println("[SSO] Plugin enabled in Roundcube config");

            // Webmail password changes go through the panel (hash + encrypted copy together)
            if (panelPort > 0) {
                boolean changed = WebmailPasswordConfig.ensure(Paths.get(ROUNDCUBE_CONFIG), panelPort,
                        org.mail_panel.security.PanelSecrets.webmailKey());
                System.out.println("[SSO] Webmail password changes routed through the panel" + (changed ? " (config updated)" : ""));
                // Con opcache.validate_timestamps=0 PHP-FPM terrebbe la configurazione di prima
                if (changed) executeCommand("service php_fpm reload >/dev/null 2>&1 || true");
            }

            // Set permissions. Il codice e' di root: chi gira come la webmail non lo puo' cambiare.
            // La configurazione ha il segreto dei gettoni (con dentro la password master di Dovecot)
            // e la chiave del vault: la legge solo il gruppo con cui gira il PHP di Roundcube,
            // roundcube dopo la migrazione (RoundcubeUser), www prima. Non piu' nginx.
            executeCommand("chown -R root:wheel " + SSO_PLUGIN_PATH);
            executeCommand("chmod 755 " + SSO_PLUGIN_PATH);
            executeCommand("chmod 644 " + SSO_PLUGIN_PATH + "/mailpanel_sso.php");
            executeCommand("chown root:" + org.mail_panel.system.RoundcubeUser.runtimeGroup() + " " + SSO_PLUGIN_PATH + "/config.inc.php");
            executeCommand("chmod 640 " + SSO_PLUGIN_PATH + "/config.inc.php");

            result.success = true;
            result.message = "SSO plugin installed successfully";
            result.pluginPath = SSO_PLUGIN_PATH;
            System.out.println("[SSO] Plugin installation complete");

        } catch (Exception e) {
            result.success = false;
            result.error = "Plugin installation failed: " + e.getMessage();
            System.err.println("[SSO] Plugin installation failed: " + e.getMessage());
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Generate Roundcube SSO plugin PHP code
     * Uses master user authentication for admin SSO access
     */
    public static String generatePluginPhp() {
        return """
<?php
/**
 * Mail Panel SSO Plugin for Roundcube
 * Auto-login users from Mail Panel with encrypted tokens
 * Uses Dovecot master user for authentication
 */
class mailpanel_sso extends rcube_plugin
{
    public $task = 'login|mail';
    private $sso_user = null;
    private $sso_pass = null;

    function init()
    {
        $this->load_config();
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('authenticate', array($this, 'authenticate'));
        $this->add_hook('login_after', array($this, 'login_after'));
    }

    /**
     * After a login with the mailbox's own password (not the panel's master-user login), the
     * panel stores the encrypted copy of that password if it is missing or out of date, so the
     * password can always be shown in the panel. The panel checks it against the bcrypt hash
     * first. If the panel does not answer, the login goes on as usual.
     */
    function login_after($args)
    {
        if ($this->sso_user) {
            return $args;
        }
        $rcmail = rcmail::get_instance();
        $url = $rcmail->config->get('mailpanel_vault_url');
        $key = $rcmail->config->get('mailpanel_vault_key');
        $user = $rcmail->get_user_name();
        $pass = $rcmail->get_user_password();
        if (empty($url) || empty($key) || empty($user) || !is_string($pass) || $pass === '' || strpos($user, '*') !== false) {
            return $args;
        }
        try {
            $client = $rcmail->get_http_client(array('verify' => false, 'timeout' => 5, 'http_errors' => false));
            $client->request('POST', $url, array(
                'form_params' => array('user' => $user, 'pass' => $pass),
                'headers' => array('X-MailPanel-Key' => $key),
            ));
        } catch (Exception $e) {
            rcube::write_log('errors', 'mailpanel_sso: the mail panel did not answer the password copy request');
        }
        return $args;
    }

    function startup($args)
    {
        $rcmail = rcmail::get_instance();

        // Check for SSO token in URL
        $token = rcube_utils::get_input_value('_sso', rcube_utils::INPUT_GET);

        if ($token) {
            // Force logout if already logged in (SSO switch user)
            if ($rcmail->user->ID) {
                $rcmail->kill_session();
            }

            $validation = $this->validate_token($token);

            if ($validation['valid']) {
                // Store credentials for authenticate hook
                $this->sso_user = $validation['email'];
                $this->sso_pass = $validation['password'];

                // Force login task
                $args['task'] = 'login';
                $args['action'] = 'login';

                // Set POST values for login form
                $_POST['_user'] = $this->sso_user;
                $_POST['_pass'] = $this->sso_pass;
                $_POST['_task'] = 'login';
                $_POST['_action'] = 'login';
                $_REQUEST['_task'] = 'login';
                $_REQUEST['_action'] = 'login';
            } else {
                error_log('mailpanel_sso: Token validation failed - ' . ($validation['error'] ?? 'unknown'));
            }
        }

        return $args;
    }

    /**
     * Authenticate hook - inject SSO credentials into login process
     * This is the proper way to do SSO in Roundcube
     */
    function authenticate($args)
    {
        if ($this->sso_user && $this->sso_pass) {
            $args['user'] = $this->sso_user;
            $args['pass'] = $this->sso_pass;
            $args['cookiecheck'] = false;
            $args['valid'] = true;
        }
        return $args;
    }

    private function validate_token($token)
    {
        $rcmail = rcmail::get_instance();
        $secret = $rcmail->config->get('mailpanel_sso_secret');

        if (empty($secret)) {
            error_log('mailpanel_sso: Secret not configured');
            return array('valid' => false, 'error' => 'SSO not configured');
        }

        try {
            // Base64 URL decode
            $token = str_replace(array('-', '_'), array('+', '/'), $token);
            $padding = 4 - (strlen($token) % 4);
            if ($padding < 4) {
                $token .= str_repeat('=', $padding);
            }
            $combined = base64_decode($token, true);

            if ($combined === false || strlen($combined) < 28) {
                error_log('mailpanel_sso: Invalid token length: ' . strlen($combined));
                return array('valid' => false, 'error' => 'Invalid token');
            }

            // Extract IV (12 bytes) and encrypted data with tag
            $iv = substr($combined, 0, 12);
            $ciphertext_with_tag = substr($combined, 12);

            // GCM tag is last 16 bytes
            $tag = substr($ciphertext_with_tag, -16);
            $ciphertext = substr($ciphertext_with_tag, 0, -16);

            // Decrypt with AES-256-GCM
            $key = base64_decode($secret);

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            if ($decrypted === false) {
                error_log('mailpanel_sso: Decryption failed - ' . openssl_error_string());
                return array('valid' => false, 'error' => 'Decryption failed');
            }

            // Parse JSON format
            $data = json_decode($decrypted, true);

            if (!$data || !isset($data['email']) || !isset($data['timestamp'])) {
                error_log('mailpanel_sso: Invalid token content');
                return array('valid' => false, 'error' => 'Invalid token format');
            }

            // Check expiry (60 seconds)
            if (time() - intval($data['timestamp']) > 60) {
                error_log('mailpanel_sso: Token expired');
                return array('valid' => false, 'error' => 'Token expired');
            }

            $email = $data['email'];
            $password = isset($data['password']) ? $data['password'] : '';
            $master_user = isset($data['master_user']) ? $data['master_user'] : '';

            // If master user is provided, use master authentication
            if (!empty($master_user) && !empty($password)) {
                $login_user = $email . '*' . $master_user;
                return array(
                    'valid' => true,
                    'email' => $login_user,
                    'password' => $password
                );
            }

            // Direct password login
            if (!empty($password)) {
                return array(
                    'valid' => true,
                    'email' => $email,
                    'password' => $password
                );
            }

            error_log('mailpanel_sso: Empty password in token');
            return array('valid' => false, 'error' => 'Empty password');

        } catch (Exception $e) {
            error_log('mailpanel_sso: Exception - ' . $e->getMessage());
            return array('valid' => false, 'error' => $e->getMessage());
        }
    }
}
""";
    }

    /**
     * Generate plugin config with shared secret
     */
    private String generatePluginConfig() {
        String base64Secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        String vault = panelPort > 0
                ? "$config['mailpanel_vault_url'] = 'https://127.0.0.1:" + panelPort + WebmailPasswordConfig.VAULT_PATH + "';\n"
                  + "$config['mailpanel_vault_key'] = '" + org.mail_panel.security.PanelSecrets.webmailKey() + "';\n"
                : "";
        return String.format("""
<?php
// Mail Panel SSO Configuration
// DO NOT EDIT - Generated automatically

$config['mailpanel_sso_secret'] = '%s';
$config['mailpanel_sso_enabled'] = true;
$config['mailpanel_sso_token_expiry'] = %d;
""", base64Secret, TOKEN_EXPIRY_SECONDS) + vault;
    }

    /**
     * Enable plugin in Roundcube config
     */
    private void enablePluginInConfig() throws Exception {
        Path configPath = Paths.get(ROUNDCUBE_CONFIG);
        if (!Files.exists(configPath)) {
            throw new Exception("Roundcube config not found");
        }

        String config = Files.readString(configPath);

        // Check if plugin already enabled
        if (config.contains("mailpanel_sso")) {
            System.out.println("[SSO] Plugin already enabled in config");
            return; // Already enabled
        }

        // Find plugins array and add our plugin
        // Handle both syntaxes: array('...') and ['...']
        if (config.contains("$config['plugins']")) {
            // Try modern syntax first: $config['plugins'] = [
            if (config.contains("['plugins'] = [")) {
                config = config.replaceFirst(
                    "(\\$config\\['plugins'\\]\\s*=\\s*\\[)",
                    "$1\n    'mailpanel_sso',"
                );
            }
            // Try array() syntax: $config['plugins'] = array('
            else if (config.contains("['plugins'] = array(")) {
                // Handle: array('first' -> array('mailpanel_sso', 'first'
                config = config.replaceFirst(
                    "(\\$config\\['plugins'\\]\\s*=\\s*array\\()'",
                    "$1'mailpanel_sso', '"
                );
                // Handle: array( with newline
                if (!config.contains("mailpanel_sso")) {
                    config = config.replaceFirst(
                        "(\\$config\\['plugins'\\]\\s*=\\s*array\\()",
                        "$1'mailpanel_sso', "
                    );
                }
            }
        } else {
            // Add plugins config
            config += "\n\n// Mail Panel SSO Plugin\n$config['plugins'] = ['mailpanel_sso'];\n";
        }

        Files.writeString(configPath, config);
    }

    /**
     * Check if SSO is configured
     */
    public SsoStatus getStatus() {
        SsoStatus status = new SsoStatus();

        try {
            // Check Roundcube installation
            status.roundcubeInstalled = Files.exists(Paths.get(ROUNDCUBE_PATH));
            status.roundcubePath = ROUNDCUBE_PATH;

            // Check plugin installation
            status.pluginInstalled = Files.exists(Paths.get(SSO_PLUGIN_PATH, "mailpanel_sso.php"));
            status.pluginPath = SSO_PLUGIN_PATH;

            // Check secret file
            status.secretConfigured = Files.exists(Paths.get(SSO_SECRET_FILE));

            // Check if plugin enabled in config
            if (Files.exists(Paths.get(ROUNDCUBE_CONFIG))) {
                String config = Files.readString(Paths.get(ROUNDCUBE_CONFIG));
                status.pluginEnabled = config.contains("mailpanel_sso");
            }

            status.configured = status.roundcubeInstalled &&
                               status.pluginInstalled &&
                               status.secretConfigured &&
                               status.pluginEnabled;

            status.roundcubeUrl = roundcubeUrl;

        } catch (Exception e) {
            status.error = e.getMessage();
        }

        return status;
    }

    /**
     * Uninstall SSO plugin
     */
    public boolean uninstallPlugin() {
        try {
            // Remove plugin directory
            if (Files.exists(Paths.get(SSO_PLUGIN_PATH))) {
                executeCommand("rm -rf " + SSO_PLUGIN_PATH);
            }

            // Remove from Roundcube config
            Path configPath = Paths.get(ROUNDCUBE_CONFIG);
            if (Files.exists(configPath)) {
                String config = Files.readString(configPath);
                config = config.replace("'mailpanel_sso',", "");
                config = config.replace("'mailpanel_sso'", "");
                Files.writeString(configPath, config);
            }

            return true;
        } catch (Exception e) {
            System.err.println("Failed to uninstall SSO plugin: " + e.getMessage());
            return false;
        }
    }

    private String executeCommand(String command) throws Exception {
        // TODO: migrate to Shell.run when touched
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        org.mail_panel.util.Shell.applyPath(pb);
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

    // Result classes
    public static class SsoToken {
        public boolean success;
        public String token;
        public String redirectUrl;
        public long expiresAt;
        public String error;
    }

    public static class TokenValidation {
        public boolean valid;
        public String email;
        public String password;
        public String error;

        public static TokenValidation invalid(String error) {
            TokenValidation v = new TokenValidation();
            v.valid = false;
            v.error = error;
            return v;
        }
    }

    public static class InstallResult {
        public boolean success;
        public String message;
        public String pluginPath;
        public String error;
    }

    public static class SsoStatus {
        public boolean configured;
        public boolean roundcubeInstalled;
        public String roundcubePath;
        public boolean pluginInstalled;
        public String pluginPath;
        public boolean secretConfigured;
        public boolean pluginEnabled;
        public String roundcubeUrl;
        public String error;
    }
}
