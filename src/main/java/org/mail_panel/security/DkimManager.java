package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * DKIM Key Manager for FreeBSD Mail Panel
 *
 * Generates RSA 2048-bit key pairs for DKIM signing.
 * Stores keys in database and writes to filesystem for Rspamd.
 *
 * DKIM (DomainKeys Identified Mail) allows the receiver to check
 * that an email was indeed sent and authorized by the owner of that domain.
 */
public class DkimManager {

    // DKIM key storage paths
    private static final String DKIM_KEY_DIR = "/usr/local/etc/mail/dkim";
    private static final String RSPAMD_DKIM_CONFIG = "/usr/local/etc/rspamd/local.d/dkim_signing.conf";

    // RSA key size (2048 is the minimum recommended, 4096 for higher security)
    private static final int RSA_KEY_SIZE = 2048;

    private final MailDatabase database;

    public DkimManager(MailDatabase database) {
        this.database = database;
    }

    /**
     * Generate DKIM keys for a domain
     *
     * @param domainId Database ID of the domain
     * @param domain Domain name (e.g., example.com)
     * @param selector DKIM selector (default: "mail")
     * @return DkimResult with success status and public key for DNS
     */
    public DkimResult generateDkimKeys(int domainId, String domain, String selector) {
        try {
            // Generate RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            // Get private key in PEM format
            String privateKeyPem = formatPrivateKeyPem(keyPair.getPrivate());

            // Get public key in DNS format (base64, no headers)
            String publicKeyDns = formatPublicKeyDns(keyPair.getPublic());

            // Full DNS TXT record value
            String dnsRecord = buildDkimDnsRecord(publicKeyDns);

            // Save to database
            database.setDkim(domainId, selector, privateKeyPem, publicKeyDns);

            // Write private key to filesystem for Rspamd
            writePrivateKeyFile(domain, selector, privateKeyPem);

            // Update Rspamd configuration
            updateRspamdConfig();

            return new DkimResult(true, selector, publicKeyDns, dnsRecord, null);

        } catch (Exception e) {
            return new DkimResult(false, selector, null, null, e.getMessage());
        }
    }

    /**
     * Format private key as PEM
     */
    private String formatPrivateKeyPem(PrivateKey privateKey) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN RSA PRIVATE KEY-----\n");

        String base64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        // Split into 64-character lines
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64.substring(i, Math.min(i + 64, base64.length())));
            pem.append("\n");
        }

        pem.append("-----END RSA PRIVATE KEY-----\n");
        return pem.toString();
    }

    /**
     * Format public key for DNS TXT record (base64, no line breaks)
     */
    private String formatPublicKeyDns(PublicKey publicKey) {
        // Extract the raw RSA public key (SubjectPublicKeyInfo format)
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Build the complete DKIM DNS TXT record value
     */
    private String buildDkimDnsRecord(String publicKeyBase64) {
        return "v=DKIM1; k=rsa; p=" + publicKeyBase64;
    }

    /**
     * Write private key to filesystem for Rspamd to use
     */
    private void writePrivateKeyFile(String domain, String selector, String privateKeyPem) throws IOException {
        // Create directory if not exists
        Path keyDir = Paths.get(DKIM_KEY_DIR);
        Files.createDirectories(keyDir);

        // Write private key file
        Path keyFile = keyDir.resolve(domain + "." + selector + ".key");
        Files.writeString(keyFile, privateKeyPem);

        // Set secure permissions (readable only by rspamd user)
        keyFile.toFile().setReadable(false, false);
        keyFile.toFile().setReadable(true, true);
        keyFile.toFile().setWritable(false, false);
        keyFile.toFile().setWritable(true, true);

        // Change ownership to rspamd (requires running as root)
        try {
            ProcessBuilder pb = new ProcessBuilder("chown", "rspamd:rspamd", keyFile.toString());
            pb.start().waitFor();

            pb = new ProcessBuilder("chmod", "600", keyFile.toString());
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Update Rspamd DKIM signing configuration with all domains
     */
    public void updateRspamdConfig() throws Exception {
        StringBuilder config = new StringBuilder();
        config.append("# DKIM Signing Configuration\n");
        config.append("# Auto-generated by FreeBSD Mail Panel\n");
        config.append("# DO NOT EDIT MANUALLY\n\n");
        config.append("allow_username_mismatch = true;\n\n");
        config.append("domain {\n");

        // Get all domains with DKIM configured
        for (MailDatabase.Domain domain : database.getDomains()) {
            if (domain.hasDkim && domain.dkimPrivateKey != null) {
                String keyPath = DKIM_KEY_DIR + "/" + domain.domain + "." + domain.dkimSelector + ".key";
                config.append("    ").append(domain.domain).append(" {\n");
                config.append("        path = \"").append(keyPath).append("\";\n");
                config.append("        selector = \"").append(domain.dkimSelector).append("\";\n");
                config.append("    }\n");
            }
        }

        config.append("}\n");

        // Write configuration
        Path configPath = Paths.get(RSPAMD_DKIM_CONFIG);
        Files.createDirectories(configPath.getParent());
        Files.writeString(configPath, config.toString());

        // Reload Rspamd to apply changes
        try {
            ProcessBuilder pb = new ProcessBuilder("service", "rspamd", "reload");
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Get DKIM info for a domain (for display in UI)
     */
    public DkimInfo getDkimInfo(int domainId) throws Exception {
        MailDatabase.Domain domain = database.getDomain(domainId);
        if (domain == null) {
            return null;
        }

        DkimInfo info = new DkimInfo();
        info.domain = domain.domain;
        info.selector = domain.dkimSelector != null ? domain.dkimSelector : "mail";
        info.configured = domain.hasDkim;

        if (domain.hasDkim && domain.dkimPublicKey != null) {
            info.publicKey = domain.dkimPublicKey;
            info.dnsRecordName = info.selector + "._domainkey." + domain.domain;
            info.dnsRecordValue = buildDkimDnsRecord(domain.dkimPublicKey);

            // Check if key file exists
            Path keyFile = Paths.get(DKIM_KEY_DIR, domain.domain + "." + info.selector + ".key");
            info.keyFileExists = Files.exists(keyFile);
        }

        return info;
    }

    /**
     * Delete DKIM configuration for a domain
     */
    public boolean deleteDkim(int domainId) {
        try {
            MailDatabase.Domain domain = database.getDomain(domainId);
            if (domain == null) {
                return false;
            }

            // Delete key file
            String selector = domain.dkimSelector != null ? domain.dkimSelector : "mail";
            Path keyFile = Paths.get(DKIM_KEY_DIR, domain.domain + "." + selector + ".key");
            Files.deleteIfExists(keyFile);

            // Clear from database
            database.setDkim(domainId, "mail", null, null);

            // Update Rspamd config
            updateRspamdConfig();

            return true;
        } catch (Exception e) {
            System.err.println("Error deleting DKIM: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify DKIM DNS record is properly configured
     * Uses dig to check if the record exists and matches
     */
    public DkimVerifyResult verifyDkimDns(String domain, String selector) {
        try {
            String recordName = selector + "._domainkey." + domain;

            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "TXT", recordName);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }

            process.waitFor();

            String result = output.toString().trim();
            if (result.isEmpty()) {
                return new DkimVerifyResult(false, "DNS record not found: " + recordName);
            }

            // Check if it contains DKIM1
            if (result.contains("v=DKIM1") && result.contains("k=rsa") && result.contains("p=")) {
                return new DkimVerifyResult(true, "DKIM DNS record verified successfully");
            } else {
                return new DkimVerifyResult(false, "Invalid DKIM record format: " + result);
            }

        } catch (Exception e) {
            return new DkimVerifyResult(false, "Error verifying DNS: " + e.getMessage());
        }
    }

    // ============== Result Classes ==============

    public static class DkimResult {
        public final boolean success;
        public final String selector;
        public final String publicKey;
        public final String dnsRecord;
        public final String error;

        public DkimResult(boolean success, String selector, String publicKey, String dnsRecord, String error) {
            this.success = success;
            this.selector = selector;
            this.publicKey = publicKey;
            this.dnsRecord = dnsRecord;
            this.error = error;
        }
    }

    public static class DkimInfo {
        public String domain;
        public String selector;
        public boolean configured;
        public String publicKey;
        public String dnsRecordName;
        public String dnsRecordValue;
        public boolean keyFileExists;
    }

    public static class DkimVerifyResult {
        public final boolean valid;
        public final String message;

        public DkimVerifyResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
    }
}
