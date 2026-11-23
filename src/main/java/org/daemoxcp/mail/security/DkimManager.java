package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * DKIM Key Manager for DaemoxCP Mail
 *
 * Generates RSA 2048-bit key pairs for DKIM signing.
 * Stores keys in database and writes to filesystem for Rspamd.
 *
 * DKIM (DomainKeys Identified Mail) allows the receiver to check
 * that an email was indeed sent and authorized by the owner of that domain.
 */
public class DkimManager {

    // DKIM key storage paths
    private static final java.util.logging.Logger LOGGER = java.util.logging.Logger.getLogger(DkimManager.class.getName());
    private static final String DKIM_KEY_DIR = "/usr/local/etc/mail/dkim";
    private static final String RSPAMD_DKIM_CONFIG = "/usr/local/etc/rspamd/local.d/dkim_signing.conf";

    // RSA key size (2048 is the minimum recommended, 4096 for higher security)
    private static final int RSA_KEY_SIZE = 2048;

    /**
     * Recommended rotation presets (in days).
     * Reference: NIST SP 800-177 and M3AAWG Email Authentication best practices:
     *  - aggressive: every month (high security)
     *  - recommended: every 3 months (industry best practice)
     *  - balanced: every 6 months
     *  - minimal: every 12 months (less often than this is not recommended)
     */
    public static final int PRESET_AGGRESSIVE   = 30;
    public static final int PRESET_RECOMMENDED  = 90;
    public static final int PRESET_BALANCED     = 180;
    public static final int PRESET_MINIMAL      = 365;

    private final MailDatabase database;
    private CloudflareManager cloudflare;

    public DkimManager(MailDatabase database) {
        this.database = database;
    }

    /** Optional: attaches a CloudflareManager for automatic rotation. */
    public void setCloudflareManager(CloudflareManager cf) {
        this.cloudflare = cf;
    }

    /**
     * Trigger context: tracks "who" started the current operation
     * ("user" = UI click / API call, "scheduler" = automatic timer).
     * The caller sets it with the try-finally pattern (API handler or scheduler).
     */
    public static final ThreadLocal<String> CURRENT_TRIGGER = new ThreadLocal<>();

    /** Returns the current trigger, default "user" if not set. */
    private static String currentTrigger() {
        String t = CURRENT_TRIGGER.get();
        return (t == null || t.isEmpty()) ? "user" : t;
    }

    /**
     * Events that are part of the "rotation chain" and must inherit the mode
     * from the domain's {@code dkim_rotation_mode} (if not specified explicitly).
     */
    private static final java.util.Set<String> ROTATION_CHAIN_EVENTS = java.util.Set.of(
        "dns_published", "dns_propagated", "key_activated",
        "rotation_completed", "rotation_cancelled"
    );

    /**
     * Helper: records an event in the rotation history.
     * If `mode` is null and the event is part of the rotation chain, it inherits
     * the mode from the domain's `dkim_rotation_mode` field.
     * Silently catches any errors (logging must not block the workflow).
     */
    private void logEvent(MailDatabase.Domain d, String eventType, String selector,
                          String mode, boolean success, String message) {
        logEventWithPrevious(d, eventType, selector, null, mode, success, message);
    }

    /**
     * Variant of logEvent that also records the previous_selector. To be used for
     * key_activated, so we know when a selector was deactivated.
     */
    private void logEventWithPrevious(MailDatabase.Domain d, String eventType, String selector,
                                      String previousSelector, String mode, boolean success, String message) {
        try {
            String effectiveMode = mode;
            if (effectiveMode == null && d != null && d.dkimRotationMode != null
                && ROTATION_CHAIN_EVENTS.contains(eventType)) {
                effectiveMode = d.dkimRotationMode;
            }
            Integer cfId = null;
            String cfLabel = null;
            if (cloudflare != null && d != null) {
                try {
                    MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(d.id);
                    if (acct != null) {
                        cfId = acct.id;
                        cfLabel = acct.label;
                    }
                } catch (Exception ignore) {}
            }
            database.logDkimRotationEvent(
                d == null ? 0 : d.id,
                d == null ? "" : d.domain,
                eventType, selector, previousSelector, effectiveMode, currentTrigger(),
                cfId, cfLabel, success, message);
        } catch (Exception e) {
            System.err.println("[DKIM-Rotation] logEvent failed: " + e.getMessage());
        }
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
            NewKey k = newKey(selector);
            install(domainId, domain, k);
            return new DkimResult(true, selector, k.publicKeyDns(), k.dnsRecord(), null);

        } catch (Exception e) {
            return new DkimResult(false, selector, null, null, e.getMessage());
        }
    }

    /** A freshly made key pair, in memory only: nobody uses it until it is installed. */
    public record NewKey(String selector, String privateKeyPem, String publicKeyDns, String dnsRecord) {}

    /** A new RSA pair, without touching the database, files or rspamd. */
    public NewKey newKey(String selector) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        String publicKeyDns = formatPublicKeyDns(keyPair.getPublic());
        return new NewKey(selector, formatPrivateKeyPem(keyPair.getPrivate()), publicKeyDns, buildDkimDnsRecord(publicKeyDns));
    }

    /** The outcome of the DKIM step of "Configure everything": succeeded or not, and the sentence to show. */
    public record RecordStep(boolean ok, String message) {}

    public interface NewKeySource { NewKey make(String selector) throws Exception; }

    public interface KeyInstaller { void install(NewKey k) throws Exception; }

    /**
     * The domain's DKIM key and its record, in this order: signing happens only with a key whose record is really
     * in the zone. Before, the key was saved and rspamd signed right away, then publishing was attempted: if there was
     * already a record on that name, or Cloudflare refused, mail went out signed with a key nobody could verify. And
     * the next round said "present" only because the key was in the database.
     *
     * With a key already in the database: if its record is there, all good; if on that name there is a record with
     * another key, this is reported and that record is left alone; if there is nothing, the record of the existing
     * key is published. Without a key: if the name is taken nothing is done; otherwise a new key in memory, record,
     * read back, and only then the installer (database, file, signing). A zone that cannot be read throws
     * ZoneReadException and nothing is written.
     */
    public static RecordStep ensurePublished(CloudflareManager cf, String token, String zoneId, String domain,
                                             String selector, String publicKey,
                                             NewKeySource newKey, KeyInstaller installer) throws Exception {
        boolean hasKey = selector != null && !selector.isBlank() && publicKey != null && !publicKey.isBlank();
        String sel = hasKey ? selector : "mail";
        String name = sel + "._domainkey." + domain;
        java.util.List<String> here = dkimContents(cf, token, zoneId, name);

        if (hasKey) {
            String expected = "p=" + publicKey.replaceAll("\\s", "");
            for (String c : here)
                if (c.replaceAll("\\s", "").contains(expected))
                    return new RecordStep(true, I18n.tr("server.cfgdom.dkimPresent", java.util.Map.of("s", sel)));
            if (!here.isEmpty())
                return new RecordStep(false, I18n.tr("server.cfgdom.dkimOtherKey", java.util.Map.of("name", name, "d", domain)));
            // The key exists and already signs, but its record is missing: publish the one for the existing key.
            return publishThenInstall(cf, token, zoneId, name, "v=DKIM1; k=rsa; p=" + publicKey, null, null);
        }

        if (!here.isEmpty())
            return new RecordStep(false, I18n.tr("server.cfgdom.dkimExists", java.util.Map.of("name", name)));
        NewKey k = newKey.make(sel);
        return publishThenInstall(cf, token, zoneId, name, k.dnsRecord(), k, installer);
    }

    /** The contents of the TXT records that sit exactly on that name. */
    private static java.util.List<String> dkimContents(CloudflareManager cf, String token, String zoneId, String name) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : cf.listTxtRecordsContaining(token, zoneId, name))
            if (t.name != null && t.name.equalsIgnoreCase(name)) out.add(DnsRules.cloudflareContent(t.content));
        return out;
    }

    /** Creates the record, reads it back, and only if it is there installs the new key (if there is one). */
    private static RecordStep publishThenInstall(CloudflareManager cf, String token, String zoneId, String name,
                                                 String value, NewKey k, KeyInstaller installer) throws Exception {
        CloudflareManager.RecordOp op = cf.createTxtRecord(token, zoneId, name, value, 3600);
        if (op == null || !op.success)
            return new RecordStep(false, I18n.tr("server.cfgdom.dkimRejected", java.util.Map.of("err",
                    String.valueOf(op == null ? I18n.tr("server.cfgdom.noAnswer") : op.error))));
        String key = value.substring(value.indexOf("p=")).replaceAll("\\s", "");
        boolean seen = false;
        for (String c : dkimContents(cf, token, zoneId, name))
            if (c.replaceAll("\\s", "").contains(key)) seen = true;
        if (!seen)
            return new RecordStep(false, I18n.tr("server.cfgdom.dkimNotConfirmed", java.util.Map.of("name", name)));
        if (k != null && installer != null) installer.install(k);
        return new RecordStep(true, I18n.tr("server.cfgdom.dkimPublished", java.util.Map.of("name", name)));
    }

    /**
     * The key becomes the domain's key and rspamd starts signing with it. "Configure everything" installs it only
     * after seeing its record published (DomainSetup): signing earlier would mean sending mail with a signature that
     * nobody can verify, if publishing then fails.
     */
    public void install(int domainId, String domain, NewKey k) throws Exception {
        database.setDkim(domainId, k.selector(), k.privateKeyPem(), k.publicKeyDns());
        writePrivateKeyFile(domain, k.selector(), k.privateKeyPem());
        updateRspamdConfig();
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
     * The key file of a domain with a selector. Domain and selector come from MySQL, which, with the panel
     * separated, the web part can also write: here, where root turns them into a path, they must have the shape of a
     * domain and of a selector (SafeNames), and the file must stay inside the keys folder. Before, a domain
     * like {@code ../x} made root write or delete a file outside the folder.
     *
     * @throws IllegalArgumentException if either of the two names does not pass
     */
    static Path keyFile(String domain, String selector) {
        if (!SafeNames.domain(domain) || !SafeNames.selector(selector))
            throw new IllegalArgumentException("invalid DKIM domain or selector");
        return SafeNames.under(Paths.get(DKIM_KEY_DIR), domain + "." + selector + ".key");
    }

    /**
     * Write private key to filesystem for Rspamd to use
     */
    private void writePrivateKeyFile(String domain, String selector, String privateKeyPem) throws IOException {
        // Create directory if not exists
        Path keyDir = Paths.get(DKIM_KEY_DIR);
        Files.createDirectories(keyDir);

        // Write private key file
        Path keyFile = keyFile(domain, selector);
        Files.writeString(keyFile, privateKeyPem);

        // Set secure permissions (readable only by rspamd user)
        keyFile.toFile().setReadable(false, false);
        keyFile.toFile().setReadable(true, true);
        keyFile.toFile().setWritable(false, false);
        keyFile.toFile().setWritable(true, true);

        // Change ownership to rspamd (requires running as root)
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("chown", "rspamd:rspamd", keyFile.toString());
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.start().waitFor();

            // TODO: migrate to Shell.run when touched
            pb = new ProcessBuilder("chmod", "600", keyFile.toString());
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Update Rspamd DKIM signing configuration with all domains.
     *
     * For each domain ONLY the currently active selector (dkim_*) is written.
     * The "pending" key is not used for signing yet: it is only published in DNS.
     * The "previous" key no longer signs (mail in transit is validated by the recipients
     * with the TXT record we leave in DNS during the grace period).
     */
    public void updateRspamdConfig() throws Exception {
        String config = rspamdConfigText();

        // Write configuration (0644: rspamd reads it with its own user, and the root part has a strict umask)
        Path configPath = Paths.get(RSPAMD_DKIM_CONFIG);
        Files.createDirectories(configPath.getParent());
        Files.writeString(configPath, config);
        Files.setPosixFilePermissions(configPath, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));

        // Reload Rspamd to apply changes
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", "rspamd", "reload");
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** The line that makes Rspamd sign only the domains with their own key (system.DkimFallback). */
    public static final String NO_FALLBACK = "try_fallback = false;";
    public static final String CONFIG_PATH = RSPAMD_DKIM_CONFIG;
    /** The start of the file as {@link #rspamdConfigText()} writes it. */
    public static final String CONFIG_HEADER = "# DKIM Signing Configuration\n# Auto-generated by ";

    /**
     * The text of dkim_signing.conf: the domains with DKIM, each with its active selector. try_fallback = false: a
     * domain that is not here is not signed, instead of looking for a key in /var/db/rspamd/dkim (which is not there:
     * an error in the Rspamd log for every local or authenticated message of that domain, for example root's
     * reports).
     */
    public String rspamdConfigText() throws java.sql.SQLException {
        StringBuilder config = new StringBuilder();
        config.append("# DKIM Signing Configuration\n");
        config.append("# Auto-generated by DaemoxCP Mail\n");
        config.append("# DO NOT EDIT MANUALLY\n\n");
        config.append("allow_username_mismatch = true;\n");
        config.append(NO_FALLBACK).append("\n\n");
        config.append("domain {\n");

        // Get all domains with DKIM configured
        for (MailDatabase.Domain domain : database.getDomains()) {
            if (domain.hasDkim && domain.dkimPrivateKey != null) {
                // Domain and selector from MySQL inside the rspamd configuration: only with their proper shape.
                if (!SafeNames.domain(domain.domain) || !SafeNames.selector(domain.dkimSelector)) {
                    LOGGER.warning("[DKIM] domain id " + domain.id + " has an invalid name or selector: left out of the signing configuration");
                    continue;
                }
                String keyPath = keyFile(domain.domain, domain.dkimSelector).toString();
                config.append("    ").append(domain.domain).append(" {\n");
                config.append("        path = \"").append(keyPath).append("\";\n");
                config.append("        selector = \"").append(domain.dkimSelector).append("\";\n");
                config.append("    }\n");
            }
        }

        config.append("}\n");
        return config.toString();
    }

    /**
     * STRICT check that the currently active DKIM key is actually
     * published in DNS. Compares the public key saved in the DB with the one
     * in the TXT record <selector>._domainkey.<domain>.
     *
     * Queries 1.1.1.1 and 8.8.8.8 (external public resolvers) to avoid local caches.
     *
     * Logs a "key_verified" event in the history.
     */
    public ActiveKeyVerifyResult verifyActiveKeyInDns(int domainId) {
        ActiveKeyVerifyResult r = new ActiveKeyVerifyResult();
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                r.success = false; r.message = I18n.tr("server.dkimm.domainNotFound"); return r;
            }
            r.domain = d.domain;
            r.selector = d.dkimSelector;
            r.dnsRecordName = (d.dkimSelector == null ? "mail" : d.dkimSelector) + "._domainkey." + d.domain;

            if (!d.hasDkim || d.dkimPublicKey == null) {
                r.success = false; r.message = I18n.tr("server.dkimm.noKey");
                logEvent(d, "key_verified", d.dkimSelector, null, false, r.message);
                return r;
            }
            r.expectedPublicKey = d.dkimPublicKey;

            // Query public DNS servers
            String[] resolvers = { "@1.1.1.1", "@8.8.8.8" };
            String lastRaw = "";
            String foundPublicKey = null;
            String resolverUsed = null;
            for (String resolver : resolvers) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", resolver, "+short", "+time=5", "+tries=2", "TXT", r.dnsRecordName);
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                Process proc = pb.start();
                StringBuilder out = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) out.append(line).append('\n');
                }
                proc.waitFor();
                String raw = out.toString().trim();
                if (!raw.isEmpty()) lastRaw = raw;
                String normalized = raw.replace("\"", "").replace(" ", "").replace("\n", "");
                // Extract p=... up to the end of the string or ;
                int idx = normalized.indexOf("p=");
                if (idx >= 0) {
                    String pVal = normalized.substring(idx + 2);
                    int semi = pVal.indexOf(';');
                    if (semi >= 0) pVal = pVal.substring(0, semi);
                    foundPublicKey = pVal;
                    resolverUsed = resolver;
                    break;
                }
            }

            r.rawDigOutput = lastRaw;
            r.actualPublicKey = foundPublicKey;

            if (foundPublicKey == null) {
                r.success = true;
                r.match = false;
                r.message = I18n.tr("server.dkimm.txtNotFound", java.util.Map.of("n", String.valueOf(r.dnsRecordName)));
                logEvent(d, "key_verified", d.dkimSelector, null, false, r.message);
                return r;
            }

            // Comparison
            String expected = r.expectedPublicKey.replaceAll("\\s+", "");
            String actual = foundPublicKey.replaceAll("\\s+", "");
            r.match = expected.equals(actual);
            r.success = true;
            if (r.match) {
                r.message = I18n.tr("server.dkimm.keyMatches", java.util.Map.of("r", String.valueOf(resolverUsed)));
            } else {
                r.message = I18n.tr("server.dkimm.keyMismatch");
            }
            logEvent(d, "key_verified", d.dkimSelector, null, r.match, r.message);
            return r;

        } catch (Exception e) {
            r.success = false;
            r.message = I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e)));
            return r;
        }
    }

    /**
     * How ALL the domains stand, in one go.
     *
     * Why it exists: the panel could answer "how does THIS domain stand", and to
     * know how they all stood you had to select them one by one and remember the numbers.
     * That way the thing that matters cannot be seen -- that one of the domains has had its key
     * expired for months, or has none at all -- because that is only seen by comparing.
     *
     * There is no new logic in here: it calls the same functions that feed
     * the card of a single domain. A second implementation of the same check
     * would diverge, and the two answers would end up contradicting each other.
     */
    public org.json.JSONObject allDomainsSummary() {
        org.json.JSONObject r = new org.json.JSONObject().put("success", true);
        org.json.JSONArray lines = new org.json.JSONArray();
        int withoutKey = 0, unverifiable = 0, withoutRotation = 0;
        try {
            for (MailDatabase.Domain d : database.getDomains()) {
                org.json.JSONObject j = new org.json.JSONObject().put("domain", d.domain);
                try {
                    DkimInfo info = getDkimInfo(d.id);
                    boolean hasKey = info != null && info.configured;
                    j.put("hasKey", hasKey);
                    j.put("selector", info == null || info.selector == null ? "" : info.selector);
                    if (!hasKey) {
                        withoutKey++;
                        // No key means no signature: it is the most serious case and must not
                        // hide among lines that talk about rotations.
                        j.put("state", "absent");
                        j.put("note", I18n.tr("server.dkimm.noPanelKey"));
                        lines.put(j);
                        continue;
                    }

                    // The real check: does the published key match the panel's key?
                    ActiveKeyVerifyResult v = verifyActiveKeyInDns(d.id);
                    j.put("checkSucceeded", v != null && v.success);
                    j.put("matches", v != null && v.match);
                    j.put("messageText", v == null ? "" : (v.message == null ? "" : v.message));
                    if (v == null || !v.success) {
                        unverifiable++;
                        j.put("state", "uncertain");
                    } else if (!v.match) {
                        j.put("state", "not_matching");
                    } else {
                        j.put("state", "ok");
                    }

                    // Age of the key and scheduled rotation.
                    ScheduleResult sc = getRotationSchedule(d.id);
                    if (sc != null) {
                        j.put("intervalDays", sc.intervalDays);
                        if (sc.lastRotationAt != null) {
                            j.put("lastRotation", sc.lastRotationAt.toString());
                            long days = (System.currentTimeMillis() - sc.lastRotationAt.getTime())
                                        / 86400000L;
                            j.put("daysSinceLast", days);
                        }
                        if (sc.nextRotationAt != null)
                            j.put("nextRotation", sc.nextRotationAt.toString());
                        if (sc.intervalDays <= 0) withoutRotation++;
                    }

                    RotationInfo ri = getRotationInfo(d.id);
                    if (ri != null && ri.rotationState != null && !ri.rotationState.isBlank()) {
                        j.put("rotationInProgress", ri.rotationState);
                        j.put("previousSelector",
                                ri.previousSelector == null ? "" : ri.previousSelector);
                    }
                } catch (Exception e) {
                    unverifiable++;
                    j.put("state", "uncertain").put("messageText", I18n.tr("server.dkimm.errorLower", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
                }
                lines.put(j);
            }
        } catch (Exception e) {
            return new org.json.JSONObject().put("success", false)
                    .put("error", I18n.tr("server.dkimm.domainsUnreadable", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
        }
        r.put("domains", lines);
        r.put("withoutKey", withoutKey).put("unverifiable", unverifiable)
         .put("withoutRotation", withoutRotation);
        return r;
    }

    public static class ActiveKeyVerifyResult {
        public boolean success;     // check ran without errors
        public boolean match;       // DB key == DNS key
        public String domain;
        public String selector;
        public String dnsRecordName;
        public String expectedPublicKey;
        public String actualPublicKey;
        public String rawDigOutput;
        public String message;
    }

    // ============== ROTATION SCHEDULE ==============

    /** Sets the automatic rotation interval (days). 0 = disables it. */
    public ScheduleResult setRotationSchedule(int domainId, int intervalDays) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new ScheduleResult(false, I18n.tr("server.dkimm.domainNotFound"), 0, null, null);
            int v = Math.max(0, intervalDays);
            database.setDkimRotationInterval(domainId, v);
            logEvent(d, "schedule_changed", d.dkimSelector, null, true,
                v == 0 ? "Scheduled rotation DISABLED"
                       : "Scheduled rotation set every " + v + " days");
            return getRotationSchedule(domainId);
        } catch (Exception e) {
            return new ScheduleResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))), 0, null, null);
        }
    }

    /** Returns the current state of the schedule + computes when it is due. */
    public ScheduleResult getRotationSchedule(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new ScheduleResult(false, I18n.tr("server.dkimm.domainNotFound"), 0, null, null);
            ScheduleResult r = new ScheduleResult(true, "OK", d.dkimRotationIntervalDays, d.dkimLastRotationAt, null);
            if (d.dkimRotationIntervalDays > 0 && d.dkimLastRotationAt != null) {
                long nextMs = d.dkimLastRotationAt.getTime() + (long) d.dkimRotationIntervalDays * 24L * 60L * 60L * 1000L;
                r.nextRotationAt = new java.sql.Timestamp(nextMs);
            } else if (d.dkimRotationIntervalDays > 0 && d.dkimLastRotationAt == null) {
                // Never rotated but schedule active: due immediately at the next tick
                r.nextRotationAt = new java.sql.Timestamp(System.currentTimeMillis());
            }
            return r;
        } catch (Exception e) {
            return new ScheduleResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))), 0, null, null);
        }
    }

    public static class ScheduleResult {
        public boolean success;
        public String message;
        public int intervalDays;
        public java.sql.Timestamp lastRotationAt;
        public java.sql.Timestamp nextRotationAt;
        public ScheduleResult(boolean success, String message, int intervalDays,
                              java.sql.Timestamp lastRotationAt, java.sql.Timestamp nextRotationAt) {
            this.success = success;
            this.message = message;
            this.intervalDays = intervalDays;
            this.lastRotationAt = lastRotationAt;
            this.nextRotationAt = nextRotationAt;
        }
    }

    // ============== ORPHAN DKIM RECORD CLEANUP ==============

    /**
     * Finds all TXT records named <selector>._domainkey.<domain> in Cloudflare,
     * marking which ones are "active" (current or pending selector) and which are "orphans".
     *
     * Useful for cleaning up old records left in DNS after rotations completed before
     * the panel had auto-cleanup via find-by-name.
     */
    public OrphanScanResult scanDkimRecords(int domainId) {
        OrphanScanResult result = new OrphanScanResult();
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) { result.success = false; result.message = I18n.tr("server.dkimm.domainNotFound"); return result; }
            result.domain = d.domain;
            result.currentSelector = d.dkimSelector;
            result.pendingSelector = d.dkimPendingSelector;
            result.previousSelector = d.dkimPreviousSelector;

            if (cloudflare == null) { result.success = false; result.message = I18n.tr("server.dkimm.noCfManager"); return result; }
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) { result.success = false; result.message = I18n.tr("server.dkimm.noAccount"); return result; }
            result.cloudflareAccountLabel = acct.label;

            // Find the zone_id
            String zoneId = d.dkimDnsZoneId;
            if (zoneId == null) {
                CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                if (!zl.found) { result.success = false; result.message = I18n.tr("server.dkimm.zoneNotFound", java.util.Map.of("e", String.valueOf(zl.error))); return result; }
                zoneId = zl.zoneId;
            }
            result.zoneId = zoneId;

            // List all _domainkey records in the zone (case-insensitive, without depending on the domain's case).
            // We use only "_domainkey" as a substring: records in a Cloudflare zone all have
            // the zone name as suffix, so filtering by "_domainkey" is enough.
            java.util.List<CloudflareManager.TxtRecordInfo> all = cloudflare.listTxtRecordsContaining(acct.apiToken, zoneId, "_domainkey");

            String domainLower = d.domain.toLowerCase();
            for (CloudflareManager.TxtRecordInfo r : all) {
                String name = r.name;
                String nameLower = name.toLowerCase();
                // Extract the selector: <selector>._domainkey.<domain>
                int idx = nameLower.indexOf("._domainkey.");
                if (idx <= 0) continue;
                // Check that the record actually belongs to the requested domain
                // (in parent zones like "example.com" records of subdomains could show up)
                String afterDomainkey = nameLower.substring(idx + "._domainkey.".length());
                if (!afterDomainkey.equalsIgnoreCase(domainLower)) continue;
                String selector = name.substring(0, idx);

                DkimRecordEntry entry = new DkimRecordEntry();
                entry.recordId = r.id;
                entry.name = r.name;
                entry.selector = selector;
                entry.contentPreview = r.content.length() > 80 ? r.content.substring(0, 80) + "..." : r.content;
                entry.comment = r.comment;
                entry.isCurrent  = d.dkimSelector != null && selector.equalsIgnoreCase(d.dkimSelector);
                entry.isPending  = d.dkimPendingSelector != null && selector.equalsIgnoreCase(d.dkimPendingSelector);
                entry.isPrevious = d.dkimPreviousSelector != null && selector.equalsIgnoreCase(d.dkimPreviousSelector);
                entry.isOrphan = !entry.isCurrent && !entry.isPending && !entry.isPrevious;

                // For orphans: check whether they are still in the "extended grace period".
                // If the selector was deactivated (i.e. replaced by a rotation) less than
                // GRACE_PERIOD_DAYS days ago, it must NOT be removable -- mail in transit
                // signed with this key might still need the TXT record.
                if (entry.isOrphan) {
                    try {
                        java.sql.Timestamp deactivatedAt = database.findSelectorDeactivationTime(d.id, selector);
                        if (deactivatedAt != null) {
                            entry.deactivatedAt = deactivatedAt;
                            long elapsedMs = System.currentTimeMillis() - deactivatedAt.getTime();
                            long graceMs = DkimRotationScheduler.GRACE_PERIOD_DAYS * 24L * 60L * 60L * 1000L;
                            if (elapsedMs < graceMs) {
                                entry.inGracePeriod = true;
                                entry.gracePeriodEndsAt = new java.sql.Timestamp(deactivatedAt.getTime() + graceMs);
                            }
                        }
                    } catch (Exception ignore) {}
                }

                result.records.add(entry);
            }

            result.success = true;
            return result;
        } catch (Exception e) {
            result.success = false;
            result.message = I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e)));
            return result;
        }
    }

    /**
     * Deletes a DNS record by ID (used to remove single orphan records identified by scanDkimRecords).
     * Checks that the record belongs to the specified domain (security).
     */
    public RotationActionResult deleteDkimRecordById(int domainId, String recordId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, I18n.tr("server.dkimm.domainNotFound"));
            if (cloudflare == null) return new RotationActionResult(false, I18n.tr("server.dkimm.noCfManager"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return new RotationActionResult(false, I18n.tr("server.dkimm.noAccountShort"));

            // GRACE PERIOD ENFORCEMENT for manual deletion of orphan records.
            // First scans the records to identify the one to delete and
            // check whether it is in the grace period.
            OrphanScanResult scan = scanDkimRecords(domainId);
            if (scan.success) {
                for (DkimRecordEntry entry : scan.records) {
                    if (recordId.equals(entry.recordId)) {
                        // Protection 1: block deletion of current/pending/previous records
                        if (entry.isCurrent || entry.isPending || entry.isPrevious) {
                            return new RotationActionResult(false, I18n.tr("server.dkimm.blockedActive", java.util.Map.of("s", String.valueOf(entry.selector), "state", String.valueOf(entry.isCurrent ? I18n.tr("server.dkimm.stateActive") : entry.isPending ? "PENDING" : "PREVIOUS"))));
                        }
                        // Protection 2: block deletion of orphans still in the grace period
                        if (entry.inGracePeriod && entry.gracePeriodEndsAt != null) {
                            long remainingMs = entry.gracePeriodEndsAt.getTime() - System.currentTimeMillis();
                            long remainingDays = (remainingMs + 24L * 60L * 60L * 1000L - 1) / (24L * 60L * 60L * 1000L);
                            return new RotationActionResult(false, I18n.tr("server.dkimm.blockedGrace", java.util.Map.of("s", String.valueOf(entry.selector), "g", String.valueOf(DkimRotationScheduler.GRACE_PERIOD_DAYS), "n", String.valueOf(remainingDays))));
                        }
                        break;
                    }
                }
            }

            String zoneId = d.dkimDnsZoneId;
            if (zoneId == null) {
                CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                if (!zl.found) return new RotationActionResult(false, I18n.tr("server.dkimm.zoneNotFound", java.util.Map.of("e", String.valueOf(zl.error))));
                zoneId = zl.zoneId;
            }
            CloudflareManager.RecordOp op = cloudflare.deleteRecord(acct.apiToken, zoneId, recordId);
            if (!op.success) return new RotationActionResult(false, I18n.tr("server.dkimm.cfError", java.util.Map.of("e", String.valueOf(op.error))));
            logEvent(d, "orphan_record_deleted", null, null, true,
                "Orphan DKIM record deleted from Cloudflare (id " + recordId + ", account '" + acct.label + "')");
            return new RotationActionResult(true, I18n.tr("server.dkimm.recordDeleted"));
        } catch (Exception e) {
            return new RotationActionResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
        }
    }

    public static class OrphanScanResult {
        public boolean success;
        public String message;
        public String domain;
        public String zoneId;
        public String cloudflareAccountLabel;
        public String currentSelector;
        public String pendingSelector;
        public String previousSelector;
        public java.util.List<DkimRecordEntry> records = new java.util.ArrayList<>();
    }

    public static class DkimRecordEntry {
        public String recordId;
        public String name;
        public String selector;
        public String contentPreview;
        public String comment;
        public boolean isCurrent;
        public boolean isPending;
        public boolean isPrevious;
        public boolean isOrphan;
        // For orphans: if the selector was deactivated recently, it is still
        // in the "extended grace period" and must be protected from manual removal.
        public boolean inGracePeriod;
        public java.sql.Timestamp deactivatedAt;
        public java.sql.Timestamp gracePeriodEndsAt;
    }

    // ============== DKIM KEY ROTATION ==============

    /**
     * Starts a DKIM rotation (PHASE 1: generate + save pending + write key to disk).
     * Does NOT change the Rspamd config: the current key keeps signing.
     * The user must manually add to DNS:
     *     <pendingSelector>._domainkey.<domain>  TXT  "v=DKIM1; k=rsa; p=<pub>"
     *
     * @return RotationStartResult with the new selector and the DNS record to publish
     */
    public RotationStartResult startRotation(int domainId) {
        return startRotation(domainId, false);
    }

    /**
     * Variant with flag {@code automatic}: if true and Cloudflare is configured,
     * creates the TXT record directly via API and sets the state to "propagated"
     * (skips waiting for the user to publish the DNS manually).
     * If Cloudflare is not configured or the zone is not found, it runs
     * the manual workflow anyway (state "pending_dns").
     */
    public RotationStartResult startRotation(int domainId, boolean automatic) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                return new RotationStartResult(false, null, null, null, I18n.tr("server.dkimm.domainNotFound"));
            }
            if (!d.hasDkim) {
                return new RotationStartResult(false, null, null, null,
                    I18n.tr("server.dkimm.noDkimYet"));
            }
            if (d.dkimRotationState != null) {
                return new RotationStartResult(false, null, null, null,
                    I18n.tr("server.dkimm.inProgress", java.util.Map.of("s", String.valueOf(d.dkimRotationState))));
            }

            // New selector with the "rYYYYMMDD" suffix (unique, readable, sortable)
            String dateSuffix = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
            String baseSelector = "r" + dateSuffix;
            String newSelector = baseSelector;

            // If for some reason it matches the current selector or a previous one,
            // add a counter (rYYYYMMDD-2, -3, ...)
            int counter = 1;
            while (newSelector.equalsIgnoreCase(d.dkimSelector)
                || newSelector.equalsIgnoreCase(d.dkimPreviousSelector)) {
                counter++;
                newSelector = baseSelector + "-" + counter;
            }

            // Generate the new key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            String privateKeyPem = formatPrivateKeyPem(keyPair.getPrivate());
            String publicKeyDns = formatPublicKeyDns(keyPair.getPublic());
            String dnsRecordValue = buildDkimDnsRecord(publicKeyDns);

            // Save as pending in DB (initial state: pending_dns).
            // Also store the rotation "mode", so all subsequent events
            // (dns_propagated, key_activated, rotation_completed) inherit it automatically.
            String rotationMode = automatic ? "automatic" : "manual";
            database.setDkimPending(domainId, newSelector, privateKeyPem, publicKeyDns, "pending_dns", rotationMode);

            // Write the key to disk (Rspamd will use it ONLY after activatePending)
            writePrivateKeyFile(d.domain, newSelector, privateKeyPem);

            String dnsRecordName = newSelector + "._domainkey." + d.domain;

            // Log: rotation started
            logEvent(d, "rotation_started", newSelector, automatic ? "automatic" : "manual", true,
                "New RSA " + RSA_KEY_SIZE + " key generated. Pending selector: " + newSelector
                + ". Old active selector: " + d.dkimSelector);

            // PHASE B: if requested and the domain has a CF account assigned, publish the record right away
            if (automatic && cloudflare != null) {
                try {
                    MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
                    if (acct == null) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            I18n.tr("server.dkimm.genNoAccount"));
                    }
                    CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                    if (!zl.found) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            I18n.tr("server.dkimm.genNoZone", java.util.Map.of("a", String.valueOf(acct.label), "e", String.valueOf(zl.error))));
                    }
                    CloudflareManager.RecordOp op = cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, dnsRecordName, dnsRecordValue, 300);
                    if (!op.success) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            I18n.tr("server.dkimm.genCfError", java.util.Map.of("a", String.valueOf(acct.label), "e", String.valueOf(op.error))));
                    }
                    // Record created: save zoneId + recordId and move to the "propagated" state
                    database.setDkimPendingCloudflareIds(domainId, zl.zoneId, op.recordId);
                    database.setDkimRotationState(domainId, "propagated");
                    logEvent(d, "dns_published", newSelector, "automatic", true,
                        "TXT record created in Cloudflare (zone " + zl.zoneName + ", record id " + op.recordId + "). State → propagated.");
                } catch (Exception cfErr) {
                    return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                        I18n.tr("server.dkimm.genCfException", java.util.Map.of("e", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", cfErr))));
                }
            }

            return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue, null);

        } catch (Exception e) {
            return new RotationStartResult(false, null, null, null, e.getMessage());
        }
    }

    /**
     * Checks whether the DNS record of the PENDING key has propagated.
     * Queries with dig +short TXT <pendingSelector>._domainkey.<domain>
     * and checks that the public string matches the expected one.
     *
     * If propagated and the state is still "pending_dns", updates it to "propagated".
     */
    public PropagationCheckResult checkPropagation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                return new PropagationCheckResult(false, false, I18n.tr("server.dkimm.domainNotFound"), null);
            }
            if (d.dkimPendingSelector == null || d.dkimPendingPublicKey == null) {
                return new PropagationCheckResult(false, false, I18n.tr("server.dkimm.noRotation"), null);
            }

            String recordName = d.dkimPendingSelector + "._domainkey." + d.domain;

            // Query 1.1.1.1 first (Cloudflare authoritative via public resolver) and then 8.8.8.8 as fallback.
            // This reduces false negatives during propagation: if at least one of the two answers
            // with the expected key, we consider the record propagated.
            String[] resolvers = { "@1.1.1.1", "@8.8.8.8" };
            String lastRaw = "";
            boolean found = false;
            for (String resolver : resolvers) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", resolver, "+short", "+time=5", "+tries=2", "TXT", recordName);
                org.daemoxcp.mail.util.Shell.applyPath(pb);
                pb.redirectErrorStream(false);
                Process proc = pb.start();
                StringBuilder out = new StringBuilder();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        out.append(line).append('\n');
                    }
                }
                proc.waitFor();
                String raw = out.toString().trim();
                if (!raw.isEmpty()) lastRaw = raw;

                // Strip quotes and concatenations (dig returns TXT strings in separate "...")
                String normalized = raw.replace("\"", "").replace(" ", "").replace("\n", "");
                String expectedTail = "p=" + d.dkimPendingPublicKey.replace(" ", "");
                if (normalized.contains("v=DKIM1") && normalized.contains(expectedTail)) {
                    found = true;
                    break;
                }
            }

            if (found) {
                // Update the state if still pending_dns
                if ("pending_dns".equals(d.dkimRotationState)) {
                    database.setDkimRotationState(domainId, "propagated");
                    logEvent(d, "dns_propagated", d.dkimPendingSelector, null, true,
                        "Pending TXT record verified in public DNS (1.1.1.1/8.8.8.8). State → propagated.");
                }
                return new PropagationCheckResult(true, true,
                    I18n.tr("server.dkimm.propagated"), lastRaw);
            } else {
                return new PropagationCheckResult(true, false,
                    lastRaw.isEmpty()
                        ? I18n.tr("server.dkimm.notYetFound")
                        : I18n.tr("server.dkimm.foundMismatch"),
                    lastRaw);
            }
        } catch (Exception e) {
            return new PropagationCheckResult(false, false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))), null);
        }
    }

    /**
     * Activates the pending key as current:
     *  - the pending key becomes active (db.promotePendingToActive)
     *  - the current key becomes "previous" (stays in DNS during the grace period)
     *  - Rspamd is reloaded so new mail is signed with the new key
     *
     * Prerequisite: state == "propagated" (or "pending_dns" if the user forces it).
     */
    public RotationActionResult activatePending(int domainId, boolean force) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, I18n.tr("server.dkimm.domainNotFound"));
            if (d.dkimPendingSelector == null) {
                return new RotationActionResult(false, I18n.tr("server.dkimm.noRotation"));
            }
            if (!force && !"propagated".equals(d.dkimRotationState)) {
                return new RotationActionResult(false,
                    I18n.tr("server.dkimm.notPropagated"));
            }

            String oldSelector = d.dkimSelector;
            String newSelector = d.dkimPendingSelector;

            // 1) Promote in DB (atomic)
            database.promotePendingToActive(domainId);

            // 2) Update the timestamp of the last rotation (for the scheduler)
            database.markDkimRotationActivated(domainId);

            // 3) Regenerate Rspamd config (it will now sign with the new selector)
            updateRspamdConfig();

            logEventWithPrevious(d, "key_activated", newSelector, oldSelector, force ? "forced" : null, true,
                "Key promoted: " + oldSelector + " → " + newSelector + ". Rspamd reloaded. Old key kept for the grace period.");

            return new RotationActionResult(true,
                I18n.tr("server.dkimm.activated", java.util.Map.of("newer", String.valueOf(newSelector), "old", String.valueOf(oldSelector))));
        } catch (Exception e) {
            return new RotationActionResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
        }
    }

    /**
     * Completes the rotation: deletes the "previous" key from the DB and resets the state.
     * After this call the user can remove the old _domainkey TXT record from DNS.
     * Also deletes the previous key's file from disk.
     */
    public RotationActionResult completeRotation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, I18n.tr("server.dkimm.domainNotFound"));
            if (d.dkimPreviousSelector == null) {
                return new RotationActionResult(false, I18n.tr("server.dkimm.noPrevious"));
            }

            // GRACE PERIOD ENFORCEMENT (server-side, not bypassable from the UI).
            // The rotation can be completed ONLY if GRACE_PERIOD_DAYS have passed since activation.
            // This prevents premature removals that would cause DKIM-fail on mail already in transit.
            if (d.dkimRotationActivatedAt != null) {
                long activatedMs = d.dkimRotationActivatedAt.getTime();
                long elapsedMs = System.currentTimeMillis() - activatedMs;
                long graceMs = DkimRotationScheduler.GRACE_PERIOD_DAYS * 24L * 60L * 60L * 1000L;
                if (elapsedMs < graceMs) {
                    long remainingMs = graceMs - elapsedMs;
                    long remainingDays = (remainingMs + 24L * 60L * 60L * 1000L - 1) / (24L * 60L * 60L * 1000L);
                    long remainingHours = (remainingMs + 60L * 60L * 1000L - 1) / (60L * 60L * 1000L);
                    String remainingText = remainingDays >= 1
                        ? (remainingDays == 1 ? I18n.tr("server.dkimm.days.one") : I18n.tr("server.dkimm.days.other", java.util.Map.of("n", String.valueOf(remainingDays))))
                        : (remainingHours == 1 ? I18n.tr("server.dkimm.hours.one") : I18n.tr("server.dkimm.hours.other", java.util.Map.of("n", String.valueOf(remainingHours))));
                    return new RotationActionResult(false,
                        I18n.tr("server.dkimm.graceNotOver", java.util.Map.of("t", String.valueOf(remainingText))));
                }
            }

            String prevSelector = d.dkimPreviousSelector;
            String cfNote = "";

            // Delete the previous key's file on disk
            try {
                Path prevKey = keyFile(d.domain, prevSelector);
                Files.deleteIfExists(prevKey);
            } catch (Exception ignore) {}

            // Try to delete the old key's DNS record via Cloudflare.
            // 3-fallback strategy, to be robust even if we have not stored the ID:
            //   1) If dkim_previous_dns_record_id is stored -> direct deletion
            //   2) Otherwise, if we have a CF account assigned -> find the record by name
            //   3) If the zone_id is unknown too -> look up the zone via API first
            String prevRecordName = prevSelector + "._domainkey." + d.domain;
            if (cloudflare != null) {
                MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
                if (acct != null) {
                    // Find the zone_id (stored or via lookup)
                    String zoneId = d.dkimDnsZoneId;
                    if (zoneId == null) {
                        try {
                            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                            if (zl.found) zoneId = zl.zoneId;
                        } catch (Exception ignore) {}
                    }
                    if (zoneId != null) {
                        // Find the record_id to delete: stored or via lookup by name
                        String recordId = d.dkimPreviousDnsRecordId;
                        if (recordId == null) {
                            try {
                                CloudflareManager.RecordOp findOp = cloudflare.findTxtRecord(acct.apiToken, zoneId, prevRecordName);
                                if (findOp.success) recordId = findOp.recordId;
                            } catch (Exception ignore) {}
                        }
                        if (recordId != null) {
                            CloudflareManager.RecordOp op = cloudflare.deleteRecord(acct.apiToken, zoneId, recordId);
                            cfNote = op.success
                                ? " " + I18n.tr("server.dkimm.cfRemoved", java.util.Map.of("n", String.valueOf(prevRecordName), "a", String.valueOf(acct.label)))
                                : " " + I18n.tr("server.dkimm.cfRemoveFailed", java.util.Map.of("e", String.valueOf(op.error)));
                        } else {
                            cfNote = " " + I18n.tr("server.dkimm.cfNotFound", java.util.Map.of("n", String.valueOf(prevRecordName)));
                        }
                    }
                }
            }

            // Clear the previous_* fields in the DB
            database.clearDkimPrevious(domainId);

            logEvent(d, "rotation_completed", d.dkimSelector, null, true,
                "Old key (" + prevSelector + ") removed from the panel." + cfNote);

            return new RotationActionResult(true,
                I18n.tr("server.dkimm.completed") + (cfNote.isEmpty()
                    ? " " + I18n.tr("server.dkimm.removeOld", java.util.Map.of("n", String.valueOf(prevRecordName)))
                    : cfNote));
        } catch (Exception e) {
            return new RotationActionResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
        }
    }

    /**
     * Cancels a rotation in progress (pre-activation PHASE).
     * Works ONLY if the state is pending_dns / propagated (i.e. not activated yet).
     * Deletes the pending key from the DB and from disk.
     */
    public RotationActionResult cancelRotation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, I18n.tr("server.dkimm.domainNotFound"));
            if (d.dkimPendingSelector == null) {
                return new RotationActionResult(false, I18n.tr("server.dkimm.nothingToCancel"));
            }
            if ("active_grace".equals(d.dkimRotationState)) {
                return new RotationActionResult(false,
                    I18n.tr("server.dkimm.alreadyActivated"));
            }

            String pendingSelector = d.dkimPendingSelector;
            String cfNote = "";

            // Delete the pending key's file
            try {
                Path pendingKey = keyFile(d.domain, pendingSelector);
                Files.deleteIfExists(pendingKey);
            } catch (Exception ignore) {}

            // Try to delete the pending key's DNS record via Cloudflare.
            // Same 3-fallback pattern as completeRotation: stored ID, lookup by name, zone lookup.
            String pendingRecordName = pendingSelector + "._domainkey." + d.domain;
            if (cloudflare != null) {
                MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
                if (acct != null) {
                    String zoneId = d.dkimDnsZoneId;
                    if (zoneId == null) {
                        try {
                            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                            if (zl.found) zoneId = zl.zoneId;
                        } catch (Exception ignore) {}
                    }
                    if (zoneId != null) {
                        String recordId = d.dkimPendingDnsRecordId;
                        if (recordId == null) {
                            try {
                                CloudflareManager.RecordOp findOp = cloudflare.findTxtRecord(acct.apiToken, zoneId, pendingRecordName);
                                if (findOp.success) recordId = findOp.recordId;
                            } catch (Exception ignore) {}
                        }
                        if (recordId != null) {
                            CloudflareManager.RecordOp op = cloudflare.deleteRecord(acct.apiToken, zoneId, recordId);
                            cfNote = op.success
                                ? " " + I18n.tr("server.dkimm.cfRemoved", java.util.Map.of("n", String.valueOf(pendingRecordName), "a", String.valueOf(acct.label)))
                                : " " + I18n.tr("server.dkimm.cfRemoveFailed", java.util.Map.of("e", String.valueOf(op.error)));
                        }
                    }
                }
            }

            database.clearDkimPending(domainId);

            logEvent(d, "rotation_cancelled", pendingSelector, null, true,
                "Pending key deleted before activation." + cfNote);

            return new RotationActionResult(true,
                I18n.tr("server.dkimm.cancelled") + (cfNote.isEmpty()
                    ? " " + I18n.tr("server.dkimm.removePending", java.util.Map.of("n", String.valueOf(pendingRecordName)))
                    : cfNote));
        } catch (Exception e) {
            return new RotationActionResult(false, I18n.tr("server.dkimm.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DkimManager", e))));
        }
    }

    /**
     * Returns detailed info about the rotation (for the UI).
     */
    public RotationInfo getRotationInfo(int domainId) throws Exception {
        MailDatabase.Domain d = database.getDomain(domainId);
        if (d == null) return null;

        RotationInfo info = new RotationInfo();
        info.domain = d.domain;
        info.currentSelector = d.dkimSelector;
        info.hasDkim = d.hasDkim;

        info.rotationState = d.dkimRotationState;
        info.startedAt = d.dkimRotationStartedAt;
        info.activatedAt = d.dkimRotationActivatedAt;

        if (d.dkimPendingSelector != null) {
            info.pendingSelector = d.dkimPendingSelector;
            info.pendingDnsName = d.dkimPendingSelector + "._domainkey." + d.domain;
            info.pendingDnsValue = buildDkimDnsRecord(d.dkimPendingPublicKey);
        }
        if (d.dkimPreviousSelector != null) {
            info.previousSelector = d.dkimPreviousSelector;
            info.previousDnsName = d.dkimPreviousSelector + "._domainkey." + d.domain;
        }
        return info;
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
            try {
                info.keyFileExists = Files.exists(keyFile(domain.domain, info.selector));
            } catch (IllegalArgumentException invalid) {
                info.keyFileExists = false;
            }
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
            Path keyFile = keyFile(domain.domain, selector);
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

            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "TXT", recordName);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
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

    /** Result of startRotation: contains the new selector and the DNS record to publish. */
    public static class RotationStartResult {
        public final boolean success;
        public final String pendingSelector;
        public final String dnsRecordName;
        public final String dnsRecordValue;
        public final String error;

        public RotationStartResult(boolean success, String pendingSelector, String dnsRecordName,
                                    String dnsRecordValue, String error) {
            this.success = success;
            this.pendingSelector = pendingSelector;
            this.dnsRecordName = dnsRecordName;
            this.dnsRecordValue = dnsRecordValue;
            this.error = error;
        }
    }

    /** Outcome of checkPropagation. */
    public static class PropagationCheckResult {
        public final boolean success;     // the check ran without errors
        public final boolean propagated;  // the DNS record matches the pending key
        public final String message;
        public final String rawDigOutput; // useful for debugging in the UI

        public PropagationCheckResult(boolean success, boolean propagated, String message, String rawDigOutput) {
            this.success = success;
            this.propagated = propagated;
            this.message = message;
            this.rawDigOutput = rawDigOutput;
        }
    }

    /** Generic outcome for activatePending / completeRotation / cancelRotation. */
    public static class RotationActionResult {
        public final boolean success;
        public final String message;

        public RotationActionResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    /** Aggregated rotation info, for the UI. */
    public static class RotationInfo {
        public String domain;
        public boolean hasDkim;
        public String currentSelector;

        public String rotationState;             // null, "pending_dns", "propagated", "active_grace"
        public java.sql.Timestamp startedAt;
        public java.sql.Timestamp activatedAt;

        public String pendingSelector;
        public String pendingDnsName;
        public String pendingDnsValue;

        public String previousSelector;
        public String previousDnsName;
    }
}
