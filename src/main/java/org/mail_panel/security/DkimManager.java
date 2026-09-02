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

    /**
     * Preset di rotazione consigliati (in giorni).
     * Riferimento NIST SP 800-177 e M3AAWG Email Authentication best practices:
     *  - aggressivo: ogni mese (alta sicurezza)
     *  - raccomandato: ogni 3 mesi (best practice industria)
     *  - equilibrato: ogni 6 mesi
     *  - minimo: ogni 12 mesi (sotto questo è sconsigliato)
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

    /** Opzionale: collega un CloudflareManager per la rotazione automatica. */
    public void setCloudflareManager(CloudflareManager cf) {
        this.cloudflare = cf;
    }

    /**
     * Trigger context: traccia "chi" ha avviato l'operazione corrente
     * ("user" = clic UI / API call, "scheduler" = timer automatico).
     * Si imposta col try-finally pattern dal chiamante (API handler o scheduler).
     */
    public static final ThreadLocal<String> CURRENT_TRIGGER = new ThreadLocal<>();

    /** Restituisce il trigger corrente, default "user" se non impostato. */
    private static String currentTrigger() {
        String t = CURRENT_TRIGGER.get();
        return (t == null || t.isEmpty()) ? "user" : t;
    }

    /**
     * Eventi che fanno parte della "catena di rotazione" e devono ereditare la modalità
     * dal {@code dkim_rotation_mode} del dominio (se non specificata esplicitamente).
     */
    private static final java.util.Set<String> ROTATION_CHAIN_EVENTS = java.util.Set.of(
        "dns_published", "dns_propagated", "key_activated",
        "rotation_completed", "rotation_cancelled"
    );

    /**
     * Helper: registra un evento nello storico rotazioni.
     * Se `mode` è null e l'evento fa parte della catena di rotazione, eredita
     * la modalità dal campo `dkim_rotation_mode` del dominio.
     * Cattura silenziosamente eventuali errori (il logging non deve bloccare il workflow).
     */
    private void logEvent(MailDatabase.Domain d, String eventType, String selector,
                          String mode, boolean success, String message) {
        logEventWithPrevious(d, eventType, selector, null, mode, success, message);
    }

    /**
     * Variante di logEvent che registra anche il previous_selector. Da usare per
     * key_activated, così sappiamo quando un selector è stato disattivato.
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
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("chown", "rspamd:rspamd", keyFile.toString());
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.start().waitFor();

            // TODO: migrate to Shell.run when touched
            pb = new ProcessBuilder("chmod", "600", keyFile.toString());
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Update Rspamd DKIM signing configuration with all domains.
     *
     * Per ogni dominio viene scritto SOLO il selector attualmente attivo (dkim_*).
     * La chiave "pending" non è ancora usata per firmare: viene solo pubblicata in DNS.
     * La chiave "previous" non firma più (le mail in transito vengono validate dai destinatari
     * con il record TXT che lasciamo in DNS durante il grace period).
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
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("service", "rspamd", "reload");
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.start().waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Verifica RIGOROSA che la chiave DKIM attualmente attiva sia effettivamente
     * pubblicata in DNS. Confronta la chiave pubblica salvata nel DB con quella
     * presente nel record TXT <selector>._domainkey.<domain>.
     *
     * Interroga 1.1.1.1 e 8.8.8.8 (resolver pubblici esterni) per evitare cache locali.
     *
     * Logga un evento "key_verified" nello storico.
     */
    public ActiveKeyVerifyResult verifyActiveKeyInDns(int domainId) {
        ActiveKeyVerifyResult r = new ActiveKeyVerifyResult();
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                r.success = false; r.message = "Dominio non trovato"; return r;
            }
            r.domain = d.domain;
            r.selector = d.dkimSelector;
            r.dnsRecordName = (d.dkimSelector == null ? "mail" : d.dkimSelector) + "._domainkey." + d.domain;

            if (!d.hasDkim || d.dkimPublicKey == null) {
                r.success = false; r.message = "Nessuna chiave DKIM configurata su questo dominio";
                logEvent(d, "key_verified", d.dkimSelector, null, false, r.message);
                return r;
            }
            r.expectedPublicKey = d.dkimPublicKey;

            // Interroga DNS pubblici
            String[] resolvers = { "@1.1.1.1", "@8.8.8.8" };
            String lastRaw = "";
            String foundPublicKey = null;
            String resolverUsed = null;
            for (String resolver : resolvers) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", resolver, "+short", "+time=5", "+tries=2", "TXT", r.dnsRecordName);
                org.mail_panel.util.Shell.applicaPath(pb);
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
                // Estrai p=... fino a fine stringa o ;
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
                r.message = "Record TXT non trovato in DNS pubblico per " + r.dnsRecordName;
                logEvent(d, "key_verified", d.dkimSelector, null, false, r.message);
                return r;
            }

            // Confronto
            String expected = r.expectedPublicKey.replaceAll("\\s+", "");
            String actual = foundPublicKey.replaceAll("\\s+", "");
            r.match = expected.equals(actual);
            r.success = true;
            if (r.match) {
                r.message = "Chiave in DNS (via " + resolverUsed + ") corrisponde ESATTAMENTE alla chiave attiva nel pannello";
            } else {
                r.message = "ATTENZIONE: la chiave in DNS non corrisponde a quella attiva nel pannello (potrebbe essere ancora una vecchia chiave o un valore manomesso)";
            }
            logEvent(d, "key_verified", d.dkimSelector, null, r.match, r.message);
            return r;

        } catch (Exception e) {
            r.success = false;
            r.message = "Errore: " + e.getMessage();
            return r;
        }
    }

    /**
     * Come stanno messi TUTTI i domini, in un colpo solo.
     *
     * Perche' esiste: il pannello sapeva rispondere "com'e' messo QUESTO dominio", e per
     * sapere come stanno tutti bisognava selezionarli uno per uno e ricordarsi i numeri.
     * Cosi' non si vede la cosa che conta — che uno dei domini abbia la chiave scaduta da
     * mesi, o non ce l'abbia affatto — perche' quella si vede solo confrontando.
     *
     * Non c'e' nessuna logica nuova qui dentro: si chiamano le stesse funzioni che alimentano
     * la scheda di un dominio solo. Una seconda implementazione della stessa verifica
     * divergerebbe, e le due risposte finirebbero per contraddirsi.
     */
    public org.json.JSONObject riepilogoTuttiIDomini() {
        org.json.JSONObject r = new org.json.JSONObject().put("success", true);
        org.json.JSONArray righe = new org.json.JSONArray();
        int senzaChiave = 0, nonVerificabili = 0, senzaRotazione = 0;
        try {
            for (MailDatabase.Domain d : database.getDomains()) {
                org.json.JSONObject j = new org.json.JSONObject().put("dominio", d.domain);
                try {
                    DkimInfo info = getDkimInfo(d.id);
                    boolean haChiave = info != null && info.configured;
                    j.put("haChiave", haChiave);
                    j.put("selettore", info == null || info.selector == null ? "" : info.selector);
                    if (!haChiave) {
                        senzaChiave++;
                        // Niente chiave vuol dire niente firma: e' il caso piu' grave e non
                        // deve nascondersi in mezzo a righe che parlano di rotazioni.
                        j.put("stato", "assente");
                        j.put("nota", "Nel pannello non esiste una chiave DKIM per questo dominio: "
                                + "la posta parte senza firma.");
                        righe.put(j);
                        continue;
                    }

                    // La verifica vera: la chiave pubblicata coincide con quella del pannello?
                    ActiveKeyVerifyResult v = verifyActiveKeyInDns(d.id);
                    j.put("verificaRiuscita", v != null && v.success);
                    j.put("corrisponde", v != null && v.match);
                    j.put("messaggio", v == null ? "" : (v.message == null ? "" : v.message));
                    if (v == null || !v.success) {
                        nonVerificabili++;
                        j.put("stato", "incerto");
                    } else if (!v.match) {
                        j.put("stato", "non_corrisponde");
                    } else {
                        j.put("stato", "ok");
                    }

                    // Eta' della chiave e rotazione programmata.
                    ScheduleResult sc = getRotationSchedule(d.id);
                    if (sc != null) {
                        j.put("intervalloGiorni", sc.intervalDays);
                        if (sc.lastRotationAt != null) {
                            j.put("ultimaRotazione", sc.lastRotationAt.toString());
                            long giorni = (System.currentTimeMillis() - sc.lastRotationAt.getTime())
                                        / 86400000L;
                            j.put("giorniDallUltima", giorni);
                        }
                        if (sc.nextRotationAt != null)
                            j.put("prossimaRotazione", sc.nextRotationAt.toString());
                        if (sc.intervalDays <= 0) senzaRotazione++;
                    }

                    RotationInfo ri = getRotationInfo(d.id);
                    if (ri != null && ri.rotationState != null && !ri.rotationState.isBlank()) {
                        j.put("rotazioneInCorso", ri.rotationState);
                        j.put("selettorePrecedente",
                                ri.previousSelector == null ? "" : ri.previousSelector);
                    }
                } catch (Exception e) {
                    nonVerificabili++;
                    j.put("stato", "incerto").put("messaggio", "errore: " + e.getMessage());
                }
                righe.put(j);
            }
        } catch (Exception e) {
            return new org.json.JSONObject().put("success", false)
                    .put("error", "non riesco a leggere l'elenco dei domini: " + e.getMessage());
        }
        r.put("domini", righe);
        r.put("senzaChiave", senzaChiave).put("nonVerificabili", nonVerificabili)
         .put("senzaRotazione", senzaRotazione);
        return r;
    }

    public static class ActiveKeyVerifyResult {
        public boolean success;     // verifica eseguita senza errori
        public boolean match;       // chiave DB == chiave DNS
        public String domain;
        public String selector;
        public String dnsRecordName;
        public String expectedPublicKey;
        public String actualPublicKey;
        public String rawDigOutput;
        public String message;
    }

    // ============== ROTATION SCHEDULE ==============

    /** Imposta l'intervallo di rotazione automatica (giorni). 0 = disattiva. */
    public ScheduleResult setRotationSchedule(int domainId, int intervalDays) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new ScheduleResult(false, "Dominio non trovato", 0, null, null);
            int v = Math.max(0, intervalDays);
            database.setDkimRotationInterval(domainId, v);
            logEvent(d, "schedule_changed", d.dkimSelector, null, true,
                v == 0 ? "Rotazione programmata DISATTIVATA"
                       : "Rotazione programmata impostata ogni " + v + " giorni");
            return getRotationSchedule(domainId);
        } catch (Exception e) {
            return new ScheduleResult(false, "Errore: " + e.getMessage(), 0, null, null);
        }
    }

    /** Ritorna lo stato corrente dello schedule + computa quando scade. */
    public ScheduleResult getRotationSchedule(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new ScheduleResult(false, "Dominio non trovato", 0, null, null);
            ScheduleResult r = new ScheduleResult(true, "OK", d.dkimRotationIntervalDays, d.dkimLastRotationAt, null);
            if (d.dkimRotationIntervalDays > 0 && d.dkimLastRotationAt != null) {
                long nextMs = d.dkimLastRotationAt.getTime() + (long) d.dkimRotationIntervalDays * 24L * 60L * 60L * 1000L;
                r.nextRotationAt = new java.sql.Timestamp(nextMs);
            } else if (d.dkimRotationIntervalDays > 0 && d.dkimLastRotationAt == null) {
                // Mai ruotato ma schedule attivo: dovuta subito al prossimo tick
                r.nextRotationAt = new java.sql.Timestamp(System.currentTimeMillis());
            }
            return r;
        } catch (Exception e) {
            return new ScheduleResult(false, "Errore: " + e.getMessage(), 0, null, null);
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
     * Trova tutti i record TXT con nome <selector>._domainkey.<dominio> in Cloudflare,
     * marcando quali sono "attivi" (selector corrente o pending) e quali "orfani".
     *
     * Utile per ripulire record vecchi rimasti in DNS dopo rotazioni completate prima
     * che il pannello avesse l'auto-cleanup tramite find-by-name.
     */
    public OrphanScanResult scanDkimRecords(int domainId) {
        OrphanScanResult result = new OrphanScanResult();
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) { result.success = false; result.message = "Dominio non trovato"; return result; }
            result.domain = d.domain;
            result.currentSelector = d.dkimSelector;
            result.pendingSelector = d.dkimPendingSelector;
            result.previousSelector = d.dkimPreviousSelector;

            if (cloudflare == null) { result.success = false; result.message = "CloudflareManager non disponibile"; return result; }
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) { result.success = false; result.message = "Nessun account Cloudflare assegnato a questo dominio"; return result; }
            result.cloudflareAccountLabel = acct.label;

            // Trova lo zone_id
            String zoneId = d.dkimDnsZoneId;
            if (zoneId == null) {
                CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                if (!zl.found) { result.success = false; result.message = "Zona DNS non trovata: " + zl.error; return result; }
                zoneId = zl.zoneId;
            }
            result.zoneId = zoneId;

            // Lista tutti i record _domainkey nella zona (case-insensitive, senza dipendenza dalla case del dominio).
            // Usiamo solo "_domainkey" come substring: i record in una zona Cloudflare hanno tutti
            // come suffisso il nome della zona, quindi filtrare per "_domainkey" è sufficiente.
            java.util.List<CloudflareManager.TxtRecordInfo> all = cloudflare.listTxtRecordsContaining(acct.apiToken, zoneId, "_domainkey");

            String domainLower = d.domain.toLowerCase();
            for (CloudflareManager.TxtRecordInfo r : all) {
                String name = r.name;
                String nameLower = name.toLowerCase();
                // Estrai il selector: <selector>._domainkey.<domain>
                int idx = nameLower.indexOf("._domainkey.");
                if (idx <= 0) continue;
                // Verifica che il record appartenga effettivamente al dominio richiesto
                // (in zone parent come "example.com" potrebbero comparire record di sotto-domini)
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

                // Per gli orfani: verifica se sono ancora in "grace period esteso".
                // Se il selector è stato disattivato (cioè rimpiazzato da una rotazione) meno di
                // GRACE_PERIOD_DAYS giorni fa, NON deve essere rimovibile — le mail in transito
                // firmate con questa chiave potrebbero ancora aver bisogno del record TXT.
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
            result.message = "Errore: " + e.getMessage();
            return result;
        }
    }

    /**
     * Cancella un record DNS per ID (usato per rimuovere singoli record orfani identificati da scanDkimRecords).
     * Verifica che il record appartenga al dominio specificato (sicurezza).
     */
    public RotationActionResult deleteDkimRecordById(int domainId, String recordId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, "Dominio non trovato");
            if (cloudflare == null) return new RotationActionResult(false, "CloudflareManager non disponibile");
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return new RotationActionResult(false, "Nessun account Cloudflare assegnato");

            // ENFORCEMENT GRACE PERIOD per cancellazione manuale di record orfani.
            // Scansiona prima i record per identificare quello da cancellare e
            // verificare se è in grace period.
            OrphanScanResult scan = scanDkimRecords(domainId);
            if (scan.success) {
                for (DkimRecordEntry entry : scan.records) {
                    if (recordId.equals(entry.recordId)) {
                        // Protezione 1: blocca cancellazione di record current/pending/previous
                        if (entry.isCurrent || entry.isPending || entry.isPrevious) {
                            return new RotationActionResult(false,
                                "Operazione bloccata: il record con selector '" + entry.selector +
                                "' è una chiave " + (entry.isCurrent ? "ATTIVA" : entry.isPending ? "PENDING" : "PREVIOUS") +
                                " — non rimovibile.");
                        }
                        // Protezione 2: blocca cancellazione di orfani ancora in grace period
                        if (entry.inGracePeriod && entry.gracePeriodEndsAt != null) {
                            long remainingMs = entry.gracePeriodEndsAt.getTime() - System.currentTimeMillis();
                            long remainingDays = (remainingMs + 24L * 60L * 60L * 1000L - 1) / (24L * 60L * 60L * 1000L);
                            return new RotationActionResult(false,
                                "Operazione bloccata: il selector '" + entry.selector +
                                "' è stato disattivato meno di " + DkimRotationScheduler.GRACE_PERIOD_DAYS +
                                " giorni fa e il suo record DNS è ancora in grace period. " +
                                "Rimuoverlo ora causerebbe DKIM-fail su email in transito. " +
                                "Riprova tra circa " + remainingDays + " giorn" + (remainingDays == 1 ? "o" : "i") + ".");
                        }
                        break;
                    }
                }
            }

            String zoneId = d.dkimDnsZoneId;
            if (zoneId == null) {
                CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                if (!zl.found) return new RotationActionResult(false, "Zona DNS non trovata: " + zl.error);
                zoneId = zl.zoneId;
            }
            CloudflareManager.RecordOp op = cloudflare.deleteRecord(acct.apiToken, zoneId, recordId);
            if (!op.success) return new RotationActionResult(false, "Errore Cloudflare: " + op.error);
            logEvent(d, "orphan_record_deleted", null, null, true,
                "Record DKIM orfano cancellato da Cloudflare (id " + recordId + ", account '" + acct.label + "')");
            return new RotationActionResult(true, "Record cancellato con successo.");
        } catch (Exception e) {
            return new RotationActionResult(false, "Errore: " + e.getMessage());
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
        // Per gli orfani: se il selector è stato disattivato di recente, è ancora
        // in "grace period esteso" e va protetto dalla rimozione manuale.
        public boolean inGracePeriod;
        public java.sql.Timestamp deactivatedAt;
        public java.sql.Timestamp gracePeriodEndsAt;
    }

    // ============== DKIM KEY ROTATION ==============

    /**
     * Avvia una rotazione DKIM (FASE 1: genera + salva pending + scrive chiave su disco).
     * NON modifica la config di Rspamd: la chiave attuale continua a firmare.
     * L'utente deve aggiungere manualmente in DNS:
     *     <pendingSelector>._domainkey.<domain>  TXT  "v=DKIM1; k=rsa; p=<pub>"
     *
     * @return RotationStartResult con il nuovo selector e il record DNS da pubblicare
     */
    public RotationStartResult startRotation(int domainId) {
        return startRotation(domainId, false);
    }

    /**
     * Variante con flag {@code automatic}: se true e Cloudflare è configurato,
     * crea direttamente il record TXT via API e setta lo stato a "propagated"
     * (salta l'attesa manuale dell'utente per pubblicare il DNS).
     * Se Cloudflare non è configurato o la zona non viene trovata, esegue
     * comunque il workflow manuale (stato "pending_dns").
     */
    public RotationStartResult startRotation(int domainId, boolean automatic) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                return new RotationStartResult(false, null, null, null, "Dominio non trovato");
            }
            if (!d.hasDkim) {
                return new RotationStartResult(false, null, null, null,
                    "Il dominio non ha ancora DKIM configurato: usa Genera DKIM (prima rotazione non applicabile)");
            }
            if (d.dkimRotationState != null) {
                return new RotationStartResult(false, null, null, null,
                    "Rotazione già in corso (stato: " + d.dkimRotationState + "). Annullala o completala prima di avviarne un'altra.");
            }

            // Nuovo selector con suffisso "rYYYYMMDD" (univoco, leggibile, ordinato)
            String dateSuffix = new java.text.SimpleDateFormat("yyyyMMdd").format(new java.util.Date());
            String baseSelector = "r" + dateSuffix;
            String newSelector = baseSelector;

            // Se per qualche motivo coincide col selector attuale o con un precedente,
            // aggiungi un counter (rYYYYMMDD-2, -3, ...)
            int counter = 1;
            while (newSelector.equalsIgnoreCase(d.dkimSelector)
                || newSelector.equalsIgnoreCase(d.dkimPreviousSelector)) {
                counter++;
                newSelector = baseSelector + "-" + counter;
            }

            // Genera la nuova coppia di chiavi
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            String privateKeyPem = formatPrivateKeyPem(keyPair.getPrivate());
            String publicKeyDns = formatPublicKeyDns(keyPair.getPublic());
            String dnsRecordValue = buildDkimDnsRecord(publicKeyDns);

            // Salva come pending in DB (stato iniziale: pending_dns).
            // Memorizza anche il "mode" della rotazione, così tutti gli eventi successivi
            // (dns_propagated, key_activated, rotation_completed) lo ereditano automaticamente.
            String rotationMode = automatic ? "automatic" : "manual";
            database.setDkimPending(domainId, newSelector, privateKeyPem, publicKeyDns, "pending_dns", rotationMode);

            // Scrivi la chiave su disco (Rspamd la userà SOLO dopo activatePending)
            writePrivateKeyFile(d.domain, newSelector, privateKeyPem);

            String dnsRecordName = newSelector + "._domainkey." + d.domain;

            // Log: rotazione avviata
            logEvent(d, "rotation_started", newSelector, automatic ? "automatic" : "manual", true,
                "Nuova chiave RSA " + RSA_KEY_SIZE + " generata. Selector pending: " + newSelector
                + ". Vecchio selector attivo: " + d.dkimSelector);

            // FASE B: se richiesto e il dominio ha un account CF assegnato, pubblica subito il record
            if (automatic && cloudflare != null) {
                try {
                    MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
                    if (acct == null) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            "Chiave generata, ma nessun account Cloudflare assegnato a questo dominio. Pubblica il record TXT manualmente.");
                    }
                    CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                    if (!zl.found) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            "Chiave generata, ma l'account Cloudflare '" + acct.label + "' non vede la zona: " + zl.error
                            + ". Pubblica il record TXT manualmente.");
                    }
                    CloudflareManager.RecordOp op = cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, dnsRecordName, dnsRecordValue, 300);
                    if (!op.success) {
                        return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                            "Chiave generata, ma errore Cloudflare ('" + acct.label + "'): " + op.error
                            + ". Pubblica il record TXT manualmente.");
                    }
                    // Record creato: salva zoneId + recordId e passa a stato "propagated"
                    database.setDkimPendingCloudflareIds(domainId, zl.zoneId, op.recordId);
                    database.setDkimRotationState(domainId, "propagated");
                    logEvent(d, "dns_published", newSelector, "automatic", true,
                        "Record TXT creato in Cloudflare (zone " + zl.zoneName + ", record id " + op.recordId + "). Stato → propagated.");
                } catch (Exception cfErr) {
                    return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue,
                        "Chiave generata, ma errore Cloudflare: " + cfErr.getMessage()
                        + ". Pubblica il record TXT manualmente.");
                }
            }

            return new RotationStartResult(true, newSelector, dnsRecordName, dnsRecordValue, null);

        } catch (Exception e) {
            return new RotationStartResult(false, null, null, null, e.getMessage());
        }
    }

    /**
     * Verifica se il record DNS della chiave PENDING è propagato.
     * Interroga con dig +short TXT <pendingSelector>._domainkey.<domain>
     * e controlla che la stringa pubblica corrisponda a quella attesa.
     *
     * Se propagato e lo stato è ancora "pending_dns", lo aggiorna a "propagated".
     */
    public PropagationCheckResult checkPropagation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) {
                return new PropagationCheckResult(false, false, "Dominio non trovato", null);
            }
            if (d.dkimPendingSelector == null || d.dkimPendingPublicKey == null) {
                return new PropagationCheckResult(false, false, "Nessuna rotazione in corso", null);
            }

            String recordName = d.dkimPendingSelector + "._domainkey." + d.domain;

            // Interroga prima 1.1.1.1 (autoritativo Cloudflare via resolver pubblico) e poi 8.8.8.8 come fallback.
            // Questo riduce i falsi negativi durante la propagazione: se almeno uno dei due risponde
            // con la chiave attesa, consideriamo il record propagato.
            String[] resolvers = { "@1.1.1.1", "@8.8.8.8" };
            String lastRaw = "";
            boolean found = false;
            for (String resolver : resolvers) {
                // TODO: migrate to Shell.run when touched
                ProcessBuilder pb = new ProcessBuilder("dig", resolver, "+short", "+time=5", "+tries=2", "TXT", recordName);
                org.mail_panel.util.Shell.applicaPath(pb);
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

                // Pulisci virgolette e concatenazioni (dig restituisce stringhe TXT in "..." separate)
                String normalized = raw.replace("\"", "").replace(" ", "").replace("\n", "");
                String expectedTail = "p=" + d.dkimPendingPublicKey.replace(" ", "");
                if (normalized.contains("v=DKIM1") && normalized.contains(expectedTail)) {
                    found = true;
                    break;
                }
            }

            if (found) {
                // Aggiorna lo stato se ancora pending_dns
                if ("pending_dns".equals(d.dkimRotationState)) {
                    database.setDkimRotationState(domainId, "propagated");
                    logEvent(d, "dns_propagated", d.dkimPendingSelector, null, true,
                        "Record TXT pending verificato in DNS pubblico (1.1.1.1/8.8.8.8). Stato → propagated.");
                }
                return new PropagationCheckResult(true, true,
                    "Record DNS propagato e corrispondente alla chiave pending", lastRaw);
            } else {
                return new PropagationCheckResult(true, false,
                    lastRaw.isEmpty()
                        ? "Record DNS non ancora trovato — il provider DNS potrebbe non averlo ancora pubblicato"
                        : "Record trovato ma non corrisponde alla chiave pending — verifica il valore TXT",
                    lastRaw);
            }
        } catch (Exception e) {
            return new PropagationCheckResult(false, false, "Errore: " + e.getMessage(), null);
        }
    }

    /**
     * Attiva la chiave pending come attuale:
     *  - la pending diventa attiva (db.promotePendingToActive)
     *  - la chiave attuale diventa "previous" (resta in DNS durante il grace period)
     *  - Rspamd viene ricaricato così le nuove mail vengono firmate con la nuova chiave
     *
     * Pre-requisito: stato == "propagated" (o "pending_dns" se l'utente forza).
     */
    public RotationActionResult activatePending(int domainId, boolean force) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, "Dominio non trovato");
            if (d.dkimPendingSelector == null) {
                return new RotationActionResult(false, "Nessuna rotazione in corso");
            }
            if (!force && !"propagated".equals(d.dkimRotationState)) {
                return new RotationActionResult(false,
                    "Il record DNS non risulta ancora propagato. Esegui prima la verifica, oppure forza l'attivazione.");
            }

            String oldSelector = d.dkimSelector;
            String newSelector = d.dkimPendingSelector;

            // 1) Promote in DB (atomico)
            database.promotePendingToActive(domainId);

            // 2) Aggiorna il timestamp dell'ultima rotazione (per lo scheduler)
            database.markDkimRotationActivated(domainId);

            // 3) Rigenera Rspamd config (ora firmerà col nuovo selector)
            updateRspamdConfig();

            logEventWithPrevious(d, "key_activated", newSelector, oldSelector, force ? "forced" : null, true,
                "Chiave promossa: " + oldSelector + " → " + newSelector + ". Rspamd ricaricato. Vecchia chiave conservata per grace period.");

            return new RotationActionResult(true,
                "Chiave attivata. Le nuove email saranno firmate con il selector " + newSelector
                    + ". La vecchia chiave (" + oldSelector + ") resta in DNS durante il grace period "
                    + "(consigliato: 7 giorni) per validare le mail già spedite.");
        } catch (Exception e) {
            return new RotationActionResult(false, "Errore: " + e.getMessage());
        }
    }

    /**
     * Completa la rotazione: cancella la "previous" key dal DB e azzera lo stato.
     * L'utente, dopo questa chiamata, può rimuovere il vecchio record _domainkey TXT dal DNS.
     * Cancella anche il file della chiave precedente da disco.
     */
    public RotationActionResult completeRotation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, "Dominio non trovato");
            if (d.dkimPreviousSelector == null) {
                return new RotationActionResult(false, "Nessuna chiave precedente da rimuovere");
            }

            // ENFORCEMENT GRACE PERIOD (server-side, non bypassabile dalla UI).
            // Si può completare la rotazione SOLO se sono passati GRACE_PERIOD_DAYS dall'attivazione.
            // Questo previene rimozioni premature che causerebbero DKIM-fail su mail già in transito.
            if (d.dkimRotationActivatedAt != null) {
                long activatedMs = d.dkimRotationActivatedAt.getTime();
                long elapsedMs = System.currentTimeMillis() - activatedMs;
                long graceMs = DkimRotationScheduler.GRACE_PERIOD_DAYS * 24L * 60L * 60L * 1000L;
                if (elapsedMs < graceMs) {
                    long remainingMs = graceMs - elapsedMs;
                    long remainingDays = (remainingMs + 24L * 60L * 60L * 1000L - 1) / (24L * 60L * 60L * 1000L);
                    long remainingHours = (remainingMs + 60L * 60L * 1000L - 1) / (60L * 60L * 1000L);
                    String remainingText = remainingDays >= 1
                        ? (remainingDays + " giorn" + (remainingDays == 1 ? "o" : "i"))
                        : (remainingHours + " or" + (remainingHours == 1 ? "a" : "e"));
                    return new RotationActionResult(false,
                        "Grace period non ancora terminato. La rotazione non può essere completata prima di " + remainingText + ". " +
                        "Questo è obbligatorio: rimuovere la vecchia chiave troppo presto causerebbe DKIM-fail su email in transito firmate con la vecchia chiave. " +
                        "Il completamento avverrà automaticamente al termine.");
                }
            }

            String prevSelector = d.dkimPreviousSelector;
            String cfNote = "";

            // Cancella file su disco della chiave previous
            try {
                Path prevKey = Paths.get(DKIM_KEY_DIR, d.domain + "." + prevSelector + ".key");
                Files.deleteIfExists(prevKey);
            } catch (Exception ignore) {}

            // Prova a cancellare il record DNS della vecchia chiave via Cloudflare.
            // Strategia in 3 fallback per essere robusti anche se non abbiamo l'ID memorizzato:
            //   1) Se dkim_previous_dns_record_id è memorizzato → cancellazione diretta
            //   2) Altrimenti, se abbiamo un account CF assegnato → trova il record per nome
            //   3) Se anche lo zone_id è ignoto → cerca prima la zona via API
            String prevRecordName = prevSelector + "._domainkey." + d.domain;
            if (cloudflare != null) {
                MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
                if (acct != null) {
                    // Trova lo zone_id (memorizzato o via lookup)
                    String zoneId = d.dkimDnsZoneId;
                    if (zoneId == null) {
                        try {
                            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
                            if (zl.found) zoneId = zl.zoneId;
                        } catch (Exception ignore) {}
                    }
                    if (zoneId != null) {
                        // Trova il record_id da cancellare: memorizzato o via lookup per nome
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
                                ? " Record DNS '" + prevRecordName + "' rimosso automaticamente via Cloudflare (account '" + acct.label + "')."
                                : " Avviso: cancellazione Cloudflare fallita (" + op.error + "); rimuovi il record manualmente.";
                        } else {
                            cfNote = " Nota: record DNS '" + prevRecordName + "' non trovato in Cloudflare — probabilmente è già stato rimosso o non era mai esistito.";
                        }
                    }
                }
            }

            // Pulisci campi previous_* nel DB
            database.clearDkimPrevious(domainId);

            logEvent(d, "rotation_completed", d.dkimSelector, null, true,
                "Vecchia chiave (" + prevSelector + ") rimossa dal pannello." + cfNote);

            return new RotationActionResult(true,
                "Rotazione completata." + (cfNote.isEmpty()
                    ? " Puoi ora rimuovere il record DNS "
                        + prevRecordName + " (vecchia chiave)."
                    : cfNote));
        } catch (Exception e) {
            return new RotationActionResult(false, "Errore: " + e.getMessage());
        }
    }

    /**
     * Annulla una rotazione in corso (FASE pre-attivazione).
     * Funziona SOLO se lo stato è pending_dns / propagated (cioè non ancora attivata).
     * Cancella la chiave pending dal DB e da disco.
     */
    public RotationActionResult cancelRotation(int domainId) {
        try {
            MailDatabase.Domain d = database.getDomain(domainId);
            if (d == null) return new RotationActionResult(false, "Dominio non trovato");
            if (d.dkimPendingSelector == null) {
                return new RotationActionResult(false, "Nessuna rotazione da annullare");
            }
            if ("active_grace".equals(d.dkimRotationState)) {
                return new RotationActionResult(false,
                    "La rotazione è già stata attivata. Per finalizzarla usa 'Completa rotazione'.");
            }

            String pendingSelector = d.dkimPendingSelector;
            String cfNote = "";

            // Cancella file della chiave pending
            try {
                Path pendingKey = Paths.get(DKIM_KEY_DIR, d.domain + "." + pendingSelector + ".key");
                Files.deleteIfExists(pendingKey);
            } catch (Exception ignore) {}

            // Prova a cancellare il record DNS della chiave pending via Cloudflare.
            // Stesso pattern in 3 fallback di completeRotation: ID memorizzato, lookup per nome, zone lookup.
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
                                ? " Record DNS '" + pendingRecordName + "' rimosso automaticamente via Cloudflare (account '" + acct.label + "')."
                                : " Avviso: cancellazione Cloudflare fallita (" + op.error + "); rimuovi il record manualmente.";
                        }
                    }
                }
            }

            database.clearDkimPending(domainId);

            logEvent(d, "rotation_cancelled", pendingSelector, null, true,
                "Chiave pending eliminata prima dell'attivazione." + cfNote);

            return new RotationActionResult(true,
                "Rotazione annullata." + (cfNote.isEmpty()
                    ? " Puoi rimuovere il record DNS "
                        + pendingRecordName + " (chiave non più necessaria)."
                    : cfNote));
        } catch (Exception e) {
            return new RotationActionResult(false, "Errore: " + e.getMessage());
        }
    }

    /**
     * Ritorna info dettagliate sulla rotazione (per la UI).
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

            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "TXT", recordName);
            org.mail_panel.util.Shell.applicaPath(pb);
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

    /** Esito di startRotation: contiene il nuovo selector e il record DNS da pubblicare. */
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

    /** Esito di checkPropagation. */
    public static class PropagationCheckResult {
        public final boolean success;     // la verifica è stata eseguita senza errori
        public final boolean propagated;  // il record DNS corrisponde alla chiave pending
        public final String message;
        public final String rawDigOutput; // utile per debug nell'UI

        public PropagationCheckResult(boolean success, boolean propagated, String message, String rawDigOutput) {
            this.success = success;
            this.propagated = propagated;
            this.message = message;
            this.rawDigOutput = rawDigOutput;
        }
    }

    /** Esito generico per activatePending / completeRotation / cancelRotation. */
    public static class RotationActionResult {
        public final boolean success;
        public final String message;

        public RotationActionResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    /** Info aggregate sulla rotazione, per l'UI. */
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
