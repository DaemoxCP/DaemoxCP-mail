package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * DNS Records Generator for FreeBSD Mail Panel
 *
 * Generates all DNS records needed for a properly configured mail server:
 * - MX Record: Mail exchange record
 * - SPF Record: Sender Policy Framework
 * - DKIM Record: DomainKeys Identified Mail
 * - DMARC Record: Domain-based Message Authentication
 * - PTR Record: Reverse DNS (info only, requires ISP)
 * - Autoconfig: Thunderbird/Outlook autodiscover
 *
 * Also verifies existing DNS configuration.
 */
public class DnsRecordsGenerator {

    private final MailDatabase database;

    // Default values
    private static final int DEFAULT_MX_PRIORITY = 10;
    private static final int DEFAULT_TTL = 3600; // 1 hour

    public DnsRecordsGenerator(MailDatabase database) {
        this.database = database;
    }

    /**
     * Generate all DNS records for a domain
     */
    public DnsRecordSet generateAllRecords(String domain, String mailServerHostname, String serverIp) throws Exception {
        DnsRecordSet records = new DnsRecordSet();
        records.domain = domain;
        records.mailServerHostname = mailServerHostname;
        records.serverIp = serverIp;
        records.records = new ArrayList<>();

        // 1. MX Record
        records.records.add(generateMxRecord(domain, mailServerHostname));

        // NOTA: Il record A per il mail server hostname (es. mail.example.com)
        // viene mostrato nella HOME page con avviso di configurazione essenziale,
        // NON qui nella lista DNS per evitare duplicazioni.

        // 2. SPF Record
        records.records.add(generateSpfRecord(domain, serverIp));

        // 4. DKIM Record (if configured)
        MailDatabase.Domain dbDomain = database.getDomainByName(domain);
        if (dbDomain != null && dbDomain.hasDkim) {
            records.records.add(generateDkimRecord(domain, dbDomain.dkimSelector, dbDomain.dkimPublicKey));
        } else {
            // Add placeholder DKIM record with instructions
            DnsRecord dkimPlaceholder = new DnsRecord();
            dkimPlaceholder.type = "TXT";
            dkimPlaceholder.name = "mail._domainkey";
            dkimPlaceholder.value = "(Da generare)";
            dkimPlaceholder.ttl = DEFAULT_TTL;
            dkimPlaceholder.dnsZone = domain;
            dkimPlaceholder.description = "DKIM - Firma digitale email (da configurare)";
            dkimPlaceholder.required = true;
            dkimPlaceholder.configured = false;
            dkimPlaceholder.explanation = """
                <div class="alert alert-warning mb-2">
                    <strong>⚠️ DKIM non ancora configurato</strong>
                </div>
                <div class="alert alert-primary mb-2">
                    <strong>📍 Andrà configurato su Cloudflare nel dominio: %s</strong>
                </div>
                <strong>Come configurare DKIM:</strong>
                <ol>
                    <li>Vai alla pagina <strong>Domini</strong> nel pannello</li>
                    <li>Clicca sul dominio <strong>%s</strong></li>
                    <li>Clicca su <strong>"Genera chiavi DKIM"</strong></li>
                    <li>Copia il valore generato e crealo su Cloudflare</li>
                </ol>
                """.formatted(domain, domain);
            records.records.add(dkimPlaceholder);
        }

        // 5. DMARC Record
        records.records.add(generateDmarcRecord(domain));

        // 6. Autodiscover records for email clients
        records.records.addAll(generateAutodiscoverRecords(domain, mailServerHostname));

        // 7. PTR Record (informational)
        records.records.add(generatePtrRecord(serverIp, mailServerHostname));

        // 8. MTA-STS (optional, for enhanced security)
        records.records.add(generateMtaStsRecord(domain));

        return records;
    }

    /**
     * Generate MX Record
     */
    private DnsRecord generateMxRecord(String domain, String mailServer) {
        DnsRecord record = new DnsRecord();
        record.type = "MX";
        record.name = "@";
        record.value = mailServer;
        record.ttl = DEFAULT_TTL;
        record.priority = DEFAULT_MX_PRIORITY;
        record.dnsZone = domain;
        record.description = "Mail Exchange - Indica quale server gestisce la posta per " + domain;
        record.required = true;
        record.copyValue = mailServer;
        record.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>MX</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>@</code> (oppure lascia vuoto)</td></tr>
                <tr><td><strong>Mail server:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>Priority:</strong></td><td><code>10</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <small class="text-muted">
            Questo dice ai server email "la posta per %s va consegnata a %s"
            </small>
            """.formatted(domain, mailServer, domain, mailServer);
        return record;
    }

    /**
     * Generate A Record for mail subdomain
     */
    private DnsRecord generateARecord(String hostname, String ip) {
        DnsRecord record = new DnsRecord();
        record.type = "A";
        // Extract subdomain part (mail.example.com -> mail)
        String[] parts = hostname.split("\\.");
        String subdomain = parts[0];
        // Extract parent domain (mail.example.com -> example.com)
        String parentDomain = hostname.substring(hostname.indexOf('.') + 1);
        record.name = subdomain;
        record.value = ip;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = parentDomain;
        record.description = "Indirizzo IP del server mail (" + hostname + ")";
        record.required = true;
        record.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>A</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>IPv4 address:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>Proxy status:</strong></td><td><span class="text-danger">⚠️ DNS only (nuvola GRIGIA, NON arancione!)</span></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <div class="alert alert-warning mt-2 mb-0">
                <strong>⚠️ IMPORTANTE:</strong> Il proxy Cloudflare (nuvola arancione) <strong>NON</strong> deve essere attivo!<br>
                Clicca sulla nuvola arancione per renderla grigia (DNS only).
            </div>
            """.formatted(parentDomain, subdomain, ip);
        return record;
    }

    /**
     * Generate SPF Record
     * SPF specifies which servers are allowed to send email for the domain
     */
    private DnsRecord generateSpfRecord(String domain, String serverIp) {
        DnsRecord record = new DnsRecord();
        record.type = "TXT";
        record.name = "@";
        String spfValue = "v=spf1 ip4:" + serverIp + " mx -all";
        record.value = spfValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "SPF - Definisce quali server possono inviare email per " + domain;
        record.required = true;
        record.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>TXT</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>@</code></td></tr>
                <tr><td><strong>Content:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <hr>
            <strong>Cosa significa:</strong>
            <ul class="mb-0 small">
                <li><code>v=spf1</code> = versione SPF</li>
                <li><code>ip4:%s</code> = autorizza questo IP a inviare email</li>
                <li><code>mx</code> = autorizza anche i server MX</li>
                <li><code>-all</code> = rifiuta tutti gli altri</li>
            </ul>
            """.formatted(domain, spfValue, serverIp);
        return record;
    }

    /**
     * Generate DKIM Record
     */
    private DnsRecord generateDkimRecord(String domain, String selector, String publicKey) {
        DnsRecord record = new DnsRecord();
        record.type = "TXT";
        String dkimName = selector + "._domainkey";
        record.name = dkimName;
        String dkimValue = "v=DKIM1; k=rsa; p=" + publicKey;
        record.value = dkimValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "DKIM - Firma digitale per autenticare le email";
        record.required = true;
        record.configured = true;
        record.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>TXT</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>Content:</strong></td><td style="word-break:break-all"><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            """.formatted(domain, dkimName, dkimValue);
        return record;
    }

    /**
     * Generate DMARC Record
     * DMARC ties SPF and DKIM together with reporting
     */
    private DnsRecord generateDmarcRecord(String domain) {
        DnsRecord record = new DnsRecord();
        record.type = "TXT";
        record.name = "_dmarc";
        String dmarcValue = "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain;
        record.value = dmarcValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "DMARC - Policy per email non autenticate";
        record.required = true;
        record.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>TXT</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>_dmarc</code></td></tr>
                <tr><td><strong>Content:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <hr>
            <strong>Cosa significa:</strong>
            <ul class="mb-0 small">
                <li><code>p=quarantine</code> = metti in spam le email non autenticate</li>
                <li><code>rua=mailto:...</code> = ricevi report (opzionale)</li>
            </ul>
            """.formatted(domain, dmarcValue);
        return record;
    }

    /**
     * Generate Autodiscover records for email clients
     */
    private List<DnsRecord> generateAutodiscoverRecords(String domain, String mailServer) {
        List<DnsRecord> records = new ArrayList<>();

        // Thunderbird autoconfig
        DnsRecord autoconfig = new DnsRecord();
        autoconfig.type = "CNAME";
        autoconfig.name = "autoconfig";
        autoconfig.value = mailServer;
        autoconfig.ttl = DEFAULT_TTL;
        autoconfig.dnsZone = domain;
        autoconfig.description = "Autoconfig per Thunderbird (autoconfig." + domain + ")";
        autoconfig.required = false;
        autoconfig.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>CNAME</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>autoconfig</code></td></tr>
                <tr><td><strong>Target:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>Proxy status:</strong></td><td>DNS only (nuvola grigia)</td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <small class="text-muted">Permette a Thunderbird di configurare automaticamente l'account email.</small>
            """.formatted(domain, mailServer);
        records.add(autoconfig);

        // Outlook autodiscover
        DnsRecord autodiscover = new DnsRecord();
        autodiscover.type = "CNAME";
        autodiscover.name = "autodiscover";
        autodiscover.value = mailServer;
        autodiscover.ttl = DEFAULT_TTL;
        autodiscover.dnsZone = domain;
        autodiscover.description = "Autodiscover per Outlook (autodiscover." + domain + ")";
        autodiscover.required = false;
        autodiscover.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>CNAME</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>autodiscover</code></td></tr>
                <tr><td><strong>Target:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>Proxy status:</strong></td><td>DNS only (nuvola grigia)</td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <small class="text-muted">Permette a Outlook di configurare automaticamente l'account email.</small>
            """.formatted(domain, mailServer);
        records.add(autodiscover);

        // SRV records for proper autodiscover
        DnsRecord srvImap = new DnsRecord();
        srvImap.type = "SRV";
        srvImap.name = "_imaps._tcp";
        srvImap.value = mailServer;
        srvImap.priority = 0;
        srvImap.ttl = DEFAULT_TTL;
        srvImap.dnsZone = domain;
        srvImap.description = "SRV per IMAP SSL (_imaps._tcp." + domain + ")";
        srvImap.required = false;
        srvImap.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>SRV</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>_imaps._tcp</code></td></tr>
                <tr><td><strong>Priority:</strong></td><td><code>0</code></td></tr>
                <tr><td><strong>Weight:</strong></td><td><code>1</code></td></tr>
                <tr><td><strong>Port:</strong></td><td><code>993</code></td></tr>
                <tr><td><strong>Target:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            """.formatted(domain, mailServer);
        records.add(srvImap);

        DnsRecord srvSmtp = new DnsRecord();
        srvSmtp.type = "SRV";
        srvSmtp.name = "_submission._tcp";
        srvSmtp.value = mailServer;
        srvSmtp.priority = 0;
        srvSmtp.ttl = DEFAULT_TTL;
        srvSmtp.dnsZone = domain;
        srvSmtp.description = "SRV per SMTP submission (_submission._tcp." + domain + ")";
        srvSmtp.required = false;
        srvSmtp.explanation = """
            <div class="alert alert-primary mb-2">
                <strong>📍 Configura su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>SRV</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>_submission._tcp</code></td></tr>
                <tr><td><strong>Priority:</strong></td><td><code>0</code></td></tr>
                <tr><td><strong>Weight:</strong></td><td><code>1</code></td></tr>
                <tr><td><strong>Port:</strong></td><td><code>587</code></td></tr>
                <tr><td><strong>Target:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            """.formatted(domain, mailServer);
        records.add(srvSmtp);

        return records;
    }

    /**
     * Generate PTR Record info (reverse DNS)
     */
    private DnsRecord generatePtrRecord(String ip, String hostname) {
        DnsRecord record = new DnsRecord();
        record.type = "PTR";
        record.name = ip;
        record.value = hostname;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = "(Provider Hosting)";
        record.description = "PTR - Reverse DNS (NON si configura su Cloudflare)";
        record.required = true;
        record.explanation = """
            <div class="alert alert-danger mb-3">
                <strong>⚠️ ATTENZIONE:</strong> Questo record <strong>NON</strong> si configura su Cloudflare!<br>
                <small>Il PTR (Reverse DNS) si configura SOLO sul pannello del tuo provider VPS/hosting.</small>
            </div>

            <div class="alert alert-dark mb-3">
                <strong>🎯 Cosa devi configurare:</strong>
                <table class="table table-sm table-bordered mt-2 mb-0 bg-white">
                    <tr><td width="120"><strong>IP Address:</strong></td><td><code>%s</code></td></tr>
                    <tr><td><strong>Hostname:</strong></td><td><code>%s</code></td></tr>
                </table>
            </div>

            <hr>

            <div class="accordion" id="ptrAccordion">
                <!-- HETZNER -->
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#hetznerGuide">
                            <strong>🟠 Guida HETZNER (Cloud Console 2025)</strong>
                        </button>
                    </h2>
                    <div id="hetznerGuide" class="accordion-collapse collapse" data-bs-parent="#ptrAccordion">
                        <div class="accordion-body">
                            <ol>
                                <li>Vai su <a href="https://console.hetzner.cloud" target="_blank"><strong>console.hetzner.cloud</strong></a></li>
                                <li>Seleziona il tuo <strong>Progetto</strong> dalla lista</li>
                                <li>Clicca su <strong>"Servers"</strong> nel menu a sinistra</li>
                                <li>Clicca sul nome del tuo server</li>
                                <li>Vai nella tab <strong>"Networking"</strong></li>
                                <li>Nella sezione <strong>"Public Network"</strong>, vedrai una tabella con:
                                    <ul>
                                        <li><strong>Primary IP</strong> - <strong>Protocol</strong> - <strong>Reverse DNS</strong></li>
                                        <li>Il tuo IP <code>%s</code> avrà un reverse DNS di default tipo <code>static.xxx.xxx.xxx.xxx.clients.your-server.de</code></li>
                                    </ul>
                                </li>
                                <li>Clicca sui <strong>tre puntini ⋮</strong> a destra della riga dell'IP</li>
                                <li>Dal menu, seleziona <strong>"Edit Reverse DNS"</strong></li>
                                <li>Nel campo inserisci: <code>%s</code></li>
                                <li>Clicca <strong>"Save"</strong></li>
                            </ol>
                            <div class="alert alert-info mb-2">
                                <small><strong>Nota:</strong> Il reverse DNS di default Hetzner è tipo <code>static.77.113.0.203.clients.your-server.de</code> - devi cambiarlo!</small>
                            </div>
                            <div class="alert alert-success mb-0">
                                <small>✅ La propagazione su Hetzner è immediata (1-5 minuti)</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- OVH -->
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#ovhGuide">
                            <strong>🔵 Guida OVH / OVHcloud (2025)</strong>
                        </button>
                    </h2>
                    <div id="ovhGuide" class="accordion-collapse collapse" data-bs-parent="#ptrAccordion">
                        <div class="accordion-body">
                            <ol>
                                <li>Vai su <a href="https://www.ovh.com/manager/" target="_blank"><strong>www.ovh.com/manager</strong></a></li>
                                <li>Effettua il login con il tuo account OVH</li>
                                <li>Nel menu a sinistra, vai su <strong>"Bare Metal Cloud"</strong> oppure <strong>"Public Cloud"</strong> (dipende dal tipo di server)</li>
                                <li><strong>Per VPS:</strong>
                                    <ul>
                                        <li>Clicca su <strong>"VPS"</strong></li>
                                        <li>Seleziona il tuo VPS dalla lista</li>
                                        <li>Vai nella sezione <strong>"IP"</strong></li>
                                    </ul>
                                </li>
                                <li><strong>Per Dedicated Server:</strong>
                                    <ul>
                                        <li>Clicca su <strong>"Server dedicati"</strong></li>
                                        <li>Seleziona il server</li>
                                        <li>Vai su <strong>"IP"</strong> nel menu</li>
                                    </ul>
                                </li>
                                <li>Trova l'IP <code>%s</code> nella lista</li>
                                <li>Clicca sui <strong>tre puntini ⋮</strong> a destra</li>
                                <li>Seleziona <strong>"Modifica il reverse"</strong></li>
                                <li>Inserisci: <code>%s</code></li>
                                <li>Clicca <strong>"Conferma"</strong></li>
                            </ol>
                            <div class="alert alert-warning mb-0">
                                <small>⏱️ OVH può richiedere fino a 24 ore per la propagazione</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- DIGITALOCEAN -->
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#doGuide">
                            <strong>🔷 Guida DigitalOcean (2025)</strong>
                        </button>
                    </h2>
                    <div id="doGuide" class="accordion-collapse collapse" data-bs-parent="#ptrAccordion">
                        <div class="accordion-body">
                            <div class="alert alert-info mb-2">
                                <strong>Nota:</strong> Su DigitalOcean, il PTR viene impostato automaticamente in base al nome del Droplet.
                            </div>
                            <ol>
                                <li>Vai su <a href="https://cloud.digitalocean.com" target="_blank"><strong>cloud.digitalocean.com</strong></a></li>
                                <li>Clicca sul tuo <strong>Droplet</strong></li>
                                <li>In alto, clicca sul <strong>nome del Droplet</strong> (es. "ubuntu-server")</li>
                                <li>Rinomina il Droplet esattamente in: <code>%s</code></li>
                                <li>Premi <strong>Enter</strong> per salvare</li>
                            </ol>
                            <div class="alert alert-success mb-0">
                                <small>✅ Il PTR si aggiorna automaticamente entro pochi minuti</small>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ALTRI PROVIDER -->
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#otherGuide">
                            <strong>⚪ Altri Provider (Vultr, Linode, AWS, etc.)</strong>
                        </button>
                    </h2>
                    <div id="otherGuide" class="accordion-collapse collapse" data-bs-parent="#ptrAccordion">
                        <div class="accordion-body">
                            <strong>Istruzioni generiche:</strong>
                            <ol>
                                <li>Accedi al pannello di controllo del tuo provider</li>
                                <li>Cerca una di queste voci nel menu:
                                    <ul>
                                        <li><strong>"Reverse DNS"</strong></li>
                                        <li><strong>"rDNS"</strong></li>
                                        <li><strong>"PTR Record"</strong></li>
                                        <li><strong>"DNS inverso"</strong></li>
                                    </ul>
                                </li>
                                <li>Associa l'IP <code>%s</code> all'hostname <code>%s</code></li>
                                <li>Salva le modifiche</li>
                            </ol>
                            <div class="alert alert-secondary mb-0">
                                <small>💡 Se non trovi l'opzione, contatta il supporto del tuo provider e chiedi di configurare il PTR per te.</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <hr>

            <div class="alert alert-warning mb-2">
                <strong>🔍 Come verificare se il PTR è configurato correttamente:</strong><br>
                Esegui questo comando dal terminale:
                <pre class="bg-dark text-light p-2 rounded mt-2 mb-0">dig -x %s +short</pre>
                <small>Deve restituire: <code>%s.</code> (con il punto finale)</small>
            </div>

            <div class="alert alert-danger mb-0">
                <strong>⚠️ Perché è FONDAMENTALE:</strong>
                <ul class="mb-0 mt-2">
                    <li><strong>Senza PTR corretto, le tue email finiranno in SPAM</strong></li>
                    <li>Gmail, Outlook e altri provider rifiutano email da IP senza PTR valido</li>
                    <li>Il PTR deve corrispondere <strong>ESATTAMENTE</strong> a <code>%s</code></li>
                    <li>Deve anche corrispondere al record A (mail.tuodominio.xx → IP → PTR → mail.tuodominio.xx)</li>
                </ul>
            </div>
            """.formatted(ip, hostname, ip, hostname, ip, hostname, hostname, ip, hostname, ip, hostname, hostname);
        return record;
    }

    /**
     * Generate MTA-STS Record (optional enhanced security)
     */
    private DnsRecord generateMtaStsRecord(String domain) {
        DnsRecord record = new DnsRecord();
        record.type = "TXT";
        record.name = "_mta-sts";
        String mtaStsValue = "v=STSv1; id=" + System.currentTimeMillis();
        record.value = mtaStsValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "MTA-STS (avanzato, opzionale)";
        record.required = false;
        record.explanation = """
            <div class="alert alert-secondary mb-2">
                <strong>ℹ️ Questo record è OPZIONALE e avanzato</strong>
            </div>
            <div class="alert alert-primary mb-2">
                <strong>📍 Se vuoi configurarlo, fallo su Cloudflare nel dominio: %s</strong>
            </div>
            <table class="table table-sm">
                <tr><td width="120"><strong>Type:</strong></td><td>TXT</td></tr>
                <tr><td><strong>Name:</strong></td><td><code>_mta-sts</code></td></tr>
                <tr><td><strong>Content:</strong></td><td><code>%s</code></td></tr>
                <tr><td><strong>TTL:</strong></td><td>Auto</td></tr>
            </table>
            <small class="text-muted">
            MTA-STS forza i server mittenti a usare TLS. Richiede anche:<br>
            - Un record CNAME <code>mta-sts</code> che punta a un web server<br>
            - Un file <code>https://mta-sts.%s/.well-known/mta-sts.txt</code>
            </small>
            """.formatted(domain, mtaStsValue, domain);
        return record;
    }

    // ============== DNS Verification ==============

    /**
     * Verify all DNS records for a domain
     */
    public DnsVerificationResult verifyAllRecords(String domain) {
        DnsVerificationResult result = new DnsVerificationResult();
        result.domain = domain;
        result.checks = new ArrayList<>();
        result.allPassed = true;

        // Get expected values
        String serverIp = detectServerIp();
        String mailHostname = database.getSetting("mail_hostname", "mail." + domain);

        // 1. Check A record for mail hostname - verify it points to our server
        DnsCheck aCheck = verifyRecord(mailHostname, "A");
        aCheck.recordType = "A";
        aCheck.expectedValue = serverIp;
        if (aCheck.passed && aCheck.currentValue != null) {
            String foundIp = aCheck.currentValue.trim().split("\\n")[0]; // Get first IP if multiple
            if (foundIp.equals(serverIp)) {
                aCheck.message = "OK: " + mailHostname + " → " + serverIp;
            } else {
                aCheck.passed = false;
                aCheck.message = "IP errato: " + foundIp + " (atteso: " + serverIp + ")";
            }
        } else {
            aCheck.message = "Record A non trovato per " + mailHostname;
        }
        result.checks.add(aCheck);
        if (!aCheck.passed) result.allPassed = false;

        // 2. Check MX - verify it points to our mail server
        DnsCheck mxCheck = verifyRecord(domain, "MX");
        mxCheck.expectedValue = "10 " + mailHostname + ".";
        if (mxCheck.passed && mxCheck.currentValue != null) {
            if (!mxCheck.currentValue.toLowerCase().contains(mailHostname.toLowerCase())) {
                mxCheck.passed = false;
                mxCheck.message = "MX non punta a " + mailHostname;
            } else {
                mxCheck.message = "OK: punta a " + mailHostname;
            }
        }
        result.checks.add(mxCheck);
        if (!mxCheck.passed) result.allPassed = false;

        // 3. Check SPF - verify it contains our server IP
        String expectedSpf = "v=spf1 ip4:" + serverIp + " mx -all";
        DnsCheck spfCheck = verifyTxtRecord(domain, "v=spf1");
        spfCheck.recordType = "SPF";
        spfCheck.expectedValue = expectedSpf;
        if (spfCheck.passed && spfCheck.currentValue != null) {
            if (spfCheck.currentValue.contains(serverIp) || spfCheck.currentValue.contains("mx")) {
                spfCheck.message = "OK: include IP/MX corretto";
            } else {
                spfCheck.passed = false;
                spfCheck.message = "SPF non include IP " + serverIp;
            }
        }
        result.checks.add(spfCheck);
        if (!spfCheck.passed) result.allPassed = false;

        // 4. Check DKIM - verify public key present
        MailDatabase.Domain dbDomain = null;
        try {
            dbDomain = database.getDomainByName(domain);
        } catch (Exception e) {
            // ignore
        }

        String selector = (dbDomain != null && dbDomain.dkimSelector != null) ? dbDomain.dkimSelector : "mail";
        DnsCheck dkimCheck = verifyTxtRecord(selector + "._domainkey." + domain, "v=DKIM1");
        dkimCheck.recordType = "DKIM";
        if (dbDomain != null && dbDomain.dkimPublicKey != null) {
            dkimCheck.expectedValue = "v=DKIM1; k=rsa; p=" + dbDomain.dkimPublicKey.substring(0, 20) + "...";
        }
        if (dkimCheck.passed && dkimCheck.currentValue != null) {
            if (dkimCheck.currentValue.contains("p=") && dkimCheck.currentValue.length() > 100) {
                // Verify the key matches if we have it
                if (dbDomain != null && dbDomain.dkimPublicKey != null) {
                    String keyPart = dbDomain.dkimPublicKey.substring(0, Math.min(50, dbDomain.dkimPublicKey.length()));
                    if (dkimCheck.currentValue.contains(keyPart)) {
                        dkimCheck.message = "OK: chiave pubblica corretta";
                    } else {
                        dkimCheck.passed = false;
                        dkimCheck.message = "Chiave DKIM non corrisponde";
                    }
                } else {
                    dkimCheck.message = "OK: chiave pubblica presente";
                }
            } else {
                dkimCheck.passed = false;
                dkimCheck.message = "Record DKIM incompleto o malformato";
            }
        }
        result.checks.add(dkimCheck);
        if (!dkimCheck.passed) result.allPassed = false;

        // 5. Check DMARC - verify policy present
        DnsCheck dmarcCheck = verifyTxtRecord("_dmarc." + domain, "v=DMARC1");
        dmarcCheck.recordType = "DMARC";
        dmarcCheck.expectedValue = "v=DMARC1; p=quarantine; ...";
        if (dmarcCheck.passed && dmarcCheck.currentValue != null) {
            if (dmarcCheck.currentValue.contains("p=none")) {
                dmarcCheck.message = "OK ma policy debole (p=none)";
            } else if (dmarcCheck.currentValue.contains("p=quarantine")) {
                dmarcCheck.message = "OK: policy quarantine";
            } else if (dmarcCheck.currentValue.contains("p=reject")) {
                dmarcCheck.message = "OK: policy reject (massima sicurezza)";
            } else {
                dmarcCheck.message = "OK: DMARC configurato";
            }
        }
        result.checks.add(dmarcCheck);
        if (!dmarcCheck.passed) result.allPassed = false;

        // 6. Check Autoconfig for Thunderbird (CNAME)
        DnsCheck autoconfigCheck = verifyRecord("autoconfig." + domain, "CNAME");
        autoconfigCheck.recordType = "Autoconfig";
        autoconfigCheck.expectedValue = mailHostname + ".";
        if (autoconfigCheck.passed && autoconfigCheck.currentValue != null) {
            if (autoconfigCheck.currentValue.toLowerCase().contains(mailHostname.toLowerCase())) {
                autoconfigCheck.message = "OK: autoconfig → " + mailHostname;
            } else {
                // Record exists but points to wrong hostname
                autoconfigCheck.passed = false;
                autoconfigCheck.message = "Punta a " + autoconfigCheck.currentValue.trim() + " invece di " + mailHostname;
            }
        } else {
            // Not critical, just informational
            autoconfigCheck.passed = false;
            autoconfigCheck.message = "Non configurato (opzionale)";
        }
        result.checks.add(autoconfigCheck);
        // Don't fail overall for optional records
        // if (!autoconfigCheck.passed) result.allPassed = false;

        // 7. Check Autodiscover for Outlook (CNAME)
        DnsCheck autodiscoverCheck = verifyRecord("autodiscover." + domain, "CNAME");
        autodiscoverCheck.recordType = "Autodiscover";
        autodiscoverCheck.expectedValue = mailHostname + ".";
        if (autodiscoverCheck.passed && autodiscoverCheck.currentValue != null) {
            if (autodiscoverCheck.currentValue.toLowerCase().contains(mailHostname.toLowerCase())) {
                autodiscoverCheck.message = "OK: autodiscover → " + mailHostname;
            } else {
                // Record exists but points to wrong hostname
                autodiscoverCheck.passed = false;
                autodiscoverCheck.message = "Punta a " + autodiscoverCheck.currentValue.trim() + " invece di " + mailHostname;
            }
        } else {
            // Not critical, just informational
            autodiscoverCheck.passed = false;
            autodiscoverCheck.message = "Non configurato (opzionale)";
        }
        result.checks.add(autodiscoverCheck);
        // Don't fail overall for optional records
        // if (!autodiscoverCheck.passed) result.allPassed = false;

        // 8. Check MTA-STS (optional but recommended)
        // Note: MTA-STS ID is just a version timestamp, doesn't need to match exactly
        DnsCheck mtaStsCheck = verifyTxtRecord("_mta-sts." + domain, "v=STSv1");
        mtaStsCheck.recordType = "MTA-STS";
        mtaStsCheck.expectedValue = "v=STSv1; id=(timestamp)";
        if (mtaStsCheck.passed && mtaStsCheck.currentValue != null) {
            // Extract ID from current value for display
            mtaStsCheck.message = "Record presente (opzionale)";
        } else {
            mtaStsCheck.passed = false;
            mtaStsCheck.message = "Non configurato (opzionale)";
        }
        result.checks.add(mtaStsCheck);
        // Don't fail overall for optional records
        // if (!mtaStsCheck.passed) result.allPassed = false;

        // 9. Check SRV records for IMAP and SMTP submission
        DnsCheck srvImapCheck = verifyRecord("_imaps._tcp." + domain, "SRV");
        srvImapCheck.recordType = "SRV (_imaps)";
        srvImapCheck.expectedValue = "0 1 993 " + mailHostname + ".";
        if (srvImapCheck.passed && srvImapCheck.currentValue != null) {
            if (srvImapCheck.currentValue.toLowerCase().contains(mailHostname.toLowerCase())) {
                srvImapCheck.message = "OK: _imaps._tcp → " + mailHostname + ":993";
            } else {
                srvImapCheck.passed = false;
                srvImapCheck.message = "Punta a " + srvImapCheck.currentValue.trim() + " invece di " + mailHostname;
            }
        } else {
            srvImapCheck.passed = false;
            srvImapCheck.message = "Non configurato (opzionale)";
        }
        result.checks.add(srvImapCheck);

        DnsCheck srvSmtpCheck = verifyRecord("_submission._tcp." + domain, "SRV");
        srvSmtpCheck.recordType = "SRV (_submission)";
        srvSmtpCheck.expectedValue = "0 1 587 " + mailHostname + ".";
        if (srvSmtpCheck.passed && srvSmtpCheck.currentValue != null) {
            if (srvSmtpCheck.currentValue.toLowerCase().contains(mailHostname.toLowerCase())) {
                srvSmtpCheck.message = "OK: _submission._tcp → " + mailHostname + ":587";
            } else {
                srvSmtpCheck.passed = false;
                srvSmtpCheck.message = "Punta a " + srvSmtpCheck.currentValue.trim() + " invece di " + mailHostname;
            }
        } else {
            srvSmtpCheck.passed = false;
            srvSmtpCheck.message = "Non configurato (opzionale)";
        }
        result.checks.add(srvSmtpCheck);

        // Calculate score - only count required records (A, MX, SPF, DKIM, DMARC)
        int requiredCount = 5;
        int requiredPassed = 0;
        for (int i = 0; i < Math.min(requiredCount, result.checks.size()); i++) {
            if (result.checks.get(i).passed) requiredPassed++;
        }
        result.score = (requiredPassed * 100) / requiredCount;

        return result;
    }

    /**
     * Verify a specific DNS record using dig
     */
    private DnsCheck verifyRecord(String name, String type) {
        DnsCheck check = new DnsCheck();
        check.recordType = type;
        check.recordName = name;

        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", type, name);
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

            String result = output.toString().trim();
            if (result.isEmpty()) {
                check.passed = false;
                check.message = "Record non trovato";
                check.currentValue = null;
            } else {
                check.passed = true;
                check.message = "Record trovato";
                check.currentValue = result;
            }

        } catch (Exception e) {
            check.passed = false;
            check.message = "Errore verifica: " + e.getMessage();
        }

        return check;
    }

    /**
     * Verify a TXT record contains expected content
     */
    private DnsCheck verifyTxtRecord(String name, String expectedContent) {
        DnsCheck check = verifyRecord(name, "TXT");

        if (check.passed && check.currentValue != null) {
            if (!check.currentValue.contains(expectedContent)) {
                check.passed = false;
                check.message = "Record trovato ma contenuto non valido";
            }
        }

        return check;
    }

    /**
     * Get server's public IP address
     */
    public String detectServerIp() {
        // Try multiple services for reliability
        String[] services = {
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip"
        };

        for (String service : services) {
            try {
                URL url = new URL(service);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    String ip = reader.readLine().trim();
                    if (isValidIp(ip)) {
                        return ip;
                    }
                }
            } catch (Exception e) {
                // Try next service
            }
        }

        // Fallback: try to get from network interface
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        String ip = addr.getHostAddress();
                        // Skip private IPs
                        if (!ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("172.")) {
                            return ip;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return "YOUR_SERVER_IP";
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // ============== Model Classes ==============

    public static class DnsRecordSet {
        public String domain;
        public String mailServerHostname;
        public String serverIp;
        public List<DnsRecord> records;
    }

    public static class DnsRecord {
        public String type;          // MX, A, TXT, CNAME, SRV, PTR
        public String name;          // Record name (e.g., example.com, mail._domainkey.example.com)
        public String value;         // Record value
        public int ttl;              // Time to live
        public int priority;         // For MX records
        public String description;   // Human-readable description
        public String explanation;   // Detailed explanation
        public boolean required;     // Is this record required?
        public boolean configured;   // Is this record already configured?
        public String copyValue;     // Value to copy (simpler version)
        public String dnsZone;       // Which DNS zone to configure this in (e.g., "domain-d.test" or "example.com")
    }

    public static class DnsVerificationResult {
        public String domain;
        public List<DnsCheck> checks;
        public boolean allPassed;
        public int score; // 0-100
    }

    public static class DnsCheck {
        public String recordType;
        public String recordName;
        public boolean passed;
        public String message;
        public String currentValue;
        public String expectedValue;
    }
}
