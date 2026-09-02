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
 * - Autoconfig e SRV: come i client trovano da soli server e porte
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
            // Anche il segnaposto dichiara la sua verifica: senza, sarebbe l'unico record a
            // ripiegare sull'appaiamento per nome, cioe' proprio sul difetto appena corretto.
            dkimPlaceholder.checkType = "DKIM";
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

        // 6. I record con cui i client trovano da soli le impostazioni
        records.records.addAll(generateRecordScopertaClient(domain, mailServerHostname));

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
        record.checkType = "MX";
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
        record.checkType = "A";
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
        record.checkType = "SPF";
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
        record.checkType = "DKIM";
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
        // RFC 9989 §5.1.5: si parte da "none". Proporre "quarantine" come primo record
        // significa mandare in quarantena la propria posta legittima prima di aver letto un
        // solo rapporto — ed e' esattamente cio' che i rapporti servono a evitare.
        String dmarcValue = "v=DMARC1; p=none; rua=mailto:dmarc@" + domain;
        record.value = dmarcValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "DMARC - Policy per email non autenticate";
        record.checkType = "DMARC";
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
                <li><code>p=none</code> = non bloccare nulla, limitati a segnalare. E&rsquo; il punto di
                    partenza: prima si guarda chi spedisce a nome tuo, poi si stringe verso
                    <code>quarantine</code> e infine <code>reject</code>.</li>
                <li><code>rua=mailto:...</code> = dove mandare i rapporti. Non &egrave; un dettaglio
                    opzionale: senza, non si sapr&agrave; mai se si pu&ograve; stringere la politica
                    senza fermare posta buona. L&rsquo;indirizzo deve esistere gi&agrave;.</li>
            </ul>
            """.formatted(domain, dmarcValue);
        return record;
    }

    /**
     * I record che aiutano i client a configurarsi: il CNAME autoconfig (Thunderbird) e i
     * due SRV di RFC 6186. Il CNAME "autodiscover" non c'e' piu': serviva solo a Outlook, e
     * un metodo che si chiama ancora come cio' che non fa piu' e' un tranello per chi legge.
     */
    private List<DnsRecord> generateRecordScopertaClient(String domain, String mailServer) {
        List<DnsRecord> records = new ArrayList<>();

        // Thunderbird autoconfig
        DnsRecord autoconfig = new DnsRecord();
        autoconfig.type = "CNAME";
        autoconfig.name = "autoconfig";
        autoconfig.value = mailServer;
        autoconfig.ttl = DEFAULT_TTL;
        autoconfig.dnsZone = domain;
        autoconfig.description = "Autoconfig per Thunderbird (autoconfig." + domain + ")";
        autoconfig.checkType = "Autoconfig";
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

        // I due SRV di RFC 6186: questi funzionano da soli, senza alcun file da servire.
        DnsRecord srvImap = new DnsRecord();
        srvImap.type = "SRV";
        srvImap.name = "_imaps._tcp";
        srvImap.value = mailServer;
        srvImap.priority = 0;
        srvImap.ttl = DEFAULT_TTL;
        srvImap.dnsZone = domain;
        srvImap.description = "SRV per IMAP SSL (_imaps._tcp." + domain + ")";
        srvImap.checkType = "SRV (_imaps)";
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
        srvSmtp.checkType = "SRV (_submission)";
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
        record.checkType = "PTR";
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
        // Il valore e' quello VERO, lo stesso che il pannello pubblica: si chiede a chi lo
        // sa, non se ne inventa un altro qui.
        //
        // Prima era "v=STSv1; id=" + System.currentTimeMillis(): un id preso dall'orologio,
        // ricalcolato a ogni caricamento della pagina. Due difetti in una riga. Il primo: chi
        // seguiva queste istruzioni pubblicava un id che non corrisponde alla politica servita
        // e che non cambia mai piu', quindi i mittenti non si accorgono delle modifiche —
        // esattamente il difetto che i record del vecchio pannello si portavano dietro. Il
        // secondo: il valore mostrato cambiava a ogni sguardo, mentre la riga accanto diceva
        // "configurato correttamente". Due modi di calcolare lo stesso record sono due record
        // che un giorno divergono; qui divergevano subito.
        String mtaStsValue = org.mail_panel.system.MtaSts.recordTxtCorrente();
        // recordTxtCorrente() torna vuoto quando non riesce a calcolarlo: meglio niente che un
        // valore inventato. Ma una casella "Content" vuota nelle istruzioni non aiuta nessuno,
        // quindi si dice a parole cosa ci andra', senza suggerire di incollare una sciocchezza.
        if (mtaStsValue == null || mtaStsValue.isBlank())
            mtaStsValue = "v=STSv1; id=<lo genera il pannello quando pubblica il record>";
        record.value = mtaStsValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = "MTA-STS (avanzato, opzionale)";
        record.checkType = "MTA-STS";
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
        } else if (aCheck.message == null || !aCheck.message.startsWith("Errore")) {
            // Solo se la query e' andata a buon fine e non ha trovato niente. Se invece era
            // fallita, il messaggio preciso c'e' gia' e sovrascriverlo con "non trovato"
            // trasforma uno strumento rotto in un record DNS mancante: due problemi con due
            // rimedi opposti, e chi legge va a cercare nel posto sbagliato.
            aCheck.message = "Record A non trovato per " + mailHostname;
        }
        result.checks.add(aCheck);
        if (!aCheck.passed) result.allPassed = false;

        // 2. Check MX - verify it points to our mail server
        DnsCheck mxCheck = verifyRecord(domain, "MX");
        mxCheck.expectedValue = "10 " + mailHostname + ".";
        if (mxCheck.passed && mxCheck.currentValue != null) {
            // Un dominio puo' avere piu' MX: basta che UNO punti qui. Ma il confronto e'
            // esatto sul nome di destinazione, non per contenimento: un MX verso
            // "xmail.esempio.it" contiene "mail.esempio.it" e passava per giusto, mentre la
            // posta sarebbe finita a un server che non e' questo.
            java.util.List<String> altrove = new java.util.ArrayList<>();
            boolean nostro = false;
            for (String riga : mxCheck.currentValue.split("\n")) {
                String t = riga.trim();
                if (t.isEmpty()) continue;
                String[] campi = t.split("\\s+");
                String bersaglio = campi.length >= 2 ? campi[1] : campi[0];
                if (RegoleDns.stessoNome(bersaglio, mailHostname)) nostro = true;
                else altrove.add(bersaglio);
            }
            if (nostro) {
                mxCheck.passed = true;
                mxCheck.message = "OK: punta a " + mailHostname
                        + (altrove.isEmpty() ? "" : ". Ci sono anche altri MX (" + String.join(", ", altrove)
                           + "): se non sono voluti, ricevono posta al posto di questo server.");
            } else {
                mxCheck.passed = false;
                mxCheck.message = "Nessun MX punta a " + mailHostname
                        + (altrove.isEmpty() ? "." : ": puntano a " + String.join(", ", altrove)
                           + ". La posta in arrivo va li', non qui.");
            }
        }
        result.checks.add(mxCheck);
        if (!mxCheck.passed) result.allPassed = false;

        // 3. Check SPF - verify it contains our server IP
        String expectedSpf = "v=spf1 ip4:" + serverIp + " mx -all";
        // Si legge il TXT grezzo e si applicano le regole di RFC 7208, invece di cercare
        // sottostringhe. Il vecchio controllo faceva contains("mx"): un SPF come
        // "v=spf1 include:_spf.mxlogic.com -all", che NON autorizza questo server, passava
        // perche' la parola "mx" compare dentro un nome di dominio. Un controllo che dice
        // "tutto a posto" davanti a un SPF che non ti autorizza e' peggio di nessun controllo.
        DnsCheck spfCheck = verifyRecord(domain, "TXT");
        spfCheck.recordType = "SPF";
        spfCheck.recordName = domain;
        spfCheck.expectedValue = expectedSpf;
        if (spfCheck.currentValue != null) {
            RegoleDns.EsitoSpf e = RegoleDns.analizzaSpf(RegoleDns.recordTxt(spfCheck.currentValue), serverIp);
            if (e.record != null) spfCheck.currentValue = e.record;
            if (!e.valido) {
                spfCheck.passed = false;
                spfCheck.message = e.problema;
            } else {
                spfCheck.passed = true;
                if (e.autorizzaEsplicito) {
                    spfCheck.message = "OK: autorizza esplicitamente " + serverIp;
                } else if (e.viaMx) {
                    spfCheck.message = "OK tramite il meccanismo \"mx\": vale finche' l'MX punta qui "
                                     + "(vedi il controllo MX qui sopra).";
                } else if (e.viaA) {
                    spfCheck.message = "OK tramite il meccanismo \"a\": vale finche' il record A punta qui.";
                } else if (e.include > 0) {
                    // Ne' promosso ne' bocciato: detto com'e'. Bocciare un SPF che delega a
                    // terzi porterebbe a "sistemare" un record che funziona.
                    spfCheck.message = "Non determinabile da qui: l'autorizzazione dipende da "
                                     + e.include + (e.include == 1 ? " termine che rimanda" : " termini che rimandano")
                                     + " ad altri record. Il server non e' elencato direttamente.";
                } else {
                    spfCheck.passed = false;
                    spfCheck.message = "L'SPF non autorizza questo server: non contiene l'IP " + serverIp
                                     + " ne' un meccanismo \"mx\" o \"a\".";
                }
            }
            if (!e.avvisi.isEmpty())
                spfCheck.message = (spfCheck.message == null ? "" : spfCheck.message + " ")
                                 + String.join(" ", e.avvisi);
        } else if (spfCheck.message != null && spfCheck.message.startsWith("Record non trovato")) {
            spfCheck.message = "Nessun record SPF: il dominio non dichiara chi puo' spedire per lui.";
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
        String attesa = (dbDomain == null || dbDomain.dkimPublicKey == null)
                ? null : dbDomain.dkimPublicKey.replaceAll("\\s+", "");

        DnsCheck dkimCheck = verifyRecord(selector + "._domainkey." + domain, "TXT");
        dkimCheck.recordType = "DKIM";
        dkimCheck.recordName = selector + "._domainkey." + domain;
        if (attesa != null)
            // substring(0, 20) senza rete di sicurezza: con una chiave corrotta piu' corta di
            // venti caratteri sollevava un'eccezione che usciva da tutto il metodo e faceva
            // sparire l'INTERA pagina di verifica, non solo questa riga.
            dkimCheck.expectedValue = "v=DKIM1; k=rsa; p="
                    + attesa.substring(0, Math.min(20, attesa.length())) + "...";

        if (dkimCheck.currentValue != null) {
            // Le chiavi da 2048 bit superano i 255 caratteri, quindi in DNS stanno in piu'
            // stringhe che vanno unite senza spazi (RFC 7208 §3.3). Confrontare l'uscita
            // grezza di dig significherebbe confrontare anche le virgolette in mezzo.
            java.util.List<String> txt = RegoleDns.recordTxt(dkimCheck.currentValue);
            java.util.List<String> chiavi = RegoleDns.soloDkim(txt);

            if (chiavi.isEmpty()) {
                dkimCheck.passed = false;
                dkimCheck.message = "Su quel nome c'e' un TXT, ma non e' una chiave DKIM: manca il tag \"p=\".";
            } else if (chiavi.size() > 1) {
                dkimCheck.passed = false;
                dkimCheck.message = "Ci sono " + chiavi.size() + " chiavi DKIM sullo stesso selector: "
                        + "chi verifica la firma non sa quale usare. Va lasciata una sola.";
            } else {
                dkimCheck.currentValue = chiavi.get(0);
                String pubblicata = RegoleDns.chiaveDkim(chiavi.get(0));
                dkimCheck.passed = true;
                if (pubblicata == null || pubblicata.isEmpty()) {
                    dkimCheck.passed = false;
                    dkimCheck.message = "Il record ha il tag \"p=\" ma vuoto: e' il modo di dichiarare una "
                            + "chiave REVOCATA, e le firme fatte con quel selector vengono rifiutate.";
                } else if (attesa == null) {
                    dkimCheck.message = "Chiave pubblicata (il pannello non ne ha una da confrontare).";
                } else if (pubblicata.equals(attesa)) {
                    // Confronto INTERO, non i primi 50 caratteri: una chiave giusta all'inizio
                    // e corrotta in fondo passava il vecchio controllo e non firmava niente.
                    dkimCheck.message = "OK: la chiave pubblicata e' esattamente quella del pannello.";
                } else {
                    dkimCheck.passed = false;
                    dkimCheck.message = "La chiave pubblicata NON e' quella del pannello: le firme non "
                            + "verranno verificate. Pubblicata " + pubblicata.length() + " caratteri, "
                            + "attesa " + attesa.length() + ".";
                }
            }
        } else if (dkimCheck.message != null && dkimCheck.message.startsWith("Record non trovato")) {
            dkimCheck.message = "Nessun record DKIM su " + selector + "._domainkey." + domain
                    + ": la posta parte firmata, ma nessuno puo' verificare la firma.";
        }
        result.checks.add(dkimCheck);
        if (!dkimCheck.passed) result.allPassed = false;

        // 5. Check DMARC - verify policy present
        // Il record si legge coi tag, non cercando "p=none" dentro la stringa: "p=none"
        // compare per sottostringa anche in "sp=none", e il verdetto uscirebbe sbagliato.
        // E p=none NON e' una "policy debole": RFC 9989 §5.1.5 dice di partire da li'.
        DnsCheck dmarcCheck = verifyRecord("_dmarc." + domain, "TXT");
        dmarcCheck.recordType = "DMARC";
        dmarcCheck.recordName = "_dmarc." + domain;
        dmarcCheck.expectedValue = "v=DMARC1; p=none; rua=mailto:dmarc@" + domain;
        if (dmarcCheck.currentValue != null) {
            RegoleDns.EsitoDmarc e = RegoleDns.analizzaDmarc(
                    RegoleDns.recordTxt(dmarcCheck.currentValue), domain);
            if (e.record != null) dmarcCheck.currentValue = e.record;
            if (!e.valido) {
                dmarcCheck.passed = false;
                dmarcCheck.message = e.problema;
            } else {
                dmarcCheck.passed = true;
                String p = e.politica == null ? "none" : e.politica.toLowerCase();
                if (p.equals("none"))
                    dmarcCheck.message = "OK: p=none, modalita' di osservazione. E' il punto di partenza "
                                       + "previsto: si leggono i rapporti e poi si irrigidisce.";
                else if (p.equals("quarantine"))
                    dmarcCheck.message = "OK: p=quarantine, chi non si autentica finisce in quarantena.";
                else if (p.equals("reject"))
                    dmarcCheck.message = "OK: p=reject, chi non si autentica viene rifiutato.";
                else
                    dmarcCheck.message = "DMARC presente.";

                // RFC 9990 §4: se il rua punta fuori dominio serve l'autorizzazione, altrimenti
                // i rapporti non partono e nessuno se ne accorge. Qui non si indovina: si guarda.
                for (String nomeAut : e.daAutorizzare) {
                    DnsCheck aut = verifyRecord(nomeAut, "TXT");
                    boolean concessa = aut.currentValue != null
                            && !RegoleDns.soloDmarc(RegoleDns.recordTxt(aut.currentValue)).isEmpty();
                    if (!concessa) {
                        // Si SEGNALA senza bocciare. Per sapere se l'autorizzazione serve davvero
                        // occorre confrontare i domini ORGANIZZATIVI, che RFC 9989 §4.10 ricava con
                        // il "tree walk": due sottodomini fratelli (a.esempio.it e b.esempio.it)
                        // appartengono allo stesso dominio organizzativo e non richiedono nulla.
                        // Senza quel calcolo, bocciare significherebbe dichiarare rotto un DMARC
                        // che funziona, e spingere a "sistemare" cio' che va gia' bene.
                        dmarcCheck.message += " DA CONTROLLARE: l'indirizzo dei rapporti sta su un altro "
                                + "dominio e non trovo l'autorizzazione. Se i due domini appartengono a "
                                + "organizzazioni diverse, "
                                + "va pubblicato un TXT su " + nomeAut + " con valore \"v=DMARC1\" "
                                + "(RFC 9990 §4), altrimenti i rapporti non vengono nemmeno inviati. Se "
                                + "invece sono due nomi della stessa organizzazione, non serve nulla.";
                    } else {
                        dmarcCheck.message += " Autorizzazione rapporti fuori dominio presente su " + nomeAut + ".";
                    }
                }
            }
            if (!e.avvisi.isEmpty())
                dmarcCheck.message = (dmarcCheck.message == null ? "" : dmarcCheck.message + " ")
                                   + String.join(" ", e.avvisi);
        } else if (dmarcCheck.message != null && dmarcCheck.message.startsWith("Record non trovato")) {
            dmarcCheck.message = "Nessun record DMARC: chiunque puo' scrivere questo dominio nel campo Da: "
                               + "e nessuno ha istruzioni su cosa farne.";
        }
        result.checks.add(dmarcCheck);
        if (!dmarcCheck.passed) result.allPassed = false;

        // 6. Check Autoconfig for Thunderbird (CNAME)
        DnsCheck autoconfigCheck = verifyRecord("autoconfig." + domain, "CNAME");
        autoconfigCheck.recordType = "Autoconfig";
        autoconfigCheck.expectedValue = mailHostname + ".";
        if (autoconfigCheck.currentValue != null) {
            String puntaA = autoconfigCheck.currentValue.trim().split("\\s+")[0];
            if (RegoleDns.stessoNome(puntaA, mailHostname)) {
                autoconfigCheck.passed = true;
                autoconfigCheck.message = "OK: autoconfig → " + mailHostname;
            } else {
                autoconfigCheck.passed = false;
                autoconfigCheck.message = "Punta a " + puntaA + " invece di " + mailHostname + ".";
            }
        } else if (autoconfigCheck.message != null && autoconfigCheck.message.startsWith("Record non trovato")) {
            autoconfigCheck.passed = false;
            autoconfigCheck.informativo = true;
            autoconfigCheck.message = "Non configurato. Serve solo a Thunderbird, e richiede un sito "
                    + "raggiungibile su https://autoconfig." + domain + " (porta 443). Apple Mail non lo "
                    + "usa: per quello c'e' il profilo di configurazione nella pagina Caselle.";
        } else {
            // NON si sovrascrive un errore preciso ("dig non raggiungibile") con "non
            // configurato": sono due guasti diversi e mandano a cercare in posti opposti.
            autoconfigCheck.passed = false;
        }
        result.checks.add(autoconfigCheck);
        // Don't fail overall for optional records
        // if (!autoconfigCheck.passed) result.allPassed = false;

        // 8. Check PTR / Reverse DNS + FCrDNS (Forward-Confirmed reverse DNS)
        //    CRITICO per la deliverability — Gmail e Outlook RIFIUTANO o spammano
        //    le mail provenienti da IP senza PTR o con FCrDNS rotto.
        DnsCheck ptrCheck = checkPtrAndFcrdns(serverIp, mailHostname);
        result.checks.add(ptrCheck);
        if (!ptrCheck.passed) result.allPassed = false;

        // 9. Check MTA-STS (optional but recommended)
        // Note: MTA-STS ID is just a version timestamp, doesn't need to match exactly
        DnsCheck mtaStsCheck = verifyTxtRecord("_mta-sts." + domain, "v=STSv1");
        mtaStsCheck.recordType = "MTA-STS";
        mtaStsCheck.expectedValue = org.mail_panel.system.MtaSts.recordTxtCorrente();
        if (mtaStsCheck.passed && mtaStsCheck.currentValue != null) {
            // Il record c'e': ora si va a CHIEDERE la politica. Guardare solo il TXT diceva
            // "fatto" su domini che dichiarano pubblicamente una protezione e poi non la
            // servono. E' una promessa non mantenuta, e il pannello la mostrava come esito
            // positivo — misurare il cartello invece della cosa.
            org.json.JSONObject prova = org.mail_panel.system.MtaSts.provaPubblica(domain);
            if (prova.optBoolean("ok", false)) {
                mtaStsCheck.message = "Attivo: il record c'e' e la politica risponde.";
            } else {
                mtaStsCheck.passed = false;
                mtaStsCheck.message = "IL RECORD C'E' MA LA POLITICA NON RISPONDE. Stai dichiarando "
                        + "pubblicamente di avere MTA-STS, e chi va a leggerlo su https://mta-sts."
                        + domain + "/.well-known/mta-sts.txt non trova niente: "
                        + prova.optString("errore", "irraggiungibile")
                        + " I mittenti proseguono come se non l'avessi (RFC 8461 §3.3), quindi non "
                        + "rompe la posta — ma e' una dichiarazione che non mantieni. O la si serve, "
                        + "o si toglie il record.";
            }
        } else {
            mtaStsCheck.passed = false;
            mtaStsCheck.informativo = true;
            mtaStsCheck.message = "Non attivo. Non e' una dimenticanza: MTA-STS richiede che la politica "
                    + "sia raggiungibile da tutto il mondo su https://mta-sts." + domain + " (porta 443), "
                    + "perche' la leggono i server mittenti. Su un server chiuso agli IP esterni non "
                    + "puo' funzionare, e pubblicare il solo record dichiarerebbe una protezione assente.";
        }
        result.checks.add(mtaStsCheck);
        // Don't fail overall for optional records
        // if (!mtaStsCheck.passed) result.allPassed = false;

        // 9. Check SRV records for IMAP and SMTP submission
        DnsCheck srvImapCheck = verifyRecord("_imaps._tcp." + domain, "SRV");
        srvImapCheck.recordType = "SRV (_imaps)";
        srvImapCheck.expectedValue = "0 1 993 " + mailHostname + ".";
        controllaSrv(srvImapCheck, mailHostname, 993, "posta in arrivo");
        result.checks.add(srvImapCheck);

        DnsCheck srvSmtpCheck = verifyRecord("_submission._tcp." + domain, "SRV");
        srvSmtpCheck.recordType = "SRV (_submission)";
        srvSmtpCheck.expectedValue = "0 1 587 " + mailHostname + ".";
        controllaSrv(srvSmtpCheck, mailHostname, 587, "posta in uscita");
        result.checks.add(srvSmtpCheck);

        // Il punteggio conta i record indispensabili: A, MX, SPF, DKIM, DMARC.
        //
        // Prima li contava PER POSIZIONE, "i primi cinque della lista". Funzionava, ma basta
        // che qualcuno inserisca un controllo in mezzo o ne sposti uno perche' il punteggio
        // cominci a misurare tutt'altro senza che niente si rompa e senza che nessuno lo
        // noti: resterebbe un numero plausibile, e sarebbe falso. Ora ogni controllo dice
        // di se' se conta, e la posizione non c'entra piu' nulla.
        for (DnsCheck c : result.checks) {
            String t = c.recordType == null ? "" : c.recordType;
            c.indispensabile = t.equals("A") || t.equals("MX") || t.equals("SPF")
                            || t.equals("DKIM") || t.equals("DMARC");
        }
        int indispensabili = 0, superati = 0;
        for (DnsCheck c : result.checks)
            if (c.indispensabile) { indispensabili++; if (c.passed) superati++; }
        result.score = indispensabili == 0 ? 0 : (superati * 100) / indispensabili;

        return result;
    }

    /**
     * Verify a specific DNS record using dig
     */
    /**
     * Check PTR (reverse DNS) + FCrDNS (Forward-Confirmed reverse DNS).
     *
     * Cosa verifica:
     *  1. L'IP del server ha un record PTR pubblico?
     *  2. Il PTR punta esattamente al mail hostname configurato?
     *  3. FCrDNS: risolvendo il PTR ottenuto, si torna allo stesso IP?
     *     (es. PTR di 1.2.3.4 = mail.dom.tld; A di mail.dom.tld = 1.2.3.4)
     *
     * Senza questi:
     *  - Gmail mette tutte le tue mail in spam (o le rifiuta)
     *  - Outlook applica score di reputation molto basso
     *  - Alcuni provider rifiutano direttamente la consegna SMTP
     *
     * Per fixare il PTR: solo il provider hosting può farlo (richiede ticket o
     * pannello cloud, NON è gestibile da DNS classico).
     */
    private DnsCheck checkPtrAndFcrdns(String serverIp, String mailHostname) {
        DnsCheck check = new DnsCheck();
        check.recordType = "PTR";
        check.recordName = serverIp;
        check.expectedValue = mailHostname;

        if (serverIp == null || serverIp.isEmpty()) {
            check.passed = false;
            check.message = "IP server non rilevato";
            return check;
        }

        try {
            // 1. Reverse lookup: dig -x <IP>
            // TODO: migrate to Shell.run when touched
            ProcessBuilder revPb = new ProcessBuilder("dig", "+short", "-x", serverIp);
            org.mail_panel.util.Shell.applicaPath(revPb);
            revPb.redirectErrorStream(true);
            Process revP = revPb.start();
            String revOut;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(revP.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append("\n");
                revOut = sb.toString().trim();
            }
            revP.waitFor();

            if (revOut.isEmpty()) {
                check.passed = false;
                check.currentValue = null;
                check.message = "Nessun record PTR per " + serverIp +
                    " — Gmail/Outlook spammano le tue mail. Va configurato dal provider hosting.";
                return check;
            }

            // Prendi il primo PTR (potrebbero esserci multipli, anomalia)
            String ptr = revOut.split("\n")[0].trim();
            // Rimuovi trailing dot tipico delle risposte DNS
            if (ptr.endsWith(".")) ptr = ptr.substring(0, ptr.length() - 1);
            check.currentValue = ptr;

            // 2. PTR matches mail hostname?
            boolean ptrMatches = ptr.equalsIgnoreCase(mailHostname);
            if (!ptrMatches) {
                check.passed = false;
                check.message = "PTR è '" + ptr + "' ma il mail hostname è '" + mailHostname
                    + "'. Gmail richiede match esatto. Chiedi al provider di aggiornarlo.";
                return check;
            }

            // 3. FCrDNS — risolvi il PTR e verifica che torni allo stesso IP
            // TODO: migrate to Shell.run when touched
            ProcessBuilder fwdPb = new ProcessBuilder("dig", "+short", "A", ptr);
            org.mail_panel.util.Shell.applicaPath(fwdPb);
            fwdPb.redirectErrorStream(true);
            Process fwdP = fwdPb.start();
            String fwdOut;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(fwdP.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append("\n");
                fwdOut = sb.toString().trim();
            }
            fwdP.waitFor();

            boolean fcrdnsOk = false;
            if (!fwdOut.isEmpty()) {
                for (String ipLine : fwdOut.split("\n")) {
                    if (ipLine.trim().equals(serverIp)) { fcrdnsOk = true; break; }
                }
            }

            if (!fcrdnsOk) {
                check.passed = false;
                check.message = "FCrDNS NON valido: PTR " + ptr + " punta a " + serverIp
                    + " ma " + ptr + " risolve a '" + fwdOut.replace("\n", ", ") + "'. "
                    + "Il forward A record deve combaciare col PTR.";
                return check;
            }

            check.passed = true;
            check.message = "OK: PTR " + ptr + " ↔ " + serverIp + " (FCrDNS valido)";
            return check;

        } catch (Exception e) {
            check.passed = false;
            check.message = "Errore verifica PTR: " + e.getMessage();
            return check;
        }
    }

    /**
     * Controlla un record SRV per davvero: destinazione E PORTA.
     *
     * Il controllo precedente guardava solo se il nome dell'host compariva da qualche parte
     * nella riga. Due cose gli sfuggivano: un SRV che punta a "xmail.esempio.it" (che
     * CONTIENE "mail.esempio.it") passava per giusto, e la porta non veniva guardata affatto
     * — mentre la porta e' l'unica ragione per cui quel record esiste.
     */
    private void controllaSrv(DnsCheck check, String mailHostname, int portaAttesa, String aCosaServe) {
        if (check.currentValue == null) {
            check.passed = false;
            if (check.message != null && check.message.startsWith("Record non trovato"))
                check.message = "Non configurato (opzionale)";
            return;
        }
        RegoleDns.Srv s = RegoleDns.analizzaSrv(check.currentValue.trim().split("\n")[0]);
        if (s == null) {
            check.passed = false;
            check.message = "Il record c'e' ma non ha la forma di un SRV: " + check.currentValue.trim();
            return;
        }
        boolean host = RegoleDns.stessoNome(s.destinazione, mailHostname);
        boolean porta = s.porta == portaAttesa;
        if (host && porta) {
            check.passed = true;
            check.message = "OK: " + aCosaServe + " su " + mailHostname + ":" + portaAttesa + ".";
            return;
        }
        check.passed = false;
        if (!host && !porta)
            check.message = "Punta a " + s.destinazione + " sulla porta " + s.porta
                    + ", invece che a " + mailHostname + " sulla " + portaAttesa + ".";
        else if (!host)
            check.message = "La porta e' giusta, ma punta a " + s.destinazione
                    + " invece che a " + mailHostname + ".";
        else
            check.message = "L'host e' giusto, ma la porta e' " + s.porta + " invece di " + portaAttesa
                    + ": i client proverebbero a collegarsi dove non risponde nessuno.";
    }

    private DnsCheck verifyRecord(String name, String type) {
        DnsCheck check = new DnsCheck();
        check.recordType = type;
        check.recordName = name;

        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", type, name);
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
            String m = e.getMessage() == null ? "" : e.getMessage();
            check.message = m.contains("Cannot run program")
                    ? "Errore: il programma dig non e' raggiungibile dal pannello. Non e' un "
                      + "problema di DNS: e' il pacchetto bind-tools, oppure il PATH con cui il "
                      + "pannello e' stato avviato. Guarda la scheda \"Ambiente del pannello\" "
                      + "negli Aggiornamenti."
                    : "Errore verifica: " + m;
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
        /**
         * A quale verifica appartiene questa scheda: lo stesso valore di DnsCheck.recordType.
         *
         * Prima la pagina appaiava schede e verifiche per NOME. All'apice del dominio ci sono
         * pero' due record diversi con lo stesso nome — MX e SPF — e il secondo sovrascriveva
         * il primo nella mappa: la scheda MX finiva per mostrare il verdetto e il valore
         * dell'SPF ("OK: autorizza esplicitamente 203.0.113.77" sotto "Mail Exchange").
         * Un accoppiamento indovinato dal nome e' un accoppiamento che prima o poi sbaglia:
         * qui viaggia esplicito.
         */
        public String checkType;
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
        /** Conta nel punteggio. Gli opzionali no: la posta funziona anche senza. */
        public boolean indispensabile;
        /**
         * Informativo: non e' un esito, e' una constatazione. Si disegna in grigio, non in
         * rosso. Una croce rossa su una cosa che si e' deciso di non fare e' rumore, e il
         * rumore insegna a ignorare tutte le altre righe.
         */
        public boolean informativo;
    }
}
