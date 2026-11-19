package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.i18n.I18n;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * DNS Records Generator for DaemoxCP Mail
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
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        // L'ip6 nell'SPF quando la posta esce in IPv6, anche solo in uscita: «mx» lo copre gia' con l'AAAA del nome della
        // posta, l'ip6 lo dice esplicito.
        records.records.add(generateSpfRecord(domain, family.v4() ? serverIp : "", family.sends6() ? detectServerIpv6() : "", family));

        // 4. DKIM Record (if configured)
        MailDatabase.Domain dbDomain = database.getDomainByName(domain);
        if (dbDomain != null && dbDomain.hasDkim) {
            records.records.add(generateDkimRecord(domain, dbDomain.dkimSelector, dbDomain.dkimPublicKey));
        } else {
            // Add placeholder DKIM record with instructions
            DnsRecord dkimPlaceholder = new DnsRecord();
            dkimPlaceholder.type = "TXT";
            dkimPlaceholder.name = "mail._domainkey";
            dkimPlaceholder.value = I18n.tr("server.dnsg.toGenerate");
            dkimPlaceholder.ttl = DEFAULT_TTL;
            dkimPlaceholder.dnsZone = domain;
            dkimPlaceholder.description = I18n.tr("server.dnsg.descDkimTodo");
            // Anche il segnaposto dichiara la sua verifica: senza, sarebbe l'unico record a
            // ripiegare sull'appaiamento per nome, cioe' proprio sul difetto appena corretto.
            dkimPlaceholder.checkType = "DKIM";
            dkimPlaceholder.required = true;
            dkimPlaceholder.configured = false;
            dkimPlaceholder.explanation = dkimPlaceholderExplanation(domain);
            records.records.add(dkimPlaceholder);
        }

        // 5. DMARC Record
        records.records.add(generateDmarcRecord(domain));

        // 6. I record con cui i client trovano da soli le impostazioni
        records.records.addAll(generateClientDiscoveryRecord(domain, mailServerHostname));

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
        record.description = I18n.tr("server.dnsg.descMx", java.util.Map.of("d", String.valueOf(domain)));
        record.checkType = "MX";
        record.fullValue = DEFAULT_MX_PRIORITY + " " + mailServer;
        record.required = true;
        record.copyValue = mailServer;
        record.explanation = zone(domain)
            + table(row("Type:", "MX"), row("Name:", "<code>@</code> " + tx("mx.orEmpty")), row("Mail server:", code(mailServer)),
                    row("Priority:", "<code>10</code>"), row("TTL:", "Auto"))
            + "<small class=\"text-muted\">\n" + tx("mx.meaning", "domain", domain, "server", mailServer) + "\n</small>\n";
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
        record.description = I18n.tr("server.dnsg.descA", java.util.Map.of("h", String.valueOf(hostname)));
        record.checkType = "A";
        record.required = true;
        record.explanation = zone(parentDomain)
            + table(row("Type:", "A"), row("Name:", code(subdomain)), row("IPv4 address:", code(ip)),
                    row("Proxy status:", "<span class=\"text-danger\">⚠️ " + tx("a.proxy") + "</span>"), row("TTL:", "Auto"))
            + "<div class=\"alert alert-warning mt-2 mb-0\">\n⚠️ " + th("a.warn") + "\n</div>\n";
        return record;
    }

    /**
     * Generate SPF Record
     * SPF specifies which servers are allowed to send email for the domain
     */
    private DnsRecord generateSpfRecord(String domain, String serverIp, String serverIp6,
                                        org.daemoxcp.mail.system.IpFamily.Family family) {
        DnsRecord record = new DnsRecord();
        record.type = "TXT";
        record.name = "@";
        // Da mostrare: con IPv4 il segnaposto si vede anche se l'indirizzo non si conosce; IPv6 solo se si conosce.
        String spfValue = "v=spf1" + (family.v4() ? " ip4:" + serverIp : "")
                + (serverIp6 != null && !serverIp6.isEmpty() ? " ip6:" + serverIp6 : "") + " mx -all";
        record.value = spfValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = I18n.tr("server.dnsg.descSpf", java.util.Map.of("d", String.valueOf(domain)));
        record.checkType = "SPF";
        record.required = true;
        record.explanation = zone(domain)
            + table(row("Type:", "TXT"), row("Name:", "<code>@</code>"), row("Content:", code(spfValue)), row("TTL:", "Auto"))
            + "<hr>\n<strong>" + tx("meaning") + "</strong>\n<ul class=\"mb-0 small\">\n"
            + li("<code>v=spf1</code> = " + tx("spf.v"))
            + (family.v4() ? li(code("ip4:" + serverIp) + " = " + tx("spf.ip")) : "")
            + (serverIp6 != null && !serverIp6.isEmpty() ? li(code("ip6:" + serverIp6) + " = " + tx("spf.ip")) : "")
            + li("<code>mx</code> = " + tx("spf.mx"))
            + li("<code>-all</code> = " + tx("spf.all"))
            + "</ul>\n";
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
        record.description = I18n.tr("server.dnsg.descDkim");
        record.checkType = "DKIM";
        record.required = true;
        record.configured = true;
        record.explanation = zone(domain)
            + table(row("Type:", "TXT"), row("Name:", code(dkimName)), wideRow("Content:", code(dkimValue)), row("TTL:", "Auto"));
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
        record.description = I18n.tr("server.dnsg.descDmarc");
        record.checkType = "DMARC";
        record.required = true;
        record.explanation = zone(domain)
            + table(row("Type:", "TXT"), row("Name:", "<code>_dmarc</code>"), row("Content:", code(dmarcValue)), row("TTL:", "Auto"))
            + "<hr>\n<strong>" + tx("meaning") + "</strong>\n<ul class=\"mb-0 small\">\n"
            + li(th("dmarc.none")) + li(th("dmarc.rua"))
            + "</ul>\n";
        return record;
    }

    /**
     * I record che aiutano i client a configurarsi: il CNAME autoconfig (Thunderbird) e i
     * due SRV di RFC 6186. Il CNAME "autodiscover" non c'e' piu': serviva solo a Outlook, e
     * un metodo che si chiama ancora come cio' che non fa piu' e' un tranello per chi legge.
     */
    private List<DnsRecord> generateClientDiscoveryRecord(String domain, String mailServer) {
        List<DnsRecord> records = new ArrayList<>();

        // Thunderbird autoconfig
        DnsRecord autoconfig = new DnsRecord();
        autoconfig.type = "CNAME";
        autoconfig.name = "autoconfig";
        autoconfig.value = mailServer;
        autoconfig.ttl = DEFAULT_TTL;
        autoconfig.dnsZone = domain;
        autoconfig.description = I18n.tr("server.dnsg.descAutoconfig", java.util.Map.of("d", String.valueOf(domain)));
        autoconfig.checkType = "Autoconfig";
        autoconfig.required = false;
        autoconfig.explanation = zone(domain)
            + table(row("Type:", "CNAME"), row("Name:", "<code>autoconfig</code>"), row("Target:", code(mailServer)),
                    row("Proxy status:", tx("dnsOnly")), row("TTL:", "Auto"))
            + "<small class=\"text-muted\">" + tx("autoconfig.note") + "</small>\n";
        records.add(autoconfig);

        // I due SRV di RFC 6186: questi funzionano da soli, senza alcun file da servire.
        DnsRecord srvImap = new DnsRecord();
        srvImap.type = "SRV";
        srvImap.name = "_imaps._tcp";
        srvImap.value = mailServer;
        srvImap.priority = 0;
        srvImap.ttl = DEFAULT_TTL;
        srvImap.dnsZone = domain;
        srvImap.description = I18n.tr("server.dnsg.descSrvImap", java.util.Map.of("d", String.valueOf(domain)));
        srvImap.checkType = "SRV (_imaps)";
        // Un SRV non e' scrivibile senza priorita', peso e porta: qui c'e' il record intero.
        srvImap.fullValue = "0 1 993 " + mailServer;
        srvImap.required = false;
        srvImap.explanation = zone(domain)
            + table(row("Type:", "SRV"), row("Name:", "<code>_imaps._tcp</code>"), row("Priority:", "<code>0</code>"),
                    row("Weight:", "<code>1</code>"), row("Port:", "<code>993</code>"), row("Target:", code(mailServer)), row("TTL:", "Auto"));
        records.add(srvImap);

        DnsRecord srvSmtp = new DnsRecord();
        srvSmtp.type = "SRV";
        srvSmtp.name = "_submission._tcp";
        srvSmtp.value = mailServer;
        srvSmtp.priority = 0;
        srvSmtp.ttl = DEFAULT_TTL;
        srvSmtp.dnsZone = domain;
        srvSmtp.description = I18n.tr("server.dnsg.descSrvSmtp", java.util.Map.of("d", String.valueOf(domain)));
        srvSmtp.checkType = "SRV (_submission)";
        srvSmtp.fullValue = "0 1 587 " + mailServer;
        srvSmtp.required = false;
        srvSmtp.explanation = zone(domain)
            + table(row("Type:", "SRV"), row("Name:", "<code>_submission._tcp</code>"), row("Priority:", "<code>0</code>"),
                    row("Weight:", "<code>1</code>"), row("Port:", "<code>587</code>"), row("Target:", code(mailServer)), row("TTL:", "Auto"));
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
        record.description = I18n.tr("server.dnsg.descPtr");
        record.checkType = "PTR";
        record.required = true;
        record.explanation = ptrExplanation(ip, hostname);
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
        String mtaStsValue = org.daemoxcp.mail.system.MtaSts.currentTxtRecord();
        // currentTxtRecord() torna vuoto quando non riesce a calcolarlo: meglio niente che un
        // valore inventato. Ma una casella "Content" vuota nelle istruzioni non aiuta nessuno,
        // quindi si dice a parole cosa ci andra', senza suggerire di incollare una sciocchezza.
        if (mtaStsValue == null || mtaStsValue.isBlank())
            mtaStsValue = "v=STSv1; id=<" + I18n.tr("server.dnsg.idByPanel") + ">";
        record.value = mtaStsValue;
        record.ttl = DEFAULT_TTL;
        record.dnsZone = domain;
        record.description = I18n.tr("server.dnsg.descSts");
        record.checkType = "MTA-STS";
        record.required = false;
        record.explanation = "<div class=\"alert alert-secondary mb-2\">\n<strong>ℹ️ " + tx("sts.optional") + "</strong>\n</div>\n"
            + "<div class=\"alert alert-primary mb-2\">\n<strong>📍 " + tx("sts.zone", "zone", domain) + "</strong>\n</div>\n"
            + table(row("Type:", "TXT"), row("Name:", "<code>_mta-sts</code>"), row("Content:", code(mtaStsValue)), row("TTL:", "Auto"))
            + "<small class=\"text-muted\">\n" + th("sts.note", "domain", domain) + "\n</small>\n";
        return record;
    }

    // ============== Le spiegazioni: la struttura qui, le frasi nei file di lingua ==============
    //
    // Le frasi stanno in server.dnsx.*. Le etichette dei campi (Type, Name, Content, TTL, Proxy
    // status) restano in inglese: sono quelle che si leggono nel pannello di Cloudflare. I valori
    // (dominio, IP, hostname) entrano sempre con l'escape; nelle chiavi .html il testo ha solo
    // strong, code e br, e lo controlla I18nTest.

    /** Una frase senza HTML, pronta per la pagina. Gli argomenti vanno a coppie: nome, valore. */
    private static String tx(String key, String... kv) {
        return I18n.escapeHtml(I18n.tr("server.dnsx." + key, pairs(kv, true)));
    }

    /** Una frase con dentro strong, code o br (chiave .html): l'escape tocca i valori, non il testo. */
    private static String th(String key, String... kv) {
        return I18n.tr("server.dnsx." + key + ".html", pairs(kv, true));
    }

    /** Come th, con un solo valore che e' gia' HTML scritto qui (un collegamento). */
    private static String thLink(String key, String linkHtml) {
        return I18n.tr("server.dnsx." + key + ".html", java.util.Map.of("link", linkHtml));
    }

    private static java.util.Map<String, String> pairs(String[] kv, boolean escape) {
        java.util.Map<String, String> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], escape ? I18n.escapeHtml(kv[i + 1]) : kv[i + 1]);
        return m;
    }

    private static String code(String value) { return "<code>" + I18n.escapeHtml(value) + "</code>"; }

    private static String li(String html) { return "<li>" + html + "</li>\n"; }

    private static String[] row(String label, String valueHtml) { return new String[] {label, valueHtml}; }

    /** Una riga col valore lungo che va a capo dove capita (la chiave DKIM). */
    private static String[] wideRow(String label, String valueHtml) { return new String[] {label, valueHtml, "wide"}; }

    private static String table(String[]... rows) {
        StringBuilder sb = new StringBuilder("<table class=\"table table-sm\">\n");
        for (int i = 0; i < rows.length; i++) {
            sb.append("<tr><td").append(i == 0 ? " width=\"120\"" : "").append("><strong>").append(rows[i][0])
              .append("</strong></td><td").append(rows[i].length > 2 ? " data-style=\"word-break:break-all\"" : "")
              .append(">").append(rows[i][1]).append("</td></tr>\n");
        }
        return sb.append("</table>\n").toString();
    }

    private static String zone(String domain) {
        return "<div class=\"alert alert-primary mb-2\">\n<strong>📍 " + tx("zone", "zone", domain) + "</strong>\n</div>\n";
    }

    private static String link(String url, String label) {
        return "<a href=\"" + url + "\" target=\"_blank\" rel=\"noopener\"><strong>" + label + "</strong></a>";
    }

    private static String guide(String id, String title, String body) {
        return "<div class=\"accordion-item\">\n<h2 class=\"accordion-header\">\n"
            + "<button class=\"accordion-button collapsed\" type=\"button\" data-bs-toggle=\"collapse\" data-bs-target=\"#" + id + "\">\n"
            + "<strong>" + title + "</strong>\n</button>\n</h2>\n"
            + "<div id=\"" + id + "\" class=\"accordion-collapse collapse\" data-bs-parent=\"#ptrAccordion\">\n"
            + "<div class=\"accordion-body\">\n" + body + "</div>\n</div>\n</div>\n";
    }

    /** DKIM non ancora generato: cosa fare, con i nomi di pagina e di pulsante che si vedono davvero. */
    private static String dkimPlaceholderExplanation(String domain) {
        return "<div class=\"alert alert-warning mb-2\">\n<strong>⚠️ " + tx("dkimTodo.title") + "</strong>\n</div>\n"
            + "<div class=\"alert alert-primary mb-2\">\n<strong>📍 " + tx("dkimTodo.zone", "zone", domain) + "</strong>\n</div>\n"
            + "<strong>" + tx("dkimTodo.how") + "</strong>\n<ol>\n"
            + li(th("dkimTodo.1", "page", I18n.tr("nav.domains")))
            + li(th("dkimTodo.2", "domain", domain))
            + li(th("dkimTodo.3", "button", I18n.tr("dns.generateDkim")))
            + li(tx("dkimTodo.4"))
            + "</ol>\n";
    }

    /** Il PTR non si configura su Cloudflare: la guida per i provider piu' comuni. */
    private static String ptrExplanation(String ip, String hostname) {
        return "<div class=\"alert alert-danger mb-3\">\n⚠️ " + th("ptr.notCf") + "<br>\n<small>" + tx("ptr.onlyHost") + "</small>\n</div>\n\n"
            + "<div class=\"alert alert-dark mb-3\">\n<strong>🎯 " + tx("ptr.what") + "</strong>\n"
            + "<table class=\"table table-sm table-bordered mt-2 mb-0 bg-white\">\n"
            + "<tr><td width=\"120\"><strong>IP Address:</strong></td><td>" + code(ip) + "</td></tr>\n"
            + "<tr><td><strong>Hostname:</strong></td><td>" + code(hostname) + "</td></tr>\n"
            + "</table>\n</div>\n\n<hr>\n\n"
            + "<div class=\"accordion\" id=\"ptrAccordion\">\n"
            + guide("hetznerGuide", "🟠 " + tx("ptr.hetzner.title"), "<ol>\n"
                + li(thLink("ptr.goTo", link("https://console.hetzner.cloud", "console.hetzner.cloud")))
                + li(th("ptr.hetzner.2")) + li(th("ptr.hetzner.3")) + li(tx("ptr.hetzner.4")) + li(th("ptr.hetzner.5"))
                + "<li>" + th("ptr.hetzner.6") + "\n<ul>\n"
                + li("<strong>Primary IP</strong> - <strong>Protocol</strong> - <strong>Reverse DNS</strong>")
                + li(th("ptr.hetzner.6b", "ip", ip))
                + "</ul>\n</li>\n"
                + li(th("ptr.hetzner.7")) + li(th("ptr.hetzner.8")) + li(th("ptr.hetzner.9", "host", hostname)) + li(th("ptr.hetzner.10"))
                + "</ol>\n"
                + "<div class=\"alert alert-info mb-2\">\n<small>" + th("ptr.hetzner.note") + "</small>\n</div>\n"
                + "<div class=\"alert alert-success mb-0\">\n<small>✅ " + tx("ptr.hetzner.prop") + "</small>\n</div>\n")
            + guide("ovhGuide", "🔵 " + tx("ptr.ovh.title"), "<ol>\n"
                + li(thLink("ptr.goTo", link("https://www.ovh.com/manager/", "www.ovh.com/manager")))
                + li(tx("ptr.ovh.2")) + li(th("ptr.ovh.3"))
                + "<li>" + th("ptr.ovh.vps") + "\n<ul>\n"
                + li(th("ptr.clickOn", "label", "VPS")) + li(tx("ptr.ovh.vps.2")) + li(th("ptr.ovh.vps.3"))
                + "</ul>\n</li>\n"
                + "<li>" + th("ptr.ovh.ded") + "\n<ul>\n"
                + li(th("ptr.clickOn", "label", I18n.tr("server.dnsx.ptr.ovh.dedLabel"))) + li(tx("ptr.ovh.ded.2")) + li(th("ptr.ovh.ded.3"))
                + "</ul>\n</li>\n"
                + li(th("ptr.ovh.4", "ip", ip)) + li(th("ptr.threeDots"))
                + li(th("ptr.ovh.select", "label", I18n.tr("server.dnsx.ptr.ovh.reverseLabel")))
                + li(th("ptr.ovh.7", "host", hostname))
                + li(th("ptr.ovh.click", "label", I18n.tr("server.dnsx.ptr.ovh.confirmLabel")))
                + "</ol>\n"
                + "<div class=\"alert alert-warning mb-0\">\n<small>⏱️ " + tx("ptr.ovh.prop") + "</small>\n</div>\n")
            + guide("doGuide", "🔷 " + tx("ptr.do.title"),
                "<div class=\"alert alert-info mb-2\">\n" + th("ptr.do.note") + "\n</div>\n<ol>\n"
                + li(thLink("ptr.goTo", link("https://cloud.digitalocean.com", "cloud.digitalocean.com")))
                + li(th("ptr.do.2")) + li(th("ptr.do.3")) + li(th("ptr.do.4", "host", hostname)) + li(th("ptr.do.5"))
                + "</ol>\n"
                + "<div class=\"alert alert-success mb-0\">\n<small>✅ " + tx("ptr.do.prop") + "</small>\n</div>\n")
            + guide("otherGuide", "⚪ " + tx("ptr.other.title"),
                "<strong>" + tx("ptr.other.generic") + "</strong>\n<ol>\n"
                + li(tx("ptr.other.1"))
                + "<li>" + tx("ptr.other.2") + "\n<ul>\n"
                + li("<strong>\"Reverse DNS\"</strong>") + li("<strong>\"rDNS\"</strong>") + li("<strong>\"PTR Record\"</strong>")
                + li("<strong>\"" + tx("ptr.other.inverse") + "\"</strong>")
                + "</ul>\n</li>\n"
                + li(th("ptr.other.3", "ip", ip, "host", hostname)) + li(tx("ptr.other.4"))
                + "</ol>\n"
                + "<div class=\"alert alert-secondary mb-0\">\n<small>💡 " + tx("ptr.other.help") + "</small>\n</div>\n")
            + "</div>\n\n<hr>\n\n"
            + "<div class=\"alert alert-warning mb-2\">\n<strong>🔍 " + tx("ptr.verify.title") + "</strong><br>\n"
            + tx("ptr.verify.run") + "\n<pre class=\"bg-dark text-light p-2 rounded mt-2 mb-0\">dig -x " + I18n.escapeHtml(ip) + " +short</pre>\n"
            + "<small>" + th("ptr.verify.expect", "host", hostname) + "</small>\n</div>\n\n"
            + "<div class=\"alert alert-danger mb-0\">\n<strong>⚠️ " + tx("ptr.why.title") + "</strong>\n<ul class=\"mb-0 mt-2\">\n"
            + li(th("ptr.why.1")) + li(tx("ptr.why.2")) + li(th("ptr.why.3", "host", hostname)) + li(tx("ptr.why.4"))
            + "</ul>\n</div>\n";
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
                aCheck.message = I18n.tr("server.dnsg.wrongIp", java.util.Map.of("found", String.valueOf(foundIp), "expected", String.valueOf(serverIp)));
            }
        } else if (aCheck.message == null || aCheck.message.equals(I18n.tr("server.dnsg.notFound"))) {
            // Solo se la query e' andata a buon fine e non ha trovato niente. Se invece era
            // fallita, il messaggio preciso c'e' gia' e sovrascriverlo con "non trovato"
            // trasforma uno strumento rotto in un record DNS mancante: due problemi con due
            // rimedi opposti, e chi legge va a cercare nel posto sbagliato.
            aCheck.message = I18n.tr("server.dnsg.noA", java.util.Map.of("h", String.valueOf(mailHostname)));
        }
        // Con solo IPv6 il record A non serve: il controllo resta da vedere, ma non conta.
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        result.checks.add(aCheck);
        if (!aCheck.passed && family.v4()) result.allPassed = false;

        // 1-bis. AAAA, quando la posta usa l'IPv6 (anche solo in uscita: un nome solo, che ha l'AAAA e il DNS inverso;
        // chi prova a consegnare in IPv6 riceve subito un rifiuto da pf) e il server ha un IPv6 pubblico (con solo IPv6,
        // sempre).
        String ip6Now = family.sends6() ? detectServerIpv6() : "";
        String serverIp6 = ip6Now;
        if (family == org.daemoxcp.mail.system.IpFamily.Family.IPV6 || !serverIp6.isEmpty()) {
            DnsCheck aaaa = verifyRecord(mailHostname, "AAAA");
            aaaa.recordType = "AAAA";
            aaaa.expectedValue = serverIp6;
            if (aaaa.passed && aaaa.currentValue != null) {
                if (!serverIp6.isEmpty() && containsAddress(aaaa.currentValue, serverIp6)) {
                    aaaa.message = "OK: " + mailHostname + " → " + serverIp6;
                } else {
                    aaaa.passed = false;
                    aaaa.message = I18n.tr("server.dnsg.wrongIp", java.util.Map.of("found", String.valueOf(aaaa.currentValue.trim().split("\\n")[0]),
                            "expected", String.valueOf(serverIp6)));
                }
            } else if (aaaa.message == null || aaaa.message.equals(I18n.tr("server.dnsg.notFound"))) {
                aaaa.message = I18n.tr("server.dnsg.noAaaa", java.util.Map.of("h", String.valueOf(mailHostname)));
            }
            result.checks.add(aaaa);
            if (!aaaa.passed) result.allPassed = false;
        }

        // 2. Check MX - verify it points to our mail server
        DnsCheck mxCheck = verifyRecord(domain, "MX");
        mxCheck.expectedValue = "10 " + mailHostname + ".";
        if (mxCheck.passed && mxCheck.currentValue != null) {
            // Un dominio puo' avere piu' MX: basta che UNO punti qui. Ma il confronto e'
            // esatto sul nome di destinazione, non per contenimento: un MX verso
            // "xmail.esempio.it" contiene "mail.esempio.it" e passava per giusto, mentre la
            // posta sarebbe finita a un server che non e' questo.
            java.util.List<String> elsewhere = new java.util.ArrayList<>();
            boolean ours = false;
            for (String line : mxCheck.currentValue.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                String[] fields = t.split("\\s+");
                String target = fields.length >= 2 ? fields[1] : fields[0];
                if (DnsRules.sameName(target, mailHostname)) ours = true;
                else elsewhere.add(target);
            }
            if (ours) {
                mxCheck.passed = true;
                mxCheck.message = I18n.tr("server.dnsg.mxOk", java.util.Map.of("h", String.valueOf(mailHostname)))
                        + (elsewhere.isEmpty() ? "" : ". " + I18n.tr("server.dnsg.mxOthers", java.util.Map.of("list", String.valueOf(String.join(", ", elsewhere)))));
            } else {
                mxCheck.passed = false;
                mxCheck.message = elsewhere.isEmpty()
                        ? I18n.tr("server.dnsg.mxNone", java.util.Map.of("h", String.valueOf(mailHostname)))
                        : I18n.tr("server.dnsg.mxElsewhere", java.util.Map.of("h", String.valueOf(mailHostname), "list", String.valueOf(String.join(", ", elsewhere))));
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
            DnsRules.SpfOutcome e = DnsRules.analyzeSpf(DnsRules.recordTxt(spfCheck.currentValue), serverIp);
            if (e.record != null) spfCheck.currentValue = e.record;
            if (!e.valid) {
                spfCheck.passed = false;
                spfCheck.message = e.problem;
            } else {
                spfCheck.passed = true;
                if (e.explicitAuthorization) {
                    spfCheck.message = I18n.tr("server.dnsg.spfOkIp", java.util.Map.of("ip", String.valueOf(serverIp)));
                } else if (e.viaMx) {
                    spfCheck.message = I18n.tr("server.dnsg.spfOkMx");
                } else if (e.viaA) {
                    spfCheck.message = I18n.tr("server.dnsg.spfOkA");
                } else if (e.include > 0) {
                    // Ne' promosso ne' bocciato: detto com'e'. Bocciare un SPF che delega a
                    // terzi porterebbe a "sistemare" un record che funziona.
                    spfCheck.message = e.include == 1
                            ? I18n.tr("server.dnsg.spfInclude.one")
                            : I18n.tr("server.dnsg.spfInclude.other", java.util.Map.of("n", String.valueOf(e.include)));
                } else {
                    spfCheck.passed = false;
                    spfCheck.message = I18n.tr("server.dnsg.spfNotAuth", java.util.Map.of("ip", String.valueOf(serverIp)));
                }
            }
            if (!e.warnings.isEmpty())
                spfCheck.message = (spfCheck.message == null ? "" : spfCheck.message + " ")
                                 + String.join(" ", e.warnings);

        } else if (spfCheck.message != null && spfCheck.message.startsWith(I18n.tr("server.dnsg.notFound"))) {
            spfCheck.message = I18n.tr("server.dnsg.noSpf");
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
        String wait = (dbDomain == null || dbDomain.dkimPublicKey == null)
                ? null : dbDomain.dkimPublicKey.replaceAll("\\s+", "");

        DnsCheck dkimCheck = verifyRecord(selector + "._domainkey." + domain, "TXT");
        dkimCheck.recordType = "DKIM";
        dkimCheck.recordName = selector + "._domainkey." + domain;
        if (wait != null)
            // substring(0, 20) senza rete di sicurezza: con una chiave corrotta piu' corta di
            // venti caratteri sollevava un'eccezione che usciva da tutto il metodo e faceva
            // sparire l'INTERA pagina di verifica, non solo questa riga.
            dkimCheck.expectedValue = "v=DKIM1; k=rsa; p="
                    + wait.substring(0, Math.min(20, wait.length())) + "...";

        if (dkimCheck.currentValue != null) {
            // Le chiavi da 2048 bit superano i 255 caratteri, quindi in DNS stanno in piu'
            // stringhe che vanno unite senza spazi (RFC 7208 §3.3). Confrontare l'uscita
            // grezza di dig significherebbe confrontare anche le virgolette in mezzo.
            java.util.List<String> txt = DnsRules.recordTxt(dkimCheck.currentValue);
            java.util.List<String> keys = DnsRules.onlyDkim(txt);

            if (keys.isEmpty()) {
                dkimCheck.passed = false;
                dkimCheck.message = I18n.tr("server.dnsg.dkimNotKey");
            } else if (keys.size() > 1) {
                dkimCheck.passed = false;
                dkimCheck.message = I18n.tr("server.dnsg.dkimMany", java.util.Map.of("n", String.valueOf(keys.size())));
            } else {
                dkimCheck.currentValue = keys.get(0);
                String published = DnsRules.dkimKey(keys.get(0));
                dkimCheck.passed = true;
                if (published == null || published.isEmpty()) {
                    dkimCheck.passed = false;
                    dkimCheck.message = I18n.tr("server.dnsg.dkimRevoked");
                } else if (wait == null) {
                    dkimCheck.message = I18n.tr("server.dnsg.dkimPublished");
                } else if (published.equals(wait)) {
                    // Confronto INTERO, non i primi 50 caratteri: una chiave giusta all'inizio
                    // e corrotta in fondo passava il vecchio controllo e non firmava niente.
                    dkimCheck.message = I18n.tr("server.dnsg.dkimOk");
                } else {
                    dkimCheck.passed = false;
                    dkimCheck.message = I18n.tr("server.dnsg.dkimMismatch", java.util.Map.of("p", String.valueOf(published.length()), "a", String.valueOf(wait.length())));
                }
            }
        } else if (dkimCheck.message != null && dkimCheck.message.startsWith(I18n.tr("server.dnsg.notFound"))) {
            dkimCheck.message = I18n.tr("server.dnsg.noDkim", java.util.Map.of("name", String.valueOf(selector + "._domainkey." + domain)));
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
            DnsRules.DmarcOutcome e = DnsRules.analyzeDmarc(
                    DnsRules.recordTxt(dmarcCheck.currentValue), domain);
            if (e.record != null) dmarcCheck.currentValue = e.record;
            if (!e.valid) {
                dmarcCheck.passed = false;
                dmarcCheck.message = e.problem;
            } else {
                dmarcCheck.passed = true;
                String p = e.policy == null ? "none" : e.policy.toLowerCase();
                if (p.equals("none"))
                    dmarcCheck.message = I18n.tr("server.dnsg.dmarcNone");
                else if (p.equals("quarantine"))
                    dmarcCheck.message = I18n.tr("server.dnsg.dmarcQuarantine");
                else if (p.equals("reject"))
                    dmarcCheck.message = I18n.tr("server.dnsg.dmarcReject");
                else
                    dmarcCheck.message = I18n.tr("server.dnsg.dmarcPresent");

                // RFC 9990 §4: se il rua punta fuori dominio serve l'autorizzazione, altrimenti
                // i rapporti non partono e nessuno se ne accorge. Qui non si indovina: si guarda.
                for (String authName : e.toAuthorize) {
                    DnsCheck authorization = verifyRecord(authName, "TXT");
                    boolean granted = authorization.currentValue != null
                            && !DnsRules.onlyDmarc(DnsRules.recordTxt(authorization.currentValue)).isEmpty();
                    if (!granted) {
                        // Si SEGNALA senza bocciare. Per sapere se l'autorizzazione serve davvero
                        // occorre confrontare i domini ORGANIZZATIVI, che RFC 9989 §4.10 ricava con
                        // il "tree walk": due sottodomini fratelli (a.esempio.it e b.esempio.it)
                        // appartengono allo stesso dominio organizzativo e non richiedono nulla.
                        // Senza quel calcolo, bocciare significherebbe dichiarare rotto un DMARC
                        // che funziona, e spingere a "sistemare" cio' che va gia' bene.
                        dmarcCheck.message += " " + I18n.tr("server.dnsg.ruaCheck", java.util.Map.of("name", String.valueOf(authName)));
                    } else {
                        dmarcCheck.message += " " + I18n.tr("server.dnsg.ruaAuthOk", java.util.Map.of("name", String.valueOf(authName)));
                    }
                }
            }
            if (!e.warnings.isEmpty())
                dmarcCheck.message = (dmarcCheck.message == null ? "" : dmarcCheck.message + " ")
                                   + String.join(" ", e.warnings);
        } else if (dmarcCheck.message != null && dmarcCheck.message.startsWith(I18n.tr("server.dnsg.notFound"))) {
            dmarcCheck.message = I18n.tr("server.dnsg.noDmarc");
        }
        result.checks.add(dmarcCheck);
        if (!dmarcCheck.passed) result.allPassed = false;

        // 6. Check Autoconfig for Thunderbird (CNAME)
        DnsCheck autoconfigCheck = verifyRecord("autoconfig." + domain, "CNAME");
        autoconfigCheck.recordType = "Autoconfig";
        autoconfigCheck.expectedValue = mailHostname + ".";
        if (autoconfigCheck.currentValue != null) {
            String pointsTo = autoconfigCheck.currentValue.trim().split("\\s+")[0];
            if (DnsRules.sameName(pointsTo, mailHostname)) {
                autoconfigCheck.passed = true;
                autoconfigCheck.message = "OK: autoconfig → " + mailHostname;
            } else {
                autoconfigCheck.passed = false;
                autoconfigCheck.message = I18n.tr("server.dnsg.pointsInstead", java.util.Map.of("a", String.valueOf(pointsTo), "h", String.valueOf(mailHostname)));
            }
        } else if (autoconfigCheck.message != null && autoconfigCheck.message.startsWith(I18n.tr("server.dnsg.notFound"))) {
            autoconfigCheck.passed = false;
            autoconfigCheck.informational = true;
            autoconfigCheck.message = I18n.tr("server.dnsg.autoconfigOff", java.util.Map.of("d", String.valueOf(domain)));
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

        // 8-bis. Il DNS inverso dell'IPv6, quando la posta esce anche in IPv6: Gmail («550 5.7.1 ... IPv6 sending
        // guidelines regarding PTR records») e Microsoft (450 4.7.25) lo pretendono. Il controllo di sopra cerca un A,
        // e per un IPv6 non poteva tornare: questo cerca un AAAA (ReverseDns).
        if (family.sends6() && !ip6Now.isEmpty()) {
            String want = mailHostname;
            ReverseDns.Check r6 = ReverseDns.check(ip6Now, want);
            DnsCheck ptr6 = new DnsCheck();
            ptr6.recordType = "PTR";
            ptr6.recordName = ip6Now;
            ptr6.expectedValue = want;
            ptr6.currentValue = r6.ptr();
            ptr6.passed = r6.ok();
            ptr6.message = r6.ok() ? "OK: " + ip6Now + " → " + want
                    : I18n.tr("server.dnsg.ptr6", java.util.Map.of("ip", ip6Now, "h", String.valueOf(want), "why", I18n.tr(r6.reason())));
            result.checks.add(ptr6);
            if (!ptr6.passed) result.allPassed = false;
        }

        // 9. Check MTA-STS (optional but recommended)
        // Note: MTA-STS ID is just a version timestamp, doesn't need to match exactly
        DnsCheck mtaStsCheck = mtaStsCheck(domain,
                org.daemoxcp.mail.system.MtaStsSetup.readTxt(domain),
                org.daemoxcp.mail.system.MtaSts::publicTest);
        mtaStsCheck.expectedValue = org.daemoxcp.mail.system.MtaSts.currentTxtRecord();
        result.checks.add(mtaStsCheck);
        // Don't fail overall for optional records
        // if (!mtaStsCheck.passed) result.allPassed = false;

        // 9. Check SRV records for IMAP and SMTP submission
        DnsCheck srvImapCheck = verifyRecord("_imaps._tcp." + domain, "SRV");
        srvImapCheck.recordType = "SRV (_imaps)";
        srvImapCheck.expectedValue = "0 1 993 " + mailHostname + ".";
        checkSrv(srvImapCheck, mailHostname, 993, I18n.tr("server.dnsg.incoming"));
        result.checks.add(srvImapCheck);

        DnsCheck srvSmtpCheck = verifyRecord("_submission._tcp." + domain, "SRV");
        srvSmtpCheck.recordType = "SRV (_submission)";
        srvSmtpCheck.expectedValue = "0 1 587 " + mailHostname + ".";
        checkSrv(srvSmtpCheck, mailHostname, 587, I18n.tr("server.dnsg.outgoing"));
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
            c.indispensable = t.equals("A") || t.equals("MX") || t.equals("SPF")
                            || t.equals("DKIM") || t.equals("DMARC");
        }
        int indispensable = 0, passed = 0;
        for (DnsCheck c : result.checks)
            if (c.indispensable) { indispensable++; if (c.passed) passed++; }
        result.score = indispensable == 0 ? 0 : (passed * 100) / indispensable;

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
            check.message = I18n.tr("server.dnsg.ipNotDetected");
            return check;
        }

        try {
            // 1. Reverse lookup: dig -x <IP>
            // TODO: migrate to Shell.run when touched
            ProcessBuilder revPb = new ProcessBuilder("dig", "+short", "-x", serverIp);
            org.daemoxcp.mail.util.Shell.applyPath(revPb);
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
                check.message = I18n.tr("server.dnsg.noPtr", java.util.Map.of("ip", String.valueOf(serverIp)));
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
                check.message = I18n.tr("server.dnsg.ptrMismatch", java.util.Map.of("ptr", String.valueOf(ptr), "h", String.valueOf(mailHostname)));
                return check;
            }

            // 3. FCrDNS — risolvi il PTR e verifica che torni allo stesso IP
            // TODO: migrate to Shell.run when touched
            ProcessBuilder fwdPb = new ProcessBuilder("dig", "+short", "A", ptr);
            org.daemoxcp.mail.util.Shell.applyPath(fwdPb);
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
                check.message = I18n.tr("server.dnsg.fcrdnsBad", java.util.Map.of("ptr", String.valueOf(ptr), "ip", String.valueOf(serverIp), "fwd", String.valueOf(fwdOut.replace("\n", ", "))));
                return check;
            }

            check.passed = true;
            check.message = I18n.tr("server.dnsg.ptrOk", java.util.Map.of("ptr", String.valueOf(ptr), "ip", String.valueOf(serverIp)));
            return check;

        } catch (Exception e) {
            check.passed = false;
            check.message = I18n.tr("server.dnsg.ptrError", java.util.Map.of("m", String.valueOf(e.getMessage())));
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
    private void checkSrv(DnsCheck check, String mailHostname, int expectedPort, String purpose) {
        if (check.currentValue == null) {
            check.passed = false;
            if (check.message != null && check.message.startsWith(I18n.tr("server.dnsg.notFound")))
                check.message = I18n.tr("server.dnsg.optionalOff");
            return;
        }
        DnsRules.Srv s = DnsRules.analyzeSrv(check.currentValue.trim().split("\n")[0]);
        if (s == null) {
            check.passed = false;
            check.message = I18n.tr("server.dnsg.notSrv", java.util.Map.of("v", String.valueOf(check.currentValue.trim())));
            return;
        }
        boolean host = DnsRules.sameName(s.destination, mailHostname);
        boolean port = s.port == expectedPort;
        if (host && port) {
            check.passed = true;
            check.message = I18n.tr("server.dnsg.srvOk", java.util.Map.of("what", String.valueOf(purpose), "h", String.valueOf(mailHostname), "port", String.valueOf(expectedPort)));
            return;
        }
        check.passed = false;
        if (!host && !port)
            check.message = I18n.tr("server.dnsg.srvBoth", java.util.Map.of("dest", String.valueOf(s.destination), "port", String.valueOf(s.port), "h", String.valueOf(mailHostname), "wait", String.valueOf(expectedPort)));
        else if (!host)
            check.message = I18n.tr("server.dnsg.srvHost", java.util.Map.of("dest", String.valueOf(s.destination), "h", String.valueOf(mailHostname)));
        else
            check.message = I18n.tr("server.dnsg.srvPort", java.util.Map.of("port", String.valueOf(s.port), "wait", String.valueOf(expectedPort)));
    }

    /**
     * La riga MTA-STS della pagina DNS, da cio' che dice il DNS del record e da come risponde
     * la politica.
     *
     * Il record si legge con la stessa funzione del piano MTA-STS (MtaStsSetup.readTxt).
     * Prima qui bastava che "v=STSv1" comparisse nell'uscita di "dig +short": due record, che
     * per i mittenti valgono zero (RFC 8461 §3.1), davano "Attivo", e un SERVFAIL dava "Non
     * attivo". Sta da sola perche' le prove la verifichino senza DNS e senza la politica vera.
     */
    static DnsCheck mtaStsCheck(String domain, org.daemoxcp.mail.system.MtaStsSetup.TxtReading txtSts,
                                    java.util.function.Function<String, org.json.JSONObject> publicTest) {
        DnsCheck mtaStsCheck = new DnsCheck();
        mtaStsCheck.recordName = "_mta-sts." + domain;
        mtaStsCheck.recordType = "MTA-STS";
        if (!txtSts.values.isEmpty()) mtaStsCheck.currentValue = String.join("  ||  ", txtSts.values);
        if (txtSts.outcome == org.daemoxcp.mail.system.MtaStsSetup.TxtOutcome.PRESENT) {
            // Il record c'e': ora si va a CHIEDERE la politica. Guardare solo il TXT diceva
            // "fatto" su domini che dichiarano pubblicamente una protezione e poi non la
            // servono. E' una promessa non mantenuta, e il pannello la mostrava come esito
            // positivo — misurare il cartello invece della cosa.
            org.json.JSONObject test = publicTest.apply(domain);
            if (test.optBoolean("ok", false)) {
                mtaStsCheck.passed = true;
                mtaStsCheck.message = I18n.tr("server.dnsg.stsActive");
            } else {
                mtaStsCheck.passed = false;
                mtaStsCheck.message = I18n.tr("server.dnsg.stsNotServed", java.util.Map.of("d", String.valueOf(domain), "e", String.valueOf(test.optString("error", I18n.tr("server.dnsg.unreachable")))));
            }
        } else if (txtSts.outcome == org.daemoxcp.mail.system.MtaStsSetup.TxtOutcome.TOO_MANY) {
            mtaStsCheck.passed = false;
            mtaStsCheck.message = I18n.tr("server.dnsg.stsMany", java.util.Map.of("n", String.valueOf(txtSts.values.size()), "d", String.valueOf(domain)));
        } else if (txtSts.outcome == org.daemoxcp.mail.system.MtaStsSetup.TxtOutcome.NOT_ASKED) {
            // NON si scrive "non attivo" su una domanda rimasta senza risposta: sono due guasti
            // diversi e mandano a cercare in posti opposti (come per autoconfig, in verifyAllRecords).
            mtaStsCheck.passed = false;
            mtaStsCheck.message = I18n.tr("server.dnsg.stsUnknown", java.util.Map.of("why", String.valueOf(txtSts.reason)));
        } else {
            mtaStsCheck.passed = false;
            mtaStsCheck.informational = true;
            mtaStsCheck.message = I18n.tr("server.dnsg.stsOff", java.util.Map.of("d", String.valueOf(domain)));
        }
        return mtaStsCheck;
    }

    private DnsCheck verifyRecord(String name, String type) {
        DnsCheck check = new DnsCheck();
        check.recordType = type;
        check.recordName = name;

        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", type, name);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
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
                check.message = I18n.tr("server.dnsg.notFound");
                check.currentValue = null;
            } else {
                check.passed = true;
                check.message = I18n.tr("server.dnsg.found");
                check.currentValue = result;
            }

        } catch (Exception e) {
            check.passed = false;
            String m = e.getMessage() == null ? "" : e.getMessage();
            check.message = m.contains("Cannot run program")
                    ? I18n.tr("server.dnsg.noDig")
                    : I18n.tr("server.dnsg.checkError", java.util.Map.of("m", String.valueOf(m)));
        }

        return check;
    }

    /**
     * L'IPv4 pubblico del server, o "" se non lo si conosce.
     *
     * Prima, quando non lo trovava, restituiva il testo "YOUR_SERVER_IP": chi controlla "vuoto = non so" lo prendeva
     * per un indirizzo, e "Configura tutto" poteva pubblicare "v=spf1 ip4:YOUR_SERVER_IP mx -all". E dalla scheda di
     * rete accettava anche un 100.64.x.x (NAT del fornitore) o un 172.32.x.x scartato per sbaglio. Adesso: un
     * indirizzo che non e' pubblico non vale, da nessuna delle due strade.
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
                    String line = reader.readLine();
                    String ip = line == null ? "" : line.trim();
                    if (isPublicIpv4(ip)) {
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
                    if (addr instanceof Inet4Address && isPublicIpv4(addr.getHostAddress())) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return "";
    }

    /**
     * Vero solo per un IPv4 pubblico, scritto in forma decimale con quattro parti. Fuori: 0/8, 10/8, 100.64/10 (NAT del
     * fornitore), 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24,
     * 203.0.113/24 (documentazione) e da 224 in su (multicast e riservati). Puro.
     */
    public static boolean isPublicIpv4(String ip) {
        if (ip == null || !ip.matches("(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}"))
            return false;
        String[] p = ip.split("\\.");
        int a = Integer.parseInt(p[0]), b = Integer.parseInt(p[1]), c = Integer.parseInt(p[2]);
        if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
        if (a == 100 && b >= 64 && b <= 127) return false;
        if (a == 169 && b == 254) return false;
        if (a == 172 && b >= 16 && b <= 31) return false;
        if (a == 192 && b == 0 && (c == 0 || c == 2)) return false;
        if (a == 192 && b == 168) return false;
        if (a == 198 && (b == 18 || b == 19)) return false;
        if (a == 198 && b == 51 && c == 100) return false;
        if (a == 203 && b == 0 && c == 113) return false;
        return true;
    }

    /**
     * L'IPv6 pubblico del server, o "" se non lo si conosce. Prima chiede a un servizio raggiungibile solo in IPv6
     * (quindi risponde solo se il server esce davvero in IPv6), poi guarda le schede di rete. Solo indirizzi globali
     * (2000::/3), mai quelli di documentazione, locali o link-local.
     */
    public String detectServerIpv6() {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL("https://api6.ipify.org").openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line = reader.readLine();
                String ip = line == null ? "" : line.trim();
                if (isPublicIpv6(ip)) return ip;
            }
        } catch (Exception e) {
            // le schede di rete
        }
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof java.net.Inet6Address) {
                        String ip = addr.getHostAddress().replaceAll("%.*$", "");
                        if (isPublicIpv6(ip)) return ip;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return "";
    }

    /** Vero solo per un IPv6 globale: 2000::/3, tranne la documentazione (2001:db8::/32). Puro. */
    public static boolean isPublicIpv6(String ip) {
        if (ip == null || !ip.matches("[0-9a-fA-F:]{2,39}") || !ip.contains(":")) return false;
        try {
            byte[] b = InetAddress.getByName(ip).getAddress();
            if (b.length != 16) return false;
            if ((b[0] & 0xE0) != 0x20) return false;
            return !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && (b[3] & 0xff) == 0xb8);
        } catch (Exception e) {
            return false;
        }
    }

    /** Vero se fra gli indirizzi di un'uscita di dig c'e' quello (confronto da indirizzo, non da testo). Puro. */
    public static boolean containsAddress(String digOutput, String ip) {
        if (digOutput == null || ip == null || ip.isEmpty()) return false;
        try {
            InetAddress want = InetAddress.getByName(ip);
            for (String tok : digOutput.trim().split("\\s+")) {
                if (!tok.matches("[0-9a-fA-F:.]{2,45}")) continue;
                try {
                    if (InetAddress.getByName(tok).equals(want)) return true;
                } catch (Exception ignore) {
                    // non e' un indirizzo
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /**
     * Il valore SPF del server per quella famiglia: ip4 e/o ip6 con gli indirizzi che si conoscono, poi mx e -all. Null
     * se non se ne conosce nessuno della famiglia: meglio nessun record che uno sbagliato. Puro.
     */
    public static String spfValue(String ip4, String ip6, org.daemoxcp.mail.system.IpFamily.Family family) {
        StringBuilder b = new StringBuilder("v=spf1");
        boolean any = false;
        if (family.v4() && isPublicIpv4(ip4)) { b.append(" ip4:").append(ip4); any = true; }
        // ip6 quando la posta esce in IPv6, anche solo in uscita (esplicito: «mx» lo copre gia' con l'AAAA).
        if (family.sends6() && isPublicIpv6(ip6)) { b.append(" ip6:").append(ip6); any = true; }
        return any ? b.append(" mx -all").toString() : null;
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
        /**
         * Il valore per intero, quando "value" da solo non basta a scrivere il record.
         *
         * Per un MX serve anche la priorita', per un SRV anche priorita', peso e porta: in
         * "value" c'e' la sola destinazione, perche' gli altri campi vivono altrove. La
         * pagina pero' lo mostrava sotto l'etichetta "Valore consigliato dal pannello", cioe'
         * prometteva qualcosa da copiare nel proprio provider DNS — e chi lo avesse copiato
         * avrebbe scritto un MX senza priorita' e un SRV senza porta. Un valore incompleto
         * presentato come completo e' peggio di nessun valore.
         */
        public String fullValue;
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
        public boolean indispensable;
        /**
         * Informativo: non e' un esito, e' una constatazione. Si disegna in grigio, non in
         * rosso. Una croce rossa su una cosa che si e' deciso di non fare e' rumore, e il
         * rumore insegna a ignorare tutte le altre righe.
         */
        public boolean informational;
    }
}
