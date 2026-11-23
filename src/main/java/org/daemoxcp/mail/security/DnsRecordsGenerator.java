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
 * - Autoconfig and SRV: how clients find servers and ports on their own
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

        // NOTE: The A record for the mail server hostname (e.g. mail.example.com)
        // is shown on the HOME page with an essential-configuration warning,
        // NOT here in the DNS list, to avoid duplication.

        // 2. SPF Record
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        // The ip6 in the SPF when mail goes out over IPv6, even outbound only: "mx" already covers it with the AAAA
        // of the mail name, the ip6 states it explicitly.
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
            // The placeholder also declares its check: without it, it would be the only record to
            // fall back on matching by name, i.e. on exactly the defect just fixed.
            dkimPlaceholder.checkType = "DKIM";
            dkimPlaceholder.required = true;
            dkimPlaceholder.configured = false;
            dkimPlaceholder.explanation = dkimPlaceholderExplanation(domain);
            records.records.add(dkimPlaceholder);
        }

        // 5. DMARC Record
        records.records.add(generateDmarcRecord(domain));

        // 6. The records with which clients find the settings on their own
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
        // To show: with IPv4 the placeholder is shown even if the address is not known; IPv6 only if it is known.
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
        // RFC 9989 Section 5.1.5: start from "none". Proposing "quarantine" as the first record
        // means quarantining your own legitimate mail before having read a
        // single report -- and that is exactly what the reports are there to prevent.
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
     * The records that help clients configure themselves: the autoconfig CNAME (Thunderbird) and the
     * two SRV records of RFC 6186. The "autodiscover" CNAME is gone: it only served Outlook, and
     * a method still named after what it no longer does is a trap for whoever reads it.
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

        // The two SRV records of RFC 6186: these work on their own, without any file to serve.
        DnsRecord srvImap = new DnsRecord();
        srvImap.type = "SRV";
        srvImap.name = "_imaps._tcp";
        srvImap.value = mailServer;
        srvImap.priority = 0;
        srvImap.ttl = DEFAULT_TTL;
        srvImap.dnsZone = domain;
        srvImap.description = I18n.tr("server.dnsg.descSrvImap", java.util.Map.of("d", String.valueOf(domain)));
        srvImap.checkType = "SRV (_imaps)";
        // An SRV cannot be written without priority, weight and port: here is the whole record.
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
        // The value is the REAL one, the same one the panel publishes: we ask whoever
        // knows it, we do not invent another one here.
        //
        // Before, it was "v=STSv1; id=" + System.currentTimeMillis(): an id taken from the clock,
        // recomputed at every page load. Two defects in one line. The first: whoever
        // followed these instructions published an id that does not match the policy served
        // and never changes again, so senders do not notice the changes --
        // exactly the defect the old panel's records carried along. The
        // second: the value shown changed at every glance, while the line next to it said
        // "configured correctly". Two ways of computing the same record are two records
        // that one day diverge; here they diverged right away.
        String mtaStsValue = org.daemoxcp.mail.system.MtaSts.currentTxtRecord();
        // currentTxtRecord() returns empty when it cannot compute it: better nothing than an
        // invented value. But an empty "Content" box in the instructions helps nobody,
        // so it says in words what will go there, without suggesting to paste nonsense.
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

    // ============== The explanations: the structure here, the sentences in the language files ==============
    //
    // The sentences live in server.dnsx.*. The field labels (Type, Name, Content, TTL, Proxy
    // status) stay in English: they are the ones you read in the Cloudflare dashboard. The values
    // (domain, IP, hostname) always go in escaped; in the .html keys the text has only
    // strong, code and br, and I18nTest checks it.

    /** A sentence without HTML, ready for the page. The arguments come in pairs: name, value. */
    private static String tx(String key, String... kv) {
        return I18n.escapeHtml(I18n.tr("server.dnsx." + key, pairs(kv, true)));
    }

    /** A sentence with strong, code or br inside (.html key): the escape touches the values, not the text. */
    private static String th(String key, String... kv) {
        return I18n.tr("server.dnsx." + key + ".html", pairs(kv, true));
    }

    /** Like th, with a single value that is already HTML written here (a link). */
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

    /** A row whose long value wraps wherever it happens to (the DKIM key). */
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

    /** DKIM not generated yet: what to do, with the page and button names that are really shown. */
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

    /** PTR is not configured on Cloudflare: the guide for the most common providers. */
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
            // Only if the query succeeded and found nothing. If instead it had
            // failed, the precise message is already there, and overwriting it with "not found"
            // turns a broken tool into a missing DNS record: two problems with two
            // opposite remedies, and the reader goes looking in the wrong place.
            aCheck.message = I18n.tr("server.dnsg.noA", java.util.Map.of("h", String.valueOf(mailHostname)));
        }
        // With IPv6 only the A record is not needed: the check is still shown, but does not count.
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        result.checks.add(aCheck);
        if (!aCheck.passed && family.v4()) result.allPassed = false;

        // 1-bis. AAAA, when mail uses IPv6 (even outbound only: a single name, which has the AAAA and the reverse DNS;
        // whoever tries to deliver over IPv6 is refused right away by pf) and the server has a public IPv6 (with IPv6
        // only, always).
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
            // A domain can have several MX records: it is enough that ONE points here. But the comparison is
            // exact on the target name, not by containment: an MX pointing to
            // "xmail.esempio.it" contains "mail.esempio.it" and passed as correct, while the
            // mail would have ended up at a server that is not this one.
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
        // The raw TXT is read and the rules of RFC 7208 are applied, instead of searching for
        // substrings. The old check did contains("mx"): an SPF like
        // "v=spf1 include:_spf.mxlogic.com -all", which does NOT authorize this server, passed
        // because the word "mx" appears inside a domain name. A check that says
        // "all good" in front of an SPF that does not authorize you is worse than no check.
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
                    // Neither passed nor failed: stated as it is. Failing an SPF that delegates to
                    // third parties would lead to "fixing" a record that works.
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
            // substring(0, 20) without a safety net: with a corrupted key shorter than
            // twenty characters it raised an exception that escaped the whole method and made
            // the ENTIRE verification page disappear, not just this row.
            dkimCheck.expectedValue = "v=DKIM1; k=rsa; p="
                    + wait.substring(0, Math.min(20, wait.length())) + "...";

        if (dkimCheck.currentValue != null) {
            // 2048-bit keys exceed 255 characters, so in DNS they sit in several
            // strings that must be joined without spaces (RFC 7208 Section 3.3). Comparing the raw
            // output of dig would mean comparing the quotes in the middle too.
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
                    // FULL comparison, not the first 50 characters: a key correct at the start
                    // and corrupted at the end passed the old check and signed nothing.
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
        // The record is read by its tags, not by searching for "p=none" inside the string: "p=none"
        // appears as a substring in "sp=none" too, and the verdict would come out wrong.
        // And p=none is NOT a "weak policy": RFC 9989 Section 5.1.5 says to start from there.
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

                // RFC 9990 Section 4: if rua points outside the domain, authorization is needed, otherwise
                // the reports do not go out and nobody notices. Here we do not guess: we look.
                for (String authName : e.toAuthorize) {
                    DnsCheck authorization = verifyRecord(authName, "TXT");
                    boolean granted = authorization.currentValue != null
                            && !DnsRules.onlyDmarc(DnsRules.recordTxt(authorization.currentValue)).isEmpty();
                    if (!granted) {
                        // It is FLAGGED without failing. To know whether the authorization is really needed
                        // one must compare the ORGANIZATIONAL domains, which RFC 9989 Section 4.10 derives
                        // with the "tree walk": two sibling subdomains (a.esempio.it and b.esempio.it)
                        // belong to the same organizational domain and require nothing.
                        // Without that computation, failing would mean declaring broken a DMARC
                        // that works, and pushing people to "fix" what is already fine.
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
            // A precise error ("dig not reachable") is NOT overwritten with "not
            // configured": they are two different faults and send you looking in opposite places.
            autoconfigCheck.passed = false;
        }
        result.checks.add(autoconfigCheck);
        // Don't fail overall for optional records
        // if (!autoconfigCheck.passed) result.allPassed = false;

        // 8. Check PTR / Reverse DNS + FCrDNS (Forward-Confirmed reverse DNS)
        //    CRITICAL for deliverability -- Gmail and Outlook REJECT or mark as spam
        //    mail coming from IPs without a PTR or with broken FCrDNS.
        DnsCheck ptrCheck = checkPtrAndFcrdns(serverIp, mailHostname);
        result.checks.add(ptrCheck);
        if (!ptrCheck.passed) result.allPassed = false;

        // 8-bis. The IPv6 reverse DNS, when mail also goes out over IPv6: Gmail ("550 5.7.1 ... IPv6 sending
        // guidelines regarding PTR records") and Microsoft (450 4.7.25) require it. The check above looks for an A,
        // and for an IPv6 it could never work: this one looks for an AAAA (ReverseDns).
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

        // The score counts the essential records: A, MX, SPF, DKIM, DMARC.
        //
        // Before, it counted them BY POSITION, "the first five in the list". It worked, but it only
        // takes someone inserting a check in the middle or moving one for the score to start
        // measuring something else entirely without anything breaking and without anyone
        // noticing: it would remain a plausible number, and it would be false. Now each check says
        // of itself whether it counts, and the position no longer has anything to do with it.
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
     * What it checks:
     *  1. Does the server's IP have a public PTR record?
     *  2. Does the PTR point exactly to the configured mail hostname?
     *  3. FCrDNS: resolving the PTR obtained, do we get back to the same IP?
     *     (e.g. PTR of 1.2.3.4 = mail.dom.tld; A of mail.dom.tld = 1.2.3.4)
     *
     * Without these:
     *  - Gmail puts all your mail in spam (or rejects it)
     *  - Outlook applies a very low reputation score
     *  - Some providers reject SMTP delivery outright
     *
     * To fix the PTR: only the hosting provider can do it (it requires a ticket or
     * the cloud panel, it CANNOT be managed from classic DNS).
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

            // Take the first PTR (there could be several, an anomaly)
            String ptr = revOut.split("\n")[0].trim();
            // Remove the trailing dot typical of DNS answers
            if (ptr.endsWith(".")) ptr = ptr.substring(0, ptr.length() - 1);
            check.currentValue = ptr;

            // 2. PTR matches mail hostname?
            boolean ptrMatches = ptr.equalsIgnoreCase(mailHostname);
            if (!ptrMatches) {
                check.passed = false;
                check.message = I18n.tr("server.dnsg.ptrMismatch", java.util.Map.of("ptr", String.valueOf(ptr), "h", String.valueOf(mailHostname)));
                return check;
            }

            // 3. FCrDNS -- resolve the PTR and check that it leads back to the same IP
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
            check.message = I18n.tr("server.dnsg.ptrError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("DnsRecordsGenerator", e)));
            return check;
        }
    }

    /**
     * Checks an SRV record for real: target AND PORT.
     *
     * The previous check only looked at whether the host name appeared somewhere
     * in the line. Two things escaped it: an SRV pointing to "xmail.esempio.it" (which
     * CONTAINS "mail.esempio.it") passed as correct, and the port was not looked at at all
     * -- while the port is the only reason that record exists.
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
     * The MTA-STS row of the DNS page, from what DNS says about the record and from how the
     * policy answers.
     *
     * The record is read with the same function as the MTA-STS plan (MtaStsSetup.readTxt).
     * Before, it was enough here for "v=STSv1" to appear in the output of "dig +short": two records,
     * which for senders count as zero (RFC 8461 Section 3.1), gave "Active", and a SERVFAIL gave
     * "Not active". It stands on its own so that the tests can check it without DNS and without the
     * real policy.
     */
    static DnsCheck mtaStsCheck(String domain, org.daemoxcp.mail.system.MtaStsSetup.TxtReading txtSts,
                                    java.util.function.Function<String, org.json.JSONObject> publicTest) {
        DnsCheck mtaStsCheck = new DnsCheck();
        mtaStsCheck.recordName = "_mta-sts." + domain;
        mtaStsCheck.recordType = "MTA-STS";
        if (!txtSts.values.isEmpty()) mtaStsCheck.currentValue = String.join("  ||  ", txtSts.values);
        if (txtSts.outcome == org.daemoxcp.mail.system.MtaStsSetup.TxtOutcome.PRESENT) {
            // The record is there: now we go and ASK for the policy. Looking only at the TXT said
            // "done" on domains that publicly declare a protection and then do not
            // serve it. It is a broken promise, and the panel showed it as a positive
            // outcome -- measuring the sign instead of the thing.
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
            // "not active" is NOT written for a question left without an answer: they are two different
            // faults and send you looking in opposite places (as for autoconfig, in verifyAllRecords).
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
     * The server's public IPv4, or "" if it is not known.
     *
     * Before, when it did not find it, it returned the text "YOUR_SERVER_IP": whoever checks "empty = I don't know"
     * took it for an address, and "Configure everything" could publish "v=spf1 ip4:YOUR_SERVER_IP mx -all". And
     * from the network interfaces it also accepted a 100.64.x.x (provider NAT), or discarded a 172.32.x.x by
     * mistake. Now: an address that is not public does not count, from either path.
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
     * True only for a public IPv4, written in decimal form with four parts. Excluded: 0/8, 10/8, 100.64/10 (provider
     * NAT), 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24,
     * 203.0.113/24 (documentation) and from 224 up (multicast and reserved). Pure.
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
     * The server's public IPv6, or "" if it is not known. First it asks a service reachable only over IPv6
     * (so it answers only if the server really goes out over IPv6), then it looks at the network interfaces. Only
     * global addresses (2000::/3), never documentation, local or link-local ones.
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
            // the network interfaces
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

    /** True only for a global IPv6: 2000::/3, except documentation (2001:db8::/32). Pure. */
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

    /** True if that address is among the addresses in a dig output (compared as an address, not as text). Pure. */
    public static boolean containsAddress(String digOutput, String ip) {
        if (digOutput == null || ip == null || ip.isEmpty()) return false;
        try {
            InetAddress want = InetAddress.getByName(ip);
            for (String tok : digOutput.trim().split("\\s+")) {
                if (!tok.matches("[0-9a-fA-F:.]{2,45}")) continue;
                try {
                    if (InetAddress.getByName(tok).equals(want)) return true;
                } catch (Exception ignore) {
                    // not an address
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    /**
     * The server's SPF value for that family: ip4 and/or ip6 with the addresses that are known, then mx and -all.
     * Null if none of that family is known: better no record than a wrong one. Pure.
     */
    public static String spfValue(String ip4, String ip6, org.daemoxcp.mail.system.IpFamily.Family family) {
        StringBuilder b = new StringBuilder("v=spf1");
        boolean any = false;
        if (family.v4() && isPublicIpv4(ip4)) { b.append(" ip4:").append(ip4); any = true; }
        // ip6 when mail goes out over IPv6, even outbound only (explicit: "mx" already covers it with the AAAA).
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
         * Which check this card belongs to: the same value as DnsCheck.recordType.
         *
         * Before, the page paired cards and checks by NAME. At the domain apex, however, there
         * are two different records with the same name -- MX and SPF -- and the second overwrote
         * the first in the map: the MX card ended up showing the verdict and the value
         * of the SPF ("OK: explicitly authorizes 203.0.113.77" under "Mail Exchange").
         * A pairing guessed from the name is a pairing that sooner or later goes wrong:
         * here it travels explicitly.
         */
        public String checkType;
        /**
         * The full value, when "value" alone is not enough to write the record.
         *
         * For an MX the priority is needed too, for an SRV also priority, weight and port: in
         * "value" there is only the target, because the other fields live elsewhere. The
         * page, however, showed it under the label "Value recommended by the panel", i.e. it
         * promised something to copy into your own DNS provider -- and whoever copied it
         * would have written an MX without priority and an SRV without port. An incomplete
         * value presented as complete is worse than no value.
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
        /** Counts in the score. The optional ones do not: mail works without them too. */
        public boolean indispensable;
        /**
         * Informational: it is not an outcome, it is an observation. It is drawn in grey, not in
         * red. A red cross on something one decided not to do is noise, and the
         * noise teaches people to ignore all the other lines.
         */
        public boolean informational;
    }
}
