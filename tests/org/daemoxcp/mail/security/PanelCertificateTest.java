package org.daemoxcp.mail.security;

import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

/**
 * The panel's certificate checked before menu option 2 saves it (reperto 243), and the provider firewall's list
 * (reperto 245). Certificates and keys are made here with openssl (FreeBSD base):
 *  1. a certificate and its key for the panel's name: saved, with what it covers, the issuer and the expiry (one
 *     made a second ago is valid: ten minutes of clock skew are tolerated on its start);
 *  2. a wildcard covers one label only; a certificate for another name, an expired one, one not valid yet, a key that
 *     is not the certificate's: refused; a panel without a domain name and a self-signed certificate: warnings;
 *  3. the key formats the TLS server reads: PKCS#8 RSA, PKCS#1 RSA, PKCS#8 EC; a path is told from a pasted PEM;
 *  4. the provider firewall: the list's fingerprint does not depend on the order; never confirmed, current, changed,
 *     unknown; the rules from this server's ports; a confirmation of a list that changed meanwhile is refused, a good
 *     one is written 0600.
 * Needs openssl: on the VM.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.PanelCertificateTest
 */
public class PanelCertificateTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Path dir;

    static void openssl(String... args) throws Exception {
        String[] cmd = new String[args.length + 1];
        cmd[0] = "openssl";
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException("openssl " + String.join(" ", args) + ": " + out);
    }

    /** A self-signed certificate (issuer = subject) for the given names, with a PKCS#8 RSA key. */
    static void selfSigned(String name, String san) throws Exception {
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=" + san.split(",")[0].replace("DNS:", ""),
                "-addext", "subjectAltName=" + san, "-keyout", name + ".key", "-out", name + ".crt");
    }

    static String read(String f) throws Exception { return Files.readString(dir.resolve(f)); }

    public static void main(String[] args) throws Exception {
        // The console speaks the panel's language (Main.chooseConsoleLanguage): here its English is read.
        org.daemoxcp.mail.i18n.I18n.setProcessLanguage("en");
        dir = Files.createTempDirectory("panel-cert-test");
        try {
            run();
        } finally {
            try (var w = Files.walk(dir)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void run() throws Exception {
        // A small CA and a certificate signed by it, like an Origin Certificate (issuer != subject).
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=Test Origin CA",
                "-keyout", "ca.key", "-out", "ca.crt");
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=example.com", "-keyout", "site.key", "-out", "site.csr");
        Files.writeString(dir.resolve("san.ext"), "subjectAltName=DNS:*.example.com,DNS:example.com\n");
        openssl("x509", "-req", "-in", "site.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "30",
                "-extfile", "san.ext", "-out", "site.crt");

        System.out.println("== 1. A certificate and its key for the panel's name");
        PemTls.Check c = PemTls.check("panel.example.com", read("site.crt"), read("site.key"), Instant.now());
        check("saved: no error, no warning (" + c.errors() + c.warnings() + ")", c.ok() && c.warnings().isEmpty());
        check("  it says what it covers, the issuer, the expiry, the key", String.join("|", c.info()).contains("*.example.com")
                && String.join("|", c.info()).contains("Test Origin CA") && String.join("|", c.info()).contains("Valid until")
                && String.join("|", c.info()).contains("belongs to the certificate"));

        System.out.println("\n== 2. What is refused, what is warned");
        check("the bare domain is covered (listed)", PemTls.check("example.com", read("site.crt"), read("site.key"), Instant.now()).ok());
        check("a wildcard covers one label only: a.b.example.com refused",
                !PemTls.check("a.b.example.com", read("site.crt"), read("site.key"), Instant.now()).ok());
        check("another domain refused, naming what it covers",
                PemTls.check("panel.example.net", read("site.crt"), read("site.key"), Instant.now()).errors().stream().anyMatch(e -> e.contains("does not cover")));
        check("the webmail's certificate checked the same way, naming the webmail",
                PemTls.check("webmail", "webmail.example.net", read("site.crt"), read("site.key"), Instant.now()).errors()
                        .stream().anyMatch(e -> e.contains("does not cover the webmail name webmail.example.net")));
        check("expired refused", PemTls.check("panel.example.com", read("site.crt"), read("site.key"), Instant.now().plus(60, ChronoUnit.DAYS))
                .errors().stream().anyMatch(e -> e.contains("expired")));
        check("not valid yet refused", PemTls.check("panel.example.com", read("site.crt"), read("site.key"), Instant.now().minus(2, ChronoUnit.DAYS))
                .errors().stream().anyMatch(e -> e.contains("not valid yet")));
        check("a server clock five minutes behind: still saved",
                PemTls.check("panel.example.com", read("site.crt"), read("site.key"), Instant.now().minus(5, ChronoUnit.MINUTES)).ok());
        check("a key that is not the certificate's refused", PemTls.check("panel.example.com", read("site.crt"), read("ca.key"), Instant.now())
                .errors().stream().anyMatch(e -> e.contains("not the certificate's")));
        check("garbage instead of a certificate refused", !PemTls.check("panel.example.com", "hello", read("site.key"), Instant.now()).ok());
        c = PemTls.check("0.0.0.0", read("site.crt"), read("site.key"), Instant.now());
        check("a panel without a domain name: saved with a warning", c.ok() && c.warnings().size() == 1);
        selfSigned("self", "DNS:panel.example.com");
        c = PemTls.check("panel.example.com", read("self.crt"), read("self.key"), Instant.now());
        check("self-signed: saved with a warning about Full (strict)", c.ok() && c.warnings().stream().anyMatch(w -> w.contains("self-signed")));

        System.out.println("\n== 3. Key formats and paths");
        openssl("genrsa", "-traditional", "-out", "pkcs1.key", "2048");
        openssl("req", "-x509", "-key", "pkcs1.key", "-days", "30", "-subj", "/CN=panel.example.com",
                "-addext", "subjectAltName=DNS:panel.example.com", "-out", "pkcs1.crt");
        check("PKCS#1 RSA key (BEGIN RSA PRIVATE KEY) matched", read("pkcs1.key").contains("BEGIN RSA PRIVATE KEY")
                && PemTls.check("panel.example.com", read("pkcs1.crt"), read("pkcs1.key"), Instant.now()).ok());
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
                "-subj", "/CN=panel.example.com", "-addext", "subjectAltName=DNS:panel.example.com", "-keyout", "ec.key", "-out", "ec.crt");
        check("PKCS#8 EC key matched", read("ec.key").contains("BEGIN PRIVATE KEY")
                && PemTls.check("panel.example.com", read("ec.crt"), read("ec.key"), Instant.now()).ok());
        check("an RSA key for an EC certificate refused", !PemTls.check("panel.example.com", read("ec.crt"), read("site.key"), Instant.now()).ok());
        check("a path is a path, a pasted PEM is not", PemTls.isPath("/root/panel.pem") && !PemTls.isPath(read("site.crt"))
                && !PemTls.isPath("relative.pem"));
        check("a PEM file is read", PemTls.readFile(dir.resolve("site.crt")).contains("BEGIN CERTIFICATE"));
        Files.createSymbolicLink(dir.resolve("link.crt"), dir.resolve("site.crt"));
        boolean refused = false;
        try { PemTls.readFile(dir.resolve("link.crt")); } catch (java.io.IOException e) { refused = true; }
        check("a link is refused", refused);
        Files.writeString(dir.resolve("notpem.txt"), "hello\n");
        refused = false;
        try { PemTls.readFile(dir.resolve("notpem.txt")); } catch (java.io.IOException e) { refused = true; }
        check("a file without a PEM block is refused", refused);

        System.out.println("\n== 4. The provider firewall's list");
        List<String> v4 = List.of("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
                "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
                "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22");
        List<String> v6 = List.of("2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
                "2a06:98c0::/29", "2c0f:f248::/32");
        ProviderFirewall.Official o = new ProviderFirewall.Official(v4, v6);
        List<String> v4r = new java.util.ArrayList<>(v4);
        java.util.Collections.reverse(v4r);
        String fp = ProviderFirewall.fingerprint(o);
        check("the fingerprint does not depend on the order", fp.equals(ProviderFirewall.fingerprint(new ProviderFirewall.Official(v4r, v6))));
        List<String> v4plus = new java.util.ArrayList<>(v4);
        v4plus.add("198.51.100.0/24");
        ProviderFirewall.Official changed = new ProviderFirewall.Official(v4plus, v6);
        check("a new range changes it", !fp.equals(ProviderFirewall.fingerprint(changed)));
        check("never confirmed: never", "never".equals(ProviderFirewall.withList(new JSONObject(), o, null).getString("state")));
        JSONObject ack = new JSONObject().put("fingerprint", fp).put("at", "2026-11-16T15:00:00Z");
        JSONObject s = ProviderFirewall.withList(new JSONObject(), o, ack);
        check("confirmed and the same: current, with the comma list", "current".equals(s.getString("state"))
                && s.getString("commaList").startsWith("173.245.48.0/20, ") && s.getString("commaList").endsWith("2c0f:f248::/32"));
        check("Cloudflare changed it: changed", "changed".equals(ProviderFirewall.withList(new JSONObject(), changed, ack).getString("state")));
        check("no list downloaded: unknown, saying so", "unknown".equals(ProviderFirewall.withList(new JSONObject(), null, ack).getString("state")));
        JSONObject rules = ProviderFirewall.rules(new java.util.TreeSet<>(), 2096, 8443, false);
        check("rules: SSH 22 when sshd's ports are unknown, mail ports, panel and webmail only for Cloudflare",
                rules.getJSONArray("ssh").toList().equals(List.of(22))
                && rules.getJSONArray("open").toList().equals(List.of(25, 80, 143, 443, 465, 587, 993))
                && rules.getJSONArray("cloudflare").toList().equals(List.of(2096, 8443)));
        check("rules with POP3 on: 110 and 995 too", ProviderFirewall.rules(new java.util.TreeSet<>(List.of(2222)), 2096, 8443, true)
                .getJSONArray("open").toList().equals(List.of(25, 80, 110, 143, 443, 465, 587, 993, 995)));

        ProviderFirewall.Source before = ProviderFirewall.source;
        Path statePath = ProviderFirewall.statePath;
        try {
            ProviderFirewall.statePath = dir.resolve("pf/provider-firewall.json");
            ProviderFirewall.source = () -> changed;
            JSONObject a = ProviderFirewall.acknowledge(fp);
            check("confirming a list that changed meanwhile: refused, nothing written", !a.optBoolean("success")
                    && !Files.exists(ProviderFirewall.statePath));
            check("a malformed fingerprint: refused", !ProviderFirewall.acknowledge("not-a-fingerprint").optBoolean("success"));
            ProviderFirewall.source = () -> o;
            ProviderFirewall.official(true);
            ProviderFirewall.acknowledge(fp);
            check("the right one: written, 0600", Files.exists(ProviderFirewall.statePath)
                    && java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(ProviderFirewall.statePath)).equals("rw-------")
                    && fp.equals(ProviderFirewall.acknowledged().getString("fingerprint")));
            ProviderFirewall.source = () -> new ProviderFirewall.Official(List.of("1.2.3.0/24"), v6);
            check("a short list from cloudflare.com is not believed", ProviderFirewall.official(true) == null);
        } finally {
            ProviderFirewall.source = before;
            ProviderFirewall.statePath = statePath;
        }
    }
}
