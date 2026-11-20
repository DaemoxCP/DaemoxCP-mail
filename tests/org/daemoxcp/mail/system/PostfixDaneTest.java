package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.util.Shell;

/**
 * DANE for outgoing mail (PostfixDane): smtp_tls_security_level = dane with smtp_dns_support_level = dnssec. Before
 * 20/11/2026 Postfix sent with opportunistic TLS (may) and never checked whose certificate it got.
 *  1. the decision: the installer's old values (may and the default): apply, if the first nameserver is this machine
 *     and it validates DNSSEC; already dane and dnssec: nothing; values set by hand: left alone;
 *  2. reading /etc/resolv.conf and drill's flags;
 *  3. the installer writes both values, and the panel's start runs the repair after PostfixSubmissionAuth;
 *  4. with -De2e.vm=yes, as root on the VM: Postfix reads dane and dnssec, the local resolver answers the root's DNSKEY
 *     with the ad flag, and posttls-finger (Postfix's own lookups, from main.cf) asks for the TLSA records of the MX of
 *     two domains that publish them (ietf.org, posteo.de: it asks only once MX and addresses are DNSSEC-validated) and
 *     for none of an unsigned domain (gmail.com). Port 25 out is closed on the VM: only the DNS part is measured.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixDaneTest
 */
public class PostfixDaneTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The decision");
        check("may and the default, local validating resolver: apply", PostfixDane.decide("may", "enabled", true, true) == PostfixDane.Action.APPLY);
        check("already dane and dnssec: nothing", PostfixDane.decide("dane", "dnssec", true, true) == PostfixDane.Action.NOTHING);
        check("no validating resolver: left as it is, and said", PostfixDane.decide("may", "enabled", true, false) == PostfixDane.Action.NO_RESOLVER);
        check("the resolver is not this machine: left as it is", PostfixDane.decide("may", "enabled", false, false) == PostfixDane.Action.NO_RESOLVER);
        check("encrypt set by hand: left alone", PostfixDane.decide("encrypt", "enabled", true, true) == PostfixDane.Action.LEFT_ALONE);
        check("DNS lookups turned off by hand: left alone", PostfixDane.decide("may", "disabled", true, true) == PostfixDane.Action.LEFT_ALONE);
        check("dane without dnssec (half done by hand): left alone", PostfixDane.decide("dane", "enabled", true, true) == PostfixDane.Action.LEFT_ALONE);

        System.out.println("\n== 2. resolv.conf and drill");
        check("nameserver 127.0.0.1 first: local", PostfixDane.localResolver("# by resolvconf\nnameserver 127.0.0.1\noptions edns0\n"));
        check("::1 first: local", PostfixDane.localResolver("nameserver ::1\nnameserver 1.1.1.1\n"));
        check("another server first: not local", !PostfixDane.localResolver("nameserver 185.12.64.1\nnameserver 127.0.0.1\n"));
        check("no nameserver: not local", !PostfixDane.localResolver("options edns0\n"));
        check("the ad flag", PostfixDane.authenticated(";; ->>HEADER<<- opcode: QUERY\n;; flags: qr rd ra ad ; QUERY: 1, ANSWER: 4\n"));
        check("no ad flag", !PostfixDane.authenticated(";; flags: qr rd ra ; QUERY: 1, ANSWER: 4\n"));
        check("«ad» elsewhere on the line does not count", !PostfixDane.authenticated(";; flags: qr rd ra ; QUERY: 1, ANSWER: 4, AD: 0 ad\n"));

        System.out.println("\n== 3. Where it is written");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("the installer: dnssec lookups and dane", installer.contains("\nsmtp_dns_support_level = dnssec\nsmtp_tls_security_level = dane\n")
                && !installer.contains("\nsmtp_tls_security_level = may\n"));
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int auth = server.indexOf("PostfixSubmissionAuth.ensureAtBoot();"), dane = server.indexOf("PostfixDane.ensureAtBoot();");
        check("the panel's start runs the repair", auth > 0 && dane > auth);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 4 skipped: it asks Postfix and the resolver on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void live() {
        System.out.println("\n== 4. Live, on the VM");
        check("Postfix reads dane", sh("postconf -h smtp_tls_security_level").trim().equals("dane"));
        check("Postfix reads dnssec", sh("postconf -h smtp_dns_support_level").trim().equals("dnssec"));
        check("the local resolver validates (root DNSKEY with ad)", PostfixDane.validates());
        for (String domain : new String[]{"ietf.org", "posteo.de"}) {
            String out = finger(domain);
            check(domain + ": Postfix asks for the TLSA of its MX and gets them", out.contains("(TLSA): OK") && out.contains("dns_get_answer: type TLSA"));
        }
        check("gmail.com (unsigned): no TLSA asked, TLS stays opportunistic", !finger("gmail.com").contains("(TLSA)"));
    }

    /**
     * posttls-finger with the level and the DNS support of main.cf: on its own it uses dane and asks for TLSA anyway
     * (measured: with may in main.cf it still asked), which would prove nothing about Postfix's settings.
     */
    static String finger(String domain) {
        return sh("timeout -f 60 posttls-finger -t 3 -vv -l \"$(postconf -h smtp_tls_security_level)\""
                + " -o smtp_dns_support_level=\"$(postconf -h smtp_dns_support_level)\" -o inet_protocols=ipv4 " + domain
                + " 2>&1 | grep -e 'TLSA' -e 'Failed' | head -20");
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(90), "sh", "-c", command).output();
    }
}
