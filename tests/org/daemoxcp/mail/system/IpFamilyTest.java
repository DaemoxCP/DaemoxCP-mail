package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.DnsRecordsGenerator;

import java.util.List;
import java.util.TreeSet;

/**
 * IPv4, IPv6 or both (IpFamily), the pure parts: what Postfix, Dovecot, nginx and pf are told for each family, how the
 * listening sockets are read, and the DNS side (public IPv6, SPF with ip4 and/or ip6, addresses compared as addresses).
 * The effect on the real services is measured by tests/ip-family-browser-test.js on the test machine.
 *
 * It runs anywhere (it calls nothing):
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.IpFamilyTest
 */
public class IpFamilyTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) {
        System.out.println("== The families ==");
        check("the saved values", IpFamily.Family.of("both") == IpFamily.Family.BOTH && IpFamily.Family.of("ipv4") == IpFamily.Family.IPV4
                && IpFamily.Family.of(" IPv6 ") == IpFamily.Family.IPV6 && IpFamily.Family.of("v6") == null && IpFamily.Family.of(null) == null);
        check("Postfix's inet_protocols read back", IpFamily.fromPostfix("all") == IpFamily.Family.BOTH
                && IpFamily.fromPostfix("ipv4, ipv6") == IpFamily.Family.BOTH && IpFamily.fromPostfix("ipv6 ipv4") == IpFamily.Family.BOTH
                && IpFamily.fromPostfix("ipv4") == IpFamily.Family.IPV4 && IpFamily.fromPostfix("ipv6") == IpFamily.Family.IPV6
                && IpFamily.fromPostfix("") == null && IpFamily.fromPostfix("ipv5") == null);
        check("what each service is told", IpFamily.Family.IPV4.postfix.equals("ipv4") && IpFamily.Family.IPV6.dovecot.equals("::")
                && IpFamily.Family.BOTH.dovecot.equals("*, ::") && IpFamily.Family.IPV4.pf.equals("inet ") && IpFamily.Family.BOTH.pf.isEmpty());

        System.out.println("\n== Dovecot: the general listen line only ==");
        String conf = "protocols = imap lmtp\nlisten = *, ::\nservice imap-login {\n  inet_listener imaps {\n    listen = 127.0.0.1\n    port = 993\n  }\n}\n";
        String v4 = IpFamily.withDovecotListen(conf, IpFamily.Family.IPV4);
        check("IPv4 only: listen = *, the listener's own line untouched",
                v4 != null && v4.contains("\nlisten = *\n") && v4.contains("    listen = 127.0.0.1\n") && v4.replace("listen = *\n", "listen = *, ::\n").equals(conf));
        check("IPv6 only: listen = ::", IpFamily.withDovecotListen(conf, IpFamily.Family.IPV6).contains("\nlisten = ::\n"));
        check("already as asked: nothing to change", IpFamily.withDovecotListen(conf, IpFamily.Family.BOTH) == null);
        check("no general listen line, or two: not the panel's file, nothing changed",
                IpFamily.withDovecotListen("protocols = imap\n", IpFamily.Family.IPV4) == null
                        && IpFamily.withDovecotListen("listen = *\nlisten = ::\n", IpFamily.Family.BOTH) == null);

        System.out.println("\n== nginx: the listen lines of one port ==");
        String nginx = "server {\n    listen 8443 ssl default_server;\n    server_name _;\n}\nserver {\n    listen 8443 ssl;\n    server_name w;\n}\nserver {\n    listen 80;\n}\n";
        String both = IpFamily.withNginxListen(nginx, 8443, IpFamily.Family.BOTH);
        check("both: each IPv4 line gets its IPv6 twin with the same options",
                both.contains("    listen 8443 ssl default_server;\n    listen [::]:8443 ssl default_server;\n")
                        && both.contains("    listen 8443 ssl;\n    listen [::]:8443 ssl;\n") && both.contains("    listen 80;\n"));
        String six = IpFamily.withNginxListen(both, 8443, IpFamily.Family.IPV6);
        check("IPv6 only: only the [::] lines, other ports untouched",
                !six.contains("listen 8443") && six.contains("listen [::]:8443 ssl default_server;") && six.contains("    listen 80;\n"));
        check("and back to IPv4 only: the original text", IpFamily.withNginxListen(six, 8443, IpFamily.Family.IPV4).equals(nginx));
        check("applying the same family twice changes nothing", IpFamily.withNginxListen(both, 8443, IpFamily.Family.BOTH).equals(both));
        check("no family chosen: the text as it is", IpFamily.withNginxListen(nginx, 8443, null).equals(nginx));
        check("port 84430 is not port 8443", IpFamily.withNginxListen("listen 84430;\n", 8443, IpFamily.Family.IPV6).equals("listen 84430;\n"));

        System.out.println("\n== The sockets that listen, from sockstat ==");
        String sock = "USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n"
                + "root     master     100   13  tcp4   *:25                  *:*\n"
                + "root     master     100   14  tcp6   *:25                  *:*\n"
                + "root     dovecot    200   20  tcp4   *:993                 *:*\n"
                + "www      nginx      300   6   tcp46  *:8443                *:*\n"
                + "root     java       400   9   tcp6   *:2096                *:*\n";
        check("25 in both families", IpFamily.listensAs(sock, 25, IpFamily.Family.BOTH) && !IpFamily.listensAs(sock, 25, IpFamily.Family.IPV4));
        check("993 in IPv4 only", IpFamily.listensAs(sock, 993, IpFamily.Family.IPV4) && !IpFamily.listensAs(sock, 993, IpFamily.Family.BOTH));
        check("tcp46 counts for both", IpFamily.listensAs(sock, 8443, IpFamily.Family.BOTH));
        check("a port that does not listen is no family", !IpFamily.listensAs(sock, 143, IpFamily.Family.IPV4)
                && !IpFamily.listensAs(sock, 143, IpFamily.Family.IPV6) && !IpFamily.listensAs(sock, 143, IpFamily.Family.BOTH));
        check("default route read from netstat", IpFamily.hasDefaultRoute("Routing tables\n\nInternet6:\nDestination Gateway Flags\ndefault fe80::1%vtnet0 UG vtnet0\n")
                && !IpFamily.hasDefaultRoute("Internet6:\n::1 link#2 UHS lo0\n"));

        System.out.println("\n== The administrator's own connection ==");
        check("the family of the connection a choice comes from", IpFamily.connectionFamily("203.0.113.7") == IpFamily.Family.IPV4
                && IpFamily.connectionFamily("::ffff:203.0.113.7") == IpFamily.Family.IPV4
                && IpFamily.connectionFamily("2001:db8::7") == IpFamily.Family.IPV6
                && IpFamily.connectionFamily("fe80:0:0:0:0:0:0:1%vtnet0") == IpFamily.Family.IPV6
                && IpFamily.connectionFamily("127.0.0.1") == null && IpFamily.connectionFamily("0:0:0:0:0:0:0:1") == null
                && IpFamily.connectionFamily(null) == null && IpFamily.connectionFamily("not an address") == null);
        List<String> cut = IpFamily.warnings(IpFamily.Family.IPV6, "203.0.113.7");
        check("IPv6 only, chosen over IPv4: one more warning, first, with the way back from the console",
                cut.size() == IpFamily.warnings(IpFamily.Family.IPV6, null).size() + 1 && cut.get(0).contains("--ip-family both"));
        List<String> cut4 = IpFamily.warnings(IpFamily.Family.IPV4, "2001:db8::7");
        check("IPv4 only, chosen over IPv6: the same warning", cut4.size() == 1 && cut4.get(0).contains("--ip-family both"));
        check("no warning when the connection stays: the same family, both, or a tunnel on the loopback",
                IpFamily.warnings(IpFamily.Family.IPV4, "203.0.113.7").isEmpty() && IpFamily.warnings(IpFamily.Family.BOTH, "2001:db8::7").isEmpty()
                        && IpFamily.warnings(IpFamily.Family.IPV4, "127.0.0.1").isEmpty()
                        && IpFamily.warnings(IpFamily.Family.IPV6, "::1").size() == IpFamily.warnings(IpFamily.Family.IPV6, null).size());

        System.out.println("\n== DNS ==");
        check("public IPv6: global unicast only", DnsRecordsGenerator.isPublicIpv6("2a01:4f8:c17:1234::1")
                && !DnsRecordsGenerator.isPublicIpv6("2001:db8::10") && !DnsRecordsGenerator.isPublicIpv6("fd12:3456:789a:1::5")
                && !DnsRecordsGenerator.isPublicIpv6("fe80::1") && !DnsRecordsGenerator.isPublicIpv6("::1")
                && !DnsRecordsGenerator.isPublicIpv6("8.8.8.8") && !DnsRecordsGenerator.isPublicIpv6("") && !DnsRecordsGenerator.isPublicIpv6("2a01:4f8::zz"));
        check("SPF by family", "v=spf1 ip4:8.8.8.8 ip6:2a01:4f8::1 mx -all".equals(DnsRecordsGenerator.spfValue("8.8.8.8", "2a01:4f8::1", IpFamily.Family.BOTH))
                && "v=spf1 ip4:8.8.8.8 mx -all".equals(DnsRecordsGenerator.spfValue("8.8.8.8", "2a01:4f8::1", IpFamily.Family.IPV4))
                && "v=spf1 ip6:2a01:4f8::1 mx -all".equals(DnsRecordsGenerator.spfValue("8.8.8.8", "2a01:4f8::1", IpFamily.Family.IPV6))
                && "v=spf1 ip4:8.8.8.8 mx -all".equals(DnsRecordsGenerator.spfValue("8.8.8.8", "", IpFamily.Family.BOTH)));
        check("no address of the family known: no SPF at all, never a placeholder",
                DnsRecordsGenerator.spfValue("", "", IpFamily.Family.BOTH) == null
                        && DnsRecordsGenerator.spfValue("YOUR_SERVER_IP", "", IpFamily.Family.IPV4) == null
                        && DnsRecordsGenerator.spfValue("8.8.8.8", "", IpFamily.Family.IPV6) == null);
        check("addresses compared as addresses, not as text",
                DnsRecordsGenerator.containsAddress("2a01:04f8:0c17:1234:0000:0000:0000:0001\n", "2a01:4f8:c17:1234::1")
                        && DnsRecordsGenerator.containsAddress("cname.example.\n8.8.8.8\n", "8.8.8.8")
                        && !DnsRecordsGenerator.containsAddress("18.8.8.8\n", "8.8.8.8") && !DnsRecordsGenerator.containsAddress("", "8.8.8.8"));

        System.out.println("\n== pf ==");
        System.out.println("  (PfPolicy is in another package: tests/org/daemoxcp/mail/security/PfPolicyTest checks the rules by family)");
        check("an IPv6 country list line counts as a CIDR", org.daemoxcp.mail.security.PfFirewallManager.countCidr(
                "2.32.0.0/12\n# IPv6\n2001:0678:0012:0000:0000:0000:0000:0000/48\nnot a line\n") == 2);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static TreeSet<Integer> set(Integer... p) { return new TreeSet<>(List.of(p)); }
}
