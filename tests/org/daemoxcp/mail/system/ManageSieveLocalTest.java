package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;

import java.util.List;

/**
 * ManageSieve (4190) only on 127.0.0.1, where the webmail uses it (ManageSieveLocal). Found on 20/11/2026 installing
 * from the README on a clean VM: Dovecot listened on *:4190 even after the panel's first start; pf stopped it from
 * outside, but the README says «local only».
 *  1. the file: the listener «sieve» of managesieve-login gets 127.0.0.1, as address in Dovecot 2.3 and as listen in
 *     2.4 (2.4 refuses address), the port stays in the main file, signed by the panel;
 *  2. the version: 2.4 and later from `dovecot --version`, 2.3 otherwise or when it cannot be read;
 *  3. reading sockstat: the addresses Dovecot listens on for 4190, and «only local» only when every one is 127.0.0.1;
 *  4. the installer writes the same file: in the 2.4 file list and in the 2.3 shell fragment.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ManageSieveLocalTest
 */
public class ManageSieveLocalTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The file");
        String f24 = ManageSieveLocal.fileContent(true), f23 = ManageSieveLocal.fileContent(false);
        check("2.4: listen = 127.0.0.1 in the listener sieve of managesieve-login",
                f24.contains("service managesieve-login {\n  inet_listener sieve {\n    listen = 127.0.0.1\n  }\n}\n"));
        check("2.3: address = 127.0.0.1 in the same place",
                f23.contains("service managesieve-login {\n  inet_listener sieve {\n    address = 127.0.0.1\n  }\n}\n"));
        check("2.4 has no address, 2.3 has no listen", !f24.contains("address =") && !f23.contains("listen ="));
        check("the port is not repeated (it stays in the main file)", !f24.contains("port") && !f23.contains("port"));
        check("signed by the panel", f24.startsWith("# " + PanelMarker.WRITTEN) && f23.startsWith("# " + PanelMarker.WRITTEN));

        System.out.println("\n== 2. The version");
        check("2.4.5 (0cbb641e3e) is 2.4", ManageSieveLocal.is24("2.4.5 (0cbb641e3e)"));
        check("3.0.1 is 2.4 or later", ManageSieveLocal.is24("3.0.1"));
        check("2.3.21.1 (d492236fa0) is not", !ManageSieveLocal.is24("2.3.21.1 (d492236fa0)"));
        check("empty, null or unreadable: not 2.4", !ManageSieveLocal.is24("") && !ManageSieveLocal.is24(null) && !ManageSieveLocal.is24("dovecot"));

        System.out.println("\n== 3. Reading sockstat");
        String before = "USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n"
                + "root     dovecot    7636  21  tcp4   *:4190                *:*\n"
                + "root     dovecot    7636  22  tcp6   *:4190                *:*\n"
                + "root     dovecot    7636  23  tcp4   *:993                 *:*\n"
                + "root     nginx      9696  6   tcp4   *:41900               *:*\n";
        String after = "root     dovecot    7636  21  tcp4   127.0.0.1:4190        *:*\n"
                + "root     dovecot    7636  23  tcp4   *:993                 *:*\n";
        List<String> b = ManageSieveLocal.listening(before), a = ManageSieveLocal.listening(after);
        check("before: Dovecot on *:4190 twice (IPv4 and IPv6), nothing else (" + b + ")", b.equals(List.of("*:4190", "*:4190")));
        check("  not only local", !ManageSieveLocal.onlyLocal(b));
        check("after: only 127.0.0.1:4190 (" + a + ")", a.equals(List.of("127.0.0.1:4190")) && ManageSieveLocal.onlyLocal(a));
        check("nobody on 4190 is not «only local»: the check must see the port", !ManageSieveLocal.onlyLocal(List.of()));
        check("127.0.0.1 plus another address is not only local",
                !ManageSieveLocal.onlyLocal(List.of("127.0.0.1:4190", "192.168.1.20:4190")));

        System.out.println("\n== 4. The installer writes the same file");
        check("Dovecot 2.4: in the file list (conf.d/" + ManageSieveLocal.FILE_NAME + ")", DovecotConfig.file24().stream().anyMatch(x ->
                x.path().equals("conf.d/" + ManageSieveLocal.FILE_NAME) && x.content().equals(f24)));
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("Dovecot 2.3: the shell fragment writes it with address",
                fragment.contains("cat > \"$DOVECOT_ETC/conf.d/" + ManageSieveLocal.FILE_NAME + "\" <<'DOVECOT_MANAGESIEVE_LOCAL'")
                && fragment.contains("    address = 127.0.0.1"));
        check("  no placeholder left in the fragment", !fragment.contains("__MANAGESIEVE_LOCAL"));
        check("the webmail reaches ManageSieve on the same address",
                new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of(
                        "src/main/java/org/daemoxcp/mail/scripts/RoundcubeScript.java"))).contains("$config['managesieve_host'] = '"
                        + ManageSieveLocal.ADDRESS + "';"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
