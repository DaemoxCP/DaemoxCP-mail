package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.scripts.PostfixScript;

import java.util.regex.Pattern;

/**
 * inet_protocols written in main.cf (reperto 207). The install script of every postfix update writes
 * "inet_protocols = ipv4" when main.cf does not say it, and at the restart postfix stops listening on IPv6
 * (reperto 42): in the rehearsal of "Update everything" on the VM the chain stopped at postfix-mysql for this.
 *  - at boot: written with the value in use, only when main.cf does not say it; a value already written stays,
 *    and a value in use that is not one of Postfix's is left alone;
 *  - the three install scripts write it.
 *
 * Usage (from the project root, after mvn package):
 *   javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/daemoxcp/mail/system/PostfixInetProtocolsTest.java
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PostfixInetProtocolsTest
 */
public class PostfixInetProtocolsTest {

    private static int failed = 0;

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    private static PostfixInetProtocols.Decision d(boolean installed, String explicit, String effective) {
        return PostfixInetProtocols.decide(installed, explicit, effective);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== At boot ==");
        PostfixInetProtocols.Decision vm = d(true, "", "all");
        check("not in main.cf, in use 'all' (the VM): written as 'all'",
                vm.action() == PostfixInetProtocols.Action.WRITE && vm.value().equals("all"));
        check("not in main.cf, in use 'ipv4, ipv6': written as it is",
                d(true, "", "ipv4,  ipv6").value().equals("ipv4, ipv6") && d(true, "", "ipv4, ipv6").action() == PostfixInetProtocols.Action.WRITE);
        check("already 'ipv4' in main.cf (the real server): nothing, the choice stays",
                d(true, "ipv4", "ipv4").action() == PostfixInetProtocols.Action.NOTHING);
        check("already 'all' in main.cf: nothing (the second boot)", d(true, "all", "all").action() == PostfixInetProtocols.Action.NOTHING);
        check("Postfix not installed: nothing", d(false, "", "").action() == PostfixInetProtocols.Action.NOTHING);
        check("in use a value that is not Postfix's, or none: left alone, nothing written",
                d(true, "", "all; rm -rf /").action() == PostfixInetProtocols.Action.LEFT_ALONE
                && d(true, "", "").action() == PostfixInetProtocols.Action.LEFT_ALONE
                && d(true, null, null).action() == PostfixInetProtocols.Action.LEFT_ALONE
                && d(true, "", "ipv4\ninet_interfaces = 0.0.0.0").action() == PostfixInetProtocols.Action.LEFT_ALONE);

        System.out.println("\n== The install scripts ==");
        Pattern line = Pattern.compile("(?m)^inet_protocols = all$");
        check("the full install writes inet_protocols = all (it did not)", line.matcher(new FullMailServerScript().getScriptContent()).find());
        check("the stack install writes it", line.matcher(new FullMailStackScript().getScriptContent()).find());
        check("the Postfix script writes it", line.matcher(new PostfixScript().getScriptContent()).find());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
