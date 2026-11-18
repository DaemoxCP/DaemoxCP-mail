package org.daemoxcp.mail.system;

import java.io.PrintStream;

/**
 * What the panel does, at start, on a server installed before the installer made Postfix the
 * local MTA (LocalMtaRepair.decide). The decision is kept apart from the system on purpose: here
 * the configurations that the three scripts of `main` really left are checked, plus the edge
 * cases. The real effect on a machine is measured by the run on the VM (reperti).
 *
 * The case that matters is the first: the full installation of main left myorigin = $mydomain
 * (the server's name) and mydestination = localhost. Enabling mailer.conf as it is bounces the
 * system mail (point 67): first myorigin = localhost.
 *
 * Runs anywhere (it calls nothing):
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.LocalMtaRepairTest
 */
public class LocalMtaRepairTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String DMA = "sendmail\t/usr/libexec/dma\nmailq\t\t/usr/libexec/dma\nnewaliases\t/usr/libexec/dma\n";
    static final String POSTFIX = "sendmail\t/usr/local/sbin/sendmail\nsend-mail\t/usr/local/sbin/sendmail\n"
            + "mailq\t\t/usr/local/sbin/sendmail\nnewaliases\t/usr/local/sbin/sendmail\n";

    static LocalMtaRepair.Action act(boolean installed, String mailer, String origin, String dest, String transport) {
        LocalMtaRepair.Decision d = LocalMtaRepair.decide(installed, mailer, origin, dest, transport);
        OUT.println("        -> " + d.action() + ": " + d.reason());
        return d.action();
    }

    public static void main(String[] args) {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");   // the panel's reasons, printed below, in English
        OUT.println("\n== The servers main left behind ==");
        check("full installation (myorigin = server name, mydestination = localhost): "
                + "FIRST myorigin = localhost, then mailer.conf",
                act(true, null, "mail.test.local", "localhost", "local:mail.test.local")
                        == LocalMtaRepair.Action.SET_MYORIGIN_THEN_ACTIVATE);
        check("«postfix» component after the real name (default mydestination, the name is local): "
                + "mailer.conf only",
                act(true, null, "mail.test.local", "mail.test.local, localhost.mail.test.local, localhost",
                        "local:mail.test.local") == LocalMtaRepair.Action.ACTIVATE);
        check("«all» button (local delivery off): NOT enabled, the system mail would bounce",
                act(true, null, "localhost", "", "error:no local mail delivery")
                        == LocalMtaRepair.Action.REFUSE);
        // The rule on an empty mydestination would refuse the previous case too: not this one.
        // Without it, the check on local_transport was never put to the test (a jar without that
        // check passed the whole test, measured on 29/10/2026).
        check("local delivery off even with localhost in mydestination: NOT enabled",
                act(true, null, "localhost", "localhost", "error:no local mail delivery")
                        == LocalMtaRepair.Action.REFUSE);

        OUT.println("\n== Already fine, or nothing to do ==");
        check("mailer.conf already for Postfix: nothing",
                act(true, POSTFIX, "mail.test.local", "localhost", "local:x") == LocalMtaRepair.Action.NOTHING);
        check("Postfix not installed: nothing, even with mailer.conf missing",
                act(false, null, "", "", "") == LocalMtaRepair.Action.NOTHING);
        check("installed by this branch (myorigin = localhost): mailer.conf already right, nothing",
                act(true, POSTFIX, "localhost", "localhost", "local:mail.test.local") == LocalMtaRepair.Action.NOTHING);

        OUT.println("\n== Edge cases ==");
        check("a mailer.conf handing over to dma counts as to repair",
                act(true, DMA, "localhost", "localhost", "local:x") == LocalMtaRepair.Action.ACTIVATE);
        check("a commented line does not count: '#sendmail /usr/local/sbin/sendmail'",
                act(true, "#sendmail\t/usr/local/sbin/sendmail\n" + DMA, "localhost", "localhost", "local:x")
                        == LocalMtaRepair.Action.ACTIVATE);
        check("mydestination without localhost and a non-local myorigin: NOT enabled",
                act(true, null, "mail.test.local", "example.org", "local:x") == LocalMtaRepair.Action.REFUSE);
        check("capitals and commas: Mail.Test.Local is in 'localhost,mail.test.local'",
                act(true, null, "Mail.Test.Local", "localhost,mail.test.local", "local:x")
                        == LocalMtaRepair.Action.ACTIVATE);
        check("empty mydestination with delivery on: NOT enabled",
                act(true, null, "mail.test.local", "", "local:x") == LocalMtaRepair.Action.REFUSE);
        check("empty local_transport (postconf did not answer) is not 'off': the rest decides",
                act(true, null, "localhost", "localhost", "") == LocalMtaRepair.Action.ACTIVATE);

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
