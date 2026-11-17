package org.daemoxcp.mail.security;

import java.util.List;

/**
 * Where the logs a jail watches are read from.
 *
 * fail2ban-client's two outputs have different shapes, and a reading that works on only one of
 * them is the defect this test exists to prevent: the card showed the log and the filter check
 * said there was none.
 */
public class LogPathTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== output of \"get <jail> logpath\" (tree characters) ==");
        List<String> r = Fail2banManager.pathsIn(
            "Current monitored log file(s):\n`- /usr/local/www/roundcube/logs/userlogins\n");
        require("finds the path after \"`-\"",
                r.equals(List.of("/usr/local/www/roundcube/logs/userlogins")));

        System.out.println("\n== several files, with \"|-\" and \"`-\" ==");
        r = Fail2banManager.pathsIn(
            "Current monitored log file(s):\n|- /var/log/maillog\n`- /var/log/auth.log\n");
        require("finds both, in order",
                r.equals(List.of("/var/log/maillog", "/var/log/auth.log")));

        System.out.println("\n== output of \"status <jail>\" ==");
        r = Fail2banManager.pathsIn(
            "Status for the jail: dovecot\n|- Filter\n|  |- Currently failed: 0\n"
          + "|  `- File list:    /var/log/maillog\n`- Actions\n   |- Currently banned: 0\n");
        require("finds the file after \"File list:\"", r.equals(List.of("/var/log/maillog")));

        System.out.println("\n== what is NOT a watched log ==");
        r = Fail2banManager.pathsIn("/usr/local/bin/fail2ban-client: command not found");
        require("the path of the command itself is discarded", r.isEmpty());
        r = Fail2banManager.pathsIn("Sorry but the jail 'x' does not exist");
        require("a message without paths does not invent any", r.isEmpty());
        require("null blows nothing up", Fail2banManager.pathsIn(null).isEmpty());

        System.out.println("\n== no duplicates ==");
        r = Fail2banManager.pathsIn("|- /var/log/maillog\n`- /var/log/maillog\n");
        require("the same file appears once only", r.size() == 1);

        System.out.println("\n== and the OLD reading on the same case ==");
        // As it was: a line had to START with "/", after removing only dashes, asterisks and
        // spaces. The tree character stayed, and the line did not pass.
        String line = "`- /usr/local/www/roundcube/logs/userlogins";
        boolean old = line.trim().replaceAll("^[-*\\s]+", "").startsWith("/");
        System.out.println("  did the line pass the old check? " + old);
        require("the old reading REJECTS a log that is there: the defect reproduces", !old);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
