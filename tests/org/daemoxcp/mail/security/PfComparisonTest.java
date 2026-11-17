package org.daemoxcp.mail.security;

/**
 * The two reads the comparison between Fail2ban's bans and the pf tables stands on.
 *
 * They are checked here because they go wrong silently. An expression that does not find the
 * table makes nothing fail: it makes the panel say "this jail does not use pf", the comparison
 * disappears from the page, and its absence reads as "all is well". A missing normalization does
 * the opposite: every address is in only one of the two sets and the check shouts at every ban.
 */
public class PfComparisonTest {

    private static int failed = 0;

    public static void main(String[] args) {
        // --- fail2ban's real ban command on FreeBSD (action.d/pf.conf) ---
        String real = "pfctl -a f2b/daemoxcp-mail-public -t f2b-daemoxcp-mail-public -T add <ip>";
        Fail2banManager.PfTarget b = Fail2banManager.targetFromCommand(real);
        real("real command: recognised", b != null);
        same("real command: table", "f2b-daemoxcp-mail-public", b == null ? null : b.table);
        same("real command: anchor", "f2b/daemoxcp-mail-public", b == null ? null : b.anchor);

        // On several lines, as fail2ban-client returns it when the action has more than one.
        Fail2banManager.PfTarget m = Fail2banManager.targetFromCommand(
            "pfctl -a f2b/dovecot -t f2b-dovecot -T add <ip>\npfctl -a f2b/dovecot -T show");
        same("several lines: table", "f2b-dovecot", m == null ? null : m.table);

        // Without an anchor: a global table. It must work all the same, with a null anchor.
        Fail2banManager.PfTarget g = Fail2banManager.targetFromCommand("pfctl -t permaban -T add <ip>");
        real("no anchor: recognised", g != null);
        same("no anchor: table", "permaban", g == null ? null : g.table);
        real("no anchor: no certain anchor", g != null && g.anchor == null);

        // --- The real case, and the one that had escaped me ---
        // fail2ban returns the command with the placeholders NOT expanded, and the action file
        // defines "pfctl = pfctl -a f2b/<name>": the anchor is inside <pfctl>, invisible here.
        // Looking for it in the text never finds it, and reading the table in the main ruleset
        // would have said "does not exist" for every healthy jail. It must be derived from the table.
        Fail2banManager.PfTarget v = Fail2banManager.targetFromCommand("<pfctl> -t f2b-dovecot -T add <ip>");
        real("placeholder <pfctl>: recognised as pf", v != null);
        same("placeholder: table", "f2b-dovecot", v == null ? null : v.table);
        real("placeholder: no certain anchor in the text", v != null && v.anchor == null);
        same("placeholder: anchor derived from the definitions", "f2b/dovecot",
            v == null ? null : v.stillLikely);
        // The name can contain dashes: it is split at the FIRST one, which separates the f2b prefix.
        same("name with dashes", "f2b/daemoxcp-mail-public",
            Fail2banManager.targetFromCommand("<pfctl> -t f2b-daemoxcp-mail-public -T add <ip>").stillLikely);
        // A table without a dash lets nothing be derived, and nothing is made up.
        real("nothing to derive", Fail2banManager.targetFromCommand("pfctl -t permaban -T add <ip>").stillLikely == null);

        // Whoever does not ban through pf must not produce an invented target.
        real("ipfw is not pf", Fail2banManager.targetFromCommand("ipfw table 1 add <ip>") == null);
        real("log only is not pf", Fail2banManager.targetFromCommand("echo <ip> >> /var/log/x") == null);
        real("pfctl without a table", Fail2banManager.targetFromCommand("pfctl -a f2b/x -f /etc/x") == null);
        real("no command", Fail2banManager.targetFromCommand(null) == null);

        // --- Normalization: the two sources write the same address in different ways ---
        // pfctl adds the mask, fail2ban does not. What matters is that they match AFTERWARDS.
        same("pf: /32 removed", "213.209.159.175", Fail2banManager.normalizeAddress("   213.209.159.175/32"));
        same("fail2ban: bare", "213.209.159.175", Fail2banManager.normalizeAddress("213.209.159.175"));
        real("the two sources match",
            Fail2banManager.normalizeAddress("   213.209.159.175/32")
                .equals(Fail2banManager.normalizeAddress("213.209.159.175")));
        same("v6: /128 removed", "2001:db8::1", Fail2banManager.normalizeAddress("2001:db8::1/128"));
        // pfctl adds the counters after the address when it runs with -v.
        same("counters ignored", "10.0.0.1", Fail2banManager.normalizeAddress("10.0.0.1   Cleared: Tue Sep  2"));
        // A real mask must NOT be removed: /24 is not a single address.
        same("/24 kept", "10.0.0.0/24", Fail2banManager.normalizeAddress("10.0.0.0/24"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    private static void same(String name, String expected, String got) {
        boolean ok = expected == null ? got == null : expected.equals(got);
        System.out.println((ok ? "  ok   " : "  NO   ") + name
            + (ok ? "" : "  expected [" + expected + "] got [" + got + "]"));
        if (!ok) failed++;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
