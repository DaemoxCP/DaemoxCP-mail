package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;
import org.json.JSONArray;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

/**
 * Mailbox quotas applied by Dovecot 2.4 (DovecotQuota, DovecotConfig): the decisions without Dovecot, and, where doveconf
 * is (the test machine), the installer's whole 2.4 configuration with the quota pieces parsed by the real doveconf.
 *
 *  1. auth-sql.conf.ext: the quota userdb goes right before userdb static, once; a file the panel did not write (its
 *     own userdb sql, two userdb static, no passdb sql) is left alone.
 *  2. What the start does: nothing on 2.3, nothing when both files are in place, otherwise apply.
 *  3. Postfix: the question to quota-status right after reject_unauth_destination, once; rules without a single
 *     reject_unauth_destination are left alone.
 *  4. doveadm -f tab quota get -A: only the STORAGE lines, in KB, with the percentage; 0 for no limit.
 *  5. The installer: the quota file and the userdb before static; with doveconf, the whole configuration parses and the
 *     quota plugin is on for LMTP (with Sieve) and IMAP (with imap_quota).
 *
 *   java -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotQuotaTest
 */
public class DovecotQuotaTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String AUTH = "sql_driver = mysql\n\nmysql 127.0.0.1 {\n  user = u\n  password = p\n  dbname = d\n}\n\n"
            + "passdb sql {\n  default_password_scheme = BLF-CRYPT\n  query = SELECT email AS user, password FROM mailboxes WHERE email = '%{user}' AND active = 1\n}\n\n"
            + "userdb static {\n  fields {\n    uid = vmail\n    gid = vmail\n    home = /var/vmail/%{user | domain}/%{user | username}/home\n  }\n}\n";

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. auth-sql.conf.ext ==");
        String with = DovecotQuota.withQuotaUserdb(AUTH);
        check("the quota userdb right before userdb static", with != null
                && with.indexOf("userdb sql {") >= 0 && with.indexOf("userdb sql {") < with.indexOf("userdb static {")
                && with.contains(DovecotConfig.QUOTA_USERDB + "userdb static {"));
        check("the rest unchanged", with != null && with.replace(DovecotConfig.QUOTA_USERDB, "").equals(AUTH));
        check("applied again: the same text", with != null && with.equals(DovecotQuota.withQuotaUserdb(with)));
        check("its own userdb sql: left alone", DovecotQuota.withQuotaUserdb(AUTH.replace("userdb static {", "userdb sql {\n  query = x\n}\nuserdb static {")) == null);
        check("two userdb static, or none, or no passdb sql: left alone",
                DovecotQuota.withQuotaUserdb(AUTH + "userdb static {\n}\n") == null
                        && DovecotQuota.withQuotaUserdb(AUTH.replace("userdb static {", "userdb passwd {")) == null
                        && DovecotQuota.withQuotaUserdb(AUTH.replace("passdb sql {", "passdb pam {")) == null
                        && DovecotQuota.withQuotaUserdb(null) == null);
        String older = AUTH.replace("userdb static {", DovecotConfig.QUOTA_USERDB_MARK + ": an older text\nuserdb sql {\n  query = SELECT 1\n  result_success = continue-ok\n}\n\nuserdb static {");
        String updated = DovecotQuota.withQuotaUserdb(older);
        check("the block of an earlier version of the panel: replaced by this one", updated != null && updated.equals(with));
        check("a query that fails goes on to userdb static (the mail does not stop)",
                DovecotConfig.QUOTA_USERDB.contains("result_internalfail = continue") && DovecotConfig.QUOTA_USERDB.startsWith(DovecotConfig.QUOTA_USERDB_MARK));
        check("the limit is quota_mb in MB, only for an active mailbox",
                DovecotConfig.QUOTA_USERDB.contains("query = SELECT CONCAT(quota_mb, 'M') AS quota_storage_size, ")
                        && DovecotConfig.QUOTA_USERDB.contains(" FROM mailboxes WHERE email = '%{user}' AND active = 1\n")
                        && DovecotConfig.QUOTA_USERDB.contains("result_success = continue-ok") && DovecotConfig.QUOTA_USERDB.contains("result_failure = continue"));

        System.out.println("\n== 2. What the start does ==");
        check("2.3: nothing", DovecotQuota.decide("2.3.21 (47349e2482)", AUTH, null).action() == DovecotQuota.Action.NOT_24);
        check("2.4 without quotas: apply", DovecotQuota.decide("2.4.5 (0cbb641e3e)", AUTH, null).action() == DovecotQuota.Action.APPLY);
        check("2.4 with the userdb but not the file: apply", DovecotQuota.decide("2.4.5", with, null).action() == DovecotQuota.Action.APPLY);
        check("2.4 with both: nothing", DovecotQuota.decide("2.4.5", with, DovecotConfig.QUOTA_FILE).action() == DovecotQuota.Action.NOTHING);
        check("2.4 with a file that says something else: apply", DovecotQuota.decide("2.4.5", with, "# old\n").action() == DovecotQuota.Action.APPLY);
        check("a configuration the panel did not write: left alone", DovecotQuota.decide("2.4.5", "userdb static {\n}\n", null).action() == DovecotQuota.Action.LEFT_ALONE);

        System.out.println("\n== 3. Postfix ==");
        String rules = "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_non_fqdn_recipient";
        String after = DovecotQuota.withPolicy(rules);
        check("right after reject_unauth_destination (" + after + ")", ("permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, "
                + DovecotQuota.POLICY + ", reject_non_fqdn_recipient").equals(after));
        check("applied again: the same", after != null && after.equals(DovecotQuota.withPolicy(after)));
        check("Dovecot down: the mail passes (default_action=DUNNO)", DovecotQuota.POLICY.contains("default_action=DUNNO"));
        check("no reject_unauth_destination, or two: left alone", DovecotQuota.withPolicy("permit_mynetworks, reject") == null
                && DovecotQuota.withPolicy("reject_unauth_destination, reject_unauth_destination") == null && DovecotQuota.withPolicy(null) == null);
        check("a longer name is not reject_unauth_destination", DovecotQuota.withPolicy("defer_reject_unauth_destination_x") == null);

        System.out.println("\n== 4. doveadm quota get ==");
        JSONArray u = DovecotQuota.parseUsage("Username\tQuota name\tType\tValue\tLimit\t%\n"
                + "a@example.test\tUser quota\tSTORAGE\t512\t1024\t50\n"
                + "a@example.test\tUser quota\tMESSAGE\t3\t-\t0\n"
                + "b@example.test\tUser quota\tSTORAGE\t2048\t-\t0\n"
                + "c@example.test\tUser quota\tSTORAGE\t3000\t1024\t292\n");
        check("only STORAGE, three mailboxes (" + u + ")", u.length() == 3);
        check("used and limit in KB, and the percentage", u.length() == 3 && u.getJSONObject(0).getLong("used_kb") == 512
                && u.getJSONObject(0).getLong("limit_kb") == 1024 && u.getJSONObject(0).getInt("percent") == 50);
        check("no limit: 0, and 0 %", u.length() == 3 && u.getJSONObject(1).getLong("limit_kb") == 0 && u.getJSONObject(1).getInt("percent") == 0);
        check("over the limit: 100 %, not more", u.length() == 3 && u.getJSONObject(2).getInt("percent") == 100);
        check("empty or unknown columns: nothing", DovecotQuota.parseUsage("").length() == 0 && DovecotQuota.parseUsage("a\tb\n1\t2").length() == 0);

        System.out.println("\n== 5. The installer ==");
        DovecotConfig.FileConf auth = null, quota = null;
        for (DovecotConfig.FileConf f : DovecotConfig.file24()) {
            if (f.path().equals("conf.d/auth-sql.conf.ext")) auth = f;
            if (f.path().equals("conf.d/" + DovecotConfig.QUOTA_FILE_NAME)) quota = f;
        }
        check("the quota file is written", quota != null && quota.content().equals(DovecotConfig.QUOTA_FILE));
        check("and the userdb before userdb static", auth != null && auth.content().contains(DovecotConfig.QUOTA_USERDB + "userdb static {"));
        check("the start would have nothing to do on it", auth != null && DovecotQuota.decide("2.4.5", auth.content(), DovecotConfig.QUOTA_FILE).action() == DovecotQuota.Action.NOTHING);

        Path doveconf = Path.of("/usr/local/bin/doveconf");
        if (!Files.isExecutable(doveconf)) {
            System.out.println("  SKIPPED the doveconf part: no doveconf here (the test machine has it)");
        } else {
            Path dir = Files.createTempDirectory("dovecot-quota-test");
            try {
                for (DovecotConfig.FileConf f : DovecotConfig.file24()) {
                    String c = f.content().replace("${SIEVE_PROTO}", " sieve").replace("${DB_USER}", "u").replace("${DB_PASS}", "p")
                            .replace("${DB_NAME}", "d").replace("!include conf.d/*.conf", "!include " + dir + "/conf.d/*.conf")
                            .replace("!include auth-", "!include " + dir + "/conf.d/auth-");
                    Path p = dir.resolve(f.path());
                    Files.createDirectories(p.getParent());
                    Files.writeString(p, c);
                }
                Files.writeString(dir.resolve("conf.d/master-users"), "");
                String n = run(doveconf.toString(), "-c", dir.resolve("dovecot.conf").toString(), "-n");
                check("doveconf accepts the whole configuration (" + n.lines().filter(l -> l.startsWith("doveconf: Fatal")).findFirst().orElse("ok") + ")",
                        !n.contains("Fatal") && n.contains("quota \"User quota\""));
                // doveconf -f prints a protocol's own entries only; they are added to the global list (the Dovecot docs'
                // own example puts imap_quota, which needs quota, under protocol imap). That LMTP really applies the quota
                // is proved with real mail in quota-browser-test.js.
                String global = run(doveconf.toString(), "-c", dir.resolve("dovecot.conf").toString(), "mail_plugins");
                String lmtp = run(doveconf.toString(), "-c", dir.resolve("dovecot.conf").toString(), "-f", "protocol=lmtp", "mail_plugins");
                String imap = run(doveconf.toString(), "-c", dir.resolve("dovecot.conf").toString(), "-f", "protocol=imap", "mail_plugins");
                check("global: quota (" + global.replaceAll("\\s+", " ").trim() + ")", global.matches("(?s).*\\bquota = yes.*") && !global.contains("imap_quota"));
                check("LMTP adds sieve (" + lmtp.replaceAll("\\s+", " ").trim() + ")", lmtp.contains("sieve = yes"));
                check("IMAP adds imap_quota (" + imap.replaceAll("\\s+", " ").trim() + ")", imap.contains("imap_quota = yes"));
            } finally {
                run("rm", "-rf", dir.toString());
            }
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static String run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        p.waitFor(30, TimeUnit.SECONDS);
        return out;
    }
}
