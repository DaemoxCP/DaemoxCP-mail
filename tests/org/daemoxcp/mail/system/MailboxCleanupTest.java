package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.database.SqlCatalog;
import org.daemoxcp.mail.integration.WebmailCleanupPlugin;
import org.daemoxcp.mail.integration.WebmailPasswordConfig;
import org.daemoxcp.mail.util.Shell;

/**
 * Automatic emptying of Junk and Trash, per mailbox, off until asked (20/11/2026: «deve essere una cosa sia del pannello
 * che di roundcube»), and the emergency emptying from the console («per le emergenze»).
 *  1. the days: never (the default), 7, 14, 30, 60, 90; the same list for the panel and the webmail;
 *  2. MySQL: the two columns (new installs and the migration), the update from the panel's window and its web-part
 *     procedure in the same order, the procedures that read mailboxes, the routines' and Dovecot's grants;
 *  3. Dovecot: the userdb query returns namespace/inbox/mailbox/{Junk,Trash}/mailbox_autoexpunge only above 0 (NULL
 *     otherwise, so Dovecot gets nothing), the same as MailDbUsers runs as Dovecot's user;
 *  4. the panel's window (two selects with the same days, labels, help) and what it sends;
 *  5. the webmail: the panel's block (address, key, the plugin on once), the plugin (the same days, the mailbox before
 *     the star of a single sign-on, the panel's answer read strictly), its texts in two languages, the route in every
 *     list it must be in;
 *  6. the emergency emptying: the words, Dovecot's count, the plan (only folders with messages), the run;
 *  7. with -De2e.vm=yes, as root on the VM: the columns, the route as Roundcube calls it (set, get, Dovecot's userdb,
 *     refusals, back to never), the plugin's PHP read by PHP, the console refusing without a terminal, and the
 *     emergency emptying of a test mailbox's Junk with Dovecot (two test messages saved, counted, expunged).
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MailboxCleanupTest
 */
public class MailboxCleanupTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The days");
        check("never, 7, 14, 30, 60, 90", MailDatabase.CLEANUP_DAYS.equals(List.of(0, 7, 14, 30, 60, 90)));
        check("never is allowed, 5 and -1 are not", MailDatabase.cleanupDaysAllowed(0) && !MailDatabase.cleanupDaysAllowed(5)
                && !MailDatabase.cleanupDaysAllowed(-1) && !MailDatabase.cleanupDaysAllowed(365));

        System.out.println("\n== 2. MySQL");
        check("new installs: the two columns, never by default", SqlCatalog.MAIL_CREATE_SCHEMA_7.contains("    junk_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n")
                && SqlCatalog.MAIL_CREATE_SCHEMA_7.contains("    trash_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n"));
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("  and the installer's table (receive_enabled too, which Postfix's map asks for)", installer.contains("    receive_enabled BOOLEAN DEFAULT TRUE,\n"
                + "    junk_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n    trash_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n"));
        check("the migration adds them, never by default", SqlCatalog.MAIL_ADD_MAILBOXES_JUNK_EXPUNGE_DAYS.endsWith("ADD COLUMN junk_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0")
                && SqlCatalog.MAIL_ADD_MAILBOXES_TRASH_EXPUNGE_DAYS.endsWith("ADD COLUMN trash_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0"));
        check("the panel's update: the days before the id", SqlCatalog.MAIL_UPDATE_MAILBOX.equals("UPDATE mailboxes SET name = ?, quota_mb = ?, active = ?,"
                + " receive_enabled = ?, junk_expunge_days = ?, trash_expunge_days = ? WHERE id = ?"));
        check("  its procedure takes them in the same order", SqlCatalog.WEB_CALL_UPDATE_MAILBOX.equals("CALL update_mailbox(?, ?, ?, ?, ?, ?, ?, ?)")
                && SqlCatalog.WEB_CREATE_UPDATE_MAILBOX.contains("IN p_receive_enabled BOOLEAN, IN p_junk_expunge_days SMALLINT UNSIGNED, IN p_trash_expunge_days SMALLINT UNSIGNED, IN p_id INT)")
                && SqlCatalog.WEB_CREATE_UPDATE_MAILBOX.contains("junk_expunge_days = p_junk_expunge_days, trash_expunge_days = p_trash_expunge_days WHERE id = p_id"));
        for (String[] p : new String[][]{{"list_domain_mailboxes", SqlCatalog.WEB_CREATE_LIST_DOMAIN_MAILBOXES}, {"list_mailboxes", SqlCatalog.WEB_CREATE_LIST_MAILBOXES},
                {"get_mailbox", SqlCatalog.WEB_CREATE_GET_MAILBOX}, {"get_mailbox_by_email", SqlCatalog.WEB_CREATE_GET_MAILBOX_BY_EMAIL}})
            check("  " + p[0] + " reads them", p[1].contains("m.junk_expunge_days, m.trash_expunge_days"));
        check("the routines may write them", SqlCatalog.WEB_DB_GRANT_ROUTINES_MAILBOXES.contains("UPDATE (name, quota_mb, active, receive_enabled, junk_expunge_days, trash_expunge_days,"));
        check("the webmail's update: only an active mailbox, by address", SqlCatalog.MAIL_UPDATE_MAILBOX_CLEANUP.equals(
                "UPDATE mailboxes SET junk_expunge_days = ?, trash_expunge_days = ? WHERE email = ? AND active = 1"));
        check("Dovecot's user reads them", SqlCatalog.MAILDB_GRANT_DOVECOT_MAILBOXES.contains("SELECT (email, password, active, quota_mb, junk_expunge_days, trash_expunge_days)")
                && MailDbUsers.DOVECOT.grants().stream().anyMatch(g -> g.columns().containsAll(List.of("junk_expunge_days", "trash_expunge_days"))));

        System.out.println("\n== 3. Dovecot");
        String userdb = org.daemoxcp.mail.scripts.DovecotConfig.QUOTA_USERDB;
        String junk = "IF(junk_expunge_days > 0, CONCAT(junk_expunge_days, 'd'), NULL) AS 'namespace/inbox/mailbox/Junk/mailbox_autoexpunge'";
        String trash = "IF(trash_expunge_days > 0, CONCAT(trash_expunge_days, 'd'), NULL) AS 'namespace/inbox/mailbox/Trash/mailbox_autoexpunge'";
        check("the userdb query: the quota, then Junk and Trash in days, NULL for never", userdb.contains("query = SELECT CONCAT(quota_mb, 'M') AS quota_storage_size, "
                + junk + ", " + trash + " FROM mailboxes WHERE email = '%{user}' AND active = 1\n"));
        check("  its first line unchanged, so DovecotQuota replaces the block of before", userdb.startsWith(org.daemoxcp.mail.scripts.DovecotConfig.QUOTA_USERDB_MARK));
        check("MailDbUsers runs the same query as Dovecot's user", SqlCatalog.MAILDB_DOVECOT_QUOTA_LOOKUP.replace("email = ?", "email = '%{user}'")
                .equals(userdb.lines().filter(l -> l.trim().startsWith("query = ")).findFirst().orElse("").trim().substring(8)));

        System.out.println("\n== 4. The panel's window");
        String page = org.daemoxcp.mail.content.PanelContent.getMailboxesHtml();
        for (String id : new String[]{"editMbJunkDays", "editMbTrashDays"}) {
            int at = page.indexOf("<select class=\"form-select\" id=\"" + id + "\">");
            String select = at < 0 ? "" : page.substring(at, page.indexOf("</select>", at));
            List<Integer> values = new ArrayList<>();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("<option value=\"(\\d+)\">").matcher(select);
            while (m.find()) values.add(Integer.parseInt(m.group(1)));
            check(id + ": a label and the panel's days", page.contains("<label class=\"form-label small\" for=\"" + id + "\">") && values.equals(MailDatabase.CLEANUP_DAYS));
        }
        check("the help tied to the group", page.contains("<fieldset class=\"mb-3\" aria-describedby=\"editMbCleanupHelp\">") && page.contains("id=\"editMbCleanupHelp\">{{t:mbx.cleanupHelp}}"));
        check("opened: the mailbox's days; saved: sent as numbers", page.contains("document.getElementById('editMbJunkDays').value = String(m.junk_expunge_days || 0);")
                && page.contains("junk_expunge_days: parseInt(document.getElementById('editMbJunkDays').value, 10),")
                && page.contains("trash_expunge_days: parseInt(document.getElementById('editMbTrashDays').value, 10),"));
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        check("the API refuses other days, and keeps them when a client of before does not send them",
                server.contains("if (!MailDatabase.cleanupDaysAllowed(junkDays) || !MailDatabase.cleanupDaysAllowed(trashDays)) {")
                && server.contains("req.has(\"junk_expunge_days\") ? req.optInt(\"junk_expunge_days\", -1) : current != null ? current.junkExpungeDays : 0"));
        check("  a change goes to the audit log, before and after", server.contains("logAudit(\"MAILBOX_CLEANUP_CHANGED\", getClientIp(exchange), \"mailbox_id=\" + id"));

        System.out.println("\n== 5. The webmail");
        String block = WebmailPasswordConfig.apply("<?php\n$config['plugins'] = ['archive'];\n", 2096, "TestKey_0123456789-abcdefgh");
        check("the block: the route's address on 127.0.0.1 and the key", block.contains("$config['daemoxcp_mail_cleanup_url'] = 'https://127.0.0.1:2096/api/internal/mailbox-cleanup';\n")
                && block.contains("$config['daemoxcp_mail_cleanup_key'] = 'TestKey_0123456789-abcdefgh';\n"));
        String again = WebmailPasswordConfig.apply(block, 2096, "TestKey_0123456789-abcdefgh");
        check("  the plugin on once, also when written again", again.split(java.util.regex.Pattern.quote("$config['plugins'][] = 'daemoxcp_mail_cleanup';"), -1).length == 2);
        String php = WebmailCleanupPlugin.php();
        check("the plugin: the panel's days", php.contains("private const DAYS = [0, 7, 14, 30, 60, 90];"));
        check("  the mailbox before the star of a single sign-on", php.contains("$user = strtolower(explode('*', (string) $rcmail->get_user_name(), 2)[0]);"));
        check("  the panel's answer read strictly", php.contains("preg_match('/^junk=([0-9]{1,3}) trash=([0-9]{1,3})$/'"));
        check("  digits only, and the days checked again before calling", php.contains("ctype_digit($junk) && ctype_digit($trash)")
                && php.contains("in_array((int) $junk, self::DAYS, true) && in_array((int) $trash, self::DAYS, true)"));
        check("  settings only, a section of its own", php.contains("public $task = 'settings';") && php.contains("'preferences_sections_list'"));
        Map<String, String> loc = WebmailCleanupPlugin.localization();
        check("its texts in English and Italian, the same labels", loc.keySet().equals(java.util.Set.of("en_US", "it_IT"))
                && labels(loc.get("en_US")).equals(labels(loc.get("it_IT"))) && labels(loc.get("en_US")).size() == 9);
        String channel = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/RootChannel.java"));
        String gate = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/RootGate.java"));
        check("the route: CSRF and Host exempt, served by the root, before sign-in, in the root's gate",
                server.split(java.util.regex.Pattern.quote("WebmailPasswordConfig.VAULT_PATH, org.daemoxcp.mail.integration.WebmailPasswordConfig.CLEANUP_PATH);"), -1).length == 4
                && channel.contains("WebmailPasswordConfig.CLEANUP_PATH);") && gate.contains("WebmailPasswordConfig.CLEANUP_PATH, POST)"));
        check("the form's days: digits only", org.daemoxcp.mail.webserver.WebmailCleanupProbe.days("30") == 30
                && org.daemoxcp.mail.webserver.WebmailCleanupProbe.days("3x") == -1 && org.daemoxcp.mail.webserver.WebmailCleanupProbe.days("1234") == -1
                && org.daemoxcp.mail.webserver.WebmailCleanupProbe.days(null) == -1);

        System.out.println("\n== 6. The emergency emptying");
        check("the words", EmergencyEmpty.folders("junk").equals(List.of("Junk")) && EmergencyEmpty.folders("trash").equals(List.of("Trash"))
                && EmergencyEmpty.folders("both").equals(List.of("Junk", "Trash")) && EmergencyEmpty.folders("all") == null && EmergencyEmpty.folders(null) == null);
        check("Dovecot's count", EmergencyEmpty.messages("messages=12\n") == 12 && EmergencyEmpty.messages("x messages=3") == 3 && EmergencyEmpty.messages("") == -1);
        Map<String, Map<String, Integer>> plan = EmergencyEmpty.plan(List.of("a@x.test", "b@x.test"), List.of("Junk", "Trash"),
                (mb, f) -> mb.startsWith("a") && f.equals("Junk") ? 3 : 0);
        check("the plan: only folders with messages", plan.equals(Map.of("a@x.test", Map.of("Junk", 3))) && EmergencyEmpty.total(plan) == 3);
        List<String> done = new ArrayList<>();
        EmergencyEmpty.Result r = EmergencyEmpty.run(Map.of("a@x.test", Map.of("Junk", 3), "b@x.test", Map.of("Trash", 1)),
                (mb, f) -> { done.add(mb + " " + f); return !mb.startsWith("b"); });
        check("the run: each folder once, a failure said", done.size() == 2 && r.emptied() == 1 && r.failed().equals(List.of("b@x.test Trash")));
        String main = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/Main.java"));
        check("the console: root, a terminal, the count typed back, the audit log", main.contains("if (!\"root\".equals(System.getProperty(\"user.name\"))) {\n            System.err.println(org.daemoxcp.mail.i18n.I18n.tr(\"console.empty.asRoot\"));")
                && main.contains("if (terminal == null || !terminal.isTerminal()) {") && main.contains("answer.trim().equals(String.valueOf(total))")
                && main.contains("mailDatabase.logAuditEvent(\"EMERGENCY_EMPTY\""));

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 7 skipped: it talks to MySQL, Dovecot and the panel on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static java.util.Set<String> labels(String inc) {
        java.util.Set<String> out = new java.util.TreeSet<>();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\$labels\\['([a-z]+)'\\]").matcher(inc);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    // ===================== 7. On the VM =====================

    static final String CONFIG = "/usr/local/www/roundcube/config/config.inc.php";

    static void live() throws Exception {
        System.out.println("\n== 7. Live, on the VM");
        String user = null;
        for (String u : sh("doveadm user '*'").trim().split("\\s+")) if (u.contains("@")) { user = u; break; }
        if (user == null) { check("a mailbox to try with", false); return; }
        String key = sh("php -r 'include \"" + CONFIG + "\"; echo $config[\"daemoxcp_mail_cleanup_key\"];'").trim();
        String url = sh("php -r 'include \"" + CONFIG + "\"; echo $config[\"daemoxcp_mail_cleanup_url\"];'").trim();
        check("the webmail has the route's address and key", url.endsWith(WebmailPasswordConfig.CLEANUP_PATH) && key.length() >= 20);
        check("the plugin is on in Roundcube", sh("php -r 'include \"" + CONFIG + "\"; echo implode(\",\", $config[\"plugins\"]);'").contains("daemoxcp_mail_cleanup"));
        Path dir = Path.of("/usr/local/www/roundcube/plugins/daemoxcp_mail_cleanup");
        check("its files are the panel's", Files.readString(dir.resolve("daemoxcp_mail_cleanup.php")).equals(WebmailCleanupPlugin.php())
                && Files.readString(dir.resolve("localization/it_IT.inc")).equals(WebmailCleanupPlugin.localization().get("it_IT")));
        check("  and PHP reads them", sh("for f in " + dir + "/*.php " + dir + "/localization/*.inc; do php -l $f; done").split("No syntax errors detected", -1).length == 4);
        try {
            check("get: never by default", post(url, key, "user=" + user + "&action=get").equals("200 junk=0 trash=0"));
            check("set Junk 7 days", post(url, key, "user=" + user + "&action=set&junk=7&trash=0").equals("200 junk=7 trash=0"));
            check("  Dovecot gets 7d for Junk and nothing for Trash", sh("doveadm user " + user).contains("namespace/inbox/mailbox/Junk/mailbox_autoexpunge\t7d")
                    && !sh("doveadm user " + user).contains("Trash/mailbox_autoexpunge"));
            check("the address in capitals is the same mailbox", post(url, key, "user=" + user.toUpperCase() + "&action=get").equals("200 junk=7 trash=0"));
            check("other days: 400", post(url, key, "user=" + user + "&action=set&junk=5&trash=0").startsWith("400"));
            check("another action: 400", post(url, key, "user=" + user + "&action=drop").startsWith("400"));
            check("an address that is not a mailbox: 404", post(url, key, "user=nobody-" + System.nanoTime() + "@example.org&action=get").startsWith("404"));
            check("without the key: 404, as a route that does not exist", post(url, "", "user=" + user + "&action=get").startsWith("404"));
        } finally {
            check("back to never", post(url, key, "user=" + user + "&action=set&junk=0&trash=0").equals("200 junk=0 trash=0"));
            check("  Dovecot gets nothing again", !sh("doveadm user " + user).contains("mailbox_autoexpunge"));
        }

        String console = sh("cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --empty-folders junk " + user + " < /dev/null 2>&1; echo \"exit=$?\"");
        check("the console without a terminal: refused, nothing done (" + console.lines().reduce((x, y) -> y).orElse("") + ")", console.contains("exit=2"));
        check("  a wrong word: the usage", sh("cd /home/panel && /usr/local/openjdk25/bin/java -jar daemoxcp-mail.jar --empty-folders spam all < /dev/null 2>&1; echo \"exit=$?\"").contains("exit=2"));

        String subject = "emergency-e2e-" + System.nanoTime();
        for (int i = 0; i < 2; i++)
            sh("printf 'From: <a@example.org>\\nTo: <" + user + ">\\nSubject: " + subject + "\\n\\njunk " + i + "\\n' | doveadm save -u " + user + " -m Junk");
        int before = EmergencyEmpty.countWithDovecot(user, "Junk");
        Map<String, Map<String, Integer>> plan = EmergencyEmpty.plan(List.of(user), List.of("Junk"), EmergencyEmpty::countWithDovecot);
        check("the emergency plan counts the Junk (" + before + ")", before >= 2 && plan.get(user).get("Junk") == before);
        EmergencyEmpty.Result r = EmergencyEmpty.run(plan, EmergencyEmpty::expungeWithDovecot);
        check("  emptied, and the Junk is empty", r.emptied() == 1 && r.failed().isEmpty() && EmergencyEmpty.countWithDovecot(user, "Junk") == 0);
    }

    /** A POST as Roundcube makes it: «status body». */
    static String post(String url, String key, String form) {
        String out = sh("curl -sk -m 20 -w '\\n%{http_code}' " + (key.isEmpty() ? "" : "-H 'X-DaemoxCP-Key: " + key + "' ") + "-d '" + form + "' '" + url + "'");
        String[] lines = out.trim().split("\n");
        return lines[lines.length - 1] + " " + (lines.length > 1 ? lines[0].trim() : "");
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(120), "sh", "-c", command).output();
    }
}
