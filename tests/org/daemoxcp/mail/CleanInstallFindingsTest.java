package org.daemoxcp.mail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What the installation from the README on a clean VM found on 20/11/2026 (release 0.9.0 build 786), kept fixed.
 *  1. The installation ends with the server closed: right after the script, before «Mail server installed
 *     successfully!», the same two closings as the first start (MysqlListen, PfPolicy). Before, pf let everything in
 *     and MySQL listened on every interface (3306 and the X protocol, 33060) until the panel's first start.
 *  2. Option 1 sets the time zone with tzsetup, never with cp: /etc/localtime is a link into /usr/share/zoneinfo,
 *     and cp wrote through it, overwriting the old zone's file with the new one.
 *  3. On a new server, where MySQL is not installed yet, the first connection does not read like a failure.
 *  4. Every yes/no window of the Updates and Diagnostics pages has its own text: the generic one said «unless the
 *     text above says otherwise» with no text above; Upgrade asked the same thing twice.
 *  5. The menu: it stays on the item just used (it went back to 1 and the next Down opened the wrong item); in a window
 *     with one field Enter confirms (it moved the focus to Cancel, and a second Enter cancelled what was typed).
 *  6. The README (EN and IT) names the start item as the menu does, says freebsd-update shows a pager, and the
 *     fixes have something to find: each check first finds the old text in a sample.
 *  7. The webmail's certificate saved from the page is checked like the menu's before anything is written (a key that
 *     was not the certificate's was saved, with the database, and only nginx refused it); nginx.conf from NginxMain.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.CleanInstallFindingsTest
 */
public class CleanInstallFindingsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String read(String path) throws Exception {
        return Files.readString(Path.of(path));
    }

    /** The code of a method, from its declaration to the next one at the same indentation. */
    static String method(String src, String declaration) {
        int i = src.indexOf(declaration);
        if (i < 0) return "";
        Matcher m = Pattern.compile("\n    (public |private |static |protected )").matcher(src);
        return m.find(i + declaration.length()) ? src.substring(i, m.start()) : src.substring(i);
    }

    /** True when the time zone script copies over /etc/localtime (the old way). */
    static boolean copiesOverLocaltime(String script) {
        return Pattern.compile("(?m)^\\s*cp\\s+[^\\n]*\\s/etc/localtime\\b").matcher(script).find();
    }

    /** The calls to the generic yes/no window without a text of their own. */
    static int confirmWithoutText(String src) {
        Matcher m = Pattern.compile("updConfirm\\(\\s*''").matcher(src);
        int n = 0;
        while (m.find()) n++;
        return n;
    }

    public static void main(String[] a) throws Exception {
        String main = read("src/main/java/org/daemoxcp/mail/Main.java");
        String content = read("src/main/java/org/daemoxcp/mail/content/PanelContent.java");
        String readme = read("README.md"), readmeIt = read("README.it.md");

        System.out.println("== 0. The checks find the old texts");
        check("the old time zone line is found", copiesOverLocaltime("            cp \"/usr/share/zoneinfo/$TZ_NAME\" /etc/localtime\n"));
        check("a yes/no window without its own text is found", confirmWithoutText("if (!await updConfirm('', t('up.wRelink'))) return;") == 1);

        System.out.println("\n== 1. The installation ends closed");
        String install = main.substring(0, Math.max(0, main.indexOf("\"Mail server installed successfully!\"")));
        int mysql = install.lastIndexOf("org.daemoxcp.mail.system.MysqlListen.ensureAtBoot();");
        int pf = install.lastIndexOf("org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();");
        int cert = install.lastIndexOf("[AUTO] Self-signed certificate loaded");
        check("MySQL on 127.0.0.1 and pf closed before «installed successfully»", mysql > 0 && pf > 0);
        check("  after the panel's port is in the configuration, MySQL first and pf last", cert > 0 && cert < mysql && mysql < pf);

        System.out.println("\n== 2. The time zone with tzsetup");
        String tz = new org.daemoxcp.mail.scripts.SetTimeOnSystem().getScriptContent();
        check("no cp over /etc/localtime", !copiesOverLocaltime(tz));
        check("tzsetup -s with the chosen name, and the script stops if it fails",
                tz.contains("if ! tzsetup -s \"$TZ_NAME\"; then") && tz.contains("exit 1"));

        System.out.println("\n== 3. MySQL not installed yet");
        String fresh = org.daemoxcp.mail.database.MailDatabase.unavailableMessage(false, "Could not create connection");
        String down = org.daemoxcp.mail.database.MailDatabase.unavailableMessage(true, "Could not create connection");
        check("not installed: says so, and that it is normal (" + fresh + ")",
                fresh.startsWith("MySQL is not installed yet") && fresh.contains("normal") && !fresh.contains("Could not"));
        check("installed but not answering: the detail stays", down.equals("MySQL not available: Could not create connection"));

        System.out.println("\n== 4. The yes/no windows");
        check("no generic yes/no window without its own text (" + confirmWithoutText(content) + ")", confirmWithoutText(content) == 0);
        String apply = method(content, "async function updApply()");
        check("Upgrade asks once: the first confirmation, not a second generic one",
                apply.contains("panelConfirm(t('up.confirmApply'))") && !apply.contains("updConfirm("));
        for (String lang : new String[] {"en", "it"}) {
            org.json.JSONObject j = new org.json.JSONObject(read("src/main/resources/lang/" + lang + ".json"));
            check(lang + ": the generic text no longer speaks of a text above",
                    !j.getString("gd.confirmText").contains("above") && !j.getString("gd.confirmText").contains("sopra"));
            check(lang + ": the four actions have their own texts", j.has("up.confirmCleanClient") && j.has("up.confirmInstallRc")
                    && j.has("up.confirmRelink") && j.has("up.confirmFixNginx"));
        }

        System.out.println("\n== 5. The menu");
        String chooser = read("src/main/java/org/daemoxcp/mail/gui/Chooser.java");
        check("the menu starts on the item used last", chooser.contains("private static int lastSelected")
                && chooser.contains("actionListBox.setSelectedIndex(") && chooser.contains("lastSelected = actionListBox.getSelectedIndex();"));
        String input = method(main, "public static String showTextInputDialogWithDefault(");
        check("Enter in the field confirms", input.contains("KeyType.Enter") && input.contains("result[0] = getText();"));
        check("  and Cancel is still the first button",
                input.indexOf("I18n.tr(\"console.cancel\")") > 0 && input.indexOf("I18n.tr(\"console.cancel\")") < input.indexOf("I18n.tr(\"console.ok\")"));

        System.out.println("\n== 7. The webmail's certificate from the page");
        String server = read("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java");
        int update = server.indexOf("\"update_ssl\".equals(action)");
        int pairCheck = server.indexOf("PemTls.check(\"webmail\"", update);
        int firstWrite = server.indexOf("Files.createDirectories(Path.of(sslDir))", update);
        check("checked like the menu's (PemTls: readable, valid, covers the name, the key is its own) before anything is written",
                update > 0 && pairCheck > update && firstWrite > pairCheck);
        check("  and nginx.conf is written from NginxMain, keeping the include, only if nginx -t accepts it",
                server.contains("NginxMain.content(domain, port, sslCert, sslKey, rcRoot,") && server.contains("NginxMain.keepIncludes(config, current)")
                && server.contains("NginxMain.write(config)"));

        System.out.println("\n== 6. The README");
        org.json.JSONObject en = new org.json.JSONObject(read("src/main/resources/lang/en.json"));
        String start = ">>> " + en.getString("console.menu.start").replace("{product}", "DaemoxCP Mail") + " <<<";
        check("EN: the start item as the menu shows it (" + start + ")", readme.contains("**" + start + "**")
                && !readme.contains(">>> Start DaemoxCP Mail web server <<<"));
        check("IT: the same", readmeIt.contains("**" + start + "**") && !readmeIt.contains(">>> Start DaemoxCP Mail web server <<<"));
        check("EN and IT: freebsd-update shows a pager, q to go on", readme.contains("in a pager: press `q` to go on")
                && readmeIt.contains("in un visualizzatore: premi `q` per andare avanti"));
        check("EN and IT: Enter confirms a window with one field", readme.contains("Enter confirms what you typed")
                && readmeIt.contains("Invio conferma"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
