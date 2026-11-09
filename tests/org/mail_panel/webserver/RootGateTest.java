package org.mail_panel.webserver;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The root part's closed list (RootGate): what it accepts from the web
 * part before any handler.
 *
 *  1. routes and methods: a route that is not in the list, or a method its handler does not use, is refused;
 *  2. the shape of every value: control characters, field names that are not names, values too long,
 *     nesting too deep are refused; text and numbers pass;
 *  3. the strict shapes, wherever the field is: a host name that starts with a dash (an option of the
 *     command it goes to: dig -f reads a file), an IP with a command after it, a jail, a port, a package, a
 *     service, a country, a log, PEM blocks with something else inside;
 *  4. from the project folder (src/ there): every call the pages make to a root route uses a method in the
 *     list, so no page feature is refused by mistake.
 *
 * Usage (on the VM, from the project folder for part 4):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RootGateTest
 */
public class RootGateTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static RootChannel.Request req(String route, String method, String query, String body) {
        return new RootChannel.Request(route, method, route, query, Map.of(), "203.0.113.7", "en", 1, 1,
                body == null ? null : body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    static boolean passes(String route, String method, String query, String body) {
        return RootGate.check(req(route, method, query, body)) == null;
    }

    static final String CERT = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2V4YW1wbGU=\nAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n-----END CERTIFICATE-----\n";

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. Routes and methods ==");
        check("a root route with its method passes", passes("/api/logs", "GET", "log=maillog&lines=100", null));
        check("a route that is not in the list is refused", !passes("/api/run", "GET", null, null));
        check("a route the web part serves itself is not in the list", !passes("/api/domains", "GET", null, null));
        check("a method the handler does not use is refused", !passes("/api/logs", "DELETE", null, null)
                && !passes("/api/service", "GET", null, null) && !passes("/api/versions", "POST", null, "{}"));

        System.out.println("\n== 2. The shape of every value ==");
        check("text, numbers, booleans and nulls pass", passes("/api/report", "POST", null,
                "{\"action\":\"save\",\"recipient\":\"admin@example.com\",\"hours\":24,\"enabled\":true,\"note\":null,\"text\":\"Riga uno\\nRiga due, è così\"}"));
        check("a control character is refused", !passes("/api/report", "POST", null, "{\"action\":\"save\",\"x\":\"a\\u0000b\"}")
                && !passes("/api/logs", "GET", "filter=a%00b", null));
        check("a field name that is not a name is refused", !passes("/api/report", "POST", null, "{\"a b\":\"x\"}")
                && !passes("/api/report", "POST", null, "{\"$where\":\"x\"}"));
        check("a value too long is refused", !passes("/api/report", "POST", null, "{\"x\":\"" + "a".repeat(RootGate.MAX_STRING + 1) + "\"}"));
        check("nesting too deep is refused", !passes("/api/report", "POST", null, "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":1}}}}}}"));
        check("a body that is not JSON is refused", !passes("/api/report", "POST", null, "{\"a\":"));
        check("a query not well encoded is refused", !passes("/api/logs", "GET", "log=%zz", null));

        System.out.println("\n== 3. The strict shapes ==");
        check("a host name passes", passes("/api/roundcube-domain", "POST", null, "{\"action\":\"check\",\"domain\":\"webmail.example.com\"}"));
        check("a host name that starts with a dash (dig -f) is refused",
                !passes("/api/roundcube-domain", "POST", null, "{\"action\":\"check\",\"domain\":\"-f /etc/master.passwd\"}")
                && !passes("/api/roundcube-domain", "POST", null, "{\"action\":\"check\",\"domain\":\"-fx\"}"));
        check("a host name with a command is refused", !passes("/api/hostname", "POST", null, "{\"hostname\":\"mail.example.com;id\"}"));
        check("IPs and networks pass", passes("/api/fail2ban", "POST", null, "{\"action\":\"ban\",\"ip\":\"203.0.113.9\",\"jail\":\"postfix-auth\"}")
                && passes("/api/firewall", "POST", null, "{\"action\":\"add\",\"cidr\":\"2001:db8::/32\"}"));
        check("an IP with something after it is refused", !passes("/api/fail2ban", "POST", null, "{\"action\":\"ban\",\"ip\":\"1.2.3.4; id\"}")
                && !passes("/api/firewall", "POST", null, "{\"cidr\":\"1.2.3.0/999\"}"));
        check("a list of IPs with a bad one is refused", !passes("/api/fail2ban", "POST", null, "{\"action\":\"x\",\"ip\":[\"1.2.3.4\",\"a;b\"]}"));
        check("a jail with a space is refused", !passes("/api/fail2ban", "POST", null, "{\"jail\":\"a b\"}"));
        check("a port out of range is refused", !passes("/api/roundcube-domain", "POST", null, "{\"port\":\"99999\"}")
                && passes("/api/roundcube-domain", "POST", null, "{\"port\":\"8443\"}"));
        check("a package that starts with a dash is refused: it would be an option of pkg (reperto 205)",
                !passes("/api/updates", "POST", null, "{\"action\":\"package_preflight\",\"package\":\"-r\"}"));
        check("a package with a slash or a space is refused", !passes("/api/updates", "POST", null, "{\"action\":\"x\",\"package\":\"../x\"}")
                && !passes("/api/updates", "POST", null, "{\"package\":\"a b\"}") && passes("/api/updates", "POST", null, "{\"package\":\"postfix-mysql\"}"));
        check("a service with a capital or a slash is refused", !passes("/api/service", "POST", null, "{\"service\":\"/bin/sh\"}"));
        check("a country of two letters passes, other refused", passes("/api/firewall", "POST", null, "{\"country\":\"ru\"}")
                && !passes("/api/firewall", "POST", null, "{\"country\":\"ru;x\"}"));
        check("a log id with a slash is refused", !passes("/api/logs", "GET", "log=../../etc/master.passwd", null));
        check("a PEM certificate passes, with the text exporters leave outside the block",
                passes("/api/ssl", "POST", null, new org.json.JSONObject().put("certificate", CERT).toString())
                && passes("/api/ssl", "POST", null, new org.json.JSONObject().put("certificate", "Bag Attributes\n    localKeyID: 01 02\n" + CERT).toString()));
        check("something else inside a PEM block is refused",
                !passes("/api/ssl", "POST", null, new org.json.JSONObject().put("certificate", CERT.replace("AQID", "load_module /tmp/x.so;\nAQID")).toString()));
        check("a PEM block that never ends, or no block at all, is refused",
                !passes("/api/ssl", "POST", null, new org.json.JSONObject().put("ssl_key", "-----BEGIN PRIVATE KEY-----\nAAAA\n").toString())
                && !passes("/api/ssl", "POST", null, new org.json.JSONObject().put("ssl_cert", "just text").toString()));

        // Reperto 204: one field name, three fingerprints. The SSH key's (Settings), and two the panel computes itself
        // and the page sends back: the state of the package branch (16 hex, PkgBranch) and of an address before it is
        // turned into a mailbox (64 hex, AddressTransform). With the SSH shape alone, the branch change and "Turn into
        // mailbox" were refused on the separated panel.
        check("the SSH key fingerprint passes", passes("/api/ssh-keys", "POST", null,
                "{\"action\":\"remove\",\"fingerprint\":\"SHA256:" + "Ab1+/".repeat(8) + "Abc\"}"));
        check("the package branch fingerprint passes (16 hex)", passes("/api/updates", "POST", null,
                "{\"action\":\"branch_change\",\"destination\":\"latest\",\"fingerprint\":\"0123456789abcdef\",\"confirm\":\"latest\"}"));
        check("the address fingerprint passes (64 hex)", passes("/api/aliases", "POST", null,
                "{\"action\":\"transform_to_mailbox\",\"source\":\"info@example.org\",\"fingerprint\":\"" + "a1".repeat(32) + "\"}"));
        check("any other fingerprint is refused: another length, capitals, an option, a space inside",
                !passes("/api/updates", "POST", null, "{\"fingerprint\":\"0123456789abcde\"}")
                && !passes("/api/updates", "POST", null, "{\"fingerprint\":\"" + "a".repeat(32) + "\"}")
                && !passes("/api/updates", "POST", null, "{\"fingerprint\":\"0123456789ABCDEF\"}")
                && !passes("/api/updates", "POST", null, "{\"fingerprint\":\"-oProxyCommand=x\"}")
                && !passes("/api/updates", "POST", null, "{\"fingerprint\":\"01234567 89abcdef\"}"));

        Path pages = Path.of("src/main/resources/pages");
        if (Files.isDirectory(pages)) {
            System.out.println("\n== 4. The pages' calls to the root routes ==");
            List<Path> files = new ArrayList<>();
            try (Stream<Path> s = Files.list(pages)) { s.filter(p -> p.toString().endsWith(".js")).forEach(files::add); }
            files.add(Path.of("src/main/java/org/mail_panel/content/MailPanelContent.java"));
            Pattern call = Pattern.compile("fetch\\(['\"`](/api/[a-z_/-]+)");
            Pattern method = Pattern.compile("method:\\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]");
            int calls = 0;
            List<String> wrong = new ArrayList<>();
            for (Path f : files) {
                String text = Files.readString(f);
                Matcher m = call.matcher(text);
                while (m.find()) {
                    String route = m.group(1);
                    if (route.endsWith("/")) route = route.substring(0, route.length() - 1);
                    if (!RootGate.METHODS.containsKey(route)) continue;
                    // The options of this fetch: up to its closing parenthesis, at most 600 characters.
                    String after = text.substring(m.end(), Math.min(text.length(), m.end() + 600));
                    int close = after.indexOf("});");
                    if (close > 0) after = after.substring(0, close);
                    Matcher mm = method.matcher(after);
                    String used = mm.find() ? mm.group(1) : "GET";
                    calls++;
                    if (!RootGate.METHODS.get(route).contains(used)) wrong.add(f.getFileName() + ": " + used + " " + route);
                }
            }
            check("every page call to a root route uses a method in the list (" + calls + " calls)" + (wrong.isEmpty() ? "" : " " + wrong),
                    calls > 30 && wrong.isEmpty());
        } else {
            System.out.println("\n  (part 4 skipped: run it from the project folder, where src/ is)");
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
