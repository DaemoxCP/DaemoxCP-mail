package org.daemoxcp.mail.util;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PasskeyService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * The text of an exception that reaches a page (reperto 231): only the panel's own messages pass; for any other
 * exception the page reads a generic text and the panel log gets the exception.
 *
 * <p>Before, the routes put {@code e.getMessage()} of any exception in the answer: a duplicate in MySQL showed the
 * page the table and key, a missing file its path, a broken JSON the name of the key.
 * <ul>
 *   <li>IllegalArgumentException and IllegalStateException with a message: the message, nothing in the log;</li>
 *   <li>PasskeyException: the text of the key it carries;</li>
 *   <li>InvalidPathException, NumberFormatException, an IOException with a path, an SQLException naming a table, a
 *       NullPointerException, no message at all: the generic text, and one WARNING line in the log with the route's
 *       method and the whole exception;</li>
 *   <li>a MySQL duplicate (1062), also wrapped in another exception: "it already exists", without the key;</li>
 *   <li>detail(): the same choice, for a text that frames the error ({error}).</li>
 * </ul>
 * And in the sources: no route answer of SSLMailServer and no "success" answer of UpdateManager puts
 * {@code getMessage()} by itself any more.
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.util.ErrorTextTest
 */
public class ErrorTextTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final List<LogRecord> LOGGED = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Logger logger = Logger.getLogger(ErrorText.class.getName());
        logger.addHandler(new Handler() {
            @Override public void publish(LogRecord r) { LOGGED.add(r); }
            @Override public void flush() {}
            @Override public void close() {}
        });
        String generic = I18n.tr("server.requestFailed");
        String inLog = I18n.tr("server.detailsInLog");
        String exists = I18n.tr("server.alreadyExists");
        check("the three texts exist in English (" + generic + " | " + inLog + " | " + exists + ")",
                !generic.equals("server.requestFailed") && !inLog.equals("server.detailsInLog") && !exists.equals("server.alreadyExists"));

        System.out.println("\n== The panel's own messages pass");
        LOGGED.clear();
        check("IllegalArgumentException: its message", ErrorText.forPage("handleX", new IllegalArgumentException("The address is not valid")).equals("The address is not valid"));
        check("IllegalStateException: its message", ErrorText.forPage("handleX", new IllegalStateException("Another update is running")).equals("Another update is running"));
        String passkey = I18n.tr("server.passkey.expired");
        check("PasskeyException: the text of its key (" + passkey + ")", !passkey.equals("server.passkey.expired")
                && ErrorText.forPage("handleX", new PasskeyService.PasskeyException("server.passkey.expired")).equals(passkey));
        check("detail() of the same: the message", ErrorText.detail("handleX", new IllegalArgumentException("Too many destinations")).equals("Too many destinations"));
        check("  nothing in the log", LOGGED.isEmpty());

        System.out.println("\n== Anything else: the generic text, and the log");
        Object[][] hidden = {
                {"an IOException with a path", new IOException("/usr/local/etc/mail-panel/secrets.json: Permission denied"), "/usr/local/etc"},
                {"an SQLException naming a table", new SQLException("Table 'mailserver.virtual_users' doesn't exist", "42S02", 1146), "virtual_users"},
                {"an InvalidPathException (a subtype of IllegalArgumentException)", new InvalidPathException("/var/mail/\0x", "Nul character not allowed"), "/var/mail"},
                {"a NumberFormatException (a subtype of IllegalArgumentException)", new NumberFormatException("For input string: \"12a\""), "12a"},
                {"a NullPointerException", new NullPointerException("Cannot invoke \"org.json.JSONObject.optString(String)\""), "org.json"},
                {"an IllegalArgumentException without a message", new IllegalArgumentException(), "IllegalArgumentException"},
        };
        for (Object[] h : hidden) {
            LOGGED.clear();
            Exception e = (Exception) h[1];
            String text = ErrorText.forPage("handleApiMailboxes", e);
            check(h[0] + ": the generic text", text.equals(generic) && !text.contains((String) h[2]));
            check("  one WARNING line with the method and the exception", LOGGED.size() == 1
                    && LOGGED.get(0).getLevel().getName().equals("WARNING")
                    && LOGGED.get(0).getMessage().contains("[handleApiMailboxes]") && LOGGED.get(0).getThrown() == e);
        }
        LOGGED.clear();
        String framed = I18n.tr("server.errorWith", java.util.Map.of("error", ErrorText.detail("handleApiSsl", new IOException("/root/.acme.sh: not found"))));
        check("detail() inside a framing text: the frame and \"" + inLog + "\" (" + framed + ")",
                framed.contains(inLog) && !framed.contains("/root") && LOGGED.size() == 1);

        System.out.println("\n== A MySQL duplicate: it already exists");
        LOGGED.clear();
        SQLException dup = new SQLIntegrityConstraintViolationException("Duplicate entry 'a@example.test' for key 'mailboxes.email'", "23000", 1062);
        check("the duplicate itself", ErrorText.forPage("handleApiMailboxes", dup).equals(exists));
        check("wrapped in a RuntimeException", ErrorText.forPage("handleApiMailboxes", new RuntimeException("insert failed", dup)).equals(exists));
        check("in detail()", ErrorText.detail("handleApiMailboxes", dup).equals(exists));
        check("  never the key nor the address, nothing in the log", LOGGED.isEmpty() && !exists.contains("mailboxes.email"));
        check("another integrity error (a foreign key, 1452): the generic text",
                ErrorText.forPage("handleApiAliases", new SQLIntegrityConstraintViolationException("Cannot add or update a child row", "23000", 1452)).equals(generic));

        System.out.println("\n== In the sources");
        List<String> bare = new ArrayList<>();
        String[] server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java")).split("\n");
        for (int i = 0; i < server.length; i++) {
            String l = server[i];
            if (!l.contains("getMessage()") || l.contains("LOGGER") || l.contains("System.") || l.contains(".append(")) continue;
            if (l.contains(".put(") || l.contains("sendJsonError(")) bare.add("SSLMailServer:" + (i + 1));
        }
        String[] updates = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/system/UpdateManager.java")).split("\n");
        for (int i = 0; i < updates.length; i++) {
            String l = updates[i];
            if (l.contains("getMessage()") && l.contains("\"success\"")) bare.add("UpdateManager:" + (i + 1));
            if (l.contains("getMessage()") && i > 0 && updates[i - 1].contains("\"success\", false") && l.contains(".put(\""))
                bare.add("UpdateManager:" + (i + 1));
        }
        check("no route answer puts getMessage() by itself " + bare, bare.isEmpty());

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
