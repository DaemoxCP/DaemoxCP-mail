package org.mail_panel.security;

import org.mail_panel.Main;
import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;

/**
 * MySQL's root password, which did not exist before, and the two roads by which the secrets left
 * the panel.
 *
 * What must be tested here, and that compiling would not tell:
 *  - the first password is GENERATED, and once generated it no longer changes. If it changed at
 *    every installation, the one written in the file and the one set in MySQL would no longer be
 *    the same secret and nobody would get in as root any more;
 *  - the root password contains no characters that would break it where it really ends up: inside
 *    IDENTIFIED BY '...' in a here-document, and inside a MySQL option file. The alphabet is not
 *    looked at: /bin/sh is made to expand the here-document and the line that comes out is looked at;
 *  - the password of the PANEL'S USER has a narrower alphabet, and the reason is not laziness: it
 *    ends up in a URL (mysql://user:password@host/db). Here the URL is rebuilt and read back,
 *    because an at sign or a percent sign inside the password would break it silently;
 *  - the secrets no longer go through the arguments nor through standard output. The check does
 *    not look at the code: it starts a real script with executeScriptWithSecrets, captures
 *    everything the panel prints, and requires the secret not to be there and to have reached the
 *    child;
 *  - the script and the caller are two parts of the same thing (r26): if one moves an argument and
 *    the other does not, the installation configures the database with the host's name. Here the
 *    list of positionals is read from the generated script and compared with what Main passes it.
 *
 * It runs from any folder:
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.MysqlRootPasswordTest
 */
public class MysqlRootPasswordTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The order of the positionals Main.installMailServer passes to the script, in order. */
    static final List<String> ARGUMENTS_FROM_THE_PANEL = List.of(
            "MYSQL_HOST", "MYSQL_PORT", "MYSQL_USER", "MYSQL_DATABASE", "MAIL_HOSTNAME",
            "ROUNDCUBE_DOMAIN", "ROUNDCUBE_PORT", "ROUNDCUBE_SSL_CERT", "ROUNDCUBE_SSL_KEY",
            "ROUNDCUBE_SSL_CHAIN");

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("mysql-root-password");
        PanelSecrets.dir = home.resolve("secrets");
        reset();
        // Without this, executeScript waits for an ENTER when the test runs from a terminal.
        var interactive = Main.class.getDeclaredField("nonInteractive");
        interactive.setAccessible(true);
        interactive.set(null, true);

        OUT.println("\n== The first root password ==");
        check("at the start it is not there", PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD).isEmpty());
        String generated = PanelSecrets.ensureMysqlRootPassword();
        check("afterwards it is there, and it is 28 long", generated.length() == 28);
        check("the second call returns THE SAME, not a new one",
                generated.equals(PanelSecrets.ensureMysqlRootPassword()));
        reset();
        check("read back from the file it is still that one",
                generated.equals(PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD)));
        PanelSecrets.setText(PanelSecrets.MYSQL_ROOT_PASSWORD, "set-by-hand");
        check("a password set by hand is not replaced",
                "set-by-hand".equals(PanelSecrets.ensureMysqlRootPassword()));
        check("the file is readable only by root, the folder only traversable by root",
                "rw-------".equals(permissions(PanelSecrets.dir.resolve("root-secrets.properties")))
                        && "rwx------".equals(permissions(PanelSecrets.dir)));

        OUT.println("\n== The root password survives the installation's here-document ==");
        // The alphabet is not looked at: the EXACT line of the script is taken, /bin/sh is made to
        // expand it, and then it is read back as MySQL reads it. The two passes break for different
        // reasons, and one alone is not enough: the backslash is eaten by the shell (in an unquoted
        // here-document "\\" becomes "\"), while the quote goes through the shell intact and closes
        // the literal in MySQL's face. Measured: with a check that compared only the expanded text,
        // an alphabet with the quote passed the test.
        int through = 0, mangledByShell = 0, mangledBySql = 0;
        for (int i = 0; i < 200; i++) {
            String password = PanelSecrets.newPassword(28);
            String expanded = expandHereDocument(password);
            String wanted = "ALTER USER 'root'@'localhost' IDENTIFIED BY '" + password + "';";
            if (!wanted.equals(expanded)) { mangledByShell++; continue; }
            if (!password.equals(passwordAsMysqlReadsIt(expanded))) { mangledBySql++; continue; }
            through++;
        }
        check("200 generated passwords reach MySQL intact (" + through + " of 200; "
                + mangledByShell + " broken by the shell, " + mangledBySql + " by the SQL literal)",
                mangledByShell == 0 && mangledBySql == 0);

        // The same, in the second form the password ends up in: the option file. An unquoted '#'
        // opens a comment, and MySQL would read half a password.
        int readBack = 0;
        for (int i = 0; i < 200; i++) {
            String password = PanelSecrets.newPassword(28);
            if (password.equals(optionFileValue(optionFile(password)))) readBack++;
        }
        check("200 passwords read back from the option file as MySQL reads it (" + readBack + " of 200)",
                readBack == 200);

        OUT.println("\n== The panel user's password ends up in a URL ==");
        int urlOk = 0, urlBroken = 0;
        for (int i = 0; i < 500; i++) {
            String password = PanelSecrets.newAlphanumericPassword(24);
            try {
                URI dsn = new URI("mysql://mailpanel:" + password + "@127.0.0.1/roundcubemail");
                boolean same = ("mailpanel:" + password).equals(dsn.getUserInfo())
                        && "127.0.0.1".equals(dsn.getHost())
                        && "/roundcubemail".equals(dsn.getPath());
                if (same) urlOk++; else urlBroken++;
            } catch (Exception e) {
                urlBroken++;
            }
        }
        check("500 panel passwords inside mysql://user:password@host/db, read back the same ("
                + urlOk + " of 500)", urlBroken == 0);
        // Made to fail: with the root alphabet the URL breaks. If one day it stopped breaking, this
        // check would no longer tell anything apart and must be removed.
        int richBroken = 0;
        for (int i = 0; i < 500; i++) {
            String password = PanelSecrets.newPassword(24);
            try {
                URI dsn = new URI("mysql://mailpanel:" + password + "@127.0.0.1/roundcubemail");
                if (!("mailpanel:" + password).equals(dsn.getUserInfo())
                        || !"127.0.0.1".equals(dsn.getHost())) richBroken++;
            } catch (Exception e) {
                richBroken++;
            }
        }
        check("and with the root alphabet the same URL breaks (" + richBroken + " of 500): that is"
                + " why the two alphabets are different", richBroken > 250);

        OUT.println("\n== The secret no longer goes through the screen nor through the arguments ==");
        Path script = home.resolve("echo-secret.sh");
        Files.writeString(script, "#!/bin/sh\n"
                + "# Writes the LENGTH of the secret, never the secret: if it printed it, this\n"
                + "# test would no longer tell the panel's standard output from the\n"
                + "# script's.\n"
                + "printf '%s' \"${MYSQL_ROOT_PASSWORD}\" > \"$1/arrived\"\n"
                + "echo \"the child got ${#MYSQL_ROOT_PASSWORD} characters\"\n", StandardCharsets.UTF_8);
        String secret = PanelSecrets.newPassword(28);
        String printed = capture(() -> Main.executeScriptWithSecrets(script.toString(),
                "test", Map.of("MYSQL_ROOT_PASSWORD", secret), home.toString()));
        check("the secret reaches the child in the environment",
                secret.equals(Files.readString(home.resolve("arrived"), StandardCharsets.UTF_8)));
        check("and it appears in nothing the panel prints", !printed.contains(secret));
        check("in its place it says how many arguments there are", printed.contains("1 (hidden"));
        // And if one day somebody puts a secret back AMONG THE ARGUMENTS, it must not appear either:
        // here it is passed on purpose as an argument and the screen is looked at.
        String asArgument = PanelSecrets.newPassword(28);
        String withSecretArgument = capture(() -> Main.executeScriptWithSecrets(script.toString(),
                "test", Map.of("MYSQL_ROOT_PASSWORD", secret), home.toString(), asArgument));
        check("a secret passed as an argument still does not end up on the screen",
                !withSecretArgument.contains(asArgument));
        String plain = capture(() -> Main.executeScript(script.toString(), "test", home.toString()));
        check("without secrets the arguments are printed as before", plain.contains(home.toString()));

        OUT.println("\n== The script and the panel agree on who number N is ==");
        String text = new FullMailServerScript().getScriptContent();
        for (int i = 0; i < ARGUMENTS_FROM_THE_PANEL.size(); i++) {
            String name = ARGUMENTS_FROM_THE_PANEL.get(i);
            String position = i < 9 ? "\"$" + (i + 1) + "\"" : "\"${" + (i + 1) + "}\"";
            check("argument " + (i + 1) + " = " + name, text.contains(name + "=" + position));
        }
        check("no password is a positional argument any more",
                !text.contains("MYSQL_PASSWORD=\"$") && !text.contains("MYSQL_ROOT_PASSWORD=\"$"));
        check("the script stops if the passwords are not in the environment",
                text.contains("MYSQL_PASSWORD not in the environment")
                        && text.contains("MYSQL_ROOT_PASSWORD not in the environment"));
        check("root no longer gets in without a password where the work is done",
                !text.contains("mysql -u root < ") && !text.contains("mysql -u root << ROUNDCUBE_DB")
                        && text.contains("--defaults-extra-file=\"$MYSQL_ROOT_CNF\""));
        check("the SQL file with the secret is no longer in /tmp", !text.contains("/tmp/mysql_setup.sql"));
        Path generatedScript = home.resolve("install_mail_server.sh");
        Files.writeString(generatedScript, text, StandardCharsets.UTF_8);
        check("the generated script passes sh -n", run("/bin/sh", "-n", generatedScript.toString()) == 0);

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** The installation's line, expanded by /bin/sh exactly as in the script. */
    static String expandHereDocument(String password) throws Exception {
        String shell = "MYSQL_ROOT_PASSWORD='" + password.replace("'", "'\\''") + "'\n"
                + "cat << EOROOT\n"
                + "ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';\n"
                + "EOROOT\n";
        return output("/bin/sh", "-c", shell).trim();
    }

    /**
     * The password MySQL reads from that line, or null if the line is no longer the statement it
     * should be.
     *
     * <p>It reads the quoted literal as MySQL reads it: the backslash is an escape, two quotes in a
     * row are a quote, the first unescaped quote closes. After the literal exactly {@code ;} must be
     * left: if the password contains a quote, the literal closes in the middle and what is left is
     * garbage, that is a broken statement — which is exactly the fault the alphabet must prevent.
     */
    static String passwordAsMysqlReadsIt(String statement) {
        String head = "ALTER USER 'root'@'localhost' IDENTIFIED BY '";
        if (!statement.startsWith(head)) return null;
        StringBuilder value = new StringBuilder();
        int i = head.length();
        while (i < statement.length()) {
            char c = statement.charAt(i);
            if (c == '\\' && i + 1 < statement.length()) {          // MySQL's escape
                value.append(unescape(statement.charAt(i + 1)));
                i += 2;
            } else if (c == '\'' && i + 1 < statement.length() && statement.charAt(i + 1) == '\'') {
                value.append('\'');                                  // '' is a quote
                i += 2;
            } else if (c == '\'') {
                return statement.substring(i + 1).equals(";") ? value.toString() : null;
            } else {
                value.append(c);
                i++;
            }
        }
        return null;                                                 // literal never closed
    }

    /** MySQL's escapes that change the character; the others give the character itself. */
    static char unescape(char c) {
        switch (c) {
            case '0': return '\0';
            case 'n': return '\n';
            case 'r': return '\r';
            case 't': return '\t';
            case 'b': return '\b';
            case 'Z': return (char) 26;
            default:  return c;
        }
    }

    /** The option file as the script writes it. */
    static String optionFile(String password) throws Exception {
        String shell = "MYSQL_ROOT_PASSWORD='" + password.replace("'", "'\\''") + "'\n"
                + "cat << EOCNF\n[client]\nuser=root\npassword=\"$MYSQL_ROOT_PASSWORD\"\nEOCNF\n";
        return output("/bin/sh", "-c", shell);
    }

    /**
     * The value MySQL reads from that file: it cuts at an unquoted '#', removes the quotes around it.
     * It is the rule of option files, written here on purpose to measure that the chosen form holds.
     */
    static String optionFileValue(String file) {
        for (String line : file.split("\n")) {
            if (!line.startsWith("password=")) continue;
            String value = line.substring("password=".length());
            if (value.startsWith("\"")) {
                int end = value.indexOf('"', 1);
                return end < 0 ? null : value.substring(1, end);
            }
            int hash = value.indexOf('#');
            return hash < 0 ? value.trim() : value.substring(0, hash).trim();
        }
        return null;
    }

    static String output(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }

    static int run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        OUT.print(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        return p.waitFor();
    }

    /** Everything the panel writes while it does something. */
    static String capture(ThrowingRunnable what) throws Exception {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        PrintStream before = System.out;
        System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        try { what.run(); } finally { System.setOut(before); }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    interface ThrowingRunnable { void run() throws Exception; }

    static String permissions(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    static void reset() throws Exception {
        var m = PanelSecrets.class.getDeclaredMethod("reset");
        m.setAccessible(true);
        m.invoke(null);
    }
}
