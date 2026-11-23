package org.daemoxcp.mail;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

import org.daemoxcp.mail.content.PanelContent;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.gui.Chooser;
import org.daemoxcp.mail.gui.ModifyData;
import org.daemoxcp.mail.gui.RoundcubeConfig;
import org.daemoxcp.mail.gui.Welcome;
import org.daemoxcp.mail.scripts.*;
import org.daemoxcp.mail.sqli.dataBaseManager;
import org.daemoxcp.mail.system.InstallLocks;
import org.daemoxcp.mail.webserver.SSLMailServer;
import org.daemoxcp.mail.webserver.WebSessions;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.ResultSet;

/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                     DaemoxCP Mail - Main Entry Point                     ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  Native mail server control panel for FreeBSD 15+                            ║
 * ║  Similar to Mailcow but WITHOUT Docker - 100% native FreeBSD services        ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                              MAIL SERVER STACK                                ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  SMTP SERVER: Postfix                                                   │ ║
 * ║  │  ─────────────────────────────────────────                              │ ║
 * ║  │  • Port 25   - Incoming mail (STARTTLS)                                 │ ║
 * ║  │  • Port 587  - Submission (STARTTLS + Auth)                             │ ║
 * ║  │  • Port 465  - Submission SSL (SMTPS + Auth)                            │ ║
 * ║  │  • Service name: postfix                                                │ ║
 * ║  │  • Config: /usr/local/etc/postfix/main.cf                               │ ║
 * ║  │  • MySQL tables: mysql-virtual-domains.cf, mysql-virtual-mailboxes.cf   │ ║
 * ║  │                                                                         │ ║
 * ║  │  NOTE: We use Postfix with MySQL virtual users.                         │ ║
 * ║  │        Delivery is via LMTP to Dovecot on port 24.                      │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  IMAP SERVER: Dovecot (POP3 off)                                        │ ║
 * ║  │  ──────────────────────────────                                         │ ║
 * ║  │  • Port 143  - IMAP (STARTTLS)                                          │ ║
 * ║  │  • Port 993  - IMAPS (SSL)                                              │ ║
 * ║  │  • LMTP socket: private/dovecot-lmtp                                    │ ║
 * ║  │  • Config: /usr/local/etc/dovecot/                                      │ ║
 * ║  │  • Mailboxes: /var/vmail/{domain}/{user}                                │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  ANTI-SPAM: Rspamd                                                      │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Port 11332 - Milter protocol (for Postfix milter)                    │ ║
 * ║  │  • Port 11333 - Normal worker                                           │ ║
 * ║  │  • Port 11334 - Controller/Web UI                                       │ ║
 * ║  │  • Config: /usr/local/etc/rspamd/                                       │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  ANTIVIRUS: ClamAV                                                      │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Socket: /var/run/clamav/clamd.sock                                   │ ║
 * ║  │  • Services: clamav_clamd, clamav_freshclam (underscore on FreeBSD)     │ ║
 * ║  │  • Integrated with Rspamd for email scanning                            │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  DATABASE: MySQL 8.0                                                    │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Port 3306                                                            │ ║
 * ║  │  • Database: daemoxcp_mail (configurable)                               │ ║
 * ║  │  • Tables: domains, mailboxes, aliases,                                 │ ║
 * ║  │            panel_admins, settings, rate_limits, etc.                    │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  CACHE: Redis                                                           │ ║
 * ║  │  ─────────────────                                                      │ ║
 * ║  │  • Unix socket /var/run/redis/redis.sock, 0770 (group redis)            │ ║
 * ║  │  • Used by Rspamd for caching                                           │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
 * ║  │  SSL CERTIFICATES                                                       │ ║
 * ║  │  ─────────────────────                                                  │ ║
 * ║  │  • Path: /usr/local/etc/ssl/mail/                                       │ ║
 * ║  │  • fullchain.pem - Certificate + chain                                  │ ║
 * ║  │  • privkey.pem   - Private key                                          │ ║
 * ║  └─────────────────────────────────────────────────────────────────────────┘ ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                           PANEL CONFIGURATION                                 ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  • SQLite database: ./database/daemoxcp-mail.db (panel settings only)          ║
 * ║  • MySQL database: mail data (domains, users, aliases)                        ║
 * ║  • Web panel: HTTPS on port 2096 (configurable)                               ║
 * ║  • Terminal GUI: Lanterna library                                             ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  IMPORTANT: This project uses Postfix with MySQL virtual users.               ║
 * ║  Postfix delivers to Dovecot via LMTP on port 24.                             ║
 * ║                                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 *
 * @author DaemoxCP Mail Team
 * @version 1.0
 */
public class Main {

    // External commands start with fork(), not with jspawnhelper. With the default mechanism
    // every command goes through jspawnhelper, which checks that it is the same version as the
    // JVM in memory: as soon as pkg updates the JDK under the running panel, every launch fails
    // ("Failed to exec spawn helper") and the panel can no longer read anything until it is
    // restarted. Tested on FreeBSD 15.1 with openjdk25 25.0.2 -> 25.0.4: with FORK the commands
    // keep starting. The property is read only once, at the first process launched:
    // that is why it is here, before anything else.
    static {
        if (System.getProperty("jdk.lang.Process.launchMechanism") == null)
            System.setProperty("jdk.lang.Process.launchMechanism", "FORK");
    }

    public static dataBaseManager dbManager;         // SQLite for panel config
    public static MailDatabase mailDatabase;         // MySQL for mail data
    public static WebSessions sessions = new WebSessions();

    // Status flags for SSLMailServer compatibility
    public static boolean mysqlAvailable = false;
    /** No active administrator: the panel waits for one to be created from the console (--create-admin). */
    public static volatile boolean setupRequired = true;

    // ANSI color codes
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_CYAN = "\u001B[36m";

    private static String getJarDirectory() throws URISyntaxException {
        String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
        return new File(jarPath).getParent();
    }

    public static void createDirectoryIfNotExists(String directoryPath) throws IOException {
        Path path = Paths.get(directoryPath);
        if (!Files.exists(path)) {
            Files.createDirectories(path);
        }
    }

    public static String showTextInputDialog(MultiWindowTextGUI gui, String title, String description) {
        return showTextInputDialogWithDefault(gui, title, description, "");
    }

    public static String showTextInputDialogWithDefault(MultiWindowTextGUI gui, String title, String description, String defaultValue) {
        final String[] result = {null};

        BasicWindow window = new BasicWindow(title);
        Panel panel = new Panel();
        panel.setLayoutManager(new GridLayout(2));

        if (description != null && !description.isEmpty()) {
            panel.addComponent(new Label(description));
            panel.addComponent(new EmptySpace());
        }

        // Enter in the field counts as OK. In Lanterna, Enter in a one-line field moves the focus to the next
        // component, which here is Cancel: whoever typed the value and pressed Enter twice, as in any form, cancelled
        // what they had typed (install from the README, 2026-11-20). Cancel stays the first button.
        TextBox textBox = new TextBox(new TerminalSize(40, 1)) {
            @Override
            public Result handleKeyStroke(com.googlecode.lanterna.input.KeyStroke key) {
                if (key.getKeyType() == com.googlecode.lanterna.input.KeyType.Enter) {
                    result[0] = getText();
                    window.close();
                    return Result.HANDLED;
                }
                return super.handleKeyStroke(key);
            }
        };
        if (defaultValue != null && !defaultValue.isEmpty()) {
            textBox.setText(defaultValue);
        }
        panel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.input")));
        panel.addComponent(textBox);

        // Cancel first = pre-selected (safety)
        panel.addComponent(new Button(org.daemoxcp.mail.i18n.I18n.tr("console.cancel"), () -> {
            result[0] = null;
            window.close();
        }));
        panel.addComponent(new Button(org.daemoxcp.mail.i18n.I18n.tr("console.ok"), () -> {
            result[0] = textBox.getText();
            window.close();
        }));

        window.setComponent(panel);
        gui.addWindowAndWait(window);

        return result[0];
    }

    /**
     * Execute a shell script with detailed output
     */
    public static boolean executeScript(String scriptPath, String scriptName, String... args) {
        return executeScript(scriptPath, scriptName, java.util.Map.of(), true, args);
    }

    /**
     * Like {@link #executeScript}, but the secrets reach the script through the <em>environment</em>,
     * and the arguments are not printed.
     *
     * <p>Two roads led the database password out, and both are closed here.
     *
     * <p>The first: {@code "Arguments: " + String.join(" ", args)} wrote them to standard
     * output. Started by the service, that standard output is a <em>file</em>: the password
     * ended up on disk in clear text, and stayed there. Now it says how many arguments there
     * are, not which.
     *
     * <p>The second, worse: a command-line argument can be read by <em>anyone</em>
     * with {@code ps}, for the whole duration of the installation, which is minutes. The
     * environment of a process, instead, on FreeBSD is visible only to its owner or root
     * ({@code procstat -e}). It is not a safe, but it is the difference between "every user
     * of the machine" and "root".
     */
    public static boolean executeScriptWithSecrets(String scriptPath, String scriptName,
                                                   java.util.Map<String, String> secrets, String... args) {
        return executeScript(scriptPath, scriptName, secrets, true, args);
    }

    /**
     * @param pause whether to wait for ENTER at the end (only with a terminal, see waitForEnter). False
     *              when after the script there is still something to do that must not depend on a
     *              key: the full installation re-locks the packages, and waits afterwards.
     */
    private static boolean executeScript(String scriptPath, String scriptName,
                                         java.util.Map<String, String> secrets, boolean pause, String... args) {
        return executeScript(scriptPath, scriptName, secrets, pause, (java.util.function.Consumer<String>) null, args);
    }

    /** Like above, and every line of the script also goes through {@code onLine} (if it is not null). */
    private static boolean executeScript(String scriptPath, String scriptName,
                                         java.util.Map<String, String> secrets, boolean pause,
                                         java.util.function.Consumer<String> onLine, String... args) {
        System.out.println();
        System.out.println(ANSI_CYAN + "═══════════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println(ANSI_CYAN + "  Executing: " + scriptName + ANSI_RESET);
        System.out.println(ANSI_CYAN + "  Script: " + scriptPath + ANSI_RESET);
        if (args.length > 0) {
            System.out.println(ANSI_CYAN + "  Arguments: "
                    + (secrets.isEmpty() ? String.join(" ", args)
                                         : args.length + " (hidden: this call carries a secret)")
                    + ANSI_RESET);
        }
        System.out.println(ANSI_CYAN + "═══════════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println();

        File scriptFile = new File(scriptPath);
        if (!scriptFile.exists()) {
            System.out.println(ANSI_RED + "[ERROR] Script file not found: " + scriptPath + ANSI_RESET);
            if (pause) waitForEnter();
            return false;
        }

        if (!scriptFile.canExecute()) {
            scriptFile.setExecutable(true);
        }

        try {
            String[] command = new String[2 + args.length];
            command[0] = "sh";
            command[1] = scriptPath;
            System.arraycopy(args, 0, command, 2, args.length);

            // TODO: migrate to Shell.run when touched
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            org.daemoxcp.mail.util.Shell.applyPath(processBuilder);
            processBuilder.environment().putAll(secrets);
            // The panel launches it, having just written it from its jar: the version check
            // the script does when launched by hand is not needed here (InstallScripts).
            processBuilder.environment().put(org.daemoxcp.mail.scripts.InstallScripts.FROM_PANEL, "1");
            processBuilder.redirectErrorStream(true);
            // The child's stdin is /dev/null, always. ProcessBuilder's default is a pipe
            // whose write end the JVM keeps open and never writes to: a script that reads
            // receives neither data nor EOF, and stays stuck forever. Measured on the VM:
            // a script with "read x" hangs executeScript in all three conditions -- the
            // panel's stdin on an open pipe, on /dev/null, and on a real pty with ENTER
            // ready. So it is not a fault of non-interactivity alone: that pipe is of no
            // use to anyone, because not even an operator at the terminal can answer (what
            // they type goes to the panel's stdin, read by waitForEnter(), not to the
            // script). That is why it is not conditional on nonInteractive.
            // With /dev/null the read returns EOF: the script no longer stops and its exit
            // code reaches the caller. Beware, whoever adds a script that reads: EOF is
            // not an error, so "read x" goes on with an EMPTY value. Whoever reads must
            // check the result of the read, otherwise it goes on with nothing.
            processBuilder.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
            processBuilder.directory(new File(System.getProperty("user.dir")));

            Process process = processBuilder.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                    System.out.flush();
                    if (onLine != null) onLine.accept(line);
                }
            }

            int exitCode = process.waitFor();

            System.out.println();
            System.out.println("═══════════════════════════════════════════════════════════════");

            if (exitCode == 0) {
                System.out.println(ANSI_GREEN + "  [SUCCESS] " + scriptName + " completed successfully!" + ANSI_RESET);
            } else {
                System.out.println(ANSI_RED + "  [FAILED] " + scriptName + " failed! Exit code: " + exitCode + ANSI_RESET);
            }

            System.out.println("═══════════════════════════════════════════════════════════════");
            System.out.println();
            System.out.flush();

            if (pause) waitForEnter();
            return exitCode == 0;

        } catch (Exception e) {
            System.out.println(ANSI_RED + "[ERROR] Failed to execute script: " + e.getMessage() + ANSI_RESET);
            if (pause) waitForEnter();
            return false;
        }
    }

    /**
     * Stops until someone presses ENTER. Without a terminal it does not stop and prints
     * nothing: the message assumes a reader who is not there, and the wait never ends.
     * With stdin closed System.in.read() reads EOF and the process rushes on; with stdin
     * on an open pipe -- ssh without -t, cron, a runner -- it reads nothing and stays stuck
     * forever. It was the second form that kept a successful installation stuck for seven
     * hours and fifty minutes: process alive, exit code 0, no error anywhere.
     */
    private static void waitForEnter() {
        if (nonInteractive) return;
        System.out.println(ANSI_YELLOW + org.daemoxcp.mail.i18n.I18n.tr("console.pressEnter") + ANSI_RESET);
        try {
            System.in.read();
            // Clear any remaining input
            while (System.in.available() > 0) {
                System.in.read();
            }
        } catch (IOException e) {
            // Ignore
        }
    }

    public static void main(String[] args) throws InterruptedException, IOException {
        // The web part of the separated panel: the root part starts it with
        // daemon(8) and the daemoxcp_mail user (PanelSeparation). None of what follows: migrations, scripts,
        // content and SQLite writes are the root's job, and it has already done them.
        for (String a : args) {
            if ("--web-part".equals(a)) {
                System.exit(startWebPart() ? 0 : 1);
                return;
            }
        }
        String directoryPath = "./database/";
        try {
            createDirectoryIfNotExists(directoryPath);
        } catch (IOException e) {
            // Silent
        }
        directoryPath = "./install_scripts/";
        try {
            createDirectoryIfNotExists(directoryPath);
        } catch (IOException e) {
            // Silent
        }

        // Generate all panel HTML content
        org.daemoxcp.mail.system.PathMigration.run();
        // The product name (DaemoxCP Mail, 2026-11-17) on a server installed before: folders, system user,
        // service, jar, jail. Only the service or the menu, as root, and before anyone reads those names.
        boolean renameApplies = org.daemoxcp.mail.system.ProductRename.applies(args);
        if (renameApplies) org.daemoxcp.mail.system.ProductRename.atServiceStart();
        // The comments that earlier versions wrote in Italian in the server's files, into English (2026-11-22):
        // after the product name, and before the repairs that recognise their blocks by the comment.
        if (renameApplies) org.daemoxcp.mail.system.EnglishComments.atBoot();
        // The start script written by the panel refers to the files that PathMigration has just renamed.
        org.daemoxcp.mail.system.RcScriptRepair.ensureAtBoot();
        // The root-only secrets (the MySQL root password and that of Roundcube's MySQL user) leave the
        // panel's file and go into root's: the web part, which runs as the daemoxcp_mail user, must not be
        // able to read them. Only as root; at the second start there is
        // nothing to move.
        if ("root".equals(System.getProperty("user.name"))) {
            java.util.logging.Logger log = java.util.logging.Logger.getLogger(Main.class.getName());
            try {
                java.util.List<String> moved = org.daemoxcp.mail.security.PanelSecrets.splitRootSecrets();
                if (!moved.isEmpty())
                    log.info("[RootSecrets] DONE: " + String.join(", ", moved) + " moved to "
                            + org.daemoxcp.mail.security.PanelSecrets.location(org.daemoxcp.mail.security.PanelSecrets.MYSQL_ROOT_PASSWORD) + ", readable only by root");
            } catch (RuntimeException e) {
                log.warning("[RootSecrets] the root-only secrets could not be moved out of the panel secrets file: "
                        + e.getMessage());
            }
        }
        PanelContent.generateAllContent();

        // If a package maintenance did not get to the end (panel killed, crash,
        // restart halfway), the packages were left UNLOCKED and nobody would notice
        // until a later update takes away a piece of the mail stack.
        // The recovery must happen here, at startup, before the panel is usable again.
        try {
            String restore = org.daemoxcp.mail.system.UpdateManager.restoreLocksAfterCrash();
            if (!restore.isEmpty()) System.out.println(restore);
        } catch (Exception e) {
            System.out.println("Restoring package locks failed: " + e.getMessage());
        }

        // Initialize database BEFORE screen to avoid warnings during GUI
        dbManager = new dataBaseManager();
        // First the table, then the columns: on a new server the reverse order left the configuration without
        // roundcube_ssl_chain until the second start (dataBaseManager.prepareAtStartup).
        boolean needsTableCreation = dbManager.prepareAtStartup();
        // The database and the MySQL users with the product name, before anyone goes into MySQL. After the table:
        // on a new server it reads the row of default values and has nothing to do.
        if (renameApplies) org.daemoxcp.mail.system.MysqlRename.ensureAtBoot(dbManager);

        // Before anything goes into MySQL: if an installation was interrupted with the
        // new password still pending, or if MySQL refuses the panel's (the servers broken
        // by the previous version, finding 156), MySQL is asked which one it knows. It holds for every
        // process: the --web service, the menu, the console commands. Usually it costs one
        // connection and changes nothing (PendingDbPassword.settleAtStartup).
        try {
            org.daemoxcp.mail.i18n.I18n.setCurrent("en");   // one startup line for every mode, service included: a log
            String decided;
            try { decided = org.daemoxcp.mail.system.PendingDbPassword.settleAtStartup(dbManager).message(); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            if (!decided.isEmpty()) System.out.println("[MYSQL] " + decided);
        } catch (Exception e) {
            System.out.println("Checking the panel's MySQL password failed: " + e.getMessage());
        }

        // The installation scripts rewritten by this jar at every start (service, menu, console
        // commands), and those that nobody writes any more set aside: never a script from an earlier
        // version on disk (InstallScripts, finding 169).
        try {
            createDirectoryIfNotExists("./install_scripts/");
            org.daemoxcp.mail.scripts.InstallScripts.refreshAtStartup();
        } catch (Exception e) {
            System.out.println("Writing the install scripts failed: " + e.getMessage());
        }

        // The console language (the on-screen menu and the commands below): --lang, then the panel's, then
        // English. Not for the service (--web): its lines are logs and stay in English.
        if (!java.util.Arrays.asList(args).contains("--web")) chooseConsoleLanguage(args);
        // Then --lang and its value are gone: the commands read their arguments by position
        // (--access-code --lang en took "--lang" as the administrator's name).
        args = org.daemoxcp.mail.i18n.ConsoleLanguage.withoutFlag(args);

        // The console commands, for whoever has a shell on the server (from the panel's folder):
        //   java -jar daemoxcp-mail.jar --create-admin <name> <email>   the first administrator
        //   java -jar daemoxcp-mail.jar --access-code [name]            a one-time access code
        //   java -jar daemoxcp-mail.jar --ip-family both|ipv4|ipv6|ipv6out   IPv4, IPv6, both, or IPv6 outbound (root)
        //   java -jar daemoxcp-mail.jar --empty-folders junk|trash|both all|<mailbox>...   emergency emptying (root)
        // The first administrator is not created from the web panel: whoever reached the page
        // first would become administrator.
        for (int i = 0; i < args.length; i++) {
            if ("--create-admin".equals(args[i])) {
                if (i + 2 >= args.length) {
                    System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd", "java -jar daemoxcp-mail.jar --create-admin <name> <email>")));
                    System.exit(2);
                }
                String notConnected = connectFromConfig();
                if (notConnected != null) {
                    System.err.println(notConnected);
                    System.exit(2);
                }
                System.exit(createFirstAdmin(args[i + 1], args[i + 2], System.out, System.err));
            }
            if ("--access-code".equals(args[i])) {
                System.exit(printAccessCode(i + 1 < args.length ? args[i + 1] : null));
            }
            if ("--ip-family".equals(args[i])) {
                System.exit(setIpFamily(i + 1 < args.length ? args[i + 1] : null));
            }
            if ("--addresses".equals(args[i])) {
                System.exit(addresses(i + 1 < args.length ? args[i + 1] : null));
            }
            if ("--empty-folders".equals(args[i])) {
                System.exit(emptyFolders(java.util.Arrays.copyOfRange(args, i + 1, args.length)));
            }
            // The full reinstallation detached from the menu (ReinstallJob): the menu option launches
            // it with daemon(8), in a session of its own, and follows it. Whoever closes the terminal
            // or kills the menu no longer stops it halfway (finding 163). The outcome goes to the given file.
            if ("--reinstall".equals(args[i])) {
                nonInteractive = true;
                String host = i + 1 < args.length ? args[i + 1].trim() : "";
                Path exitFile = i + 2 < args.length ? Path.of(args[i + 2]) : null;
                if (!org.daemoxcp.mail.system.ReinstallJob.validHostname(host)) {
                    System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd", "java -jar daemoxcp-mail.jar --reinstall <mail hostname> [result file]")));
                    if (exitFile != null) org.daemoxcp.mail.system.ReinstallJob.writeExit(exitFile, false);
                    System.exit(2);
                }
                // The script is ALWAYS rewritten from this jar, right before running it: launched by hand
                // after a jar update, a "only if missing" would use the old one (finding 169).
                createDirectoryIfNotExists("./install_scripts/");
                new FullMailServerScript().write_file();
                boolean ok = false;
                try {
                    ok = runInstallation(host);
                } finally {
                    if (exitFile != null) org.daemoxcp.mail.system.ReinstallJob.writeExit(exitFile, ok);
                }
                System.out.flush();
                System.exit(ok ? 0 : 1);
            }
        }

        // Web-only mode: no on-screen menu.
        //
        // It is needed because the panel must be able to come back up ON ITS OWN after it shut down to
        // update its own JVM. The on-screen interface (Lanterna) demands a terminal,
        // and a detached script does not have one: without this mode the process would restart
        // and die at once, leaving the web panel unreachable.
        // The web server on its own has never needed the terminal: it only uses System.out.
        boolean webOnly = false;
        for (String a1 : args) if ("--web".equals(a1)) webOnly = true;
        if (webOnly) {
            // --web is the service: no key to press, whatever the terminal says.
            nonInteractive = true;
            System.out.println("Starting in web-only mode: no on-screen menu.");
            System.out.println("To see the menu again: stop this process and start it again without --web.");
            // If the server does not start the process must exit non-zero: with exit 0 whoever
            // restarted the panel believes it is back up, while it is actually down.
            System.exit(startWebServer() ? 0 : 1);
            return;
        }

        // Convenience, not dependency: the panel needs run.sh neither to work nor
        // to restart on its own (it rebuilds the restart line from the live process).
        // If it is missing, though, it writes it, so there is a short way to start --web by hand.
        try {
            // The message shared with the panel, in the console language.
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            String created;
            try { created = org.daemoxcp.mail.system.UpdateManager.createRunSh(); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            if (!created.isEmpty()) System.out.println(created);
        } catch (Exception e) {
            // If it cannot write next to the jar it is not a problem: it was only for convenience.
        }

        // NOW start screen (after SQLite native libs are loaded)
        Screen screen = null;
        try {
            screen = new DefaultTerminalFactory().createScreen();
            screen.startScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        MultiWindowTextGUI gui = new MultiWindowTextGUI(screen, new DefaultWindowManager(), new EmptySpace(TextColor.ANSI.BLUE));
        Welcome simpleBox = new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.info"), org.daemoxcp.mail.i18n.I18n.tr("console.welcome", java.util.Map.of("product", org.daemoxcp.mail.i18n.I18n.tr("brand.name"))));
        simpleBox.show(gui);

        if (needsTableCreation) {
            Welcome success = new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.info"), org.daemoxcp.mail.i18n.I18n.tr("console.dbReady"));
            success.show(gui);
        }

        // Generate install scripts
        generateInstallScripts(gui);

        // If the last full reinstallation did not finish, it is said as soon as the menu opens, with the
        // two roads: option 6 (the previous server) or option 4 (redo it).
        String unfinished = reinstallAttention();
        if (!unfinished.isEmpty()) new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.attention"), unfinished).show(gui);

        // Main loop
        if (dbManager.check_tables() > 0) {
            while (true) {
                Chooser chooser = new Chooser();
                try {
                    chooser.run(gui);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                switch (chooser.option) {
                    case 0:
                        // Exit
                        screen.stopScreen();
                        System.exit(0);
                        break;

                    case 1: {
                        // Time zone, NTP and DNS. The time zone is chosen by whoever installs (finding 242):
                        // before it was always Europe/Rome. The one the system already has is proposed, and a
                        // wrong name does not go.
                        String zone = showTextInputDialogWithDefault(gui, org.daemoxcp.mail.i18n.I18n.tr("console.tz.title"),
                                org.daemoxcp.mail.i18n.I18n.tr("console.tz.ask"),
                                org.daemoxcp.mail.system.SystemTimeZone.current());
                        if (zone == null) break;
                        zone = zone.trim();
                        String zoneProblem = org.daemoxcp.mail.system.SystemTimeZone.problem(zone);
                        if (zoneProblem != null) {
                            new com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder().setTitle(org.daemoxcp.mail.i18n.I18n.tr("console.tz.title")).setText(zoneProblem)
                                    .addButton(MessageDialogButton.OK).build().showDialog(gui);
                            break;
                        }
                        try {
                            screen.stopScreen();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        executeScript("./install_scripts/setup_timezone_and_dns.sh", "Time zone, clock (NTP) and DNS resolver", zone);
                        try {
                            screen.startScreen();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    }

                    case 2:
                        // Edit Panel Configuration
                        ModifyData data = new ModifyData(dbManager);
                        data.show(gui);
                        break;

                    case 3:
                        // Edit Roundcube Configuration
                        RoundcubeConfig rcConfig = new RoundcubeConfig(dbManager);
                        rcConfig.show(gui);
                        break;

                    case 4:
                        // Install/Reinstall Complete Mail Server
                        installMailServer(screen, gui);
                        break;

                    case 5:
                        // The emergency access code (or the first administrator)
                        emergencyAccess(gui);
                        break;

                    case 6:
                        // Go back to the server as it was before the last reinstallation (ReinstallReturn)
                        goBackFromMenu(screen, gui);
                        break;

                    case 100:
                        // Start the DaemoxCP Mail web server
                        try {
                            screen.stopScreen();
                            startWebServer();
                        } catch (Exception ex) {
                            ex.printStackTrace();
                        }
                        break;

                    default:
                        continue;
                }
            }
        }

        try {
            screen.stopScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void generateInstallScripts(MultiWindowTextGUI gui) {
        // The scripts are rewritten at every start (InstallScripts.refreshAtStartup, before the menu): here
        // they are rewritten again and something is said only if they are NOT written. Before, written only "if
        // missing", the window appeared the first time; written always, two windows would appear
        // to close at every opening of the menu (finding 172).
        SetTimeOnSystemScript timezoneScript = new SetTimeOnSystemScript();
        timezoneScript.write_file();
        if (!timezoneScript.writed)
            new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.attention"), org.daemoxcp.mail.i18n.I18n.tr("console.cannotWriteScript", java.util.Map.of("script", "install_scripts/setup_timezone_and_dns.sh"))).show(gui);

        FullMailServerScript mailServerScript = new FullMailServerScript();
        mailServerScript.write_file();
        if (!mailServerScript.writed)
            new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.attention"), org.daemoxcp.mail.i18n.I18n.tr("console.cannotWriteScript", java.util.Map.of("script", "install_scripts/install_mail_server.sh"))).show(gui);
    }

    /**
     * The text for the menu if the last full reinstallation did not finish: interrupted (the notice from
     * PackageRecovery knows it) or failed after it began changing the system (ReinstallJob). ""
     * if there is nothing to say.
     */
    static String reinstallAttention() {
        boolean interrupted = org.daemoxcp.mail.system.PackageRecovery.notice().optBoolean("reinstall");
        String failedLog = org.daemoxcp.mail.system.ReinstallJob.lastFailedAfterChanges();
        if (!interrupted && failedLog.isEmpty()) return "";
        String wayBack = org.daemoxcp.mail.system.ReinstallReturn.latest();
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            return org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.menuAttention", java.util.Map.of(
                    "log", failedLog.isEmpty() ? "-" : failedLog,
                    "wayBack", wayBack.isEmpty() ? org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.none") : wayBack));
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
    }

    /**
     * Menu option 6: goes back to the server as it was before the last reinstallation, with the mail that
     * arrived afterwards merged in (ReinstallReturn). Then asks whether to restart now: the moment is chosen by
     * whoever is at the terminal.
     */
    private static void goBackFromMenu(Screen screen, MultiWindowTextGUI gui) {
        String name = org.daemoxcp.mail.system.ReinstallReturn.latest();
        if (name.isEmpty()) {
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try { new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.menu.backTitle"), org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.none")).show(gui); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            return;
        }
        try { screen.stopScreen(); } catch (IOException e) { throw new RuntimeException(e); }
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            System.out.println(ANSI_CYAN + "[WAY BACK] " + name + ANSI_RESET);
            JSONObjectHolder.last = org.daemoxcp.mail.system.ReinstallReturn.goBack(name,
                    line -> System.out.println(ANSI_CYAN + "[WAY BACK] " + line + ANSI_RESET));
            org.json.JSONObject r = JSONObjectHolder.last;
            if (!r.optBoolean("success")) {
                System.out.println(ANSI_RED + "[STOPPED] " + r.optString("error") + ANSI_RESET);
            } else {
                System.out.println(ANSI_GREEN + r.optString("note") + ANSI_RESET);
                if (!nonInteractive) {
                    System.out.print(org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.askReboot") + " ");
                    System.out.flush();
                    String answer = new BufferedReader(new InputStreamReader(System.in)).readLine();
                    if (answer != null && answer.trim().equalsIgnoreCase("yes")) {
                        System.out.println(org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.rebooting"));
                        System.out.flush();
                        org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(30), "shutdown -r now");
                    } else {
                        System.out.println(org.daemoxcp.mail.i18n.I18n.tr("server.wayBack.rebootLater"));
                    }
                }
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + e.getMessage() + ANSI_RESET);
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
        System.out.flush();
        waitForEnter();
        try { screen.startScreen(); } catch (IOException e) { throw new RuntimeException(e); }
    }

    /** The outcome of the last return requested from the menu (the tests read it). */
    static final class JSONObjectHolder { static volatile org.json.JSONObject last; }

    /** The panel name saved with option 2, "" if there is none. */
    private static String savedPanelHost() {
        try (ResultSet r = dbManager.get_data_config()) {
            if (r.next()) {
                String h = r.getString("panel_host");
                return h == null ? "" : h.trim();
            }
        } catch (Exception ignored) {
            // no configuration: no name
        }
        return "";
    }

    /**
     * Install/Reinstall the complete mail server
     */
    private static void installMailServer(Screen screen, MultiWindowTextGUI gui) {
        // Always ask for hostname (pre-fill with saved value if exists)
        String savedHostname = dbManager.getMailHostname();
        String defaultValue = (savedHostname != null && !savedHostname.trim().isEmpty())
                ? savedHostname : "mail.example.com";

        String mailHostname = showTextInputDialogWithDefault(gui, org.daemoxcp.mail.i18n.I18n.tr("console.install.hostTitle"),
                org.daemoxcp.mail.i18n.I18n.tr("console.install.hostAsk"), defaultValue);

        if (mailHostname == null || mailHostname.trim().isEmpty()) {
            Welcome cancelled = new Welcome(org.daemoxcp.mail.i18n.I18n.tr("console.install.cancelledTitle"), org.daemoxcp.mail.i18n.I18n.tr("console.install.cancelled"));
            cancelled.show(gui);
            return;
        }

        // The three names before starting (finding 244): the webmail no longer the example one, mail and web on
        // different names (mail stays outside Cloudflare's proxy). The warnings let you choose.
        org.daemoxcp.mail.system.InstallNames.Result names = org.daemoxcp.mail.system.InstallNames.check(
                mailHostname.trim(), dbManager.getRoundcubeDomain(), savedPanelHost());
        if (!names.problems().isEmpty()) {
            new com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder().setTitle(org.daemoxcp.mail.i18n.I18n.tr("console.install.beforeTitle"))
                    .setText(org.daemoxcp.mail.i18n.I18n.tr("console.install.notStarting") + "\n\n- " + String.join("\n- ", names.problems()))
                    .addButton(MessageDialogButton.OK).build().showDialog(gui);
            return;
        }
        if (!names.warnings().isEmpty()) {
            MessageDialogButton go = new com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder().setTitle(org.daemoxcp.mail.i18n.I18n.tr("console.install.beforeTitle"))
                    .setText("- " + String.join("\n- ", names.warnings()) + "\n\n" + org.daemoxcp.mail.i18n.I18n.tr("console.install.anyway"))
                    .addButton(MessageDialogButton.Cancel).addButton(MessageDialogButton.OK).build().showDialog(gui);
            if (go != MessageDialogButton.OK) return;
        }

        try {
            screen.stopScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Detached from the menu (ReinstallJob): the menu launches it and follows it. If this terminal
        // closes, the reinstallation goes on by itself to the end.
        org.daemoxcp.mail.system.ReinstallJob.runFromMenu(mailHostname.trim(), System.out);

        // A single wait, at the end: after re-locking the packages, not before. With the wait
        // inside executeScript, whoever closed the terminal in front of "Press ENTER" killed the
        // process with the packages still unlocked (only the next start re-locked them).
        waitForEnter();

        try {
            screen.startScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The full installation, without the name window: it is what the menu option does
     * after the name has been written. Public for the test driver
     * (tests/org/daemoxcp/mail/system/MenuReinstall.java), which in this way tests exactly this code.
     *
     * On the package turn, with the locked packages unlocked first and re-locked
     * at the end (InstallLocks). The turn and the unlock come BEFORE any change:
     * before the name, the service flags and above all the new MySQL password, which,
     * saved without an installation, would leave the panel with a password MySQL does not know.
     *
     * @return true if the script exited with 0
     */
    public static boolean runInstallation(String mailHostname) {
        InstallLocks.Start start;
        // The way back (finding 156): a boot environment made with the turn taken and BEFORE the
        // unlock, that is, with the server as it is now, locked packages included. The script deletes
        // the configurations, empties /var/vmail and recreates the MySQL tables: without it, going back
        // from a reinstallation gone wrong was not possible. If the system has boot environments and
        // this one cannot be created, the installation does not start (the rule of package jobs).
        org.daemoxcp.mail.system.PackageWayBack.Prepared[] wayBack = {null};
        java.util.function.Consumer<String> wayBackLog =
                line -> { if (!line.isEmpty()) System.out.println(ANSI_CYAN + "[WAY BACK] " + line + ANSI_RESET); };
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            start = InstallLocks.prepare(org.daemoxcp.mail.i18n.I18n.tr("server.reinstall.turn"), () -> {
                try {
                    // The space before the way back: with less than 1 GB free it stops here, and
                    // otherwise it says how much the way back will keep occupied (finding 170).
                    String noSpace = org.daemoxcp.mail.system.PackageWayBack.reinstallSpace(wayBackLog);
                    if (noSpace != null) return noSpace;
                    wayBack[0] = org.daemoxcp.mail.system.PackageWayBack.beforeInstallation(wayBackLog);
                    return null;
                } catch (IllegalStateException e) {
                    return e.getMessage();
                }
            });
        }
        finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
        if (start.refusal() != null) {
            System.out.println(ANSI_RED + "[STOPPED] " + start.refusal() + ANSI_RESET);
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try { System.out.println(ANSI_RED + org.daemoxcp.mail.i18n.I18n.tr("server.reinstall.notStarted") + ANSI_RESET); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            System.out.flush();
            return false;
        }
        if (!start.report().isEmpty()) System.out.println(ANSI_YELLOW + "[LOCKS] " + start.report() + ANSI_RESET);
        boolean success = false;
        java.util.concurrent.atomic.AtomicBoolean systemTouched = new java.util.concurrent.atomic.AtomicBoolean(false);
        try {
            success = installOnTurn(mailHostname, systemTouched);
        } finally {
            String back;
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try { back = InstallLocks.finish(start.held()); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            if (!back.isEmpty()) {
                boolean allBack = !org.daemoxcp.mail.system.PackageQueue.statePresent();
                System.out.println((allBack ? ANSI_GREEN : ANSI_RED) + "[LOCKS] " + back + ANSI_RESET);
            }
            // After re-locking: the boot environment stays if the script began changing
            // the system, and is removed if it stopped before.
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try { org.daemoxcp.mail.system.PackageWayBack.afterInstallation(wayBackLog, wayBack[0], systemTouched.get()); }
            catch (RuntimeException e) { System.out.println(ANSI_YELLOW + "[WAY BACK] " + e.getMessage() + ANSI_RESET); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            System.out.flush();
        }
        return success;
    }

    /** The body of the installation, with the turn already taken and the packages already unlocked. */
    private static boolean installOnTurn(String mailHostname) {
        return installOnTurn(mailHostname, new java.util.concurrent.atomic.AtomicBoolean(false));
    }

    /**
     * @param systemTouched becomes true when the script reaches phase 1, that is, starts
     *        stopping services and deleting configurations. Before that point the script only checks
     *        (turn, parameters, Roundcube, locked packages) and changes nothing.
     */
    private static boolean installOnTurn(String mailHostname, java.util.concurrent.atomic.AtomicBoolean systemTouched) {
        // Save hostname
        dbManager.setMailHostname(mailHostname);

        // Reset all service flags in SQLite (fresh install/reinstall)
        System.out.println(ANSI_YELLOW + "[RESET] Resetting service flags for fresh installation..." + ANSI_RESET);
        dbManager.resetAllServices();

        // Read MySQL config (the password from the panel secrets file)
        String mysqlHost = "127.0.0.1";
        String mysqlPort = "3306";
        String mysqlUser = org.daemoxcp.mail.system.Product.ID;
        String mysqlPassword = "";
        String mysqlDatabase = org.daemoxcp.mail.system.Product.ID;

        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                mysqlHost = result.getString("mysql_host");
                mysqlPort = result.getString("mysql_port");
                mysqlUser = result.getString("mysql_user");
                mysqlPassword = dbManager.mysqlPassword();
                mysqlDatabase = result.getString("mysql_database");
            }
        } catch (Exception e) {
            System.out.println(ANSI_YELLOW + "[WARNING] Could not read MySQL config: " + e.getMessage() + ANSI_RESET);
        }

        // A new password at every installation, but PENDING: the panel's stays the
        // old one until MySQL knows the new one. Before, it was written at once as the panel's
        // password, and every exit of the script before phase 3 (Roundcube not configured, a
        // missing parameter, the turn, a locked package, pkg) left the panel with a
        // password MySQL refused (finding 156). The decision is after the script, below.
        org.daemoxcp.mail.system.PendingDbPassword.Store passwordStore =
                org.daemoxcp.mail.system.PendingDbPassword.panelStore(dbManager);
        org.daemoxcp.mail.system.PendingDbPassword.Probe mysqlProbe =
                org.daemoxcp.mail.system.PendingDbPassword.mysqlProbe(mysqlHost, mysqlPort, mysqlUser);
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            org.daemoxcp.mail.system.PendingDbPassword.Prepared prepared =
                    org.daemoxcp.mail.system.PendingDbPassword.prepare(passwordStore, mysqlProbe, mysqlUser);
            mysqlPassword = prepared.password();
            if (!prepared.note().isEmpty()) System.out.println(ANSI_YELLOW + "[MYSQL] " + prepared.note() + ANSI_RESET);
            System.out.println(ANSI_GREEN + "[AUTO] " + org.daemoxcp.mail.i18n.I18n.tr("server.dbPassword.aside") + ANSI_RESET);
        } catch (RuntimeException e) {
            System.out.println(ANSI_RED + "[STOPPED] " + org.daemoxcp.mail.i18n.I18n.tr("server.dbPassword.cannotAside",
                    java.util.Map.of("err", String.valueOf(e.getMessage()))) + ANSI_RESET);
            System.out.flush();
            return false;
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }

        // The MySQL root password. That one is NOT regenerated at every installation: it is
        // generated the first time and then it stays, because if MySQL is already there root already uses it
        // (a reinstallation of the panel is not a reinstallation of the database). Before, it
        // did not exist at all and root got in with nothing: the script ran "mysql -u root"
        // and, if that failed, "mysql -u root --password=".
        String mysqlRootPassword = org.daemoxcp.mail.security.PanelSecrets.ensureMysqlRootPassword();
        System.out.println(ANSI_GREEN + "[AUTO] MySQL root password ready in the panel secrets file" + ANSI_RESET);

        // The password of the webmail's MySQL user (roundcube): like root's, it is generated
        // only once, because the boot migration reads it back from there (RoundcubeDbUser).
        String roundcubeDbPassword = org.daemoxcp.mail.security.PanelSecrets.ensureRoundcubeDbPassword();

        // Read Roundcube configuration
        String roundcubeDomain = dbManager.getRoundcubeDomain();
        String roundcubePort = dbManager.getRoundcubePort();
        String roundcubeSslCert = dbManager.getRoundcubeSslCert();
        String roundcubeSslKey = dbManager.getRoundcubeSslKey();
        String roundcubeSslChain = dbManager.getRoundcubeSslChain();

        // If Roundcube SSL is not configured, use Panel's SSL certificates
        if ((roundcubeSslCert == null || roundcubeSslCert.isEmpty()) &&
            (roundcubeSslKey == null || roundcubeSslKey.isEmpty())) {
            try {
                // Read panel's SSL certificates from database
                try (java.sql.ResultSet configResult = dbManager.get_data_config()) {
                    if (configResult.next()) {
                        String panelCert = configResult.getString("panel_ssl_cert");
                        String panelKey = dbManager.panelTlsKey();
                        String panelChain = null;
                        try {
                            panelChain = configResult.getString("panel_ssl_chain");
                        } catch (Exception ignored) {}

                        if (panelCert != null && !panelCert.isEmpty() &&
                            panelKey != null && !panelKey.isEmpty() &&
                            panelCert.contains("-----BEGIN CERTIFICATE-----")) {

                            // Save panel certificates to files for nginx
                            String panelSslDir = "/usr/local/etc/ssl/panel";
                            java.nio.file.Files.createDirectories(java.nio.file.Paths.get(panelSslDir));

                            String panelCertPath = panelSslDir + "/fullchain.pem";
                            String panelKeyPath = panelSslDir + "/privkey.pem";
                            String panelChainPath = panelSslDir + "/chain.pem";

                            java.nio.file.Files.writeString(java.nio.file.Paths.get(panelCertPath), panelCert);
                            java.nio.file.Files.writeString(java.nio.file.Paths.get(panelKeyPath), panelKey);

                            // Set secure permissions on key
                            Runtime.getRuntime().exec(new String[]{"chmod", "600", panelKeyPath}).waitFor();

                            // Use panel's certificate paths for Roundcube
                            roundcubeSslCert = panelCertPath;
                            roundcubeSslKey = panelKeyPath;

                            if (panelChain != null && !panelChain.isEmpty()) {
                                java.nio.file.Files.writeString(java.nio.file.Paths.get(panelChainPath), panelChain);
                                roundcubeSslChain = panelChainPath;
                            }

                            System.out.println(ANSI_GREEN + "[SSL] Using Panel SSL certificates for Roundcube" + ANSI_RESET);
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println(ANSI_YELLOW + "[SSL] Could not load Panel certificates: " + e.getMessage() + ANSI_RESET);
            }
        }

        // Execute the unified mail server installation script. The passwords travel
        // in the environment and not among the arguments: anyone can read an argument with "ps".
        // Without waiting for a key at the end: installMailServer does it, after re-locking.
        // DAEMOXCP_MAIL_PACKAGE_TURN tells the script that the package turn is held by this
        // process, its parent: without it, the script would take the turn itself with lockf, would
        // find it taken by us and would stop. The script does not take our word for it: it checks
        // that the lock is taken and that this pid is inside (FullMailServerScript).
        boolean success = executeScript("./install_scripts/install_mail_server.sh",
                "Complete Mail Server Installation",
                java.util.Map.of("MYSQL_PASSWORD", mysqlPassword,
                                 "MYSQL_ROOT_PASSWORD", mysqlRootPassword,
                                 "ROUNDCUBE_DB_PASSWORD", roundcubeDbPassword,
                                 "DAEMOXCP_MAIL_PACKAGE_TURN", String.valueOf(ProcessHandle.current().pid())),
                false,
                line -> { if (line.contains("[PHASE 1/10]")) systemTouched.set(true); },
                mysqlHost, mysqlPort, mysqlUser, mysqlDatabase, mailHostname.trim(),
                roundcubeDomain, roundcubePort, roundcubeSslCert, roundcubeSslKey, roundcubeSslChain);

        // Which password MySQL knows now: MySQL says it, not the exit code. A script
        // that failed after phase 3 has already given MySQL (and Postfix and Dovecot) the new password;
        // one stopped before has not. The package turn is still ours (runInstallation).
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            org.daemoxcp.mail.system.PendingDbPassword.Result decided =
                    org.daemoxcp.mail.system.PendingDbPassword.settle(passwordStore, mysqlProbe, mysqlUser);
            if (decided.outcome() == org.daemoxcp.mail.system.PendingDbPassword.Outcome.NEW_ADOPTED) {
                // The rest of the MySQL configuration (host, port, user, database) in SQLite.
                dbManager.update_mysql_config(mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase);
                // A new password the webmail has never had: nothing to change at startup (finding 232).
                org.daemoxcp.mail.system.PanelDbPassword.markFreshFromInstallation();
            }
            boolean good = decided.outcome() == org.daemoxcp.mail.system.PendingDbPassword.Outcome.NEW_ADOPTED
                    || decided.outcome() == org.daemoxcp.mail.system.PendingDbPassword.Outcome.OLD_KEPT
                    || decided.outcome() == org.daemoxcp.mail.system.PendingDbPassword.Outcome.COPY_ADOPTED;
            if (!decided.message().isEmpty())
                System.out.println((good ? ANSI_GREEN : ANSI_YELLOW) + "[MYSQL] " + decided.message() + ANSI_RESET);
        } catch (RuntimeException e) {
            System.out.println(ANSI_YELLOW + "[MYSQL] " + org.daemoxcp.mail.i18n.I18n.tr("server.dbPassword.settleFailed",
                    java.util.Map.of("err", String.valueOf(e.getMessage()))) + ANSI_RESET);
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
        System.out.flush();

        // The scripts write the panel's user into Postfix's maps and Dovecot's connection: we switch
        // at once to their own users (MailDbUsers), which read only the columns they use. If something does not
        // add up the files stay as the script wrote them, and the next panel start tries again.
        // First the panel's tables, complete (finding 248): the installation creates only the mail ones, and the
        // others (access, passkeys, columns added later like mailboxes.receive_enabled) arrived only at the first
        // start of the web server or with --create-admin. Without them, MailDbUsers below did not find
        // receive_enabled and left Postfix and Dovecot on the panel's user until startup, and menu option 5
        // stopped.
        if (success) {
            String notConnected = connectFromConfig();
            if (notConnected != null) {
                System.out.println(ANSI_YELLOW + "[PANEL] the panel's tables are completed at the first start: " + notConnected + ANSI_RESET);
            } else {
                try {
                    mailDatabase.createSchema();
                    mailDatabase.ensureColumnUpgrades();
                } catch (Exception e) {
                    System.out.println(ANSI_YELLOW + "[PANEL] the panel's tables are completed at the first start: " + e.getMessage() + ANSI_RESET);
                }
            }
        }
        if (success) org.daemoxcp.mail.system.MailDbUsers.ensureAfterInstall(mysqlHost, mysqlPort, mysqlUser, mysqlDatabase);

        if (success) {
            // Mark all services as installed
            dbManager.setServiceInstalled("postfix", true);
            dbManager.setServiceInstalled("dovecot", true);
            dbManager.setServiceInstalled("rspamd", true);
            dbManager.setServiceInstalled("clamav", true);

            // The panel's accounts go away with the tables (the script recreates them empty): whoever
            // reinstalled must know that the web panel lets nobody in until they create the
            // first administrator from the console.
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try {
                System.out.println(ANSI_YELLOW + "[PANEL] " + org.daemoxcp.mail.i18n.I18n.tr("server.reinstall.accountsDeleted") + ANSI_RESET);
            } finally {
                org.daemoxcp.mail.i18n.I18n.clearCurrent();
            }

            // Auto-load the generated self-signed certificate ONLY if no certificate is configured
            // This prevents overwriting user-configured Cloudflare certificates
            try {
                // Check if user already has certificates configured
                boolean hasCertConfigured = false;
                try (ResultSet configResult = dbManager.get_data_config()) {
                    if (configResult.next()) {
                        String existingCert = configResult.getString("panel_ssl_cert");
                        if (existingCert != null && !existingCert.trim().isEmpty()
                            && existingCert.contains("-----BEGIN CERTIFICATE-----")) {
                            hasCertConfigured = true;
                            System.out.println(ANSI_GREEN + "[KEEP] Existing SSL certificate preserved (not overwritten)" + ANSI_RESET);
                        }
                    }
                }

                // Only load self-signed if no certificate is configured. The name, port and prefix written with
                // option 2 stay (finding 244): before, they always became 0.0.0.0, 2096 and daemoxcp-mail-.
                String keptHost = "", keptPort = "", keptPrefix = "";
                try (ResultSet configResult = dbManager.get_data_config()) {
                    if (configResult.next()) {
                        keptHost = String.valueOf(configResult.getString("panel_host")).trim();
                        keptPort = String.valueOf(configResult.getString("panel_port")).trim();
                        keptPrefix = String.valueOf(configResult.getString("panel_sessions_prefix")).trim();
                    }
                }
                if (!hasCertConfigured) {
                    String certPath = "/usr/local/etc/ssl/mail/fullchain.pem";
                    String keyPath = "/usr/local/etc/ssl/mail/privkey.pem";

                    java.io.File certFile = new java.io.File(certPath);
                    java.io.File keyFile = new java.io.File(keyPath);

                    if (certFile.exists() && keyFile.exists()) {
                        String certContent = new String(java.nio.file.Files.readAllBytes(certFile.toPath()));
                        String keyContent = new String(java.nio.file.Files.readAllBytes(keyFile.toPath()));

                        // Update panel config with the self-signed cert so web panel can start
                        dbManager.update_panel_config(
                            org.daemoxcp.mail.security.PemTls.dnsName(keptHost) ? keptHost : "0.0.0.0",
                            keptPort.matches("[0-9]{1,5}") ? keptPort : "2096",
                            certContent,
                            keyContent,
                            "",          // chain (empty for self-signed)
                            keptPrefix.matches("[a-zA-Z0-9_-]{1,20}") ? keptPrefix : org.daemoxcp.mail.system.Product.SLUG + "-"
                        );
                        System.out.println(ANSI_GREEN + "[AUTO] Self-signed certificate loaded into panel configuration" + ANSI_RESET);
                        System.out.println(ANSI_YELLOW + "The panel uses the mail server's self-signed certificate for now:"
                                + " set the panel's own certificate (for example the Cloudflare Origin Certificate) with"
                                + " menu option 2." + ANSI_RESET);
                    }
                }
            } catch (Exception e) {
                System.out.println(ANSI_YELLOW + "[WARNING] Could not auto-load certificate: " + e.getMessage() + ANSI_RESET);
            }

            // The installation ends with the server already closed (install from the README, 2026-11-20). The script
            // leaves a minimal pf.conf that lets everything through, and MySQL listening on every interface, X protocol
            // too (33060): until today only the panel's first start closed them, and whoever installed without starting
            // it, or started it hours later, stayed open. The same two closures as the first start, with the same code:
            // afterwards, the start finds nothing to do. They read the panel and webmail ports from the configuration
            // just written above. MySQL first, because it restarts it; then pf.
            org.daemoxcp.mail.system.MysqlListen.ensureAtBoot();
            org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();

            System.out.println(ANSI_GREEN + "Mail server installed successfully!" + ANSI_RESET);
            System.out.flush();
        }
        return success;
    }

    /**
     * True when there is nobody who can press a key: start from rc.d, from cron, from a
     * runner, or an `ssh host 'java ...'` without -t.
     *
     * It is class state and not a parameter because it used to be a parameter: it reached this
     * function only and the other six waits stayed uncovered, executeScript() included, which is the one
     * that kept a process stuck for seven hours and fifty minutes after an installation that ended well.
     * Here it is read by waitForEnter() and startWebServer(), which are all the points where the
     * process stops to wait for a person.
     *
     * The terminal decides it, not the command line: Console.isTerminal() is true only if
     * stdin AND stdout are a tty, so even a `| tail` turns it off. --web forces it anyway,
     * because it means "be the service" even if whoever launches it has a terminal in front of them.
     */
    private static boolean nonInteractive = !hasTerminal();

    private static boolean hasTerminal() {
        java.io.Console console = System.console();
        return console != null && console.isTerminal();
    }

    /**
     * Starts the panel's server and keeps listening.
     *
     * @return true if the server started, false on every configuration error and if the
     *         port was taken. The non-interactive caller makes it its own exit
     *         code: without a terminal nobody reads the red message on screen.
     *         On the success path it does not return: either it keeps listening, or it waits for ENTER.
     */
    private static boolean startWebServer() {
        // One panel at a time (PanelInstanceLock): before any repair at startup and before taking the
        // place of the web part, which, if a panel is already running, belongs to it.
        String running = org.daemoxcp.mail.system.PanelInstanceLock.acquire(java.time.Duration.ofSeconds(30));
        if (running != null) {
            System.out.println();
            System.out.println(ANSI_YELLOW + org.daemoxcp.mail.system.Product.NAME + " is ALREADY RUNNING (pid " + running
                    + "): nothing was started, and the running panel was not touched." + ANSI_RESET);
            System.out.println("If it was started from the menu, press Enter in that terminal; if it is the service: "
                    + "service " + org.daemoxcp.mail.system.PanelRcScript.NAME + " stop");
            waitForEnter();
            return false;
        }
        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                String certContent = result.getString("panel_ssl_cert");
                String keyContent = dbManager.panelTlsKey();
                int port = Integer.parseInt(result.getString("panel_port"));
                String host = result.getString("panel_host");

                // Validate SSL
                if (certContent == null || certContent.trim().isEmpty()) {
                    System.out.println(ANSI_RED + "ERROR: SSL Certificate is empty!" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Configure SSL in 'Edit Panel Configuration'" + ANSI_RESET);
                    waitForEnter();
                    return false;
                }

                if (keyContent == null || keyContent.trim().isEmpty()) {
                    System.out.println(ANSI_RED + "ERROR: SSL Private Key is empty!" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Configure SSL in 'Edit Panel Configuration'" + ANSI_RESET);
                    waitForEnter();
                    return false;
                }

                if (!certContent.contains("-----BEGIN CERTIFICATE-----")) {
                    System.out.println(ANSI_RED + "ERROR: Invalid SSL Certificate format!" + ANSI_RESET);
                    waitForEnter();
                    return false;
                }

                if (!keyContent.contains("-----BEGIN PRIVATE KEY-----") &&
                    !keyContent.contains("-----BEGIN RSA PRIVATE KEY-----") &&
                    !keyContent.contains("-----BEGIN EC PRIVATE KEY-----")) {
                    System.out.println(ANSI_RED + "ERROR: Invalid SSL Private Key format!" + ANSI_RESET);
                    waitForEnter();
                    return false;
                }

                // From now on the panel looks at the request's Host, and with a wildcard
                // address that name does not exist: localhost and the addresses of
                // this machine are accepted. It is the normal state after installation, which writes
                // 0.0.0.0, so it is said at startup instead of leaving it to be discovered by whoever
                // opens the panel with a name and gets refused.
                if (org.daemoxcp.mail.webserver.HostCheck.isWildcardHost(host)) {
                    System.out.println(ANSI_YELLOW + "The panel address is " + host
                            + " (listen everywhere), so it answers to localhost and to this"
                            + " machine's own addresses "
                            + org.daemoxcp.mail.webserver.HostCheck.localAddresses() + "." + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "To reach it by name — and the passkeys need"
                            + " a name — write it in 'Edit Panel Configuration'." + ANSI_RESET);
                }

                // Connect to MySQL for mail data
                String mysqlHost = result.getString("mysql_host");
                String mysqlPort = result.getString("mysql_port");
                String mysqlUser = result.getString("mysql_user");
                String mysqlPassword = dbManager.mysqlPassword();
                String mysqlDatabase = result.getString("mysql_database");
                // Once the values are read, the SQLite read is closed HERE and not at the end of the try: on
                // the good path this method does not return (it keeps listening), and the open ResultSet
                // kept the read, that is, the SHARED lock on the file, for the whole life of the service.
                // Every write by another process from the same folder (the menu, the console)
                // ended in SQLITE_BUSY: measured on the clone on 2026-11-06 (findings 156 and 160).
                result.close();

                mailDatabase = new MailDatabase();

                mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // reads the password again at every reconnection
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mysqlAvailable = true;
                    // The tables of passwordless access, before the server answers.
                    try {
                        if (mailDatabase.hasAdminUser()) {
                            org.daemoxcp.mail.security.AuthStore.migrate();
                            warnIfNoLogin();
                        }
                    } catch (Exception e) {
                        System.out.println(ANSI_RED + "Login tables not ready: " + e.getMessage() + ANSI_RESET);
                    }
                    setupRequired = !mailDatabase.hasAdminUser();
                    if (setupRequired)
                        System.out.println(ANSI_YELLOW + "No administrator yet. Create the first one from the console:\n"
                                + "  java -jar daemoxcp-mail.jar --create-admin <name> <email>" + ANSI_RESET);
                    System.out.println(ANSI_GREEN + "Connected to MySQL database" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_YELLOW + "[WARNING] Could not connect to MySQL database" + ANSI_RESET);
                    System.out.println(ANSI_YELLOW + "Some features will be unavailable" + ANSI_RESET);
                }

                // A port already taken almost always means one thing only: the panel is
                // already running. Since it can restart on its own after the JVM update,
                // it happens that someone launches it believing it is down -- and a Java stack
                // trace is not an answer to "what happened?". Here it says who holds the port.
                // The separated panel: the web part with the daemoxcp_mail user on the port, this root part
                // with no ports. If a condition is missing it stays as today, and says so (PanelSeparation).
                SSLMailServer.Mode mode = SSLMailServer.Mode.LEGACY;
                String notSeparated = org.daemoxcp.mail.system.PanelSeparation.prepare(port, setupRequired, mysqlAvailable);
                if (notSeparated == null) mode = SSLMailServer.Mode.ROOT_PART;
                else separationNotApplied(notSeparated);
                SSLMailServer server;
                try {
                    server = new SSLMailServer(port, certContent, keyContent, mode);
                    if (mode == SSLMailServer.Mode.ROOT_PART) {
                        // Before starting the web part: its MySQL user, which can only call its procedures
                        // (0.8.2). If it is not ready the web part logs in as before, and says so.
                        String webDb = org.daemoxcp.mail.database.WebDbAccess.ensure(mailDatabase);
                        if (webDb != null)
                            System.out.println(ANSI_YELLOW + "[WebDbAccess] the web part keeps the panel's MySQL user: " + webDb + ANSI_RESET);
                        final SSLMailServer root = server;
                        String failed = org.daemoxcp.mail.system.PanelSeparation.startWebPart(port, root::serveForwarded);
                        if (failed != null) {
                            separationNotApplied(failed);
                            server.becomeLegacy();
                        }
                    }
                } catch (java.net.BindException be) {
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "Port " + port + " is already in use: "
                            + "the panel is most likely ALREADY RUNNING." + ANSI_RESET);
                    String who = "";
                    try {
                        who = org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(20),
                                "sockstat -46l -p " + port + " 2>/dev/null | grep -v '^USER'").outputTrim();
                    } catch (Exception ignored) { }
                    if (!who.isEmpty()) {
                        System.out.println("Who is using it:");
                        System.out.println(who);
                        System.out.println();
                        System.out.println("To stop it:  kill <PID>    (the PID is the third column)");
                    }
                    System.out.println("Or open it in the browser: https://" + host + ":" + port);
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "Nothing was started: the running panel "
                            + "was not touched." + ANSI_RESET);
                    waitForEnter();
                    return false;
                }
                server.start();
                // The watchdog of package jobs that died halfway while the service is running
                // (UpdateManager.startInterruptionWatch): before, only the startup took care of it.
                org.daemoxcp.mail.system.UpdateManager.startInterruptionWatch();

                // The lock rule: the mail stack packages stay locked,
                // except those unlocked on purpose by an administrator.
                try {
                    String policy = org.daemoxcp.mail.system.UpdateManager.applyLockPolicy();
                    if (!policy.isEmpty()) System.out.println(policy);
                } catch (Exception e) {
                    System.out.println("Applying the package lock rule failed: " + e.getMessage());
                }

                if (server.mode() == SSLMailServer.Mode.ROOT_PART)
                    System.out.println(ANSI_GREEN + org.daemoxcp.mail.system.Product.NAME + " started: the web part answers on port " + port + " as "
                            + org.daemoxcp.mail.system.PanelSeparation.USER + ", this root part on no port" + ANSI_RESET);
                else
                    System.out.println(ANSI_GREEN + org.daemoxcp.mail.system.Product.NAME + " server started on port " + port + ANSI_RESET);
                System.out.println(ANSI_GREEN + "Open your browser: https://" + host + ":" + port + ANSI_RESET);
                System.out.println();
                System.out.println("Press ENTER to stop the server.");
                System.out.flush();

                // Handle Ctrl+C properly
                final SSLMailServer finalServer = server;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println();
                    System.out.println(ANSI_YELLOW + "Shutting down server..." + ANSI_RESET);
                    // First the web part, which without the root would no longer serve the APIs.
                    org.daemoxcp.mail.system.PanelSeparation.stop();
                    finalServer.stop();
                }));

                if (nonInteractive) {
                    // Without a terminal stdin is not read, in either of the two forms it
                    // takes: closed, readLine() returns null at once and the server would shut down
                    // an instant after starting; an open pipe, it never returns. Here we
                    // stay still until a signal arrives, and the shutdown hook takes care of that.
                    System.out.println("Listening. To stop it: kill " + ProcessHandle.current().pid());
                    System.out.flush();
                    try { new java.util.concurrent.CountDownLatch(1).await(); }
                    catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    return true;
                }

                // Wait for ENTER to stop (blocks until input)
                BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
                consoleReader.readLine();

                System.out.println(ANSI_YELLOW + "Stopping server..." + ANSI_RESET);
                server.stop();
                System.out.println(ANSI_GREEN + "Server stopped. Goodbye!" + ANSI_RESET);
                System.exit(0);
                return true;
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
            waitForEnter();
        }
        // No configuration row in the table, or an exception: the server did not start.
        return false;
    }

    /**
     * The separation does not happen: a warning in the log, except when it is a choice (turned off by hand) or it is
     * not the service (the menu, which runs as root with a terminal in front).
     */
    private static void separationNotApplied(String why) {
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(Main.class.getName());
        String text = "[PanelSeparation] NOT_APPLIED: " + why + "; the panel serves everything as root, as before";
        // Expected states, not faults: turned off by hand, installation not finished, the menu without root.
        boolean expected = why.startsWith("switched off") || why.startsWith("the first installation")
                || why.startsWith("the panel is not running as root");
        if (expected || !nonInteractive) log.info(text);
        else log.warning(text);
    }

    /**
     * The web part of the separated panel, with the daemoxcp_mail user: the panel's port, the filters, the access,
     * the pages and the public routes; the APIs of whoever has logged in are passed to the root part
     * (SSLMailServer in WEB_PART mode). SQLite read-only: only root writes the configuration.
     *
     * @return false if it did not start: daemon(8) restarts it, and the root after ANSWER_SECONDS goes back to
     *         today's mode
     */
    /** True in the web part of the separated panel (--web-part). */
    static volatile boolean webPart = false;

    private static boolean startWebPart() {
        nonInteractive = true;
        webPart = true;
        // From here the web part runs no system commands, except its own few (Shell.webPartOnly), and in the
        // database it runs only the statements on its list (CatalogGuard).
        org.daemoxcp.mail.util.Shell.webPartOnly();
        org.daemoxcp.mail.database.CatalogGuard.webPartOnly();
        if ("root".equals(System.getProperty("user.name"))) {
            System.err.println("--web-part is the panel's web part: the root part starts it as the user "
                    + org.daemoxcp.mail.system.PanelSeparation.USER + ", never as root.");
            return false;
        }
        try {
            dbManager = dataBaseManager.readOnly();
            String certContent, keyContent, host, mysqlHost, mysqlPort, mysqlUser, mysqlDatabase;
            int port;
            try (ResultSet result = dbManager.get_data_config()) {
                if (result == null || !result.next()) {
                    System.err.println("Web part: no panel configuration in SQLite");
                    return false;
                }
                certContent = result.getString("panel_ssl_cert");
                port = Integer.parseInt(result.getString("panel_port"));
                host = result.getString("panel_host");
                mysqlHost = result.getString("mysql_host");
                mysqlPort = result.getString("mysql_port");
                mysqlUser = result.getString("mysql_user");
                mysqlDatabase = result.getString("mysql_database");
            }
            keyContent = dbManager.panelTlsKey();
            if (certContent == null || certContent.isBlank() || keyContent == null || keyContent.isBlank()) {
                System.err.println("Web part: the panel's TLS certificate or key is missing");
                return false;
            }
            mailDatabase = new MailDatabase();
            mailDatabase.setHost(mysqlHost);
            mailDatabase.setPort(Integer.parseInt(mysqlPort));
            mailDatabase.setDatabase(mysqlDatabase);
            // Its MySQL user, which can only call the web part's procedures (0.8.2, WebDbAccess), if the root
            // has prepared and tested it; otherwise, as before, the panel's user.
            String webPassword = org.daemoxcp.mail.security.PanelSecrets.text(org.daemoxcp.mail.security.PanelSecrets.MYSQL_WEB_PASSWORD);
            if (!webPassword.isEmpty()) {
                mailDatabase.useRoutines(org.daemoxcp.mail.database.WebDbAccess.WEB_USER, () ->
                        org.daemoxcp.mail.security.PanelSecrets.text(org.daemoxcp.mail.security.PanelSecrets.MYSQL_WEB_PASSWORD));
            } else {
                mailDatabase.setPasswordSource(dbManager::mysqlPassword);
                mailDatabase.setCredentials(mysqlUser, dbManager.mysqlPassword());
            }
            if (mailDatabase.connect()) {
                mysqlAvailable = true;
                setupRequired = !mailDatabase.hasAdminUser();
                System.out.println("Web part: MySQL as " + (mailDatabase.usesRoutines()
                        ? org.daemoxcp.mail.database.WebDbAccess.WEB_USER + ", only the web part's procedures"
                        : mysqlUser + ", the panel's user (the web part's own user is not ready)"));
            } else {
                System.out.println("[WARNING] Web part: could not connect to MySQL");
            }
            // The session key belongs to the root, which creates the sessions (A): without it, the web part would
            // recognise no session, and it does not start (daemon restarts it).
            byte[] sessionKey = SSLMailServer.sessionKeyFromRoot(30_000);
            if (sessionKey == null) {
                System.err.println("Web part: the root part did not give the session key");
                return false;
            }
            org.daemoxcp.mail.webserver.WebSessions.adoptRunKey(sessionKey);
            SSLMailServer server = new SSLMailServer(port, certContent, keyContent, SSLMailServer.Mode.WEB_PART);
            server.start();
            System.out.println("Web part listening on https://" + host + ":" + port + " as " + System.getProperty("user.name")
                    + " (pid " + ProcessHandle.current().pid() + ")");
            System.out.flush();
            Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
            try { new java.util.concurrent.CountDownLatch(1).await(); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            return true;
        } catch (Exception e) {
            System.err.println("Web part: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static void setupMySQLDatabase() {
        System.out.println(ANSI_CYAN + "Setting up MySQL database for mail server..." + ANSI_RESET);

        try (ResultSet result = dbManager.get_data_config()) {
            if (result.next()) {
                String mysqlHost = result.getString("mysql_host");
                String mysqlPort = result.getString("mysql_port");
                String mysqlUser = result.getString("mysql_user");
                String mysqlPassword = dbManager.mysqlPassword();
                String mysqlDatabase = result.getString("mysql_database");
                result.close();     // values read: the SQLite read does not stay open while working on MySQL

                mailDatabase = new MailDatabase();

                mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // reads the password again at every reconnection
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mailDatabase.createSchema();
                    System.out.println(ANSI_GREEN + "MySQL database setup completed!" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_RED + "Failed to connect to MySQL" + ANSI_RESET);
                }
            }
        } catch (Exception e) {
            System.out.println(ANSI_RED + "ERROR: " + e.getMessage() + ANSI_RESET);
        }

        waitForEnter();
    }

    private static void resetMySQLDatabase() {
        resetDatabase();
        waitForEnter();
    }

    /**
     * Empties the panel's database and recreates the empty tables. True only if no table from
     * before is left: "completed" is written only then, otherwise it says what is left.
     */
    private static boolean resetDatabase() {
        System.out.println(ANSI_RED + "RESETTING MySQL database..." + ANSI_RESET);

        try (ResultSet result = dbManager.get_data_config()) {
            if (!result.next()) {
                System.out.println(ANSI_RED + "No MySQL configuration: database not touched." + ANSI_RESET);
                return false;
            }
            String mysqlHost = result.getString("mysql_host");
            String mysqlPort = result.getString("mysql_port");
            String mysqlUser = result.getString("mysql_user");
            String mysqlPassword = dbManager.mysqlPassword();
            String mysqlDatabase = result.getString("mysql_database");
            result.close();     // values read: the SQLite read does not stay open while MySQL is reset

            mailDatabase = new MailDatabase();

            mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // reads the password again at every reconnection
            mailDatabase.setCredentials(mysqlUser, mysqlPassword);
            mailDatabase.setHost(mysqlHost);
            mailDatabase.setPort(Integer.parseInt(mysqlPort));
            mailDatabase.setDatabase(mysqlDatabase);

            if (!mailDatabase.connect()) {
                System.out.println(ANSI_RED + "Failed to connect to MySQL: database not touched." + ANSI_RESET);
                return false;
            }
            String error = null;
            java.util.List<String> deleted = java.util.List.of();
            try {
                deleted = mailDatabase.dropAllTables();
            } catch (java.sql.SQLException e) {
                error = e.getMessage();
            }
            try {
                // Even after a failed reset: the panel gets back the tables that are missing.
                mailDatabase.createSchema();
            } catch (java.sql.SQLException e) {
                error = (error == null ? "" : error + " ") + "Tables not recreated: " + e.getMessage();
            }
            if (error != null) {
                System.out.println(ANSI_RED + "Database NOT reset. " + error + ANSI_RESET);
                return false;
            }
            System.out.println("Tables dropped: "
                    + (deleted.isEmpty() ? "none, the database was already empty" : String.join(", ", deleted)));
            System.out.println(ANSI_GREEN + "Database reset completed!" + ANSI_RESET);
            return true;
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Database NOT reset: " + e.getMessage() + ANSI_RESET);
            return false;
        }
    }

    private static void fullReset() {
        System.out.println(ANSI_RED + "════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println(ANSI_RED + "                    FULL RESET                          " + ANSI_RESET);
        System.out.println(ANSI_RED + "════════════════════════════════════════════════════════" + ANSI_RESET);
        System.out.println();

        // Stop all services (try both ClamAV naming conventions for FreeBSD compatibility)
        System.out.println(ANSI_YELLOW + "Stopping all mail services..." + ANSI_RESET);
        executeCommand("service postfix stop");
        executeCommand("service dovecot stop");
        executeCommand("service rspamd stop");
        executeCommand("service clamav_clamd stop 2>/dev/null || service clamav-clamd stop");
        executeCommand("service clamav_freshclam stop 2>/dev/null || service clamav-freshclam stop");

        // Remove configurations
        System.out.println(ANSI_YELLOW + "Removing configurations..." + ANSI_RESET);
        executeCommand("rm -rf /usr/local/etc/postfix/* /var/spool/postfix/*");
        executeCommand("rm -rf /usr/local/etc/dovecot/*");
        executeCommand("rm -rf /usr/local/etc/rspamd/*");

        // Reset database
        boolean databaseReset = resetDatabase();

        // Reset service status in SQLite
        dbManager.resetAllServices();

        if (databaseReset) {
            System.out.println(ANSI_GREEN + "Full reset completed!" + ANSI_RESET);
            System.out.println(ANSI_YELLOW + "You can now reinstall services from the menu." + ANSI_RESET);
        } else {
            System.out.println(ANSI_RED + "Reset NOT complete: services stopped and configurations removed, "
                    + "but the panel database was not reset (see above)." + ANSI_RESET);
        }

        waitForEnter();
    }

    private static void executeCommand(String command) {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            pb.inheritIO();
            Process p = pb.start();
            p.waitFor();
        } catch (Exception e) {
            System.out.println(ANSI_YELLOW + "[WARNING] Command failed: " + command + ANSI_RESET);
        }
    }

    /**
     * java -jar daemoxcp-mail.jar --create-admin <name> <email>: the first administrator,
     * superadmin, without a password. Only if there is no active one: the others are added
     * from the Administrators page, and whoever lost access uses --access-code. Prints a one-time
     * access code, because the server's email might not go out yet (DNS still to do).
     * Expects mailDatabase already connected; returns the process exit code.
     */
    public static int createFirstAdmin(String username, String email, java.io.PrintStream out, java.io.PrintStream err) {
        if (!org.daemoxcp.mail.webserver.SecurityUtils.isValidUsername(username)) {
            err.println(org.daemoxcp.mail.i18n.I18n.tr("console.admin.badName"));
            return 2;
        }
        if (!org.daemoxcp.mail.security.LoginCodes.validEmail(email)) {
            err.println(org.daemoxcp.mail.i18n.I18n.tr("console.admin.badEmail"));
            return 2;
        }
        try {
            mailDatabase.createSchema();
            org.daemoxcp.mail.security.AuthStore.migrate();
        } catch (Exception e) {
            err.println(org.daemoxcp.mail.i18n.I18n.tr("console.admin.tablesFailed", java.util.Map.of("e", String.valueOf(e.getMessage()))));
            return 2;
        }
        if (mailDatabase.hasAdminUser()) {
            err.println(org.daemoxcp.mail.i18n.I18n.tr("console.admin.exists"));
            return 2;
        }
        org.daemoxcp.mail.security.AuthStore.Created created =
                org.daemoxcp.mail.security.AuthStore.createAdmin(username, email, "superadmin");
        if (created.result() != org.daemoxcp.mail.security.AuthStore.CreateResult.CREATED) {
            err.println(switch (created.result()) {
                case NAME_TAKEN -> org.daemoxcp.mail.i18n.I18n.tr("console.admin.nameTaken");
                case EMAIL_TAKEN -> org.daemoxcp.mail.i18n.I18n.tr("console.admin.emailTaken");
                default -> org.daemoxcp.mail.i18n.I18n.tr("console.admin.notCreated");
            });
            return 2;
        }
        // The mail server name, written by the installation from the menu, in the settings too.
        String hostname = dbManager != null ? dbManager.getMailHostname() : null;
        if (hostname != null && hostname.trim().contains(".") && mailDatabase.getSetting("mail_hostname", "").isEmpty())
            mailDatabase.setSetting("mail_hostname", hostname.trim().toLowerCase(java.util.Locale.ROOT));
        org.daemoxcp.mail.security.AuthStore.Admin admin =
                org.daemoxcp.mail.security.AuthStore.adminById(created.id()).orElseThrow();
        String code = org.daemoxcp.mail.security.LoginCodes.issueConsoleCode(admin);
        out.println(org.daemoxcp.mail.i18n.I18n.tr("console.admin.created", java.util.Map.of("name", username, "email", email)));
        out.println(org.daemoxcp.mail.i18n.I18n.tr("console.code.line", java.util.Map.of("name", username, "code", code.substring(0, 4) + " " + code.substring(4))));
        out.println(org.daemoxcp.mail.i18n.I18n.tr("console.code.useFirst", java.util.Map.of("link", org.daemoxcp.mail.i18n.I18n.tr("login.consoleLink"))));
        return 0;
    }

    /**
     * The panel without an administrator notices as soon as one is created from the console: at the first
     * request afterwards, it prepares the access tables and shows the login page.
     */
    public static synchronized void refreshSetupState() {
        if (!setupRequired || !mysqlAvailable || mailDatabase == null || !mailDatabase.hasAdminUser()) return;
        // The web part migrates nothing: the access tables are set up by the root, the only one that writes them (A).
        if (webPart) {
            setupRequired = false;
            return;
        }
        try {
            org.daemoxcp.mail.security.AuthStore.migrate();
            setupRequired = false;
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Login tables not ready: " + e.getMessage() + ANSI_RESET);
        }
    }

    /**
     * The connection to MySQL with the configuration data, for the console and menu commands.
     * Null if it succeeds, otherwise the reason (to show to whoever asked for it).
     */
    static String connectFromConfig() {
        try (ResultSet result = dbManager.get_data_config()) {
            if (!result.next())
                return org.daemoxcp.mail.i18n.I18n.tr("console.notConfigured");
            mailDatabase = configuredMailDatabase(result);
        } catch (Exception e) {
            return org.daemoxcp.mail.i18n.I18n.tr("console.configUnreadable", java.util.Map.of("e", String.valueOf(e.getMessage())));
        }
        if (!mailDatabase.connect()) return org.daemoxcp.mail.i18n.I18n.tr("console.mysqlDown");
        mysqlAvailable = true;
        return null;
    }

    /** The console language: chooseConsoleLanguage picks it, once, at startup. */
    static String consoleLanguage = "en";

    /**
     * True if the language comes from --lang or from the terminal: then a command for an administrator does not
     * change it.
     */
    static boolean consoleLanguageAsked = false;

    /**
     * The console language (on-screen menu and command-line commands), in ConsoleLanguage's order: --lang xx,
     * the terminal's language (LC_ALL, LC_MESSAGES, LANG), the panel's language (of the first active administrator who
     * has chosen one), English (also on a server not yet installed, or with MySQL stopped). The language of an
     * administrator for their own commands is set by useAdminLanguage. It becomes the process language (I18n), so every
     * console text follows it without passing it around.
     */
    static void chooseConsoleLanguage(String[] args) {
        java.util.List<String> languages = org.daemoxcp.mail.i18n.I18n.LANGUAGES;
        String flag = org.daemoxcp.mail.i18n.ConsoleLanguage.fromFlag(args, languages,
                v -> System.err.println("--lang " + v + ": the panel has " + String.join(", ", languages)));
        String terminal = flag == null ? org.daemoxcp.mail.i18n.ConsoleLanguage.fromTerminal(System.getenv(), languages) : null;
        consoleLanguageAsked = flag != null || terminal != null;
        String panel = consoleLanguageAsked ? null : savedPanelLanguage();
        useConsoleLanguage(org.daemoxcp.mail.i18n.ConsoleLanguage.choose(flag, terminal, null, panel));
    }

    /**
     * A command for an administrator (--access-code name) speaks the language they chose in the panel, if there is one
     * and if --lang or the terminal have not already given one: the code is for them.
     */
    static void useAdminLanguage(String username) {
        if (consoleLanguageAsked || username == null || mailDatabase == null) return;
        String own = mailDatabase.getAdminLanguage(username);
        if (own != null) useConsoleLanguage(org.daemoxcp.mail.i18n.ConsoleLanguage.choose(null, null, own, consoleLanguage));
    }

    private static void useConsoleLanguage(String lang) {
        consoleLanguage = lang;
        org.daemoxcp.mail.i18n.I18n.setProcessLanguage(consoleLanguage);
        // The buttons of Lanterna's windows too (OK, Cancel, Yes, No): it picks them from the default language.
        java.util.Locale.setDefault(java.util.Locale.forLanguageTag(consoleLanguage));
    }

    /** The panel language read from MySQL with a single connection, closed at once; null if it cannot be read. */
    static String savedPanelLanguage() {
        try (ResultSet result = dbManager.get_data_config()) {
            if (!result.next()) return null;
            MailDatabase db = configuredMailDatabase(result);
            if (!db.connect()) return null;
            try { return db.getPanelLanguage(); } finally { db.close(); }
        } catch (Exception e) {
            return null;
        }
    }

    /** A MailDatabase with the panel's configuration (the SQLite row), not yet connected. */
    static MailDatabase configuredMailDatabase(ResultSet result) throws java.sql.SQLException {
        MailDatabase db = new MailDatabase();
        db.setPasswordSource(dbManager::mysqlPassword);   // reads the password again at every reconnection
        db.setCredentials(result.getString("mysql_user"), dbManager.mysqlPassword());
        db.setHost(result.getString("mysql_host"));
        db.setPort(Integer.parseInt(result.getString("mysql_port")));
        db.setDatabase(result.getString("mysql_database"));
        return db;
    }

    /** The outcome of a console command: the text to show and whether it succeeded. */
    record ConsoleResult(boolean ok, String text) {}

    /**
     * A one-time access code for an active administrator (the one with the given name, or the only one).
     * Expects mailDatabase already connected.
     */
    static ConsoleResult accessCode(String username) {
        try {
            // The schema first, like --create-admin (finding 248): on a freshly installed server the access
            // tables are not there yet.
            mailDatabase.createSchema();
            org.daemoxcp.mail.security.AuthStore.migrate();
        } catch (Exception e) {
            return new ConsoleResult(false, org.daemoxcp.mail.i18n.I18n.tr("console.code.tablesFailed", java.util.Map.of("e", String.valueOf(e.getMessage()))));
        }
        java.util.List<org.daemoxcp.mail.security.AuthStore.Admin> admins = org.daemoxcp.mail.security.AuthStore.admins().stream()
                .filter(org.daemoxcp.mail.security.AuthStore.Admin::active).toList();
        java.util.Optional<org.daemoxcp.mail.security.AuthStore.Admin> admin = username != null
                ? org.daemoxcp.mail.security.AuthStore.adminByUsername(username)
                : admins.size() == 1 ? java.util.Optional.of(admins.get(0)) : java.util.Optional.empty();
        if (admin.isEmpty()) {
            return new ConsoleResult(false, username != null ? org.daemoxcp.mail.i18n.I18n.tr("console.code.noSuchAdmin", java.util.Map.of("name", username))
                    : admins.isEmpty() ? org.daemoxcp.mail.i18n.I18n.tr("console.code.noAdmin", java.util.Map.of("cmd", "--create-admin <name> <email>"))
                    : org.daemoxcp.mail.i18n.I18n.tr("console.code.whichAdmin", java.util.Map.of("cmd", "--access-code <name>", "names", String.join(", ", admins.stream().map(org.daemoxcp.mail.security.AuthStore.Admin::username).toList()))));
        }
        String code = org.daemoxcp.mail.security.LoginCodes.issueConsoleCode(admin.get());
        return new ConsoleResult(true, org.daemoxcp.mail.i18n.I18n.tr("console.code.line", java.util.Map.of("name", admin.get().username(), "code", code.substring(0, 4) + " " + code.substring(4))) + "\n"
                + org.daemoxcp.mail.i18n.I18n.tr("console.code.use", java.util.Map.of("link", org.daemoxcp.mail.i18n.I18n.tr("login.consoleLink"))));
    }

    /**
     * From the terminal menu: the emergency access code, for when passkeys and email are not
     * enough. If there is no administrator yet, the first one is created here.
     */
    private static void emergencyAccess(MultiWindowTextGUI gui) {
        String title = org.daemoxcp.mail.i18n.I18n.tr("console.menu.code");
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            message(gui, title, notConnected);
            return;
        }
        try {
            mailDatabase.createSchema();   // finding 248, like --create-admin
            org.daemoxcp.mail.security.AuthStore.migrate();
        } catch (Exception e) {
            message(gui, title, org.daemoxcp.mail.i18n.I18n.tr("console.code.tablesFailed", java.util.Map.of("e", String.valueOf(e.getMessage()))));
            return;
        }
        java.util.List<String> names = org.daemoxcp.mail.security.AuthStore.admins().stream()
                .filter(org.daemoxcp.mail.security.AuthStore.Admin::active)
                .map(org.daemoxcp.mail.security.AuthStore.Admin::username).toList();
        if (names.isEmpty()) {
            String name = showTextInputDialog(gui, org.daemoxcp.mail.i18n.I18n.tr("console.admin.firstTitle"),
                    org.daemoxcp.mail.i18n.I18n.tr("console.admin.askName"));
            if (name == null || name.isBlank()) return;
            String email = showTextInputDialog(gui, org.daemoxcp.mail.i18n.I18n.tr("console.admin.firstTitle"), org.daemoxcp.mail.i18n.I18n.tr("console.admin.askEmail"));
            if (email == null || email.isBlank()) return;
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
            int rc = createFirstAdmin(name.trim(), email.trim(), new java.io.PrintStream(out, true, java.nio.charset.StandardCharsets.UTF_8),
                    new java.io.PrintStream(err, true, java.nio.charset.StandardCharsets.UTF_8));
            message(gui, org.daemoxcp.mail.i18n.I18n.tr("console.admin.firstTitle"), (rc == 0 ? out : err).toString(java.nio.charset.StandardCharsets.UTF_8).trim());
            return;
        }
        String chosen = names.size() == 1 ? names.get(0)
                : new com.googlecode.lanterna.gui2.dialogs.ListSelectDialogBuilder<String>()
                        .setTitle(title).setDescription(org.daemoxcp.mail.i18n.I18n.tr("console.code.whichTitle"))
                        .addListItems(names.toArray(new String[0])).build().showDialog(gui);
        if (chosen == null) return;
        message(gui, title, accessCode(chosen).text());
    }

    private static void message(MultiWindowTextGUI gui, String title, String text) {
        new com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder().setTitle(title).setText(text)
                .addButton(MessageDialogButton.OK).build().showDialog(gui);
    }

    /**
     * java -jar daemoxcp-mail.jar --access-code [name]: a one-time eight-digit code
     * to get in without email or passkey (first access, lost email). Only whoever has a
     * shell on the server can generate it; it is valid for 15 minutes, once. Returns the process exit code.
     */
    static int printAccessCode(String username) {
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            System.err.println(notConnected);
            return 2;
        }
        useAdminLanguage(username);
        ConsoleResult r = accessCode(username);
        (r.ok() ? System.out : System.err).println(r.text());
        return r.ok() ? 0 : 2;
    }

    /**
     * --ip-family: IPv4, IPv6, both, or mail over IPv6 outbound only (ipv6out), from the console, like the Settings
     * tab but without warnings to confirm: it is the road for whoever chose a single family and from there can no
     * longer reach the panel. The same checks (address and route in the family that remains) and the same return
     * to how it was if a service does not hold.
     * As root: rewrites the Postfix, Dovecot and nginx configurations and reloads pf.
     */
    /**
     * --empty-folders: the emergency emptying of Junk and/or Trash, of all mailboxes (all) or of the given
     * ones, right now (EmergencyEmpty). Only as root and from a terminal: shows how many messages it removes and
     * asks to type that number. The everyday emptying is automatic, mailbox by mailbox, from the panel or from
     * the webmail.
     */
    static int emptyFolders(String[] rest) {
        String usage = org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd",
                "java -jar daemoxcp-mail.jar --empty-folders junk|trash|both all|<mailbox>..."));
        java.util.List<String> folders = rest.length < 2 ? null : org.daemoxcp.mail.system.EmergencyEmpty.folders(rest[0]);
        if (folders == null) {
            System.err.println(usage);
            return 2;
        }
        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.asRoot"));
            return 2;
        }
        // Since Java 22 System.console() exists even without a terminal: isTerminal() says whether someone is on
        // the other side.
        java.io.Console terminal = System.console();
        if (terminal == null || !terminal.isTerminal()) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.terminal"));
            return 2;
        }
        java.util.logging.Logger rootLogger = java.util.logging.Logger.getLogger("");
        rootLogger.setLevel(java.util.logging.Level.WARNING);
        for (java.util.logging.Handler h : rootLogger.getHandlers()) h.setLevel(java.util.logging.Level.WARNING);
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            System.err.println(notConnected);
            return 2;
        }
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            java.util.List<String> mailboxes = new java.util.ArrayList<>();
            java.util.List<org.daemoxcp.mail.database.MailDatabase.Mailbox> all = mailDatabase.getAllMailboxes();
            java.util.Set<String> known = new java.util.HashSet<>();
            for (org.daemoxcp.mail.database.MailDatabase.Mailbox m : all) if (m.active) known.add(m.email.toLowerCase(java.util.Locale.ROOT));
            if (rest.length == 2 && rest[1].equals("all")) {
                for (org.daemoxcp.mail.database.MailDatabase.Mailbox m : all) if (m.active) mailboxes.add(m.email.toLowerCase(java.util.Locale.ROOT));
            } else {
                for (int k = 1; k < rest.length; k++) {
                    String mb = rest[k].trim().toLowerCase(java.util.Locale.ROOT);
                    if (!known.contains(mb)) {
                        System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.unknown", java.util.Map.of("mailbox", mb)));
                        return 2;
                    }
                    if (!mailboxes.contains(mb)) mailboxes.add(mb);
                }
            }
            java.util.Map<String, java.util.Map<String, Integer>> plan = org.daemoxcp.mail.system.EmergencyEmpty.plan(mailboxes, folders,
                    org.daemoxcp.mail.system.EmergencyEmpty::countWithDovecot);
            int total = org.daemoxcp.mail.system.EmergencyEmpty.total(plan);
            if (total == 0) {
                System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.nothing"));
                return 0;
            }
            for (java.util.Map.Entry<String, java.util.Map<String, Integer>> e : plan.entrySet())
                for (java.util.Map.Entry<String, Integer> f : e.getValue().entrySet())
                    System.out.println("  " + e.getKey() + "  " + f.getKey() + ": " + f.getValue());
            String answer = terminal.readLine("%s", org.daemoxcp.mail.i18n.I18n.tr("console.empty.confirm",
                    java.util.Map.of("n", String.valueOf(total), "mailboxes", String.valueOf(plan.size()))) + " ");
            if (answer == null || !answer.trim().equals(String.valueOf(total))) {
                System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.cancelled"));
                return 1;
            }
            org.daemoxcp.mail.system.EmergencyEmpty.Result r = org.daemoxcp.mail.system.EmergencyEmpty.run(plan,
                    org.daemoxcp.mail.system.EmergencyEmpty::expungeWithDovecot);
            mailDatabase.logAuditEvent("EMERGENCY_EMPTY", "127.0.0.1", String.join("+", folders) + " of " + plan.size()
                    + " mailbox(es), " + total + " message(s), " + r.emptied() + " folder(s) emptied"
                    + (r.failed().isEmpty() ? "" : ", failed: " + String.join(", ", r.failed())) + " (console)", "console");
            System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.done", java.util.Map.of("folders", String.valueOf(r.emptied()))));
            for (String f : r.failed()) System.out.println("  " + org.daemoxcp.mail.i18n.I18n.tr("console.empty.failed", java.util.Map.of("what", f)));
            return r.failed().isEmpty() ? 0 : 1;
        } catch (java.sql.SQLException e) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.empty.noMailboxes"));
            return 1;
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
    }

    static int setIpFamily(String value) {
        org.daemoxcp.mail.system.IpFamily.Family f = org.daemoxcp.mail.system.IpFamily.Family.of(value);
        if (f == null) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd", "java -jar daemoxcp-mail.jar --ip-family both|ipv4|ipv6|ipv6out")));
            return 2;
        }
        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.ipf.asRoot"));
            return 2;
        }
        // In the console the INFO lines of the services touched are noise: warnings and errors remain, and the
        // outcome below.
        java.util.logging.Logger rootLogger = java.util.logging.Logger.getLogger("");
        rootLogger.setLevel(java.util.logging.Level.WARNING);
        for (java.util.logging.Handler h : rootLogger.getHandlers()) h.setLevel(java.util.logging.Level.WARNING);
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            System.err.println(notConnected);
            return 2;
        }
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            org.daemoxcp.mail.system.IpFamily.Outcome o = org.daemoxcp.mail.system.IpFamily.choose(f, true, null);
            if (!o.done()) {
                System.err.println(o.error());
                return 1;
            }
            mailDatabase.logAuditEvent("IP_FAMILY_CHANGED", "127.0.0.1", f.key + " (console)", "console");
            // The panel's firewall (lists, countries) follows the choice: its first rule refuses the closed family.
            org.daemoxcp.mail.security.PfFirewallManager.ApplyResult fw = org.daemoxcp.mail.security.PfFirewallManager.reapplySaved();
            if (fw != null && !fw.success) System.out.println("  " + org.daemoxcp.mail.i18n.I18n.tr("console.ipf.fwNotReloaded", java.util.Map.of("e", String.valueOf(fw.message))));
            System.out.println(switch (f) {
                case BOTH -> org.daemoxcp.mail.i18n.I18n.tr("console.ipf.doneBoth");
                case IPV4 -> org.daemoxcp.mail.i18n.I18n.tr("console.ipf.doneV4");
                case IPV6 -> org.daemoxcp.mail.i18n.I18n.tr("console.ipf.doneV6");
                case IPV6_OUT -> org.daemoxcp.mail.i18n.I18n.tr("console.ipf.doneOut6");
            });
            for (String w : o.warnings()) System.out.println("  " + w);
            return 0;
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
    }

    /**
     * --addresses: the server's addresses from the console, the way out for whoever can no longer reach the
     * panel after a step of the guide (ServerAddresses). show displays them; ipv6-off removes the IPv6 added by
     * the panel and puts back the previous rc.conf lines; ipv4-dhcp takes IPv4 back with DHCP. The same checks
     * and the same return to how it was as the page. As root: ifconfig, route and rc.conf. SSH is not touched.
     */
    static int addresses(String value) {
        if (value == null || !java.util.List.of("show", "ipv6-off", "ipv4-dhcp").contains(value)) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd", "java -jar daemoxcp-mail.jar --addresses show|ipv6-off|ipv4-dhcp")));
            return 2;
        }
        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.addr.asRoot"));
            return 2;
        }
        java.util.logging.Logger rootLogger = java.util.logging.Logger.getLogger("");
        rootLogger.setLevel(java.util.logging.Level.WARNING);
        for (java.util.logging.Handler h : rootLogger.getHandlers()) h.setLevel(java.util.logging.Level.WARNING);
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            System.err.println(notConnected);
            return 2;
        }
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            if ("show".equals(value)) {
                org.daemoxcp.mail.system.ServerAddresses.State s = org.daemoxcp.mail.system.ServerAddresses.read();
                System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.addr.iface", java.util.Map.of("name", s.iface() == null ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.noIface") : s.iface())));
                System.out.println("IPv4: " + (s.v4().addresses().isEmpty() ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.noV4") : String.join(", ", s.v4().addresses()))
                        + (s.v4().route() ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.route", java.util.Map.of("gw", String.valueOf(s.v4().gateway()))) : org.daemoxcp.mail.i18n.I18n.tr("console.addr.noRoute"))
                        + (s.v4().present() ? (org.daemoxcp.mail.system.ServerAddresses.goesOut("ipv4") ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.out") : org.daemoxcp.mail.i18n.I18n.tr("console.addr.noOut")) : ""));
                System.out.println("IPv6: " + (s.v6().addresses().isEmpty() ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.noV6") : String.join(", ", s.v6().addresses()))
                        + (s.v6().route() ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.route", java.util.Map.of("gw", String.valueOf(s.v6().gateway()))) : org.daemoxcp.mail.i18n.I18n.tr("console.addr.noRoute"))
                        + (!s.v6().addresses().isEmpty() && s.v6().route() ? (org.daemoxcp.mail.system.ServerAddresses.goesOut("ipv6") ? org.daemoxcp.mail.i18n.I18n.tr("console.addr.out") : org.daemoxcp.mail.i18n.I18n.tr("console.addr.noOut")) : ""));
                System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.addr.mail", java.util.Map.of("family", org.daemoxcp.mail.system.IpFamily.effective().key)));
                return 0;
            }
            org.daemoxcp.mail.system.ServerAddresses.Result r = "ipv6-off".equals(value)
                    ? org.daemoxcp.mail.system.ServerAddresses.removeIpv6()
                    : org.daemoxcp.mail.system.ServerAddresses.addIpv4();
            String event = "ipv6-off".equals(value) ? "SERVER_ADDRESSES_REMOVE_IPV6" : "SERVER_ADDRESSES_ADD_IPV4";
            mailDatabase.logAuditEvent(r.ok() ? event : event + "_FAILED", "127.0.0.1", r.journal() + " (console)", "console");
            (r.ok() ? System.out : System.err).println(org.daemoxcp.mail.i18n.I18n.tr(r.message()));
            if (!r.journal().isEmpty()) System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.addr.log", java.util.Map.of("path", "/var/db/daemoxcp-mail/jobs/" + r.journal())));
            return r.ok() ? 0 : 1;
        } finally {
            org.daemoxcp.mail.i18n.I18n.clearCurrent();
        }
    }

    /** At startup: if no administrator can get in, how to do it. */
    static void warnIfNoLogin() {
        boolean someoneCanLogIn = org.daemoxcp.mail.security.AuthStore.admins().stream().anyMatch(a -> a.active()
                && (a.hasEmail() || !org.daemoxcp.mail.security.AuthStore.passkeysOf(a.id()).isEmpty()));
        if (!someoneCanLogIn)
            System.out.println(ANSI_YELLOW + "No administrator has a login email or a passkey yet. Get a one-time code with:\n"
                    + "  java -jar daemoxcp-mail.jar --access-code" + ANSI_RESET);
    }
}
