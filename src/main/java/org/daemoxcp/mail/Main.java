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

    // I comandi esterni partono con fork(), non con jspawnhelper. Con il meccanismo predefinito
    // ogni comando passa da jspawnhelper, che controlla di essere della stessa versione della
    // JVM in memoria: appena pkg aggiorna il JDK sotto il pannello acceso, ogni avvio fallisce
    // ("Failed to exec spawn helper") e il pannello non legge piu' niente finche' non lo si
    // riavvia. Provato su FreeBSD 15.1 con openjdk25 25.0.2 -> 25.0.4: con FORK i comandi
    // continuano a partire. La proprieta' si legge una volta sola, al primo processo lanciato:
    // per questo sta qui, prima di qualunque altra cosa.
    static {
        if (System.getProperty("jdk.lang.Process.launchMechanism") == null)
            System.setProperty("jdk.lang.Process.launchMechanism", "FORK");
    }

    public static dataBaseManager dbManager;         // SQLite for panel config
    public static MailDatabase mailDatabase;         // MySQL for mail data
    public static WebSessions sessions = new WebSessions();

    // Status flags for SSLMailServer compatibility
    public static boolean mysqlAvailable = false;
    /** Nessun amministratore attivo: il pannello aspetta che lo si crei dalla console (--create-admin). */
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

        // Invio nel campo vale come OK. In Lanterna Invio in un campo di una riga sposta il fuoco al componente dopo,
        // che qui e' Annulla: chi scriveva il valore e premeva Invio due volte, come si fa in ogni modulo, annullava
        // quello che aveva scritto (installazione dal README, 20/11/2026). Annulla resta il primo pulsante.
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
     * Come {@link #executeScript}, ma i segreti arrivano allo script dall'<em>ambiente</em>, e
     * gli argomenti non si stampano.
     *
     * <p>Due strade portavano fuori la password del database, e sono tutte e due chiuse qui.
     *
     * <p>La prima: {@code "Arguments: " + String.join(" ", args)} le scriveva sullo standard
     * output. Avviato dal servizio, quello standard output e' un <em>file</em>: la password
     * finiva su disco in chiaro, e ci restava. Adesso si dice quanti argomenti ci sono, non
     * quali.
     *
     * <p>La seconda, peggiore: un argomento della riga di comando lo legge <em>chiunque</em>
     * con {@code ps}, per tutta la durata dell'installazione, che sono minuti. L'ambiente di
     * un processo invece su FreeBSD lo vede solo chi ne e' proprietario o root
     * ({@code procstat -e}). Non e' una cassaforte, ma e' la differenza fra "ogni utente
     * della macchina" e "root".
     */
    public static boolean executeScriptWithSecrets(String scriptPath, String scriptName,
                                                   java.util.Map<String, String> secrets, String... args) {
        return executeScript(scriptPath, scriptName, secrets, true, args);
    }

    /**
     * @param pause se aspettare ENTER alla fine (solo con un terminale, vedi waitForEnter). Falso
     *              quando dopo lo script c'e' ancora qualcosa da fare che non deve dipendere da un
     *              tasto: l'installazione completa riprotegge i pacchetti, e aspetta dopo.
     */
    private static boolean executeScript(String scriptPath, String scriptName,
                                         java.util.Map<String, String> secrets, boolean pause, String... args) {
        return executeScript(scriptPath, scriptName, secrets, pause, (java.util.function.Consumer<String>) null, args);
    }

    /** Come sopra, e ogni riga dello script passa anche da {@code onLine} (se non e' null). */
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
            // Lo lancia il pannello, che l'ha appena scritto dal suo jar: il controllo della versione
            // che lo script fa quando lo si lancia a mano qui non serve (InstallScripts).
            processBuilder.environment().put(org.daemoxcp.mail.scripts.InstallScripts.FROM_PANEL, "1");
            processBuilder.redirectErrorStream(true);
            // Lo stdin del figlio e' /dev/null, sempre. L'impostazione predefinita di
            // ProcessBuilder e' una pipe di cui la JVM tiene aperto il capo in scrittura e
            // su cui non scrive mai: uno script che legge non riceve ne' dati ne' EOF, e
            // resta fermo per sempre. Misurato sulla VM: uno script con "read x" appende
            // executeScript in tutte e tre le condizioni -- stdin del pannello su pipe
            // aperta, su /dev/null, e su una pty vera con l'ENTER pronto. Non e' quindi un
            // guasto della sola non interattivita': quella pipe non serve a nessuno, perche'
            // nemmeno un operatore al terminale puo' rispondere (quello che digita va allo
            // stdin del pannello, che lo legge waitForEnter(), non allo script). Per questo
            // non e' condizionato a nonInteractive.
            // Con /dev/null la lettura torna EOF: lo script non si ferma piu' e il suo codice
            // d'uscita arriva al chiamante. Attenzione a chi aggiunge uno script che legge:
            // EOF non e' un errore, quindi "read x" prosegue con un valore VUOTO. Chi legge
            // deve controllare l'esito della lettura, altrimenti va avanti su niente.
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
     * Si ferma finche' qualcuno non preme ENTER. Senza terminale non si ferma e non stampa
     * niente: il messaggio da' per inteso un lettore che non c'e', e l'attesa non finisce.
     * Con stdin chiuso System.in.read() legge EOF e il processo prosegue di corsa; con stdin
     * su una pipe aperta -- ssh senza -t, cron, un runner -- non legge niente e resta fermo
     * per sempre. E' la seconda forma che ha tenuto un'installazione riuscita ferma per sette
     * ore e cinquanta: processo vivo, exit code 0, nessun errore da nessuna parte.
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
        // La parte web del pannello separato: la avvia la parte root con
        // daemon(8) e l'utente daemoxcp_mail (PanelSeparation). Niente di quello che segue: migrazioni, script,
        // contenuti e SQLite in scrittura sono lavoro della root, che li ha gia' fatti.
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
        // Il nome del prodotto (DaemoxCP Mail, 17/11/2026) su un server installato prima: cartelle, utente di sistema,
        // servizio, jar, jail. Solo il servizio o il menu, da root, e prima che qualcuno legga quei nomi.
        boolean renameApplies = org.daemoxcp.mail.system.ProductRename.applies(args);
        if (renameApplies) org.daemoxcp.mail.system.ProductRename.atServiceStart();
        // Lo script di avvio scritto dal pannello cita i file che PathMigration ha appena rinominato.
        org.daemoxcp.mail.system.RcScriptRepair.ensureAtBoot();
        // I segreti solo di root (le password di root di MySQL e dell'utente MySQL di Roundcube) escono dal
        // file del pannello e vanno in quello di root: la parte web, che gira con l'utente daemoxcp_mail, non li
        // deve poter leggere. Solo da root; al secondo avvio non c'e'
        // niente da spostare.
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

        // Se una manutenzione dei pacchetti non e' arrivata in fondo (pannello ucciso, crash,
        // riavvio a meta'), i pacchetti sono rimasti SBLOCCATI e nessuno se ne accorgerebbe
        // finche' un aggiornamento successivo non porta via un pezzo dello stack di posta.
        // Il ripristino va fatto qui, all'avvio, prima che il pannello torni utilizzabile.
        try {
            String restore = org.daemoxcp.mail.system.UpdateManager.restoreLocksAfterCrash();
            if (!restore.isEmpty()) System.out.println(restore);
        } catch (Exception e) {
            System.out.println("Restoring package locks failed: " + e.getMessage());
        }

        // Initialize database BEFORE screen to avoid warnings during GUI
        dbManager = new dataBaseManager();
        // Prima la tabella, poi le colonne: su un server nuovo l'ordine inverso lasciava la configurazione senza
        // roundcube_ssl_chain fino al secondo avvio (dataBaseManager.prepareAtStartup).
        boolean needsTableCreation = dbManager.prepareAtStartup();
        // Il database e gli utenti MySQL col nome del prodotto, prima che qualcuno entri in MySQL. Dopo la tabella:
        // su un server nuovo legge la riga dei valori predefiniti e non ha niente da fare.
        if (renameApplies) org.daemoxcp.mail.system.MysqlRename.ensureAtBoot(dbManager);

        // Prima che qualunque cosa entri in MySQL: se un'installazione e' stata interrotta con la
        // password nuova ancora in attesa, o se MySQL rifiuta quella del pannello (i server rotti
        // dalla versione di prima, reperto 156), si chiede a MySQL quale conosce. Vale per ogni
        // processo: il servizio --web, il menu, i comandi da console. Di solito costa una
        // connessione e non cambia niente (PendingDbPassword.settleAtStartup).
        try {
            org.daemoxcp.mail.i18n.I18n.setCurrent("en");   // una riga d'avvio di ogni modo, servizio compreso: un registro
            String decided;
            try { decided = org.daemoxcp.mail.system.PendingDbPassword.settleAtStartup(dbManager).message(); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            if (!decided.isEmpty()) System.out.println("[MYSQL] " + decided);
        } catch (Exception e) {
            System.out.println("Checking the panel's MySQL password failed: " + e.getMessage());
        }

        // Gli script d'installazione riscritti da questo jar a ogni avvio (servizio, menu, comandi da
        // console), e quelli che nessuno scrive piu' messi da parte: mai uno script di una versione di
        // prima su disco (InstallScripts, reperto 169).
        try {
            createDirectoryIfNotExists("./install_scripts/");
            org.daemoxcp.mail.scripts.InstallScripts.refreshAtStartup();
        } catch (Exception e) {
            System.out.println("Writing the install scripts failed: " + e.getMessage());
        }

        // La lingua della console (il menu a schermo e i comandi qui sotto): --lang, poi quella del pannello, poi
        // l'inglese. Non per il servizio (--web): le sue righe sono registri e restano in inglese.
        if (!java.util.Arrays.asList(args).contains("--web")) chooseConsoleLanguage(args);
        // Poi --lang e il suo valore non ci sono piu': i comandi leggono i loro argomenti per posizione
        // (--access-code --lang en prendeva «--lang» per il nome dell'amministratore).
        args = org.daemoxcp.mail.i18n.ConsoleLanguage.withoutFlag(args);

        // I comandi da console, per chi ha una shell sul server (dalla cartella del pannello):
        //   java -jar daemoxcp-mail.jar --create-admin <nome> <email>   il primo amministratore
        //   java -jar daemoxcp-mail.jar --access-code [nome]            un codice di accesso monouso
        //   java -jar daemoxcp-mail.jar --ip-family both|ipv4|ipv6|ipv6out   IPv4, IPv6, tutte e due, o IPv6 solo in uscita (da root)
        //   java -jar daemoxcp-mail.jar --empty-folders junk|trash|both all|<casella>...   svuotamento d'emergenza (da root)
        // Il primo amministratore non si crea dal pannello web: chi raggiungesse per primo la
        // pagina diventerebbe amministratore.
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
            // La reinstallazione completa staccata dal menu (ReinstallJob): la lancia la voce del
            // menu con daemon(8), in una sessione sua, e la segue. Chi chiude il terminale o uccide
            // il menu non la ferma piu' a meta' (reperto 163). L'esito va nel file indicato.
            if ("--reinstall".equals(args[i])) {
                nonInteractive = true;
                String host = i + 1 < args.length ? args[i + 1].trim() : "";
                Path exitFile = i + 2 < args.length ? Path.of(args[i + 2]) : null;
                if (!org.daemoxcp.mail.system.ReinstallJob.validHostname(host)) {
                    System.err.println(org.daemoxcp.mail.i18n.I18n.tr("console.usage", java.util.Map.of("cmd", "java -jar daemoxcp-mail.jar --reinstall <mail hostname> [result file]")));
                    if (exitFile != null) org.daemoxcp.mail.system.ReinstallJob.writeExit(exitFile, false);
                    System.exit(2);
                }
                // Lo script si riscrive SEMPRE da questo jar, appena prima di eseguirlo: lanciato a mano
                // dopo un aggiornamento del jar, un «solo se manca» userebbe quello di prima (reperto 169).
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

        // Modalita' solo-web: nessun menu a schermo.
        //
        // Serve perche' il pannello deve poter tornare su DA SOLO dopo che si e' spento per
        // aggiornare la propria JVM. L'interfaccia a schermo (Lanterna) pretende un terminale,
        // e uno script staccato non ne ha uno: senza questa modalita' il processo ripartirebbe
        // e morirebbe subito, lasciando il pannello web irraggiungibile.
        // Il server web di suo non ha mai avuto bisogno del terminale: usa solo System.out.
        boolean webOnly = false;
        for (String a1 : args) if ("--web".equals(a1)) webOnly = true;
        if (webOnly) {
            // --web e' il servizio: nessun tasto da premere, qualunque cosa dica il terminale.
            nonInteractive = true;
            System.out.println("Starting in web-only mode: no on-screen menu.");
            System.out.println("To see the menu again: stop this process and start it again without --web.");
            // Se il server non parte il processo deve uscire diverso da zero: con exit 0 chi
            // ha riavviato il pannello crede che sia tornato su, e invece e' spento.
            System.exit(startWebServer() ? 0 : 1);
            return;
        }

        // Comodita', non dipendenza: il pannello non ha bisogno di run.sh per funzionare ne'
        // per riaccendersi da solo (la riga di riavvio la ricostruisce dal processo vivo).
        // Se pero' non c'e', se lo scrive, cosi' esiste un modo breve per avviare --web a mano.
        try {
            // Il messaggio condiviso con il pannello, nella lingua della console.
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            String created;
            try { created = org.daemoxcp.mail.system.UpdateManager.createRunSh(); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            if (!created.isEmpty()) System.out.println(created);
        } catch (Exception e) {
            // Se non si puo' scrivere accanto al jar non e' un problema: serviva solo a comodita'.
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

        // Se l'ultima reinstallazione completa non e' finita, lo si dice appena il menu si apre, con le
        // due strade: la voce 6 (il server di prima) o la 4 (rifarla).
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
                        // Fuso orario, NTP e DNS. Il fuso lo sceglie chi installa (reperto 242): prima era sempre
                        // Europe/Rome. Si propone quello che il sistema ha gia', e un nome sbagliato non parte.
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
                        // Il codice di accesso di emergenza (o il primo amministratore)
                        emergencyAccess(gui);
                        break;

                    case 6:
                        // Tornare al server di prima dell'ultima reinstallazione (ReinstallReturn)
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
        // Gli script si riscrivono a ogni avvio (InstallScripts.refreshAtStartup, prima del menu): qui
        // si riscrivono ancora e si dice qualcosa solo se NON si scrivono. Prima, scritti solo «se
        // mancano», la finestra compariva la prima volta; scritti sempre, comparirebbero due finestre
        // da chiudere a ogni apertura del menu (reperto 172).
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
     * Il testo per il menu se l'ultima reinstallazione completa non e' finita: interrotta (l'avviso di
     * PackageRecovery lo sa) o fallita dopo aver cominciato a cambiare il sistema (ReinstallJob). ""
     * se non c'e' niente da dire.
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
     * Voce 6 del menu: torna al server com'era prima dell'ultima reinstallazione, con la posta arrivata
     * dopo fusa dentro (ReinstallReturn). Poi chiede se riavviare adesso: il momento lo sceglie chi e'
     * al terminale.
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

    /** L'esito dell'ultimo ritorno chiesto dal menu (le prove lo leggono). */
    static final class JSONObjectHolder { static volatile org.json.JSONObject last; }

    /** Il nome del pannello salvato con la voce 2, "" se non c'e'. */
    private static String savedPanelHost() {
        try (ResultSet r = dbManager.get_data_config()) {
            if (r.next()) {
                String h = r.getString("panel_host");
                return h == null ? "" : h.trim();
            }
        } catch (Exception ignored) {
            // nessuna configurazione: nessun nome
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

        // I tre nomi prima di partire (reperto 244): la webmail non piu' quella di esempio, posta e web su nomi
        // diversi (la posta resta fuori dal proxy di Cloudflare). Gli avvisi lasciano scegliere.
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

        // Staccata dal menu (ReinstallJob): il menu la lancia e la segue. Se questo terminale si
        // chiude, la reinstallazione va avanti da sola fino in fondo.
        org.daemoxcp.mail.system.ReinstallJob.runFromMenu(mailHostname.trim(), System.out);

        // Un'attesa sola, alla fine: dopo la riprotezione dei pacchetti, non prima. Con l'attesa
        // dentro executeScript, chi chiudeva il terminale davanti a "Press ENTER" uccideva il
        // processo con i pacchetti ancora sbloccati (li riproteggeva solo il prossimo avvio).
        waitForEnter();

        try {
            screen.startScreen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * L'installazione completa, senza la finestra del nome: e' quello che fa la voce del menu
     * dopo che il nome e' stato scritto. Pubblica per il conduttore delle prove
     * (tests/org/daemoxcp/mail/system/MenuReinstall.java), che cosi' prova proprio questo codice.
     *
     * Sul turno dei lavori sui pacchetti, con i pacchetti protetti sbloccati prima e riprotetti
     * alla fine (InstallLocks). Il turno e lo sblocco vengono PRIMA di qualunque cambiamento:
     * prima del nome, dei flag dei servizi e soprattutto della nuova password di MySQL, che
     * salvata senza installazione lascerebbe il pannello con una password che MySQL non conosce.
     *
     * @return vero se lo script e' uscito con 0
     */
    public static boolean runInstallation(String mailHostname) {
        InstallLocks.Start start;
        // La via di ritorno (reperto 156): un boot environment fatto col turno preso e PRIMA dello
        // sblocco, cioe' col server com'e' adesso, pacchetti protetti compresi. Lo script cancella
        // le configurazioni, svuota /var/vmail e ricrea le tabelle di MySQL: senza, tornare indietro
        // da una reinstallazione andata male non si poteva. Se il sistema ha i boot environment e
        // questo non si crea, l'installazione non parte (la regola dei lavori sui pacchetti).
        org.daemoxcp.mail.system.PackageWayBack.Prepared[] wayBack = {null};
        java.util.function.Consumer<String> wayBackLog =
                line -> { if (!line.isEmpty()) System.out.println(ANSI_CYAN + "[WAY BACK] " + line + ANSI_RESET); };
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            start = InstallLocks.prepare(org.daemoxcp.mail.i18n.I18n.tr("server.reinstall.turn"), () -> {
                try {
                    // Lo spazio prima della via di ritorno: con meno di 1 GB libero si ferma qui, e
                    // altrimenti dice quanto la via di ritorno terra' occupato (reperto 170).
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
            // Dopo la riprotezione: il boot environment resta se lo script ha cominciato a cambiare
            // il sistema, si toglie se si e' fermato prima.
            org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
            try { org.daemoxcp.mail.system.PackageWayBack.afterInstallation(wayBackLog, wayBack[0], systemTouched.get()); }
            catch (RuntimeException e) { System.out.println(ANSI_YELLOW + "[WAY BACK] " + e.getMessage() + ANSI_RESET); }
            finally { org.daemoxcp.mail.i18n.I18n.clearCurrent(); }
            System.out.flush();
        }
        return success;
    }

    /** Il corpo dell'installazione, con il turno gia' preso e i pacchetti gia' sbloccati. */
    private static boolean installOnTurn(String mailHostname) {
        return installOnTurn(mailHostname, new java.util.concurrent.atomic.AtomicBoolean(false));
    }

    /**
     * @param systemTouched diventa vero quando lo script arriva alla fase 1, cioe' comincia a
     *        fermare servizi e cancellare configurazioni. Prima di li' lo script controlla soltanto
     *        (turno, parametri, Roundcube, pacchetti protetti) e non cambia niente.
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

        // Una password nuova a ogni installazione, ma IN ATTESA: quella del pannello resta la
        // vecchia finche' MySQL non conosce la nuova. Prima la si scriveva subito come password del
        // pannello, e ogni uscita dello script prima della fase 3 (Roundcube non configurato, un
        // parametro mancante, il turno, un pacchetto protetto, pkg) lasciava il pannello con una
        // password che MySQL rifiutava (reperto 156). La decisione e' dopo lo script, qui sotto.
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

        // La password di root di MySQL. Quella NON si rigenera a ogni installazione: la si
        // genera la prima volta e poi e' quella, perche' se MySQL c'e' gia' root la usa gia'
        // (una reinstallazione del pannello non e' una reinstallazione del database). Prima
        // non esisteva affatto e root entrava senza niente: lo script faceva "mysql -u root"
        // e, se falliva, "mysql -u root --password=".
        String mysqlRootPassword = org.daemoxcp.mail.security.PanelSecrets.ensureMysqlRootPassword();
        System.out.println(ANSI_GREEN + "[AUTO] MySQL root password ready in the panel secrets file" + ANSI_RESET);

        // La password dell'utente MySQL della webmail (roundcube): come quella di root si genera
        // una volta sola, perche' la migrazione all'avvio la rilegge da li' (RoundcubeDbUser).
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

        // Execute the unified mail server installation script. Le password viaggiano
        // nell'ambiente e non fra gli argomenti: un argomento lo legge chiunque con "ps".
        // Senza l'attesa di un tasto alla fine: la fa installMailServer, dopo la riprotezione.
        // DAEMOXCP_MAIL_PACKAGE_TURN dice allo script che il turno dei pacchetti lo tiene questo
        // processo, suo padre: senza, lo script prenderebbe il turno da se' con lockf, lo
        // troverebbe preso da noi e si fermerebbe. Lo script non ci crede sulla parola: controlla
        // che il lock sia preso e che dentro ci sia questo pid (FullMailServerScript).
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

        // Quale password conosce MySQL adesso: lo dice MySQL, non il codice d'uscita. Uno script
        // fallito dopo la fase 3 ha gia' dato a MySQL (e a Postfix e Dovecot) la password nuova;
        // uno fermato prima no. Il turno dei pacchetti e' ancora nostro (runInstallation).
        org.daemoxcp.mail.i18n.I18n.setCurrent(consoleLanguage);
        try {
            org.daemoxcp.mail.system.PendingDbPassword.Result decided =
                    org.daemoxcp.mail.system.PendingDbPassword.settle(passwordStore, mysqlProbe, mysqlUser);
            if (decided.outcome() == org.daemoxcp.mail.system.PendingDbPassword.Outcome.NEW_ADOPTED) {
                // Il resto della configurazione MySQL (host, porta, utente, database) in SQLite.
                dbManager.update_mysql_config(mysqlHost, mysqlPort, mysqlUser, mysqlPassword, mysqlDatabase);
                // Una password nuova che la webmail non ha mai avuto: niente da cambiare all'avvio (reperto 232).
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

        // Gli script scrivono nelle mappe di Postfix e nella connessione di Dovecot l'utente del pannello: si passa
        // subito ai loro utenti (MailDbUsers), che leggono solo le colonne che usano. Se qualcosa non torna i file
        // restano come li ha scritti lo script, e ci riprova il prossimo avvio del pannello.
        // Prima le tabelle del pannello complete (reperto 248): l'installazione crea solo quelle della posta, e le
        // altre (accesso, passkey, colonne aggiunte dopo come mailboxes.receive_enabled) arrivavano solo al primo
        // avvio del server web o con --create-admin. Senza, MailDbUsers qui sotto non trovava receive_enabled e
        // lasciava Postfix e Dovecot sull'utente del pannello fino all'avvio, e la voce 5 del menu si fermava.
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

            // Le utenze del pannello se ne vanno con le tabelle (lo script le ricrea vuote): chi ha
            // reinstallato deve sapere che il pannello web non fa entrare nessuno finche' non crea il
            // primo amministratore dalla console.
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

                // Only load self-signed if no certificate is configured. Il nome, la porta e il prefisso scritti con la
                // voce 2 restano (reperto 244): prima diventavano sempre 0.0.0.0, 2096 e daemoxcp-mail-.
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

            // L'installazione finisce col server gia' chiuso (installazione dal README, 20/11/2026). Lo script lascia un
            // pf.conf minimo che fa passare tutto, e MySQL in ascolto su ogni interfaccia anche col protocollo X (33060):
            // fino a oggi li chiudeva solo il primo avvio del pannello, e chi installava senza avviarlo, o lo avviava
            // ore dopo, restava aperto. Le stesse due chiusure del primo avvio, con lo stesso codice: dopo, l'avvio non
            // trova niente da fare. Le porte del pannello e della webmail le leggono dalla configurazione appena scritta
            // qui sopra. MySQL prima, perche' lo riavvia; poi pf.
            org.daemoxcp.mail.system.MysqlListen.ensureAtBoot();
            org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();

            System.out.println(ANSI_GREEN + "Mail server installed successfully!" + ANSI_RESET);
            System.out.flush();
        }
        return success;
    }

    /**
     * Vero quando non c'e' nessuno che possa premere un tasto: avvio da rc.d, da cron, da un
     * runner, o un `ssh host 'java ...'` senza -t.
     *
     * E' stato di classe e non un parametro perche' parametro era: arrivava a questa funzione
     * sola e le altre sei attese restavano scoperte, executeScript() compresa, che e' quella
     * che ha tenuto fermo un processo per sette ore e cinquanta a installazione finita bene.
     * Qui lo leggono waitForEnter() e startWebServer(), che sono tutti i punti in cui il
     * processo si ferma ad aspettare una persona.
     *
     * Lo decide il terminale, non la riga di comando: Console.isTerminal() e' vero solo se
     * stdin E stdout sono un tty, quindi anche un `| tail` lo spegne. --web lo forza comunque,
     * perche' significa "fai il servizio" anche se chi lo lancia ha un terminale davanti.
     */
    private static boolean nonInteractive = !hasTerminal();

    private static boolean hasTerminal() {
        java.io.Console console = System.console();
        return console != null && console.isTerminal();
    }

    /**
     * Accende il server del pannello e resta in ascolto.
     *
     * @return vero se il server e' partito, falso su ogni errore di configurazione e se la
     *         porta era occupata. Il chiamante non interattivo ne fa il proprio codice
     *         d'uscita: senza terminale il messaggio rosso a schermo non lo legge nessuno.
     *         Sul percorso di successo non torna: o resta in ascolto, o aspetta ENTER.
     */
    private static boolean startWebServer() {
        // Un pannello alla volta (PanelInstanceLock): prima di qualunque riparazione all'avvio e prima di prendere il
        // posto della parte web, che se c'e' gia' un pannello acceso e' la sua.
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

                // Da adesso il pannello guarda l'Host della richiesta, e con un indirizzo
                // wildcard quel nome non c'e': si accettano localhost e gli indirizzi di
                // questa macchina. E' lo stato normale dopo l'installazione, che scrive
                // 0.0.0.0, quindi lo si dice all'avvio invece di lasciarlo scoprire a chi
                // apre il pannello con un nome e si vede rifiutare.
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
                // Letti i valori, la lettura di SQLite si chiude QUI e non alla fine del try: sul
                // percorso buono questo metodo non torna (resta in ascolto), e il ResultSet aperto
                // teneva la lettura, cioe' il lock SHARED sul file, per tutta la vita del servizio.
                // Ogni scrittura di un altro processo dalla stessa cartella (il menu, la console)
                // finiva in SQLITE_BUSY: misurato sul clone il 06/11/2026 (reperti 156 e 160).
                result.close();

                mailDatabase = new MailDatabase();

                mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // rilegge la password a ogni ricollegamento
                mailDatabase.setCredentials(mysqlUser, mysqlPassword);
                mailDatabase.setHost(mysqlHost);
                mailDatabase.setPort(Integer.parseInt(mysqlPort));
                mailDatabase.setDatabase(mysqlDatabase);

                if (mailDatabase.connect()) {
                    mysqlAvailable = true;
                    // Le tabelle dell'accesso senza password, prima che il server risponda.
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

                // La porta gia' occupata quasi sempre vuol dire una cosa sola: il pannello e'
                // gia' acceso. Da quando puo' riaccendersi da solo dopo l'aggiornamento della
                // JVM, capita di lanciarlo credendolo spento — e una traccia di stack Java non
                // e' una risposta a "che e' successo?". Qui si dice chi occupa la porta.
                // Il pannello separato: la parte web con l'utente daemoxcp_mail sulla porta, questa parte root
                // senza porte. Se una condizione manca si resta come oggi, e lo si dice (PanelSeparation).
                SSLMailServer.Mode mode = SSLMailServer.Mode.LEGACY;
                String notSeparated = org.daemoxcp.mail.system.PanelSeparation.prepare(port, setupRequired, mysqlAvailable);
                if (notSeparated == null) mode = SSLMailServer.Mode.ROOT_PART;
                else separationNotApplied(notSeparated);
                SSLMailServer server;
                try {
                    server = new SSLMailServer(port, certContent, keyContent, mode);
                    if (mode == SSLMailServer.Mode.ROOT_PART) {
                        // Prima di accendere la web: il suo utente MySQL, che puo' solo chiamare le sue procedure
                        // (0.8.2). Se non e' pronto la web entra come prima, e lo si dice.
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
                // Il guardiano dei lavori sui pacchetti morti a meta' mentre il servizio e' acceso
                // (UpdateManager.startInterruptionWatch): prima ci pensava solo l'avvio.
                org.daemoxcp.mail.system.UpdateManager.startInterruptionWatch();

                // La regola dei blocchi: i pacchetti dello stack di posta restano bloccati,
                // tranne quelli sbloccati apposta da un amministratore.
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
                    // Prima la parte web, che senza la root non servirebbe piu' le API.
                    org.daemoxcp.mail.system.PanelSeparation.stop();
                    finalServer.stop();
                }));

                if (nonInteractive) {
                    // Senza terminale non si legge da stdin, in nessuna delle due forme che
                    // prende: chiuso, readLine() torna subito null e il server si spegnerebbe
                    // un istante dopo essersi acceso; pipe aperta, non torna affatto. Qui si
                    // resta fermi finche' non arriva un segnale, e a quello pensa lo shutdown hook.
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
        // Nessuna riga di configurazione in tabella, o un'eccezione: il server non e' partito.
        return false;
    }

    /**
     * La separazione non si fa: un avviso nel registro, tranne quando e' una scelta (spenta a mano) o non
     * e' il servizio (il menu, che gira da root con un terminale davanti).
     */
    private static void separationNotApplied(String why) {
        java.util.logging.Logger log = java.util.logging.Logger.getLogger(Main.class.getName());
        String text = "[PanelSeparation] NOT_APPLIED: " + why + "; the panel serves everything as root, as before";
        // Stati attesi, non guasti: spenta a mano, installazione non finita, il menu senza root.
        boolean expected = why.startsWith("switched off") || why.startsWith("the first installation")
                || why.startsWith("the panel is not running as root");
        if (expected || !nonInteractive) log.info(text);
        else log.warning(text);
    }

    /**
     * La parte web del pannello separato, con l'utente daemoxcp_mail: la porta del pannello, i filtri, l'accesso,
     * le pagine e le rotte pubbliche; le API di chi ha fatto l'accesso le passa alla parte root
     * (SSLMailServer in modo WEB_PART). SQLite in sola lettura: la configurazione la scrive solo root.
     *
     * @return falso se non e' partita: daemon(8) la riavvia, e la root dopo ANSWER_SECONDS torna al modo di oggi
     */
    /** Vero nella parte web del pannello separato (--web-part). */
    static volatile boolean webPart = false;

    private static boolean startWebPart() {
        nonInteractive = true;
        webPart = true;
        // Da qui la parte web non lancia comandi di sistema, salvo i pochi suoi (Shell.webPartOnly), e nel
        // database fa solo le istruzioni del suo elenco (CatalogGuard).
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
            // Il suo utente MySQL, che puo' solo chiamare le procedure della web (0.8.2, WebDbAccess), se la root
            // lo ha preparato e provato; altrimenti, come prima, l'utente del pannello.
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
            // La chiave delle sessioni e' della root, che le crea (A): senza, la web non riconoscerebbe nessuna
            // sessione, e non parte (daemon la riavvia).
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
                result.close();     // letti i valori: la lettura di SQLite non resta aperta mentre si lavora su MySQL

                mailDatabase = new MailDatabase();

                mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // rilegge la password a ogni ricollegamento
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
     * Svuota il database del pannello e ricrea le tabelle vuote. Vero solo se non e' rimasta
     * nessuna tabella di prima: "completato" si scrive solo allora, altrimenti si dice cosa resta.
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
            result.close();     // letti i valori: la lettura di SQLite non resta aperta mentre si azzera MySQL

            mailDatabase = new MailDatabase();

            mailDatabase.setPasswordSource(dbManager::mysqlPassword);   // rilegge la password a ogni ricollegamento
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
                // Anche dopo un reset non riuscito: il pannello ritrova le tabelle che mancano.
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
     * java -jar daemoxcp-mail.jar --create-admin <nome> <email>: il primo amministratore,
     * superadmin, senza password. Solo se non ce n'e' nessuno attivo: gli altri si aggiungono
     * dalla pagina Amministratori, e chi ha perso l'accesso usa --access-code. Stampa un codice
     * di accesso monouso, perche' l'email del server potrebbe non partire ancora (DNS da fare).
     * Si aspetta mailDatabase gia' collegato; restituisce il codice di uscita del processo.
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
        // Il nome del server di posta, scritto dall'installazione dal menu, anche nelle impostazioni.
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
     * Il pannello senza amministratore se ne accorge appena lo si crea dalla console: alla prima
     * richiesta dopo, prepara le tabelle dell'accesso e mostra la pagina di accesso.
     */
    public static synchronized void refreshSetupState() {
        if (!setupRequired || !mysqlAvailable || mailDatabase == null || !mailDatabase.hasAdminUser()) return;
        // La parte web non migra niente: le tabelle dell'accesso le sistema la root, che sola le scrive (A).
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
     * Il collegamento a MySQL con i dati della configurazione, per i comandi da console e dal menu.
     * Null se riesce, altrimenti il perche' (da mostrare a chi l'ha chiesto).
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

    /** La lingua della console: la sceglie chooseConsoleLanguage, una volta, all'avvio. */
    static String consoleLanguage = "en";

    /** Vero se la lingua viene da --lang o dal terminale: allora un comando per un amministratore non la cambia. */
    static boolean consoleLanguageAsked = false;

    /**
     * La lingua della console (menu a schermo e comandi da riga di comando), nell'ordine di ConsoleLanguage: --lang xx,
     * la lingua del terminale (LC_ALL, LC_MESSAGES, LANG), la lingua del pannello (del primo amministratore attivo che
     * ne ha scelta una), l'inglese (anche su un server non ancora installato, o con MySQL fermo). La lingua di un
     * amministratore per i suoi comandi la mette useAdminLanguage. Diventa la lingua del processo (I18n), cosi' ogni
     * testo della console la segue senza passarsela.
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
     * Un comando per un amministratore (--access-code nome) parla la lingua che lui ha scelto nel pannello, se c'e' e
     * se --lang o il terminale non ne hanno gia' detta una: il codice e' per lui.
     */
    static void useAdminLanguage(String username) {
        if (consoleLanguageAsked || username == null || mailDatabase == null) return;
        String own = mailDatabase.getAdminLanguage(username);
        if (own != null) useConsoleLanguage(org.daemoxcp.mail.i18n.ConsoleLanguage.choose(null, null, own, consoleLanguage));
    }

    private static void useConsoleLanguage(String lang) {
        consoleLanguage = lang;
        org.daemoxcp.mail.i18n.I18n.setProcessLanguage(consoleLanguage);
        // Anche i pulsanti delle finestre di Lanterna (OK, Annulla, Si', No): li sceglie dalla lingua predefinita.
        java.util.Locale.setDefault(java.util.Locale.forLanguageTag(consoleLanguage));
    }

    /** La lingua del pannello letta da MySQL con una connessione sola, chiusa subito; null se non si legge. */
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

    /** Un MailDatabase con la configurazione del pannello (la riga di SQLite), non ancora collegato. */
    static MailDatabase configuredMailDatabase(ResultSet result) throws java.sql.SQLException {
        MailDatabase db = new MailDatabase();
        db.setPasswordSource(dbManager::mysqlPassword);   // rilegge la password a ogni ricollegamento
        db.setCredentials(result.getString("mysql_user"), dbManager.mysqlPassword());
        db.setHost(result.getString("mysql_host"));
        db.setPort(Integer.parseInt(result.getString("mysql_port")));
        db.setDatabase(result.getString("mysql_database"));
        return db;
    }

    /** L'esito di un comando da console: il testo da mostrare e se e' riuscito. */
    record ConsoleResult(boolean ok, String text) {}

    /**
     * Un codice di accesso monouso per un amministratore attivo (quello col nome dato, o l'unico).
     * Si aspetta mailDatabase gia' collegato.
     */
    static ConsoleResult accessCode(String username) {
        try {
            // Lo schema prima, come --create-admin (reperto 248): su un server appena installato le tabelle
            // dell'accesso non ci sono ancora.
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
     * Dal menu del terminale: il codice di accesso di emergenza, per quando passkey ed email non
     * bastano. Se non c'e' ancora nessun amministratore, si crea qui il primo.
     */
    private static void emergencyAccess(MultiWindowTextGUI gui) {
        String title = org.daemoxcp.mail.i18n.I18n.tr("console.menu.code");
        String notConnected = connectFromConfig();
        if (notConnected != null) {
            message(gui, title, notConnected);
            return;
        }
        try {
            mailDatabase.createSchema();   // reperto 248, come --create-admin
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
     * java -jar daemoxcp-mail.jar --access-code [nome]: un codice monouso di otto cifre
     * per entrare senza email ne' passkey (primo accesso, email persa). Lo genera solo chi ha una
     * shell sul server; vale 15 minuti, una volta. Restituisce il codice di uscita del processo.
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
     * --ip-family: IPv4, IPv6, tutte e due, o la posta in IPv6 solo in uscita (ipv6out), dalla console, come la scheda delle Impostazioni ma senza avvisi da
     * confermare: e' la strada di chi ha scelto una famiglia sola e da li' non raggiunge piu' il pannello. Gli stessi
     * controlli (indirizzo e rotta nella famiglia che resta) e lo stesso ritorno a com'era se un servizio non regge.
     * Da root: riscrive le configurazioni di Postfix, Dovecot e nginx e ricarica pf.
     */
    /**
     * --empty-folders: lo svuotamento d'emergenza della Junk e/o del Cestino, di tutte le caselle (all) o di quelle
     * date, subito (EmergencyEmpty). Solo da root e da un terminale: mostra quanti messaggi toglie e chiede di scrivere
     * quel numero. Lo svuotamento di tutti i giorni e' automatico, casella per casella, dal pannello o dalla webmail.
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
        // Da Java 22 System.console() c'e' anche senza un terminale: isTerminal() dice se dall'altra parte c'e' qualcuno.
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
        // In console le righe INFO dei servizi toccati sono rumore: restano avvisi ed errori, e l'esito qui sotto.
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
            // Il firewall del pannello (liste, paesi) segue la scelta: la sua prima regola rifiuta la famiglia chiusa.
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
     * --addresses: gli indirizzi del server dalla console, la via d'uscita di chi non raggiunge piu' il pannello dopo un
     * passo della guida (ServerAddresses). show li mostra; ipv6-off toglie l'IPv6 aggiunto dal pannello e rimette le
     * righe di rc.conf di prima; ipv4-dhcp riprende l'IPv4 col DHCP. Gli stessi controlli e lo stesso ritorno a com'era
     * della pagina. Da root: ifconfig, route e rc.conf. SSH non si tocca.
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

    /** All'avvio: se nessun amministratore puo' entrare, come si fa. */
    static void warnIfNoLogin() {
        boolean someoneCanLogIn = org.daemoxcp.mail.security.AuthStore.admins().stream().anyMatch(a -> a.active()
                && (a.hasEmail() || !org.daemoxcp.mail.security.AuthStore.passkeysOf(a.id()).isEmpty()));
        if (!someoneCanLogIn)
            System.out.println(ANSI_YELLOW + "No administrator has a login email or a passkey yet. Get a one-time code with:\n"
                    + "  java -jar daemoxcp-mail.jar --access-code" + ANSI_RESET);
    }
}
