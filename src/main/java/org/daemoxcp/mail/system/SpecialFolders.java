package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Le cartelle speciali di ogni casella (Bozze, Inviata, Cestino, Junk) e lo spam nella Junk.
 *
 * Misurato sulla VM il 20/11/2026, installata da zero dal README:
 * <ul>
 *   <li>la posta che Rspamd segna (azione «add header», punteggio fra 6 e 15) arrivava nella INBOX con la sola riga
 *       «X-Spam: Yes»: nessuna regola la spostava nella Junk;</li>
 *   <li>peggio, le regole del pannello giravano anche su quella: con la risposta automatica accesa, un messaggio con
 *       «X-Spam: Yes» consegnato via LMTP ha avuto la sua risposta («vacation action: sent vacation response»), cioe'
 *       una lettera verso un mittente che nello spam e' quasi sempre falso (backscatter: rovina la reputazione del
 *       server). La documentazione di Pigeonhole sulla risposta automatica elenca i messaggi a cui non risponde (liste,
 *       Auto-Submitted, Precedence bulk/junk/list, mittente vuoto o di sistema): nessuna intestazione di spam. Lo stesso
 *       per l'inoltro: lo spam usciva verso l'indirizzo di inoltro, a nome di questo server;</li>
 *   <li>Dovecot non diceva ai programmi di posta quali sono le cartelle speciali (IMAP SPECIAL-USE, RFC 6154): nessun
 *       blocco namespace, quindi nessuna \Drafts, \Sent, \Trash, \Junk. Ogni programma se le crea col suo nome (Apple
 *       «Sent Messages» e «Deleted Messages», Outlook «Sent Items»), e la posta inviata finisce divisa. Sul server vero,
 *       contate il 20/11/2026: 8 caselle su 12 con Drafts, Sent, Trash e Junk (le crea la webmail al primo accesso,
 *       create_default_folders = true), una «Sent Messages» e due «Deleted Messages».</li>
 * </ul>
 *
 * Il rimedio, dalla documentazione di Dovecot e di Pigeonhole (2.3 e 2.4):
 * <ul>
 *   <li>il namespace della INBOX con le quattro cartelle e il loro special_use, con auto = subscribe: Dovecot le crea e
 *       le sottoscrive per ogni casella, con gli stessi nomi che la webmail gia' crea; cosi' un programma che le cerca le
 *       trova invece di inventarne altre. Il separatore resta quello di prima (il punto di Maildir, misurato: LIST
 *       risponde "." prima e dopo) e nessuna cartella cambia nome;</li>
 *   <li>uno script Sieve fisso, di root, che gira per primo, prima delle regole del pannello e di quelle della casella:
 *       «X-Spam: Yes» (l'intestazione che il proxy di Rspamd aggiunge con l'azione add header, la spam_header
 *       predefinita) va nella Junk e la sequenza si ferma. Nella documentazione di Pigeonhole lo script dopo gira solo se
 *       e' in vigore un keep: dopo fileinto e stop non c'e', quindi niente risposta automatica, niente inoltro e niente
 *       regole della casella sullo spam. Nella 2.4 l'ordine lo da' precedence (piu' bassa prima; le altre hanno quella
 *       predefinita, infinita); nella 2.3 sieve_before e sieve_before2, e le regole del pannello passano alla seconda.</li>
 * </ul>
 *
 * Chi manda posta puo' scriversi da solo «X-Spam: Yes»: ottiene solo che il suo messaggio vada nella Junk. Rspamd non
 * scrive «X-Spam: No», quindi non c'e' niente da falsificare nell'altro verso.
 *
 * L'installatore scrive gli stessi due file (DovecotConfig); sui server installati prima li scrive questa riparazione
 * all'avvio. Lo script lo compila sievec come utente sievec (SieveCompiler), mai root, a ogni avvio se e' cambiato
 * Pigeonhole. Prima di toccare la configurazione controlla che l'autenticazione funzioni e che nessun altro abbia
 * scritto un suo namespace; dopo, che Dovecot giri, che l'autenticazione passi ancora e che una casella veda la Junk
 * come \Junk. Se qualcosa non torna toglie il file e ricarica: Dovecot torna com'era. Al secondo avvio non fa niente.
 */
public final class SpecialFolders {

    private static final Logger LOGGER = Logger.getLogger(SpecialFolders.class.getName());

    public static final String FILE_NAME = "15-special-folders.conf";
    /** Lo script, relativo alla cartella di Dovecot: lo stesso per l'installatore e per la riparazione. */
    public static final String SCRIPT_IN_ETC = "sieve/spam-to-junk.sieve";
    public static final Path SCRIPT = Path.of("/usr/local/etc/dovecot").resolve(SCRIPT_IN_ETC);
    /** Le regole del pannello nella 2.3: le stesse di DovecotConfig.SIEVE23, che qui passano a sieve_before2. */
    static final String PANEL_RULES_23 = "/var/mail/sieve/%d/%n/.dovecot.sieve";
    /** L'intestazione dello spam: quella che il proxy di Rspamd scrive con l'azione add header (spam_header). */
    public static final String SPAM_HEADER = "X-Spam";
    public static final String JUNK = "Junk";
    /** Il nome del blocco sieve_script nella 2.4. */
    static final String SCRIPT_BLOCK = "spam_to_junk";

    /** Le cartelle e il loro uso speciale (RFC 6154), coi nomi che la webmail usa gia'. */
    static final String[][] FOLDERS = {{"Drafts", "\\Drafts"}, {"Sent", "\\Sent"}, {"Trash", "\\Trash"}, {JUNK, "\\Junk"}};

    private SpecialFolders() {}

    /** Lo script Sieve: lo stesso per l'installatore e per la riparazione. */
    public static String scriptContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Spam that Rspamd marks (" + SPAM_HEADER + ": Yes) into " + JUNK + ", before any other rule: no\n"
             + "# automatic reply, forward or mailbox rules on spam.\n"
             + "require [\"fileinto\", \"mailbox\"];\n"
             + "\n"
             + "if header :is \"" + SPAM_HEADER + "\" \"Yes\" {\n"
             + "  fileinto :create \"" + JUNK + "\";\n"
             + "  stop;\n"
             + "}\n";
    }

    /** Il file di conf.d: lo stesso per l'installatore (DovecotConfig) e per la riparazione. */
    public static String fileContent(boolean dovecot24) {
        StringBuilder s = new StringBuilder();
        s.append("# ").append(PanelMarker.WRITTEN).append(".\n")
         .append("# The special folders (IMAP SPECIAL-USE, RFC 6154): mail programs find them here instead of\n")
         .append("# creating their own. Dovecot creates and subscribes them for every mailbox, with the webmail's names.\n")
         .append("namespace inbox {\n")
         .append("  inbox = yes\n");
        for (String[] f : FOLDERS) {
            s.append("  mailbox ").append(f[0]).append(" {\n")
             .append("    special_use = ").append(f[1]).append("\n")
             .append("    auto = subscribe\n")
             .append("  }\n");
        }
        s.append("}\n\n")
         .append("# Spam (").append(SPAM_HEADER).append(": Yes, from Rspamd) into ").append(JUNK)
         .append(" before the panel's and the mailbox's rules.\n");
        if (dovecot24) {
            s.append("sieve_script ").append(SCRIPT_BLOCK).append(" {\n")
             .append("  type = before\n")
             .append("  driver = file\n")
             .append("  path = ").append(SCRIPT).append("\n")
             .append("  # Lowest first: the others have the default one (infinite).\n")
             .append("  precedence = 1\n")
             .append("}\n");
        } else {
            s.append("plugin {\n")
             .append("  sieve_before = ").append(SCRIPT).append("\n")
             .append("  # The panel's rules after: this line replaces their sieve_before of 10-master.conf.\n")
             .append("  sieve_before2 = ").append(PANEL_RULES_23).append("\n")
             .append("}\n");
        }
        return s.toString();
    }

    /** In `doveconf -n` c'e' gia' un namespace scritto da altri (il nostro file non c'e'). Pura. */
    static boolean otherNamespace(String doveconf, boolean ourFileThere) {
        return !ourFileThere && doveconf != null && doveconf.matches("(?s)(.*\\n)?namespace [^\\n]*\\{.*");
    }

    /** Le regole del pannello sono gia' configurate: Pigeonhole c'e' e il pannello l'ha impostato. Pura. */
    static boolean panelSieve(String doveconf, boolean dovecot24) {
        if (doveconf == null) return false;
        return dovecot24 ? doveconf.contains("sieve_script panel {") : doveconf.contains("sieve_before");
    }

    /** La risposta di LIST con RETURN (SPECIAL-USE) segna la Junk come \Junk. Pura. */
    static boolean junkMarked(String imap) {
        return imap != null && imap.matches("(?s).*\\* LIST \\([^)]*\\\\Junk[^)]*\\) \"[^\"]*\" \"?" + JUNK + "\"?\\r?\\n.*");
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF)) || !Files.isExecutable(Path.of(ManageSieveLocal.DOVECOT))) return;
            Shell.Result version = Shell.run(Duration.ofSeconds(15), ManageSieveLocal.DOVECOT, "--version");
            if (!version.success()) return;
            boolean v24 = ManageSieveLocal.is24(version.outputTrim());
            Shell.Result conf = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!conf.success() || !panelSieve(conf.output(), v24)) return;

            boolean scriptChanged = writeScript();
            if (scriptChanged || !Files.exists(SieveCompiler.binaryFor(SCRIPT))) {
                SieveCompiler.Outcome o = SieveCompiler.compile(SCRIPT);
                if (o.status() != SieveCompiler.Status.COMPILED)
                    LOGGER.warning("[SpecialFolders] " + SCRIPT + " not precompiled (" + o.status() + ": " + o.message()
                            + "): Dovecot compiles it at each delivery");
            } else {
                // Pigeonhole aggiornato: il compilato si rifa' se sievec oggi ne fa uno diverso.
                SieveCompiler.Outcome o = SieveCompiler.refresh(SCRIPT);
                if (o.status() == SieveCompiler.Status.COMPILED)
                    LOGGER.info("[SpecialFolders] DONE: " + SCRIPT + " compiled again for the Sieve now installed");
            }

            Path file = Path.of(DovecotAuthWorker.CONF_D, FILE_NAME);
            String wanted = fileContent(v24);
            boolean there = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
            if (there && wanted.equals(Files.readString(file, StandardCharsets.UTF_8))) return;
            if (otherNamespace(conf.output(), there)) {
                LOGGER.warning("[SpecialFolders] Dovecot already has a namespace written by someone else: special folders and"
                        + " spam to " + JUNK + " not configured, nothing changed");
                return;
            }
            apply(file, wanted, v24);
        } catch (Throwable t) {
            LOGGER.warning("[SpecialFolders] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Lo script al suo posto, di root e leggibile (Dovecot lo legge come vmail): vero se e' stato scritto adesso. */
    static boolean writeScript() throws Exception {
        String wanted = scriptContent();
        if (Files.isRegularFile(SCRIPT, LinkOption.NOFOLLOW_LINKS)
                && wanted.equals(Files.readString(SCRIPT, StandardCharsets.UTF_8))) return false;
        Path dir = SCRIPT.getParent();
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
        write(SCRIPT, wanted);
        return true;
    }

    static boolean apply(Path file, String content, boolean v24) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[SpecialFolders] Dovecot is not running: folders left as they are, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[SpecialFolders] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): folders left as they are");
            return false;
        }
        Path saved = Files.exists(file) ? Files.createTempFile(file.getParent().getParent(), ".special-folders-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, content);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[SpecialFolders] ROLLED_BACK: doveconf refuses the settings (" + firstLine(check.outputTrim())
                        + "): nothing changed");
                return false;
            }
            reload();
            String problem = verify(v24);
            if (problem != null) {
                putBack(file, saved, true);
                LOGGER.warning("[SpecialFolders] ROLLED_BACK: " + problem + "; everything put back");
                return false;
            }
            LOGGER.info("[SpecialFolders] DONE: every mailbox has Drafts, Sent, Trash and " + JUNK + " marked for the mail"
                    + " programs, and mail that Rspamd marks as spam goes to " + JUNK + " before any other rule (" + file + ")");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /** Dopo il reload: Dovecot gira, l'autenticazione passa, la configurazione ha lo script, una casella vede \Junk. */
    static String verify(boolean v24) throws InterruptedException {
        String last = "Dovecot did not come back";
        for (int i = 0; i < 20; i++) {
            Thread.sleep(500);
            if (!DovecotAuthWorker.running()) { last = "Dovecot is not running after the reload"; continue; }
            int rc = DovecotAuthWorker.lookup();
            if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) { last = "doveadm auth lookup fails (exit " + rc + ")"; continue; }
            String conf = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n").output();
            if (!(v24 ? conf.contains("sieve_script " + SCRIPT_BLOCK + " {") : conf.contains("sieve_before = " + SCRIPT))) {
                last = "the spam script is not in the configuration Dovecot reads"; continue;
            }
            String user = firstUser();
            if (user != null) {
                String imap = list(user);
                if (!junkMarked(imap)) { last = "IMAP does not show " + JUNK + " as \\Junk"; continue; }
            }
            return null;
        }
        return last;
    }

    /** Una casella qualunque, per la prova di LIST; null se non ce n'e' ancora nessuna. */
    static String firstUser() {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "doveadm", "user", "*");
        if (!r.success()) return null;
        for (String line : r.output().split("\n")) {
            String u = line.trim();
            if (u.matches("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")) return u;
        }
        return null;
    }

    /** LIST della Junk con RETURN (SPECIAL-USE), da un IMAP lanciato per la casella (doveadm exec, come root). */
    static String list(String user) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "sh", "-c",
                "printf 'a LIST \"\" \"" + JUNK + "\" RETURN (SPECIAL-USE)\\r\\nb LOGOUT\\r\\n' | timeout -f 20 doveadm exec imap -u \"$1\" 2>/dev/null",
                "sh", user);
        return r.output();
    }

    static void reload() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean reload) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (reload) reload();
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
