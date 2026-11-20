package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.logging.Logger;

/**
 * Rspamd impara dagli utenti: un messaggio spostato (o copiato) nella Junk e' spam, uno tolto dalla Junk e' posta buona,
 * tranne quando va nel Cestino.
 *
 * Prima Rspamd imparava solo da chi lanciava rspamc a mano: il filtro bayesiano (Redis, almeno 200 messaggi per parte
 * prima di dire la sua) restava vuoto. Adesso, con IMAPSieve di Pigeonhole (Dovecot 2.4: il plugin imap_sieve, i blocchi
 * mailbox e imapsieve_from della sua documentazione), quando un programma di posta o il pulsante «Spam» della webmail
 * (markasjunk) sposta un messaggio, Dovecot lo passa con vnd.dovecot.pipe a un programma del pannello, che lo deposita
 * in /var/spool/daemoxcp-learn/spam o /ham. Il programma gira come vmail, come IMAP; non conosce nessuna password.
 * Rspamd impara solo dal controller con la password «enable» (learnspam e learnham sono comandi privilegiati), che
 * resta nei segreti di root: la consegna a Rspamd la fa la parte root del pannello (SpamLearner), ogni minuto, e
 * cancella il messaggio appena Rspamd risponde. Dare quella password a vmail gli avrebbe dato anche tutto il resto del
 * controller (pesi, mappe, statistiche).
 *
 * Misurato sulla VM il 20/11/2026 (Dovecot 2.4.5, Rspamd 4.1): MOVE e COPY nella Junk fanno partire lo script (cause
 * = copy vale anche per MOVE); Junk -> INBOX da' ham; Junk -> Trash niente; la regola dello spam alla consegna
 * (SpecialFolders) non interviene sugli spostamenti, e un messaggio segnato X-Spam tolto dalla Junk resta dove l'utente
 * l'ha messo; nessun errore di Sieve nel registro. Rspamd risponde 204 quando impara, 401 senza password, 400 a un corpo
 * vuoto. sievec non conosce vnd.dovecot.pipe e imapsieve senza -P sieve_imapsieve -P sieve_extprograms -x: con quelle
 * opzioni il compilato dell'utente sievec e' identico a quello di root.
 *
 * Solo Dovecot 2.4 (sulla 2.3 la configurazione e' un'altra: il pannello lo dice e non tocca niente), e solo dove c'e'
 * la Junk del pannello (SpecialFolders). Prima di toccare qualcosa controlla che Dovecot giri e che l'autenticazione
 * funzioni; dopo il reload, che Dovecot giri, che l'autenticazione funzioni, che il plugin sia attivo per IMAP, che IMAP
 * si apra per una casella e che il programma, come vmail, possa scrivere nella cartella. Se qualcosa non torna toglie il
 * file di configurazione e ricarica: Dovecot torna com'era (gli script e il programma da soli non fanno niente). Un file
 * di configurazione con lo stesso nome scritto a mano resta com'e'. Al secondo avvio non fa niente.
 */
public final class SpamLearning {

    private static final Logger LOGGER = Logger.getLogger(SpamLearning.class.getName());

    static final Path ETC = Path.of("/usr/local/etc/dovecot");
    public static final String CONF_NAME = "16-learn-from-users.conf";
    public static final String SPAM_SCRIPT_IN_ETC = "sieve/learn-spam.sieve";
    public static final String HAM_SCRIPT_IN_ETC = "sieve/learn-ham.sieve";
    public static final String PIPE_DIR = "/usr/local/libexec/daemoxcp-mail/sieve-pipe";
    public static final String PROGRAM = "daemoxcp-learn";
    public static final String SPOOL = "/var/spool/daemoxcp-learn";
    public static final List<String> KINDS = List.of("spam", "ham");
    static final String VMAIL = "vmail";
    /** Oltre questa misura un messaggio non si deposita: Rspamd non impara da allegati enormi, e la cartella non si gonfia. */
    public static final long MAX_BYTES = 10L << 20;
    /** sievec senza queste opzioni non conosce le estensioni degli script (misurato). */
    static final List<String> SIEVEC_OPTIONS = List.of("-P", "sieve_imapsieve", "-P", "sieve_extprograms", "-x", "+vnd.dovecot.pipe +imapsieve");

    private SpamLearning() {}

    /** La configurazione di Dovecot 2.4. Pura. */
    public static String confContent() {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# Rspamd learns from the users (SpamLearning): a message moved or copied into " + SpecialFolders.JUNK + " is spam,\n"
             + "# one moved out of it (not into " + TRASH + ") is ham. The scripts hand it to " + PROGRAM + ", which leaves it in\n"
             + "# " + SPOOL + "; the panel's root part gives it to Rspamd and deletes it.\n"
             + "protocol imap {\n"
             + "  mail_plugins {\n"
             + "    imap_sieve = yes\n"
             + "  }\n"
             + "}\n"
             + "sieve_plugins {\n"
             + "  sieve_imapsieve = yes\n"
             + "  sieve_extprograms = yes\n"
             + "}\n"
             + "sieve_global_extensions {\n"
             + "  vnd.dovecot.pipe = yes\n"
             + "}\n"
             + "sieve_pipe_bin_dir = " + PIPE_DIR + "\n"
             + "mailbox " + SpecialFolders.JUNK + " {\n"
             + "  sieve_script learn_spam {\n"
             + "    type = before\n"
             + "    cause = copy\n"
             + "    path = " + ETC + "/" + SPAM_SCRIPT_IN_ETC + "\n"
             + "  }\n"
             + "}\n"
             + "imapsieve_from " + SpecialFolders.JUNK + " {\n"
             + "  sieve_script learn_ham {\n"
             + "    type = before\n"
             + "    cause = copy\n"
             + "    path = " + ETC + "/" + HAM_SCRIPT_IN_ETC + "\n"
             + "  }\n"
             + "}\n";
    }

    static final String TRASH = "Trash";

    public static String spamScript() {
        return "# " + PanelMarker.WRITTEN + " (SpamLearning): moved or copied into " + SpecialFolders.JUNK + ", Rspamd learns it as spam.\n"
             + "require [\"vnd.dovecot.pipe\", \"copy\", \"imapsieve\"];\n"
             + "pipe :copy \"" + PROGRAM + "\" [\"spam\"];\n";
    }

    public static String hamScript() {
        return "# " + PanelMarker.WRITTEN + " (SpamLearning): moved out of " + SpecialFolders.JUNK + ", Rspamd learns it as ham;\n"
             + "# not when it goes to " + TRASH + ".\n"
             + "require [\"vnd.dovecot.pipe\", \"copy\", \"imapsieve\", \"environment\", \"variables\"];\n"
             + "if environment :matches \"imap.mailbox\" \"*\" { set \"mailbox\" \"${1}\"; }\n"
             + "if string \"${mailbox}\" \"" + TRASH + "\" { stop; }\n"
             + "pipe :copy \"" + PROGRAM + "\" [\"ham\"];\n";
    }

    /**
     * Il programma: legge tutto il messaggio (Pigeonhole lo vuole), ne tiene al massimo MAX_BYTES, lo scrive con un nome
     * che comincia col punto e poi lo rinomina, cosi' la parte root vede solo messaggi interi. Con «check» prova solo a
     * scrivere (la verifica dopo il reload). Esce sempre 0: un errore qui non deve fermare lo spostamento. Pura.
     */
    public static String programContent() {
        return "#!/bin/sh\n"
             + "# " + PanelMarker.WRITTEN + " (SpamLearning): Dovecot pipes here a message moved into or out of "
             + SpecialFolders.JUNK + ".\n"
             + "# It runs as " + VMAIL + " and only leaves the message in " + SPOOL + "/<kind>; the panel gives it to Rspamd.\n"
             + "umask 077\n"
             + "PATH=/bin:/usr/bin; export PATH\n"
             + "case \"$1\" in\n"
             + "  spam|ham) ;;\n"
             + "  check) t=$(mktemp \"" + SPOOL + "/spam/.check.XXXXXXXX\") && rm -f \"$t\" && echo ok; exit 0 ;;\n"
             + "  *) cat > /dev/null; exit 0 ;;\n"
             + "esac\n"
             + "dir=" + SPOOL + "/$1\n"
             + "tmp=$(mktemp \"$dir/.in.XXXXXXXX\") || { cat > /dev/null; exit 0; }\n"
             + "head -c " + MAX_BYTES + " > \"$tmp\"\n"
             + "cat > /dev/null\n"
             + "mv \"$tmp\" \"$dir/$(date +%s).${tmp##*.in.}\"\n"
             + "exit 0\n";
    }

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    /**
     * Che cosa fare. is24: Dovecot 2.4; junk: c'e' la Junk del pannello (il file di SpecialFolders); conf: il file di
     * adesso (null se non c'e'); partsCurrent: script, programma e cartella sono gia' quelli giusti. Pura.
     */
    static Action decide(boolean is24, boolean junk, String conf, boolean partsCurrent) {
        if (!is24 || !junk) return Action.NOTHING;
        if (conf == null) return Action.APPLY;
        if (!conf.contains(PanelMarker.WRITTEN)) return Action.LEFT_ALONE;
        return conf.equals(confContent()) && partsCurrent ? Action.NOTHING : Action.APPLY;
    }

    static Path conf() { return ETC.resolve("conf.d").resolve(CONF_NAME); }
    static Path spamScriptPath() { return ETC.resolve(SPAM_SCRIPT_IN_ETC); }
    static Path hamScriptPath() { return ETC.resolve(HAM_SCRIPT_IN_ETC); }
    static Path program() { return Path.of(PIPE_DIR, PROGRAM); }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF)) || !Files.isExecutable(Path.of(ManageSieveLocal.DOVECOT))) return;
            Shell.Result version = Shell.run(Duration.ofSeconds(15), ManageSieveLocal.DOVECOT, "--version");
            if (!version.success()) return;
            boolean is24 = ManageSieveLocal.is24(version.outputTrim());
            boolean junk = Files.isRegularFile(ETC.resolve("conf.d").resolve(SpecialFolders.FILE_NAME), LinkOption.NOFOLLOW_LINKS);
            if (!is24) {
                LOGGER.info("[SpamLearning] Rspamd learning from the users' moves needs Dovecot 2.4: not set up");
                return;
            }
            Path conf = conf();
            String current = Files.isRegularFile(conf, LinkOption.NOFOLLOW_LINKS) ? Files.readString(conf, StandardCharsets.UTF_8)
                    : Files.exists(conf, LinkOption.NOFOLLOW_LINKS) ? "" : null;
            switch (decide(true, junk, current, partsCurrent())) {
                case NOTHING -> {
                    if (current != null) refreshBinaries();
                }
                case LEFT_ALONE -> LOGGER.info("[SpamLearning] " + conf + " was not written by the panel: left as it is");
                case APPLY -> apply(conf, current);
            }
        } catch (Throwable t) {
            LOGGER.warning("[SpamLearning] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** Script, programma e cartella di raccolta come li vuole il pannello. */
    static boolean partsCurrent() {
        try {
            if (!same(spamScriptPath(), spamScript()) || !same(hamScriptPath(), hamScript()) || !same(program(), programContent())) return false;
            if (!Files.isExecutable(program())) return false;
            for (String k : KINDS) if (!spoolDirRight(Path.of(SPOOL, k))) return false;
            return spoolDirRight(Path.of(SPOOL));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean same(Path file, String content) throws Exception {
        return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && content.equals(Files.readString(file, StandardCharsets.UTF_8));
    }

    /** Una cartella vera, di vmail, 0700. */
    static boolean spoolDirRight(Path dir) throws Exception {
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return false;
        PosixFileAttributes a = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName().equals(VMAIL) && a.group().getName().equals(VMAIL)
                && PosixFilePermissions.toString(a.permissions()).equals("rwx------");
    }

    /** Se Pigeonhole e' cambiato, i compilati si rifanno (come SpecialFolders); altrimenti niente. */
    static void refreshBinaries() {
        for (Path s : List.of(spamScriptPath(), hamScriptPath())) {
            SieveCompiler.Outcome o = SieveCompiler.refresh(s, SIEVEC_OPTIONS);
            if (o.status() == SieveCompiler.Status.COMPILED) LOGGER.info("[SpamLearning] DONE: " + s + " compiled again for the Sieve now installed");
        }
    }

    static boolean apply(Path conf, String previous) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[SpamLearning] Dovecot is not running: learning from the users not set up, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[SpamLearning] authentication already fails before any change (doveadm auth lookup exit " + before
                    + "): learning from the users not set up");
            return false;
        }
        // Le parti che da sole non fanno niente: la cartella di raccolta, il programma, gli script compilati.
        String spool = makeSpool();
        if (spool != null) {
            LOGGER.warning("[SpamLearning] " + spool + ": learning from the users not set up");
            return false;
        }
        Files.createDirectories(Path.of(PIPE_DIR), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")));
        write(program(), programContent(), "rwxr-xr-x");
        write(spamScriptPath(), spamScript(), "rw-r--r--");
        write(hamScriptPath(), hamScript(), "rw-r--r--");
        for (Path s : List.of(spamScriptPath(), hamScriptPath())) {
            SieveCompiler.Outcome o = SieveCompiler.compile(s, SIEVEC_OPTIONS);
            if (o.status() != SieveCompiler.Status.COMPILED)
                LOGGER.warning("[SpamLearning] " + s + " not precompiled (" + o.status() + ": " + o.message() + "): Dovecot compiles it at each move");
        }
        write(conf, confContent(), "rw-r--r--");
        Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
        if (!check.success()) {
            putBack(conf, previous, false);
            LOGGER.warning("[SpamLearning] ROLLED_BACK: doveconf refuses the configuration: nothing changed");
            return false;
        }
        reload();
        String problem = verify();
        if (problem != null) {
            putBack(conf, previous, true);
            LOGGER.warning("[SpamLearning] ROLLED_BACK: " + problem + "; Dovecot put back as it was");
            return false;
        }
        LOGGER.info("[SpamLearning] DONE: Rspamd learns from the users: moved into " + SpecialFolders.JUNK + " is spam, moved out"
                + " of it is ham (" + conf + ")");
        return true;
    }

    /** /var/spool/daemoxcp-learn e le sue due cartelle: di vmail, 0700. null se va bene, altrimenti il problema. */
    static String makeSpool() throws Exception {
        for (Path d : List.of(Path.of(SPOOL), Path.of(SPOOL, "spam"), Path.of(SPOOL, "ham"))) {
            if (Files.isSymbolicLink(d)) return d + " is a link";
            if (!Files.exists(d, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(d);
            if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) return d + " is not a folder";
            Shell.Result r = Shell.run(Duration.ofSeconds(15), "/usr/sbin/chown", "-h", VMAIL + ":" + VMAIL, d.toString());
            if (!r.success()) return "cannot give " + d + " to " + VMAIL;
            Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwx------"));
        }
        return null;
    }

    /** Dopo il reload: Dovecot gira, l'autenticazione passa, il plugin e' attivo per IMAP, IMAP si apre, vmail scrive. */
    static String verify() throws InterruptedException {
        String last = "Dovecot did not come back";
        for (int i = 0; i < 20; i++) {
            Thread.sleep(500);
            if (!DovecotAuthWorker.running()) { last = "Dovecot is not running after the reload"; continue; }
            int rc = DovecotAuthWorker.lookup();
            if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) { last = "doveadm auth lookup fails (exit " + rc + ")"; continue; }
            String imap = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-h", "-f", "protocol=imap", "mail_plugins").output();
            if (!imap.contains("imap_sieve")) { last = "the imap_sieve plugin is not on for IMAP"; continue; }
            String opened = imapOpens();
            if (opened != null) { last = opened; continue; }
            Shell.Result w = Shell.run(Duration.ofSeconds(15), "su", "-m", VMAIL, "-c", program() + " check");
            if (!w.outputTrim().equals("ok")) { last = VMAIL + " cannot write in " + SPOOL; continue; }
            return null;
        }
        return last;
    }

    /** Una sessione IMAP vera per la prima casella (CAPABILITY e LOGOUT, niente altro): null se si apre senza errori. */
    static String imapOpens() {
        String user = null;
        for (String u : Shell.run(Duration.ofSeconds(15), "doveadm", "user", "*").output().trim().split("\\s+"))
            if (u.contains("@")) { user = u; break; }
        if (user == null) return null;
        Shell.Result r = Shell.runWithInput(Duration.ofSeconds(30), "a CAPABILITY\r\nz LOGOUT\r\n", "doveadm", "exec", "imap", "-u", user);
        String out = r.output();
        if (!out.contains("a OK") || out.contains("Error") || out.contains("Fatal")) return "IMAP does not open with the new configuration";
        return null;
    }

    static void reload() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content, String perms) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(perms));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path conf, String previous, boolean reload) throws Exception {
        if (previous != null && !previous.isEmpty()) write(conf, previous, "rw-r--r--");
        else Files.deleteIfExists(conf);
        if (reload) reload();
    }
}
