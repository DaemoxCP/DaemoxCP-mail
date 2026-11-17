package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.util.Shell;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.Comparator;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * L'utente master di Dovecot con cui il pannello apre la webmail («Apri webmail»): Roundcube entra
 * come "casella*admin" con la chiave di {@link #KEY_FILE}, che il pannello mette nel gettone
 * dell'SSO (RoundcubeSsoManager). Dovecot conosce solo l'hash della chiave, in {@link #MASTER_USERS}.
 *
 * <p>Il difetto, misurato sulla VM FreeBSD 15.1 il 05/11/2026 su tre installazioni su tre:
 * FullMailServerScript scriveva master-users PRIMA di dovecot.conf, l'hash lo chiedeva a "doveadm
 * pw", e doveadm senza configurazione esce con 75 («Fatal: Error reading configuration») senza
 * scrivere niente. Il file restava "admin:" con l'hash vuoto, Dovecot rifiutava l'utente master, e
 * il pulsante non funzionava da nessuna parte. FullMailStackScript l'hash lo scriveva, ma dava il
 * file a root:wheel: Dovecot lo legge col processo auth, che gira come dovecot, e quindi non poteva
 * aprirlo («Permission denied ... euid=143(dovecot)», misurato lo stesso giorno).
 *
 * <p>Gli script adesso usano tutti {@link #shell()}: "doveadm -O pw", che non legge la
 * configurazione, la password dallo standard input, l'hash controllato con "doveadm pw -t" contro
 * la chiave, il file root:dovecot 640.
 *
 * <p>All'avvio ({@link #ensureAtBoot()}) i server installati prima si riparano da soli, senza
 * scegliere per nessuno. Si tocca master-users solo se e' uno dei due file che scrivevano gli
 * script, riconoscibili dal contenuto:
 * <ul>
 *   <li>la riga "admin:" senza hash: si scrive l'hash della chiave (bcrypt, come per le caselle);</li>
 *   <li>la riga "admin:" con l'hash DELLA CHIAVE, ma con proprietario, gruppo o permessi diversi da
 *       root:dovecot 640: si mettono quelli.</li>
 * </ul>
 * Prima di cambiare si guarda che Dovecot risponda (doveadm user di una casella attiva); dopo, che
 * l'utente master entri davvero (doveadm auth test "casella*admin", con la chiave dallo standard
 * input). Se non entra, il file torna com'era, byte per byte, con proprietario, gruppo e permessi,
 * e al prossimo avvio ci si riprova. Senza caselle attive non c'e' con chi entrare: l'hash si fa
 * verificare da Dovecot con "doveadm pw -t", e il log lo dice.
 *
 * <p>Non si tocca: un master-users scritto a mano (altri utenti, altri schemi, commenti), un link,
 * un hash che non e' quello della chiave (lo si dice nel log: l'SSO non puo' entrare), un file senza
 * la chiave accanto. Nel log c'e' il numero della casella di prova, mai l'indirizzo ne' la chiave.
 */
public final class DovecotMasterUser {

    private static final Logger LOGGER = Logger.getLogger(DovecotMasterUser.class.getName());

    /** Il nome dell'utente master: lo stesso di RoundcubeSsoManager.MASTER_USER (la prova li confronta). */
    public static final String USER = "admin";
    public static final String MASTER_USERS = "/usr/local/etc/dovecot/master-users";
    /** La chiave: lo stesso percorso di RoundcubeSsoManager.MASTER_PASSWORD_FILE (la prova li confronta). */
    public static final String KEY_FILE = "/var/db/daemoxcp-mail/dovecot_master.key";
    public static final String OWNER = "root";
    /** Il processo auth di Dovecot, che legge master-users, gira con questo utente. */
    public static final String GROUP = "dovecot";
    static final Set<PosixFilePermission> MODE = PosixFilePermissions.fromString("rw-r-----");
    /** Il costo di bcrypt delle password delle caselle (MailDatabase): Dovecot lo accetta, misurato. */
    static final int COST = 12;

    /** Com'era dopo l'installazione: l'utente master senza hash. */
    private static final Pattern WITHOUT_HASH = Pattern.compile("\\A" + USER + ":\\n?\\z");
    /** Com'e' dopo l'installazione quando l'hash c'e': una riga sola, BLF-CRYPT come doveadm pw o jBCrypt. */
    private static final Pattern WITH_HASH = Pattern.compile(
            "\\A" + USER + ":(\\{BLF-CRYPT\\}\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53})\\n?\\z");
    /** Una chiave: testo stampabile senza spazi, fino al limite di bcrypt. Gli script ne scrivono 24 lettere e cifre. */
    private static final Pattern KEY = Pattern.compile("[\\x21-\\x7E]{8,72}");
    /** Un indirizzo che puo' andare fra gli argomenti di doveadm: niente "*" (il separatore del master). */
    private static final Pattern MAILBOX = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+");

    private DovecotMasterUser() {}

    // ===================== il pezzo degli script d'installazione =====================

    /** Il pezzo di shell di FullMailServerScript, FullMailStackScript e DovecotScript, coi percorsi veri. */
    public static String shell() {
        return shell(KEY_FILE, MASTER_USERS);
    }

    /** Lo stesso, con altri percorsi: la prova lo esegue in una cartella sua, col doveadm vero. */
    static String shell(String keyFile, String masterUsers) {
        return """
            # --- L'utente master di Dovecot, per «Apri webmail» del pannello (DovecotMasterUser.java) ---
            # La chiave la legge il pannello e la mette nel gettone dell'SSO; Dovecot ne conosce solo
            # l'hash, in master-users. "doveadm -O pw" non legge dovecot.conf: senza -O, con lo script
            # che passa di qui prima di scriverla, doveadm usciva con 75 senza stampare niente, e
            # master-users restava "admin:" senza hash (05/11/2026, tre installazioni su tre).
            # La password passa dallo standard input, non fra gli argomenti, dove la vedrebbe ps. Ma
            # se le due righe non coincidono doveadm la richiede, legge la fine del file e stampa con
            # 0 l'hash della password VUOTA: per questo l'hash si controlla con "pw -t" contro la chiave.
            MASTER_KEY_FILE='__KEY__'
            MASTER_USERS_FILE='__USERS__'
            MASTER_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | head -c 24)
            mkdir -p "$(dirname "$MASTER_KEY_FILE")" "$(dirname "$MASTER_USERS_FILE")"
            ( umask 077; printf '%s\\n' "$MASTER_PASSWORD" > "$MASTER_KEY_FILE" )
            chmod 600 "$MASTER_KEY_FILE"
            MASTER_PASSWORD_HASH=$(printf '%s\\n%s\\n' "$MASTER_PASSWORD" "$MASTER_PASSWORD" | doveadm -O pw -s BLF-CRYPT 2>/dev/null) || MASTER_PASSWORD_HASH=''
            case "$MASTER_PASSWORD_HASH" in
                '{BLF-CRYPT}$2'?'$'*) ;;
                *) MASTER_PASSWORD_HASH='' ;;
            esac
            if [ -n "$MASTER_PASSWORD_HASH" ] && ! printf '%s\\n' "$MASTER_PASSWORD" | doveadm -O pw -t "$MASTER_PASSWORD_HASH" >/dev/null 2>&1; then
                MASTER_PASSWORD_HASH=''
            fi
            if [ -z "$MASTER_PASSWORD_HASH" ]; then
                echo "[ERROR] doveadm gave no hash of the Dovecot master user's key: the webmail SSO of the"
                echo "        panel cannot log in. The panel writes the hash itself at its next start."
            fi
            # Il processo auth di Dovecot gira come dovecot: con root:wheel non potrebbe leggerlo.
            ( umask 027; printf '%s:%s\\n' '__USER__' "$MASTER_PASSWORD_HASH" > "$MASTER_USERS_FILE.new" )
            chown __OWNER__:__GROUP__ "$MASTER_USERS_FILE.new"
            chmod 640 "$MASTER_USERS_FILE.new"
            mv -f "$MASTER_USERS_FILE.new" "$MASTER_USERS_FILE"
            unset MASTER_PASSWORD MASTER_PASSWORD_HASH
            """
            .replace("__KEY__", keyFile)
            .replace("__USERS__", masterUsers)
            .replace("__USER__", USER)
            .replace("__OWNER__", OWNER)
            .replace("__GROUP__", GROUP);
    }

    // ===================== la riparazione all'avvio =====================

    public enum Outcome { NOTHING, DONE, NOT_OURS, NO_KEY, MISMATCH, NOT_ANSWERING, ROLLED_BACK }

    public record Report(Outcome outcome, String detail) {}

    record Places(Path masterUsers, Path keyFile) {
        static Places real() { return new Places(Path.of(MASTER_USERS), Path.of(KEY_FILE)); }
    }

    /** La casella con cui provare l'accesso master: nel log va il numero, l'indirizzo no. */
    record Mailbox(int id, String email) {
        String who() { return "mailbox #" + id; }
    }

    interface Services {
        /** Una casella attiva, la prima per numero; null se non ce n'e'. Eccezione se non si sa. */
        Mailbox testMailbox() throws Exception;
        /** doveadm user: Dovecot risponde e trova la casella. Prima di cambiare. */
        Shell.Result lookup(String email);
        /** doveadm auth test, con la password dallo standard input. */
        Shell.Result authTest(String login, String password);
        /** doveadm -O pw -t, con la password dallo standard input: solo senza caselle. */
        Shell.Result verifyHash(String hash, String password);
    }

    public static void ensureAtBoot() {
        try {
            Report r = repair(Places.real(), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[DovecotMasterUser] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE || r.outcome() == Outcome.NOT_OURS) LOGGER.info(line);
            else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[DovecotMasterUser] failed: " + t);
        }
    }

    static Report repair(Places at, Services sv) throws IOException {
        Path file = at.masterUsers();
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.NOT_OURS, file + " is not a regular file: nothing changed");
        // Quello degli script e' una riga di un centinaio di byte: un file grande e' di qualcun altro.
        if (Files.size(file) > 4096)
            return new Report(Outcome.NOT_OURS, file + " is not the file the installer writes (too long): nothing changed");
        String content;
        try {
            content = StandardCharsets.US_ASCII.newDecoder().decode(ByteBuffer.wrap(Files.readAllBytes(file))).toString();
        } catch (CharacterCodingException e) {
            return new Report(Outcome.NOT_OURS, file + " is not ASCII: nothing changed");
        }
        Matcher withHash = WITH_HASH.matcher(content);
        boolean withoutHash = WITHOUT_HASH.matcher(content).matches();
        if (!withoutHash && !withHash.matches())
            return new Report(Outcome.NOT_OURS, file + " is not the file the installer writes (one line "
                    + USER + ": with or without a BLF-CRYPT hash): nothing changed");

        String key = readKey(at.keyFile());
        if (key == null)
            return new Report(Outcome.NO_KEY, at.keyFile() + " is missing or is not a key: the webmail SSO cannot log in; "
                    + file + " not changed");

        PosixFileAttributes attrs = Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        boolean attrsRight = OWNER.equals(attrs.owner().getName()) && GROUP.equals(attrs.group().getName())
                && MODE.equals(attrs.permissions());
        String was = attrs.owner().getName() + ":" + attrs.group().getName() + " " + PosixFilePermissions.toString(attrs.permissions());
        String hash;
        if (withHash.matches()) {
            hash = withHash.group(1);
            if (!matches(key, hash))
                return new Report(Outcome.MISMATCH, file + " has a hash that is not the one of " + at.keyFile()
                        + ": the webmail SSO cannot log in; nothing changed");
            if (attrsRight) return new Report(Outcome.NOTHING, "");
        } else {
            hash = "{BLF-CRYPT}" + BCrypt.hashpw(key, BCrypt.gensalt(COST));
        }

        // Prima di cambiare, Dovecot deve rispondere: altrimenti dopo non si saprebbe dire se l'accesso
        // master non va per il file nuovo o per Dovecot.
        Mailbox box;
        try {
            box = sv.testMailbox();
        } catch (Exception e) {
            return new Report(Outcome.NOT_ANSWERING, "cannot list the mailboxes (" + e.getClass().getSimpleName()
                    + "): nothing changed, retrying at the next start");
        }
        if (box != null) {
            Shell.Result r = sv.lookup(box.email());
            if (!r.success())
                return new Report(Outcome.NOT_ANSWERING, "Dovecot does not find " + box.who() + " now (doveadm user, exit "
                        + r.exitCode() + "): nothing changed, retrying at the next start");
        }
        UserPrincipal owner;
        GroupPrincipal group;
        try {
            UserPrincipalLookupService names = file.getFileSystem().getUserPrincipalLookupService();
            owner = names.lookupPrincipalByName(OWNER);
            group = names.lookupPrincipalByGroupName(GROUP);
        } catch (IOException e) {
            return new Report(Outcome.NOT_ANSWERING, "the user " + OWNER + " or the group " + GROUP
                    + " does not exist: nothing changed");
        }

        Snapshot before = Snapshot.of(file, attrs);
        String change;
        try {
            if (withoutHash) {
                write(file, (USER + ":" + hash + "\n").getBytes(StandardCharsets.US_ASCII), owner, group, MODE);
                change = "the master user had no hash (as the installer left it): hash of " + at.keyFile() + " written";
            } else {
                PosixFileAttributeView v = Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                v.setOwner(owner);
                v.setGroup(group);
                v.setPermissions(MODE);
                change = "it was " + was + ", and Dovecot reads it as " + GROUP + ": now " + OWNER + ":" + GROUP + " "
                        + PosixFilePermissions.toString(MODE);
            }
        } catch (IOException e) {
            return rollBack(before, "cannot write " + file + " (" + e.getMessage() + ")");
        }

        String failed = verify(sv, box, hash, key);
        if (failed != null) return rollBack(before, change + ", but " + failed);
        return new Report(Outcome.DONE, file + ": " + change + "; "
                + (box != null ? "Dovecot lets " + box.who() + "*" + USER + " in with the key"
                               : "verified with doveadm pw -t only: there is no active mailbox for a real master login"));
    }

    /** La chiave come la legge RoundcubeSsoManager (trim): null se manca, e' un link o non e' una chiave. */
    static String readKey(Path p) throws IOException {
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) || Files.size(p) > 4096) return null;
        String k = new String(Files.readAllBytes(p), StandardCharsets.US_ASCII).trim();
        return KEY.matcher(k).matches() ? k : null;
    }

    /** L'hash e' quello della chiave? jBCrypt conosce solo $2a$: bcryptPart traduce $2y$ e $2b$. */
    static boolean matches(String key, String hash) {
        String b = MailDatabase.bcryptPart(hash);
        try {
            return b != null && BCrypt.checkpw(key, b);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** null se l'utente master entra con la chiave; se no il perche', senza indirizzi ne' chiave. */
    private static String verify(Services sv, Mailbox box, String hash, String key) {
        if (box != null) {
            Shell.Result r = sv.authTest(box.email() + "*" + USER, key);
            if (r.success() && r.output().contains("auth succeeded")) return null;
            return "doveadm auth test as " + box.who() + "*" + USER + " failed (exit " + r.exitCode() + ": "
                    + oneLine(r.output().replace(box.email(), box.who()).replace(key, "<key>")) + ")";
        }
        Shell.Result r = sv.verifyHash(hash, key);
        if (r.success() && r.output().contains("(verified)")) return null;
        return "doveadm pw -t refused the hash (exit " + r.exitCode() + ")";
    }

    private static String oneLine(String s) {
        String t = s.trim().replaceAll("\\s*\\n\\s*", " | ");
        return t.length() > 300 ? t.substring(0, 300) + "..." : t;
    }

    private static Report rollBack(Snapshot before, String why) {
        try {
            before.restore();
            return new Report(Outcome.ROLLED_BACK, why + "; " + before.path() + " put back as it was");
        } catch (IOException e) {
            return new Report(Outcome.ROLLED_BACK, why + "; " + before.path() + " NOT put back: " + e.getMessage());
        }
    }

    /**
     * Scrive al posto del file, in un colpo solo: un file temporaneo nella stessa cartella, gia' coi
     * suoi proprietario, gruppo e permessi, poi rename. Dovecot vede il file di prima o quello nuovo.
     */
    private static void write(Path file, byte[] content, UserPrincipal owner, GroupPrincipal group,
                              Set<PosixFilePermission> mode) throws IOException {
        Path tmp = Files.createTempFile(file.getParent(), "." + file.getFileName() + ".", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.write(tmp, content);
            PosixFileAttributeView v = Files.getFileAttributeView(tmp, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            v.setOwner(owner);
            v.setGroup(group);
            v.setPermissions(mode);
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Il file com'era: contenuto, proprietario, gruppo e permessi. */
    record Snapshot(Path path, byte[] content, UserPrincipal owner, GroupPrincipal group, Set<PosixFilePermission> mode) {
        static Snapshot of(Path p, PosixFileAttributes a) throws IOException {
            return new Snapshot(p, Files.readAllBytes(p), a.owner(), a.group(), a.permissions());
        }
        void restore() throws IOException {
            write(path, content, owner, group, mode);
        }
    }

    // ===================== i servizi veri =====================

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);

        @Override public Mailbox testMailbox() throws Exception {
            if (org.daemoxcp.mail.Main.mailDatabase == null) throw new IllegalStateException("no mail database");
            return org.daemoxcp.mail.Main.mailDatabase.getAllMailboxes().stream()
                    .filter(b -> b.active && b.email != null && MAILBOX.matcher(b.email).matches())
                    .min(Comparator.comparingInt(b -> b.id))
                    .map(b -> new Mailbox(b.id, b.email)).orElse(null);
        }
        @Override public Shell.Result lookup(String email) {
            return Shell.run(SHORT, "doveadm", "user", email);
        }
        @Override public Shell.Result authTest(String login, String password) {
            return Shell.runWithInput(SHORT, password + "\n", "doveadm", "auth", "test", login);
        }
        @Override public Shell.Result verifyHash(String hash, String password) {
            return Shell.runWithInput(SHORT, password + "\n", "doveadm", "-O", "pw", "-t", hash);
        }
    }
}
