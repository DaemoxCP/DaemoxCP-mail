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
 * The Dovecot master user with which the panel opens the webmail ("Open webmail"): Roundcube logs in
 * as "mailbox*admin" with the key from {@link #KEY_FILE}, which the panel puts in the SSO token
 * (RoundcubeSsoManager). Dovecot knows only the hash of the key, in {@link #MASTER_USERS}.
 *
 * <p>The defect, measured on the FreeBSD 15.1 VM on 2026-11-05 on three installations out of three:
 * FullMailServerScript wrote master-users BEFORE dovecot.conf, it asked "doveadm pw" for the hash, and
 * doveadm without a configuration exits with 75 ("Fatal: Error reading configuration") without writing
 * anything. The file stayed "admin:" with an empty hash, Dovecot rejected the master user, and the
 * button did not work anywhere. FullMailStackScript did write the hash, but gave the file to
 * root:wheel: Dovecot reads it with the auth process, which runs as dovecot, and so could not open it
 * ("Permission denied ... euid=143(dovecot)", measured the same day).
 *
 * <p>The scripts now all use {@link #shell()}: "doveadm -O pw", which does not read the
 * configuration, the password from standard input, the hash checked with "doveadm pw -t" against
 * the key, the file root:dovecot 640.
 *
 * <p>At startup ({@link #ensureAtBoot()}) servers installed earlier repair themselves, without
 * choosing for anyone. master-users is touched only if it is one of the two files that the
 * scripts used to write, recognisable by their content:
 * <ul>
 *   <li>the "admin:" line without a hash: the hash of the key is written (bcrypt, as for the mailboxes);</li>
 *   <li>the "admin:" line with the hash OF THE KEY, but with owner, group or permissions other than
 *       root:dovecot 640: those are set.</li>
 * </ul>
 * Before changing anything it checks that Dovecot answers (doveadm user of an active mailbox);
 * afterwards, that the master user really logs in (doveadm auth test "mailbox*admin", with the key
 * from standard input). If it does not log in, the file goes back to how it was, byte for byte, with
 * owner, group and permissions, and at the next startup it tries again. Without active mailboxes there
 * is no one to log in as: the hash is verified by Dovecot with "doveadm pw -t", and the log says so.
 *
 * <p>Not touched: a master-users written by hand (other users, other schemes, comments), a link,
 * a hash that is not the key's (the log says so: the SSO cannot log in), a file without the key
 * next to it. The log has the number of the test mailbox, never the address nor the key.
 */
public final class DovecotMasterUser {

    private static final Logger LOGGER = Logger.getLogger(DovecotMasterUser.class.getName());

    /** The name of the master user: the same as RoundcubeSsoManager.MASTER_USER (the test compares them). */
    public static final String USER = "admin";
    public static final String MASTER_USERS = "/usr/local/etc/dovecot/master-users";
    /** The key: the same path as RoundcubeSsoManager.MASTER_PASSWORD_FILE (the test compares them). */
    public static final String KEY_FILE = "/var/db/daemoxcp-mail/dovecot_master.key";
    public static final String OWNER = "root";
    /** Dovecot's auth process, which reads master-users, runs as this user. */
    public static final String GROUP = "dovecot";
    static final Set<PosixFilePermission> MODE = PosixFilePermissions.fromString("rw-r-----");
    /** The bcrypt cost of the mailbox passwords (MailDatabase): Dovecot accepts it, measured. */
    static final int COST = 12;

    /** How it was after installation: the master user without a hash. */
    private static final Pattern WITHOUT_HASH = Pattern.compile("\\A" + USER + ":\\n?\\z");
    /** How it is after installation when the hash is there: a single line, BLF-CRYPT like doveadm pw or jBCrypt. */
    private static final Pattern WITH_HASH = Pattern.compile(
            "\\A" + USER + ":(\\{BLF-CRYPT\\}\\$2[aby]\\$[0-9]{2}\\$[./A-Za-z0-9]{53})\\n?\\z");
    /** A key: printable text without spaces, up to bcrypt's limit. The scripts write 24 letters and digits. */
    private static final Pattern KEY = Pattern.compile("[\\x21-\\x7E]{8,72}");
    /** An address that can go among doveadm's arguments: no "*" (the master separator). */
    private static final Pattern MAILBOX = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+");

    private DovecotMasterUser() {}

    // ===================== the snippet of the installation scripts =====================

    /** The shell snippet of FullMailServerScript, FullMailStackScript and DovecotScript, with the real paths. */
    public static String shell() {
        return shell(KEY_FILE, MASTER_USERS);
    }

    /** The same, with other paths: the test runs it in a folder of its own, with the real doveadm. */
    static String shell(String keyFile, String masterUsers) {
        return """
            # --- Dovecot's master user, for the panel's "Open webmail" (DovecotMasterUser.java) ---
            # The panel reads the key and puts it in the SSO token; Dovecot only knows its
            # hash, in master-users. "doveadm -O pw" does not read dovecot.conf: without -O, with the script
            # passing here before writing it, doveadm exited with 75 without printing anything, and
            # master-users stayed "admin:" without a hash (05/11/2026, three installations out of three).
            # The password goes through standard input, not among the arguments, where ps would see it. But
            # if the two lines differ doveadm asks again, reads the end of the file and prints, with
            # 0, the hash of the EMPTY password: that is why the hash is checked with "pw -t" against the key.
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
            # Dovecot's auth process runs as dovecot: with root:wheel it could not read it.
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

    // ===================== the boot repair =====================

    public enum Outcome { NOTHING, DONE, NOT_OURS, NO_KEY, MISMATCH, NOT_ANSWERING, ROLLED_BACK }

    public record Report(Outcome outcome, String detail) {}

    record Places(Path masterUsers, Path keyFile) {
        static Places real() { return new Places(Path.of(MASTER_USERS), Path.of(KEY_FILE)); }
    }

    /** The mailbox with which to test the master login: the number goes into the log, the address does not. */
    record Mailbox(int id, String email) {
        String who() { return "mailbox #" + id; }
    }

    interface Services {
        /** An active mailbox, the first by number; null if there is none. An exception if it cannot be known. */
        Mailbox testMailbox() throws Exception;
        /** doveadm user: Dovecot answers and finds the mailbox. Before changing anything. */
        Shell.Result lookup(String email);
        /** doveadm auth test, with the password from standard input. */
        Shell.Result authTest(String login, String password);
        /** doveadm -O pw -t, with the password from standard input: only when there are no mailboxes. */
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
        // The scripts' file is a line of about a hundred bytes: a large file belongs to someone else.
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

        // Before changing anything, Dovecot must answer: otherwise afterwards there would be no telling
        // whether the master login fails because of the new file or because of Dovecot.
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

    /** The key as RoundcubeSsoManager reads it (trim): null if it is missing, is a link or is not a key. */
    static String readKey(Path p) throws IOException {
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) || Files.size(p) > 4096) return null;
        String k = new String(Files.readAllBytes(p), StandardCharsets.US_ASCII).trim();
        return KEY.matcher(k).matches() ? k : null;
    }

    /** Is the hash the key's? jBCrypt knows only $2a$: bcryptPart translates $2y$ and $2b$. */
    static boolean matches(String key, String hash) {
        String b = MailDatabase.bcryptPart(hash);
        try {
            return b != null && BCrypt.checkpw(key, b);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** null if the master user logs in with the key; if not, the reason, without addresses or key. */
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
     * Writes in place of the file, in one go: a temporary file in the same folder, already with its
     * owner, group and permissions, then rename. Dovecot sees either the previous file or the new one.
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

    /** The file as it was: content, owner, group and permissions. */
    record Snapshot(Path path, byte[] content, UserPrincipal owner, GroupPrincipal group, Set<PosixFilePermission> mode) {
        static Snapshot of(Path p, PosixFileAttributes a) throws IOException {
            return new Snapshot(p, Files.readAllBytes(p), a.owner(), a.group(), a.permissions());
        }
        void restore() throws IOException {
            write(path, content, owner, group, mode);
        }
    }

    // ===================== the real services =====================

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
