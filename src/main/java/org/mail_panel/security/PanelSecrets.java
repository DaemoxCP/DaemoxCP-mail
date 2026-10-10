package org.mail_panel.security;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

/**
 * Le chiavi e i segreti del pannello in un file leggibile solo da root, mai nel database ne' nel
 * repository: cifratura dei dati (email degli amministratori, indirizzi delle sessioni), indice
 * cieco, impronte dei codici monouso, token CSRF, chiave della webmail; e i segreti di testo che
 * prima stavano nel database SQLite di configurazione (password MySQL, chiave privata TLS).
 *
 * Il file sta in /usr/local/etc/mail-panel/panel-secrets.properties, accanto a master.key del
 * vault. La cartella e' 700 e il file 600; le chiavi si generano al primo uso con SecureRandom.
 * Chi copia il database senza questo file non legge le email cifrate e non puo' fabbricare un
 * codice valido. I test spostano la cartella con -Dmailpanel.secrets.dir=...
 */
public final class PanelSecrets {

    private PanelSecrets() {}

    static final String DATA_KEY = "data_key";
    static final String INDEX_KEY = "index_key";
    static final String CODE_KEY = "code_key";
    static final String SESSION_KEY = "session_key";
    /** La chiave che la webmail (Roundcube) manda al pannello per cambiare una password di casella. */
    static final String WEBMAIL_KEY = "webmail_key";
    /** La password dell'utente MySQL del pannello (prima stava nel database SQLite di configurazione). */
    public static final String MYSQL_PASSWORD = "mysql_password";
    /** La chiave privata TLS (PEM) del pannello (prima stava nel database SQLite di configurazione). */
    public static final String PANEL_TLS_KEY = "panel_tls_key";

    /** La cartella del file; i test la spostano in una cartella temporanea. */
    static Path dir = Paths.get(System.getProperty("mailpanel.secrets.dir", "/usr/local/etc/mail-panel"));
    private static final String FILE = "panel-secrets.properties";
    private static final String LOCK = "panel-secrets.lock";
    private static final SecureRandom RANDOM = new SecureRandom();

    /*
     * Il file lo usano due processi: il pannello e il comando da console (--access-code). Ognuno
     * tiene una copia in memoria; se l'altro ha scritto il file, la copia si rilegge (data e
     * dimensione cambiate). Le scritture rileggono dal disco sotto un lock del file system, cosi'
     * una chiave mancante la genera uno solo: se ciascuno ne generasse una sua, il codice dato
     * dalla console non sarebbe mai giusto per il pannello.
     */
    private static Properties cache;
    private static String cacheStamp = "";

    static synchronized void reset() { cache = null; cacheStamp = ""; }

    private static Path file() { return dir.resolve(FILE); }

    private static String stamp() {
        try {
            Path f = file();
            return Files.exists(f) ? Files.getLastModifiedTime(f).toMillis() + ":" + Files.size(f) : "";
        } catch (IOException e) {
            return "?";
        }
    }

    private static Properties readFile() {
        Properties p = new Properties();
        Path f = file();
        if (Files.exists(f)) {
            try (Reader r = Files.newBufferedReader(f, StandardCharsets.UTF_8)) {
                p.load(r);
            } catch (IOException e) {
                throw new IllegalStateException("Panel secrets file unreadable: " + f.toAbsolutePath(), e);
            }
        }
        return p;
    }

    private static synchronized Properties load() {
        String now = stamp();
        if (cache != null && now.equals(cacheStamp)) return cache;
        cache = readFile();
        cacheStamp = now;
        return cache;
    }

    /** Legge, cambia e riscrive il file tenendo il lock: un solo processo alla volta. */
    private static synchronized Properties update(java.util.function.UnaryOperator<Properties> change) {
        try {
            Files.createDirectories(dir);
            setPermissions(dir, "rwx------");
            try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(dir.resolve(LOCK),
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
                 java.nio.channels.FileLock ignored = ch.lock()) {
                setPermissions(dir.resolve(LOCK), "rw-------");
                Properties p = readFile();
                Properties changed = change.apply(p);
                if (changed != null) store(changed);
                else { cache = p; cacheStamp = stamp(); }
                return cache;
            }
        } catch (IOException e) {
            throw new IllegalStateException("Panel secrets file not writable: " + file().toAbsolutePath(), e);
        }
    }

    private static void store(Properties p) throws IOException {
        Path tmp = dir.resolve(FILE + ".tmp");
        Files.deleteIfExists(tmp);
        Files.createFile(tmp);
        setPermissions(tmp, "rw-------");
        try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
            p.store(w, "FreeBSD Mail Panel secrets - root only, never in the database or the repository");
        }
        try {
            Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING);
        }
        setPermissions(file(), "rw-------");
        cache = p;
        cacheStamp = stamp();
    }

    private static void setPermissions(Path p, String perms) throws IOException {
        try {
            Set<PosixFilePermission> s = PosixFilePermissions.fromString(perms);
            Files.setPosixFilePermissions(p, s);
        } catch (UnsupportedOperationException ignored) {
            // File system senza permessi POSIX: resta quello che c'e'.
        }
    }

    private static synchronized String get(String name) {
        return load().getProperty(name, "");
    }

    /** Una chiave di 32 byte, generata e scritta la prima volta che serve (da un processo solo). */
    static synchronized byte[] key(String name) {
        String v = get(name);
        if (v.isEmpty()) {
            v = update(p -> {
                if (!p.getProperty(name, "").isEmpty()) return null;     // l'ha appena scritta l'altro processo
                byte[] k = new byte[32];
                RANDOM.nextBytes(k);
                p.setProperty(name, Base64.getEncoder().encodeToString(k));
                return p;
            }).getProperty(name, "");
        }
        byte[] k = Base64.getDecoder().decode(v);
        if (k.length != 32) throw new IllegalStateException("Panel secret " + name + " is not a 32-byte key");
        return k;
    }

    /** Un segreto di testo (password, chiave PEM); "" se non c'e'. */
    public static String text(String name) {
        return get(name);
    }

    /** Scrive (o con "" o null toglie) un segreto di testo; un processo alla volta, file 600. */
    public static synchronized void setText(String name, String value) {
        String v = value == null ? "" : value;
        update(p -> {
            if (v.equals(p.getProperty(name, ""))) return null;
            if (v.isEmpty()) p.remove(name);
            else p.setProperty(name, v);
            return p;
        });
    }

    /**
     * La chiave della webmail in base64url senza '=': va scritta nella configurazione di Roundcube
     * (letta solo da www), che la manda nell'intestazione X-MailPanel-Key.
     */
    public static String webmailKey() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(key(WEBMAIL_KEY));
    }

    /** All'avvio: tutte le chiavi esistono prima che un altro processo possa servirsene. */
    public static void ensureKeys() {
        key(DATA_KEY);
        key(INDEX_KEY);
        key(CODE_KEY);
        key(SESSION_KEY);
        key(WEBMAIL_KEY);
    }
}
