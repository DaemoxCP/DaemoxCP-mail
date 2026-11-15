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
 * cieco, impronte dei codici monouso, chiave della webmail; e i segreti di testo che
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
    // La chiave "session_key" (token CSRF) non si crea piu': i token di sessione, CSRF e di prima
    // dell'accesso dipendono da una chiave che vive solo nella memoria del processo (WebSessions,
    // reperto 184). Nei file di prima resta, inutilizzata.
    /** La chiave che la webmail (Roundcube) manda al pannello per cambiare una password di casella. */
    static final String WEBMAIL_KEY = "webmail_key";
    /** La password dell'utente MySQL del pannello (prima stava nel database SQLite di configurazione). */
    public static final String MYSQL_PASSWORD = "mysql_password";
    /**
     * La password nuova dell'utente MySQL del pannello finche' MySQL non l'ha accettata: la scrive
     * l'installazione prima dello script, e diventa {@link #MYSQL_PASSWORD} solo quando MySQL la
     * conosce (org.mail_panel.system.PendingDbPassword). Di solito non c'e'.
     */
    public static final String MYSQL_PASSWORD_PENDING = "mysql_password_pending";
    /**
     * Lo stato del cambio, una volta, della password dell'utente MySQL del pannello (org.mail_panel.system.PanelDbPassword,
     * reperto 232): "retained:" e l'impronta della vecchia a meta', "done " e la data a cose fatte. Solo di root.
     */
    public static final String MYSQL_PASSWORD_ROTATION = "mysql_password_rotation";
    /** La password di root di MySQL: prima non esisteva, e root entrava senza nulla. */
    public static final String MYSQL_ROOT_PASSWORD = "mysql_root_password";
    /**
     * La password dell'utente MySQL della webmail (roundcube), che puo' toccare solo il database
     * di Roundcube. Prima la webmail entrava con l'utente del pannello: vedi RoundcubeDbUser.
     */
    public static final String ROUNDCUBE_DB_PASSWORD = "roundcube_db_password";
    /** La chiave privata TLS (PEM) del pannello (prima stava nel database SQLite di configurazione). */
    public static final String PANEL_TLS_KEY = "panel_tls_key";
    /**
     * La password dell'utente MySQL della parte web (mailpanel_web), che puo' solo chiamare le procedure della web.
     * La scrive la root quando l'utente e' pronto e provato.
     */
    public static final String MYSQL_WEB_PASSWORD = "mysql_web_password";
    /**
     * La chiave privata del vault (RSA, PKCS#8 in base64): legge le copie delle password delle caselle. Solo nel file
     * di root (PasswordVault); quella di prima dell'ultima rotazione accanto.
     */
    public static final String VAULT_PRIVATE_KEY = "vault_private_key";
    public static final String VAULT_PREVIOUS_PRIVATE_KEY = "vault_previous_private_key";
    /** La chiave pubblica del vault (X.509 in base64): la web cifra con questa le copie delle password nuove. */
    public static final String VAULT_PUBLIC_KEY = "vault_public_key";
    /** Le password degli utenti MySQL di Postfix e Dovecot (MailDbUsers): solo di root, e nei loro file di configurazione. */
    public static final String POSTFIX_DB_PASSWORD = "postfix_db_password";
    public static final String DOVECOT_DB_PASSWORD = "dovecot_db_password";

    /** La cartella dei file; i test la spostano in una cartella temporanea. */
    static Path dir = Paths.get(System.getProperty("mailpanel.secrets.dir", "/usr/local/etc/mail-panel"));
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * I segreti che restano solo di root. La parte web del pannello
     * gira con l'utente mailpanel e legge il suo file; questi due li usano soltanto installatori e
     * migrazioni, che girano da root, e con la password di root di MySQL chi bucasse la parte web avrebbe
     * tutto il database. Stanno in un file a parte, 0600 di root, nella stessa cartella.
     */
    public static final Set<String> ROOT_ONLY = Set.of(MYSQL_ROOT_PASSWORD, ROUNDCUBE_DB_PASSWORD, VAULT_PRIVATE_KEY,
            VAULT_PREVIOUS_PRIVATE_KEY, POSTFIX_DB_PASSWORD, DOVECOT_DB_PASSWORD, MYSQL_PASSWORD_ROTATION);

    /**
     * I segreti che passano nel file di root quando la parte web ha il suo utente MySQL ({@link #MYSQL_WEB_PASSWORD}
     * nel file della web): la password dell'utente MySQL del pannello, che puo' tutto nel database, e quella in
     * sospeso dell'installazione. Finche' la web non ha il suo, stanno nel file della web, che li usa.
     *
     * <p>Si leggono da tutti e due i file, prima da quello giusto (a meta' di uno spostamento sono in entrambi,
     * uguali). La web non legge mai il file di root: per lei esiste solo il suo.
     */
    static final Set<String> MOVE_TO_ROOT = Set.of(MYSQL_PASSWORD, MYSQL_PASSWORD_PENDING);

    /**
     * Il gruppo della parte web del pannello separato. Col pannello separato (PanelSeparation) la cartella
     * e' 0750 root:mailpanel e il file della web 0640 root:mailpanel: la web lo legge, non lo scrive mai (le
     * chiavi le genera la root all'avvio, prima di avviarla). Ogni riscrittura da root crea un file nuovo
     * (un rename): prende il gruppo e i permessi di quello che sostituisce, cosi' chiunque scriva (la root,
     * il menu, un comando da console) lascia la web in grado di leggere. Il file di root resta 0600.
     */
    static final String WEB_GROUP = "mailpanel";

    static final Store WEB = new Store("panel-secrets.properties", "panel-secrets.lock", true);
    static final Store ROOT = new Store("root-secrets.properties", "root-secrets.lock", false);

    private static Store storeFor(String name) {
        if (ROOT_ONLY.contains(name)) return ROOT;
        if (MOVE_TO_ROOT.contains(name) && webHasItsOwnUser()) return ROOT;
        return WEB;
    }

    /** La parte web entra in MySQL col suo utente: i segreti di MOVE_TO_ROOT stanno nel file di root. */
    static boolean webHasItsOwnUser() {
        return !WEB.load().getProperty(MYSQL_WEB_PASSWORD, "").isEmpty();
    }

    static synchronized void reset() { WEB.reset(); ROOT.reset(); }

    private static boolean runningAsRoot() { return "root".equals(System.getProperty("user.name")); }

    /*
     * Ogni file lo usano piu' processi: il pannello e i comandi da console (--access-code); col pannello
     * separato anche le sue due parti. Ognuno tiene una copia in memoria; se un altro ha scritto il
     * file, la copia si rilegge (data e dimensione cambiate). Le scritture rileggono dal disco sotto un
     * lock del file system, cosi' una chiave mancante la genera uno solo: se ciascuno ne generasse una
     * sua, il codice dato dalla console non sarebbe mai giusto per il pannello.
     */
    static final class Store {
        private final String fileName;
        private final String lockName;
        private final boolean web;
        private Properties cache;
        private String cacheStamp = "";

        Store(String fileName, String lockName, boolean web) {
            this.fileName = fileName;
            this.lockName = lockName;
            this.web = web;
        }

        synchronized void reset() { cache = null; cacheStamp = ""; }

        Path file() { return dir.resolve(fileName); }

        private String stamp() {
            try {
                Path f = file();
                return Files.exists(f) ? Files.getLastModifiedTime(f).toMillis() + ":" + Files.size(f) : "";
            } catch (IOException e) {
                return "?";
            }
        }

        Properties readFile() {
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

        synchronized Properties load() {
            String now = stamp();
            if (cache != null && now.equals(cacheStamp)) return cache;
            cache = readFile();
            cacheStamp = now;
            return cache;
        }

        /** Legge, cambia e riscrive il file tenendo il lock: un solo processo alla volta. */
        synchronized Properties update(java.util.function.UnaryOperator<Properties> change) {
            try {
                if (runningAsRoot() || !Files.isDirectory(dir)) {
                    Files.createDirectories(dir);
                    setPermissions(dir, webGroup(dir) ? "rwxr-x---" : "rwx------");
                }
                Path lock = dir.resolve(lockName);
                try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(lock,
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
                     java.nio.channels.FileLock ignored = ch.lock()) {
                    setPermissions(lock, "rw-------");
                    rootOnly(lock);
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

        private void store(Properties p) throws IOException {
            Path tmp = dir.resolve(fileName + ".tmp");
            Files.deleteIfExists(tmp);
            Files.createFile(tmp);
            setPermissions(tmp, "rw-------");
            try (Writer w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                p.store(w, web ? "FreeBSD Mail Panel secrets - the panel only, never in the database or the repository"
                               : "FreeBSD Mail Panel root secrets - root only, never in the database or the repository");
            }
            // Il file della web, col pannello separato: il nuovo resta leggibile dal gruppo della web come
            // quello che sostituisce. Prima del rename, cosi' non c'e' un istante in cui la web non legge.
            boolean forWeb = web && Files.exists(file()) && webGroup(file());
            if (forWeb) {
                setGroup(tmp, WEB_GROUP);
                setPermissions(tmp, "rw-r-----");
            } else {
                rootOnly(tmp);
            }
            try {
                Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file(), StandardCopyOption.REPLACE_EXISTING);
            }
            setPermissions(file(), forWeb ? "rw-r-----" : "rw-------");
            cache = p;
            cacheStamp = stamp();
        }
    }

    /** Vero se il file e' del gruppo della parte web (il pannello separato l'ha aperto alla web). */
    static boolean webGroup(Path p) {
        try {
            return WEB_GROUP.equals(Files.readAttributes(p, java.nio.file.attribute.PosixFileAttributes.class,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS).group().getName());
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    private static void setPermissions(Path p, String perms) throws IOException {
        try {
            Set<PosixFilePermission> s = PosixFilePermissions.fromString(perms);
            Files.setPosixFilePermissions(p, s);
        } catch (UnsupportedOperationException ignored) {
            // File system senza permessi POSIX: resta quello che c'e'.
        }
    }

    /**
     * Un file solo di root col gruppo di root. Su FreeBSD un file nuovo prende il gruppo della cartella
     * (open(2)), e col pannello separato la cartella e' del gruppo della web: a 0600 il gruppo non legge
     * comunque, ma chi guarda deve vedere root:wheel, e un chmod sbagliato domani non apre niente.
     */
    private static void rootOnly(Path p) throws IOException {
        if (runningAsRoot() && webGroup(p)) setGroup(p, "wheel");
    }

    private static void setGroup(Path p, String group) throws IOException {
        Files.getFileAttributeView(p, java.nio.file.attribute.PosixFileAttributeView.class)
                .setGroup(p.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(group));
    }

    private static String get(String name) {
        if (MOVE_TO_ROOT.contains(name)) {
            Store first = storeFor(name), other = first == ROOT ? WEB : ROOT;
            String v = first == ROOT && !runningAsRoot() ? "" : first.load().getProperty(name, "");
            if (!v.isEmpty() || (other == ROOT && !runningAsRoot())) return v;
            return other.load().getProperty(name, "");
        }
        return storeFor(name).load().getProperty(name, "");
    }

    /** Una chiave di 32 byte, generata e scritta la prima volta che serve (da un processo solo). */
    static synchronized byte[] key(String name) {
        String v = get(name);
        if (v.isEmpty()) {
            v = storeFor(name).update(p -> {
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

    /**
     * Un segreto di testo letto adesso dal disco, non dalla copia in memoria: per chi deve sapere
     * che una password e' davvero nel file prima di metterla in un servizio (MysqlRoot).
     */
    public static synchronized String reread(String name) {
        return storeFor(name).readFile().getProperty(name, "");
    }

    /** Dove sta il file del pannello, da dire nei messaggi a chi deve andare a cercarlo. */
    public static String location() {
        return WEB.file().toAbsolutePath().toString();
    }

    /** Dove sta il file che tiene questo segreto. */
    public static String location(String name) {
        return storeFor(name).file().toAbsolutePath().toString();
    }

    /** Scrive (o con "" o null toglie) un segreto di testo; un processo alla volta, file 600. */
    public static synchronized void setText(String name, String value) {
        String v = value == null ? "" : value;
        Store store = storeFor(name);
        store.update(p -> {
            if (v.equals(p.getProperty(name, ""))) return null;
            if (v.isEmpty()) p.remove(name);
            else p.setProperty(name, v);
            return p;
        });
        // Spostato nel file di root: nell'altro non deve restare un valore vecchio.
        if (store == ROOT && MOVE_TO_ROOT.contains(name)) {
            WEB.update(p -> p.remove(name) == null ? null : p);
        }
    }

    /**
     * WebDbAccess, da root, quando l'utente MySQL della web e' pronto e provato: la sua password nel file della
     * web, e i segreti di {@link #MOVE_TO_ROOT} da quel file a quello di root. Prima si scrive il file di root e
     * lo si rilegge; poi, in una sola scrittura del file della web, la password della web entra e gli altri
     * escono. A meta' strada ogni segreto c'e' in almeno un file, e chi legge lo trova (get). Vero se ha
     * cambiato qualcosa: al secondo avvio non scrive niente.
     */
    public static synchronized boolean giveWebItsOwnUser(String webPassword) {
        if (webPassword == null || webPassword.isEmpty()) throw new IllegalArgumentException("no password for the web part's MySQL user");
        Properties web = WEB.readFile();
        boolean changed = false;
        for (String name : MOVE_TO_ROOT) {
            String v = web.getProperty(name, "");
            if (v.isEmpty()) continue;
            ROOT.update(p -> {
                if (v.equals(p.getProperty(name, ""))) return null;
                p.setProperty(name, v);
                return p;
            });
            if (!v.equals(ROOT.readFile().getProperty(name, "")))
                throw new IllegalStateException("Root secret " + name + " not saved in " + ROOT.file());
            changed = true;
        }
        if (changed || !webPassword.equals(web.getProperty(MYSQL_WEB_PASSWORD, ""))) {
            WEB.update(p -> {
                p.setProperty(MYSQL_WEB_PASSWORD, webPassword);
                for (String name : MOVE_TO_ROOT) p.remove(name);
                return p;
            });
            changed = true;
        }
        return changed;
    }

    /**
     * All'avvio, da root: i segreti solo di root che stanno ancora nel file del pannello (i server di
     * prima) passano nel file di root e poi spariscono da quello del pannello. Prima si scrive il file di
     * root e lo si rilegge, poi si toglie dall'altro: a meta' strada il segreto c'e' sempre in almeno un
     * file. Se il file di root ha gia' un valore diverso vince il suo, che e' quello scritto dopo. I nomi
     * spostati, o nessuno.
     */
    public static synchronized java.util.List<String> splitRootSecrets() {
        Properties web = WEB.readFile();
        java.util.List<String> moved = new java.util.ArrayList<>();
        for (String name : ROOT_ONLY) {
            String v = web.getProperty(name, "");
            if (v.isEmpty()) continue;
            ROOT.update(p -> {
                if (!p.getProperty(name, "").isEmpty()) return null;
                p.setProperty(name, v);
                return p;
            });
            if (ROOT.readFile().getProperty(name, "").isEmpty())
                throw new IllegalStateException("Root secret " + name + " not saved in " + ROOT.file());
            moved.add(name);
        }
        if (!moved.isEmpty()) {
            WEB.update(p -> {
                for (String name : moved) p.remove(name);
                return p;
            });
        }
        return moved;
    }

    /**
     * Le lettere con cui si genera una password.
     *
     * <p>Mancano apposta l'apice, le virgolette, la barra rovescia e l'accento grave: la
     * password finisce dentro {@code IDENTIFIED BY '...'} in un here-document dello script
     * d'installazione, e uno di quei caratteri la spezzerebbe o verrebbe preso per un'escape
     * di MySQL. Il dollaro resta: l'espansione del here-document avviene una volta sola,
     * quindi un dollaro <em>dentro</em> la password non viene riespanso.
     */
    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=".toCharArray();

    /**
     * Solo lettere e cifre: l'alfabeto per la password dell'utente del pannello e per quella
     * della webmail.
     *
     * <p>Non e' una scelta pigra. Quelle password, a differenza di quella di root, finiscono
     * in posti che <em>non</em> sono SQL: l'URL di collegamento di Roundcube
     * ({@code mysql://utente:password@127.0.0.1/roundcubemail}), i file di Postfix e la
     * configurazione di Dovecot. In un URL una chiocciola spezza l'indirizzo, un
     * {@code %} apre una sequenza di decodifica e una barra cambia il percorso; nei file di
     * configurazione un {@code #} puo' aprire un commento. Qui un carattere in piu' non
     * aggiunge difesa che valga quelle rotture: ventiquattro caratteri alfanumerici sono
     * circa 143 bit.
     */
    private static final char[] ALPHANUMERIC =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    /** Una password nuova per SQL, presa da un generatore crittografico. */
    public static String newPassword(int length) {
        return newPassword(length, ALPHABET);
    }

    /** Una password nuova di sole lettere e cifre, per i posti che non sono SQL. */
    public static String newAlphanumericPassword(int length) {
        return newPassword(length, ALPHANUMERIC);
    }

    private static String newPassword(int length, char[] alphabet) {
        StringBuilder b = new StringBuilder(length);
        for (int i = 0; i < length; i++) b.append(alphabet[RANDOM.nextInt(alphabet.length)]);
        return b.toString();
    }

    /**
     * La password di root di MySQL, generandola se non c'e' ancora.
     *
     * <p>Prima non ce n'era nessuna: lo script d'installazione faceva {@code mysql -u root} e
     * poi {@code mysql -u root --password=}, cioe' dava per scontato che root entrasse senza
     * segreto. Su FreeBSD e' proprio come resta un MySQL appena installato, e root senza
     * password vuol dire che <em>qualunque</em> utente locale — compreso {@code www}, che fa
     * girare Roundcube — ha i pieni poteri sul database.
     *
     * <p>La <strong>prima</strong> password non si configura: si genera, una volta sola, con
     * un generatore crittografico; da quel momento <em>quella</em> e' la password, e si
     * rilegge da qui. Altrimenti quella nel file e quella impostata in MySQL non sarebbero
     * piu' lo stesso segreto. Una password messa a mano non viene mai sostituita.
     *
     * <p>Si puo' chiamare da piu' processi insieme: la generazione avviene sotto il lock del
     * file e chi arriva secondo trova quella del primo, invece di sovrascriverla con una sua
     * che in MySQL non e' mai stata impostata.
     */
    public static synchronized String ensureMysqlRootPassword() {
        return ensureGenerated(MYSQL_ROOT_PASSWORD, () -> newPassword(28));
    }

    /**
     * La password dell'utente MySQL della webmail, generandola se non c'e' ancora. Come quella di
     * root si genera una volta sola e poi si rilegge: la usano gli script d'installazione e la
     * migrazione all'avvio, e devono dare a MySQL e a config.inc.php lo stesso segreto. Solo
     * lettere e cifre, perche' finisce nell'URL di db_dsnw.
     */
    public static synchronized String ensureRoundcubeDbPassword() {
        return ensureGenerated(ROUNDCUBE_DB_PASSWORD, () -> newAlphanumericPassword(24));
    }

    /**
     * La password di uno degli utenti MySQL di Postfix e Dovecot (MailDbUsers), generandola se non c'e' ancora:
     * 32 lettere e cifre, perche' finisce nelle mappe di Postfix e nella riga connect di Dovecot, dove uno spazio,
     * un apice o un cancelletto cambierebbero il senso della riga.
     */
    public static synchronized String ensureServiceDbPassword(String name) {
        if (!POSTFIX_DB_PASSWORD.equals(name) && !DOVECOT_DB_PASSWORD.equals(name))
            throw new IllegalArgumentException("not a mail service password: " + name);
        return ensureGenerated(name, () -> newAlphanumericPassword(32));
    }

    /** Il segreto se c'e'; altrimenti lo genera sotto il lock del file, e chi arriva secondo trova il primo. */
    private static synchronized String ensureGenerated(String name, java.util.function.Supplier<String> generator) {
        String v = get(name);
        if (!v.isEmpty()) return v;
        return storeFor(name).update(p -> {
            if (!p.getProperty(name, "").isEmpty()) return null;   // l'ha appena scritta un altro
            p.setProperty(name, generator.get());
            return p;
        }).getProperty(name, "");
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
        key(WEBMAIL_KEY);
    }
}
