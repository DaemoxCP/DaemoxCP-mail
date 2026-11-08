package org.mail_panel.system;

import org.mail_panel.database.MysqlRoot;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MySQL ascolta solo da questa macchina, e senza il protocollo X.
 *
 * Misurato il 07/11/2026 sul server vero (MySQL 8.4.11, my.cnf uguale a my.cnf.sample del pacchetto):
 * la 3306 su 127.0.0.1, ma la 33060 del protocollo X su tutti gli indirizzi, perche' il file del
 * pacchetto non la nomina e il suo predefinito e' "*". Il pannello, Postfix, Dovecot e Roundcube usano
 * solo il protocollo classico. Sulla VM my.cnf non c'era affatto: anche la 3306 su tutti gli
 * indirizzi.
 *
 * Il manuale di MySQL 8.4 (x-plugin-disabling, x-plugin-options-system-variables): il plugin X si
 * spegne all'avvio con mysqlx=0 (o OFF), e mysqlx_bind_address si legge solo all'avvio. Quindi qui:
 * nella sezione [mysqld] si aggiungono, solo se mancano, bind-address = 127.0.0.1 e mysqlx = OFF; una
 * scelta gia' scritta da qualcuno non si tocca. Se my.cnf non c'e' se ne scrive uno con quelle due
 * righe e basta: copiare il file del pacchetto cambierebbe anche log binari, memoria e cartelle.
 *
 * Poi: `mysqld --validate-config` come l'utente mysql, il riavvio, e i controlli (MySQL risponde,
 * ascolta solo su 127.0.0.1 e niente 33060, Dovecot e Postfix trovano ancora le caselle). Se uno non
 * torna, my.cnf torna com'era e MySQL si riavvia di nuovo. Al secondo avvio non c'e' niente da fare.
 */
public final class MysqlListen {

    private static final Logger LOGGER = Logger.getLogger(MysqlListen.class.getName());

    static Path myCnf = Path.of("/usr/local/etc/mysql/my.cnf");
    static final String MYSQLD = "/usr/local/libexec/mysqld";
    static final String POSTFIX_MAP = "/usr/local/etc/postfix/mysql-virtual-mailboxes.cf";

    private static final Pattern SECTION = Pattern.compile("^\\s*\\[([^\\]]+)\\]\\s*$");
    private static final Pattern OPTION = Pattern.compile("^\\s*(?:loose[-_])?([A-Za-z0-9_-]+)\\s*(=.*)?$");

    static final String COMMENT = "# Aggiunto dal pannello: MySQL solo da questa macchina, e niente protocollo X (porta 33060).";

    private MysqlListen() {}

    /** Il nome di un'opzione come lo intende MySQL: minuscolo, con '-' al posto di '_'. */
    static String key(String option) {
        return option.toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /**
     * Il my.cnf con le due righe che mancano, o null se non manca niente. Funzione pura.
     *
     * @param text il my.cnf di adesso, o null se non c'e'
     */
    static String harden(String text) {
        if (text == null) return "[mysqld]\n" + COMMENT + "\nbind-address = 127.0.0.1\nmysqlx = OFF\n";
        List<String> lines = new ArrayList<>(List.of(text.split("\n", -1)));
        int header = -1, last = -1;
        boolean bind = false, mysqlx = false;
        String section = "";
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i);
            Matcher s = SECTION.matcher(l);
            if (s.matches()) {
                section = s.group(1).trim().toLowerCase(Locale.ROOT);
                if (section.equals("mysqld") && header < 0) { header = i; last = i; }
                continue;
            }
            if (!section.equals("mysqld") || l.trim().isEmpty() || l.trim().startsWith("#") || l.trim().startsWith(";")) continue;
            Matcher o = OPTION.matcher(l);
            if (!o.matches()) continue;
            String k = key(o.group(1));
            if (k.equals("bind-address")) bind = true;
            if (k.equals("mysqlx") || k.equals("skip-mysqlx") || k.equals("mysqlx-bind-address")) mysqlx = true;
            if (header >= 0 && i > last) last = i;
        }
        if (bind && mysqlx) return null;
        List<String> add = new ArrayList<>();
        add.add(COMMENT);
        if (!bind) add.add("bind-address                    = 127.0.0.1");
        if (!mysqlx) add.add("mysqlx                          = OFF");
        if (header < 0) {
            String sep = text.endsWith("\n") || text.isEmpty() ? "" : "\n";
            return text + sep + "\n[mysqld]\n" + String.join("\n", add) + "\n";
        }
        lines.addAll(last + 1, add);
        return String.join("\n", lines);
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(MYSQLD))) return;
            String before = Files.exists(myCnf) ? Files.readString(myCnf) : null;
            String after = harden(before);
            if (after == null) return;
            apply(before, after);
        } catch (Throwable t) {
            LOGGER.warning("[MysqlListen] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply(String before, String after) throws Exception {
        boolean running = Shell.run(Duration.ofSeconds(15), "service", "mysql-server", "status").success();
        String lookupsBefore = running ? lookups() : "";
        write(after);
        Shell.Result valid = Shell.run(Duration.ofSeconds(120), "su", "-m", "mysql", "-c", MYSQLD + " --validate-config");
        if (!valid.success()) {
            putBack(before, false);
            LOGGER.warning("[MysqlListen] ROLLED_BACK: mysqld --validate-config refuses the new my.cnf ("
                    + firstLine(valid.outputTrim()) + "): nothing changed");
            return false;
        }
        if (!running) {
            LOGGER.info("[MysqlListen] DONE: my.cnf now keeps MySQL on 127.0.0.1 without the X protocol; MySQL is not"
                    + " running, it applies at its next start");
            return true;
        }
        Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
        String problem = verify(lookupsBefore);
        if (problem != null) {
            putBack(before, true);
            String again = waitForMysql() ? "MySQL answers again" : "MySQL DOES NOT ANSWER";
            LOGGER.warning("[MysqlListen] ROLLED_BACK: " + problem + "; my.cnf put back and MySQL restarted (" + again + ")");
            return false;
        }
        LOGGER.info("[MysqlListen] DONE: MySQL listens only on 127.0.0.1, the X protocol (33060) is off;"
                + " Dovecot and Postfix still find the mailboxes");
        return true;
    }

    /** Dopo il riavvio: MySQL risponde, ascolta solo in locale, e le ricerche di posta tornano come prima. */
    static String verify(String lookupsBefore) throws InterruptedException {
        if (!waitForMysql()) return "MySQL does not answer after the restart";
        List<String> open = new ArrayList<>();
        for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l").outputTrim().split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 6 && f[1].startsWith("mysqld")) {
                String addr = f[5];
                if (addr.endsWith(":33060") || !(addr.startsWith("127.0.0.1:") || addr.startsWith("[::1]:"))) open.add(addr);
            }
        }
        if (!open.isEmpty()) return "MySQL still listens on " + open;
        // Dovecot e Postfix tengono una connessione a MySQL: dopo il riavvio la prima domanda trova la
        // connessione caduta e risponde "riprova" (Dovecot 75), la seguente si ricollega. Misurato sulla VM
        // il 07/11/2026 nella prova del passaggio: si aspetta che si ricolleghino, fino a 30 secondi.
        String lookupsAfter = "";
        for (int i = 0; i < 30; i++) {
            lookupsAfter = lookups();
            if (lookupsAfter.equals(lookupsBefore)) return null;
            Thread.sleep(1000);
        }
        return "mail lookups changed: before " + lookupsBefore + ", after " + lookupsAfter + " for 30 seconds";
    }

    static boolean waitForMysql() throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            if ("1".equals(MysqlRoot.query(org.mail_panel.database.SqlCatalog.MYSQL_ROOT_PING))) return true;
            Thread.sleep(1000);
        }
        return false;
    }

    /**
     * Le ricerche che il server di posta fa in MySQL, con un indirizzo che non esiste: Dovecot (passdb sql)
     * e Postfix (la mappa delle caselle). Si confrontano prima e dopo: un errore di connessione cambia
     * l'uscita, "non trovato" no.
     */
    static String lookups() {
        StringBuilder b = new StringBuilder();
        if (Files.isExecutable(Path.of(DovecotAuthWorker.DOVEADM)))
            b.append("dovecot=").append(DovecotAuthWorker.lookup());
        if (Files.exists(Path.of(POSTFIX_MAP)) && Shell.resolve("postmap") != null) {
            Shell.Result r = Shell.run(Duration.ofSeconds(20), "postmap", "-q", DovecotAuthWorker.PROBE, "mysql:" + POSTFIX_MAP);
            b.append(b.length() > 0 ? " " : "").append("postfix=").append(r.exitCode());
        }
        return b.toString();
    }

    private static void write(String text) throws Exception {
        if (myCnf.getParent() != null) Files.createDirectories(myCnf.getParent());
        Path tmp = myCnf.resolveSibling("." + myCnf.getFileName() + ".mailpanel.tmp");
        Files.writeString(tmp, text);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, myCnf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(String before, boolean restart) throws Exception {
        if (before == null) Files.deleteIfExists(myCnf); else write(before);
        if (restart) Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
    }

    private static String firstLine(String s) {
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
