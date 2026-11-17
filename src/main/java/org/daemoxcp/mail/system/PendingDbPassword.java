package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PanelSecrets;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * La password MySQL del pannello cambia solo quando MySQL la conosce.
 *
 * <p>Perche' esiste: misurato il 06/11/2026 sulla VM FreeBSD 15.1 (reperto 156). L'installazione
 * completa dal menu generava la password nuova dell'utente MySQL del pannello e la scriveva SUBITO
 * nel file dei segreti, poi lanciava install_mail_server.sh, che la imposta in MySQL solo alla
 * fase 3. Ogni uscita prima di li' (Roundcube non configurato, un parametro mancante, il turno dei
 * pacchetti preso, un pacchetto protetto, pkg che fallisce) lasciava il pannello con una password
 * che MySQL rifiutava, fino alla reinstallazione successiva.
 *
 * <p>Adesso la password nuova nasce <em>in attesa</em> ({@link PanelSecrets#MYSQL_PASSWORD_PENDING}),
 * accanto a quella del pannello, che non si tocca. Finito lo script si chiede a MySQL: se accetta
 * quella in attesa, diventa quella del pannello; se rifiuta quella e accetta la vecchia, la nuova si
 * butta. Lo decide MySQL, non il codice d'uscita dello script: uno script che fallisce DOPO la fase 3
 * ha gia' cambiato la password, e Postfix e Dovecot l'hanno gia' scritta nei loro file.
 *
 * <p>Se il pannello muore mentre lo script lavora, la password in attesa resta nel file, e il
 * prossimo avvio fa la stessa domanda ({@link #settleAtStartup}). Se MySQL non risponde non si
 * decide niente: la password in attesa resta, e l'installazione successiva da' a MySQL di nuovo
 * quella, invece di buttarla per una nuova che MySQL di sicuro non conosce.
 *
 * <p>All'avvio c'e' anche il rimedio per i server gia' rotti dalla versione di prima, che non aveva
 * la password in attesa: se MySQL rifiuta la password del pannello, si prova quella che usa Postfix
 * ({@link #postfixMap}, scritta dallo script alla fase 6 e cancellata solo alla fase 1, quindi
 * intatta dopo ogni uscita anticipata). Se MySQL la accetta, e' quella giusta e diventa del pannello.
 * Non si sceglie mai una password che MySQL non ha accettato davanti a noi.
 */
public final class PendingDbPassword {

    private static final Logger LOGGER = Logger.getLogger(PendingDbPassword.class.getName());

    private PendingDbPassword() {}

    /** Che cosa dice MySQL di una password. */
    public enum Answer { ACCEPTED, REJECTED, NO_ANSWER }

    /** Come e' finita una decisione. */
    public enum Outcome {
        /** Niente in attesa, e la password del pannello va bene (o non c'e' niente da chiedere). */
        NOTHING_TO_DO,
        /** MySQL accetta la password in attesa: adesso e' quella del pannello. */
        NEW_ADOPTED,
        /** MySQL non conosce la password in attesa e accetta quella di prima: si tiene quella. */
        OLD_KEPT,
        /** MySQL rifiuta quella del pannello e accetta quella di Postfix: adesso e' quella del pannello. */
        COPY_ADOPTED,
        /** MySQL non risponde: non si decide, la password in attesa resta. */
        UNDECIDED,
        /** MySQL rifiuta tutte le password che il pannello conosce: non cambia niente. */
        NONE_ACCEPTED,
        /** Un altro processo del pannello tiene il turno (forse un'installazione): decide lui. */
        NOT_NOW
    }

    /** L'esito, con il messaggio da mostrare ("" se non c'e' niente da dire). */
    public record Result(Outcome outcome, String message) {}

    /** La password per lo script, e che cosa e' successo a quella rimasta in attesa da prima. */
    public record Prepared(String password, String note) {}

    /** Dove stanno le password. In produzione il file dei segreti (e SQLite); nelle prove un finto. */
    public interface Store {
        /** La password che il pannello usa per entrare in MySQL ("" se non ce n'e' ancora una). */
        String current();
        /** Da adesso e' questa la password del pannello. */
        void adopt(String password);
        /** La password in attesa ("" se non ce n'e'). */
        String pending();
        /** Scrive la password in attesa; con "" la toglie. */
        void setPending(String password);
    }

    /** La domanda a MySQL: entra l'utente del pannello con questa password? */
    public interface Probe {
        Answer ask(String password);
    }

    /**
     * Il file di Postfix con la password dell'utente del pannello. E' una variabile solo perche' le
     * prove non leggano quello vero.
     */
    static Path postfixMap = Path.of("/usr/local/etc/postfix/mysql-virtual-domains.cf");

    // ---------------------------------------------------------------- la decisione

    /**
     * Prima dello script: la password che lo script dara' a MySQL, scritta in attesa.
     *
     * <p>Se una password in attesa c'e' gia' (un'installazione di prima non arrivata alla
     * decisione), prima si decide quella. Se MySQL non sa rispondere, si riusa: MySQL potrebbe
     * conoscerla, e buttarla per una nuova lascerebbe il pannello senza la sola password giusta se
     * anche questo script si ferma prima di MySQL.
     *
     * @throws IllegalStateException se la password non si puo' scrivere in attesa: lo script non
     *         deve partire, perche' cambierebbe MySQL senza che il pannello sappia con che cosa.
     */
    public static Prepared prepare(Store store, Probe probe, String user) {
        String note = "";
        String left = store.pending();
        if (!left.isEmpty()) {
            Result r = settle(store, probe, user);
            if (r.outcome() == Outcome.UNDECIDED)
                return new Prepared(left, I18n.tr("server.dbPassword.reused"));
            note = r.message();
        }
        String fresh = PanelSecrets.newAlphanumericPassword(24);
        store.setPending(fresh);
        if (!fresh.equals(store.pending()))
            throw new IllegalStateException("the new password was not kept aside");
        return new Prepared(fresh, note);
    }

    /**
     * Dopo lo script (o all'avvio): quale password conosce MySQL. Chi la chiama tiene il turno dei
     * pacchetti, o e' una prova: un'installazione in corso in un altro processo cambierebbe MySQL
     * mentre qui si decide.
     */
    public static Result settle(Store store, Probe probe, String user) {
        String pending = store.pending();
        String current = store.current();

        if (!pending.isEmpty()) {
            Answer p = probe.ask(pending);
            if (p == Answer.ACCEPTED) {
                // Prima la si adotta, poi si toglie l'attesa: un arresto in mezzo lascia le due
                // uguali, e la prossima decisione le trova accettate tutte e due.
                store.adopt(pending);
                store.setPending("");
                return new Result(Outcome.NEW_ADOPTED, I18n.tr("server.dbPassword.newAdopted"));
            }
            if (p == Answer.NO_ANSWER) return undecided();
            Answer c = current.isEmpty() || current.equals(pending) ? Answer.REJECTED : probe.ask(current);
            if (c == Answer.NO_ANSWER) return undecided();
            if (c == Answer.ACCEPTED) {
                store.setPending("");
                return new Result(Outcome.OLD_KEPT, I18n.tr("server.dbPassword.oldKept"));
            }
            // MySQL ha detto di no a tutte e due: la nuova non serve piu' a niente.
            Result copy = tryPostfixCopy(store, probe, user, pending, current);
            store.setPending("");
            if (copy != null) return copy;
            return new Result(Outcome.NONE_ACCEPTED, I18n.tr("server.dbPassword.noneAccepted",
                    Map.of("user", String.valueOf(user), "file", String.valueOf(postfixMap))));
        }

        if (current.isEmpty()) return new Result(Outcome.NOTHING_TO_DO, "");   // mai installato
        Answer c = probe.ask(current);
        if (c != Answer.REJECTED) return new Result(Outcome.NOTHING_TO_DO, "");
        Result copy = tryPostfixCopy(store, probe, user, "", current);
        if (copy != null) return copy;
        return new Result(Outcome.NONE_ACCEPTED, I18n.tr("server.dbPassword.noneAccepted",
                Map.of("user", String.valueOf(user), "file", String.valueOf(postfixMap))));
    }

    private static Result undecided() {
        return new Result(Outcome.UNDECIDED, I18n.tr("server.dbPassword.undecided"));
    }

    /** La password di Postfix, se e' un'altra e MySQL la accetta. null altrimenti. */
    private static Result tryPostfixCopy(Store store, Probe probe, String user, String pending, String current) {
        String copy = postfixCopy(user);
        if (copy.isEmpty() || copy.equals(pending) || copy.equals(current)) return null;
        if (probe.ask(copy) != Answer.ACCEPTED) return null;
        store.adopt(copy);
        return new Result(Outcome.COPY_ADOPTED, I18n.tr("server.dbPassword.copyAdopted",
                Map.of("file", String.valueOf(postfixMap))));
    }

    /**
     * La password nel file di Postfix, se il file e' dell'utente del pannello; "" altrimenti (file
     * assente, illeggibile, di un altro utente). Il formato e' quello che scrive lo script:
     * {@code chiave = valore}, una per riga.
     */
    static String postfixCopy(String user) {
        try {
            if (!Files.isRegularFile(postfixMap)) return "";
            String fileUser = null, password = null;
            for (String line : Files.readAllLines(postfixMap, StandardCharsets.UTF_8)) {
                int eq = line.indexOf('=');
                if (eq < 0 || line.trim().startsWith("#")) continue;
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                if (key.equals("user")) fileUser = value;
                else if (key.equals("password")) password = value;
            }
            if (password == null || fileUser == null || !fileUser.equals(user)) return "";
            return password;
        } catch (Exception e) {
            return "";
        }
    }

    // ---------------------------------------------------------------- il pannello vero

    /** Le password del pannello vero: il file dei segreti, e la colonna di SQLite se e' ancora piena. */
    public static Store panelStore(org.daemoxcp.mail.sqli.dataBaseManager db) {
        return new Store() {
            public String current() { return db.mysqlPassword(); }
            public void adopt(String password) { db.setMysqlPassword(password); }
            public String pending() { return PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD_PENDING); }
            public void setPending(String password) { PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD_PENDING, password); }
        };
    }

    /**
     * La domanda vera a MySQL, senza scegliere un database: conta solo se l'utente entra.
     * «Access denied» (1045, SQLSTATE 28000) e' un no; qualunque altra cosa (connessione
     * rifiutata, tempo scaduto, MySQL che si sta avviando) e' «non risponde», e non decide niente.
     */
    public static Probe mysqlProbe(String host, String port, String user) {
        return password -> {
            if (password == null || password.isEmpty()) return Answer.REJECTED;
            String url = "jdbc:mysql://" + host + ":" + port + "/?connectTimeout=5000&socketTimeout=10000"
                    + "&useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
            try (Connection c = org.daemoxcp.mail.database.CatalogGuard.open(url, user, password)) {
                return c.isValid(5) ? Answer.ACCEPTED : Answer.NO_ANSWER;
            } catch (SQLException e) {
                if (e.getErrorCode() == 1045 || "28000".equals(e.getSQLState())) return Answer.REJECTED;
                return Answer.NO_ANSWER;
            }
        };
    }

    /** Host, porta e utente MySQL dalla configurazione del pannello, con i valori di sempre se manca. */
    public static String[] mysqlTarget(org.daemoxcp.mail.sqli.dataBaseManager db) {
        String host = "127.0.0.1", port = "3306", user = "mailpanel";
        try (ResultSet r = db.get_data_config()) {
            if (r.next()) {
                if (notBlank(r.getString("mysql_host"))) host = r.getString("mysql_host");
                if (notBlank(r.getString("mysql_port"))) port = r.getString("mysql_port");
                if (notBlank(r.getString("mysql_user"))) user = r.getString("mysql_user");
            }
        } catch (Exception e) {
            // configurazione non ancora creata: i valori di sempre
        }
        return new String[]{host, port, user};
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    /**
     * All'avvio di ogni processo del pannello, prima che qualcuno entri in MySQL.
     *
     * <p>Il caso di sempre (niente in attesa, MySQL accetta la password del pannello) costa una
     * connessione e non prende il turno. Il turno serve solo quando c'e' da decidere qualcosa: se lo
     * tiene un altro processo, li' forse sta girando un'installazione, che decidera' da se' alla
     * fine; qui non si tocca niente.
     */
    public static Result settleAtStartup(org.daemoxcp.mail.sqli.dataBaseManager db) {
        Store store = panelStore(db);
        String[] t = mysqlTarget(db);
        Probe probe = mysqlProbe(t[0], t[1], t[2]);
        String pending, current;
        try {
            pending = store.pending();
            current = store.current();
        } catch (RuntimeException e) {
            return new Result(Outcome.NOTHING_TO_DO, "");    // file dei segreti illeggibile: lo dice gia' chi lo legge
        }
        if (pending.isEmpty()) {
            if (current.isEmpty()) return new Result(Outcome.NOTHING_TO_DO, "");
            if (probe.ask(current) != Answer.REJECTED) return new Result(Outcome.NOTHING_TO_DO, "");
        }
        // takeForLocks e non take: un elenco di pacchetti rimasto aperto non c'entra con la password.
        String refusal = PackageQueue.takeForLocks("db-password", I18n.tr("server.dbPassword.turn"));
        if (refusal != null) {
            String msg = pending.isEmpty() ? "" : I18n.tr("server.dbPassword.notNow", Map.of("why", refusal));
            if (!msg.isEmpty()) LOGGER.info(msg);
            return new Result(Outcome.NOT_NOW, msg);
        }
        try {
            Result r = settle(store, probe, t[2]);
            if (!r.message().isEmpty()) LOGGER.warning(r.message());
            return r;
        } catch (RuntimeException e) {
            LOGGER.warning("Deciding the panel's MySQL password failed: " + e.getMessage());
            return new Result(Outcome.UNDECIDED, "");
        } finally {
            PackageQueue.release("db-password");
        }
    }
}
