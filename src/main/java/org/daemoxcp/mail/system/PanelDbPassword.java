package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MysqlRoot;
import org.daemoxcp.mail.database.SqlCatalog;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * La password dell'utente MySQL del pannello cambiata una volta (reperto 232).
 *
 * <p>Sui server installati prima della PR #91 quella password e' stata per tutta la loro vita in config.inc.php di
 * Roundcube, leggibile dalla webmail. Adesso la webmail entra con un utente suo (RoundcubeDbUser), Postfix e Dovecot
 * coi loro (MailDbUsers), la parte web con mailpanel_web: la password del pannello la usa solo il pannello. Ma chi
 * l'avesse presa la ha ancora, e con lei legge e scrive tutto il database della posta. Toglierla dalla webmail non
 * bastava: va cambiata.
 *
 * <p>Senza fermare niente, con la doppia password di MySQL (8.0.14 e successivi):
 * <ol>
 *   <li>si scrive lo stato («a meta'», con l'impronta SHA-256 della vecchia: la vecchia stessa no) e la password
 *       nuova in attesa (PendingDbPassword): un arresto da qui in poi lo decide l'avvio dopo;</li>
 *   <li>{@code ALTER USER ... IDENTIFIED BY nuova RETAIN CURRENT PASSWORD} su ogni account locale dell'utente
 *       (localhost e 127.0.0.1: MySQL porta 127.0.0.1 sull'account localhost): da qui valgono tutte e due;</li>
 *   <li>MySQL deve accettarle tutte e due davanti a noi; poi il pannello adotta la nuova (le connessioni nuove la
 *       rileggono dal file dei segreti, quelle aperte restano buone) e le copie lasciate dagli script vecchi che
 *       contengono la vecchia la ricevono;</li>
 *   <li>{@code DISCARD OLD PASSWORD} su ogni account; MySQL deve rifiutare la vecchia, accettare la nuova, e nessun
 *       account deve avere ancora una seconda password. Lo stato diventa «fatto», con la data UTC.</li>
 * </ol>
 * Fino al passo 3 un errore rimette MySQL com'era (la vecchia di nuovo principale, la seconda scartata) e toglie la
 * nuova; al prossimo avvio si riprova. Dopo il passo 3 il pannello e' gia' sulla nuova e non si torna indietro: se il
 * DISCARD non riesce lo si rifa' all'avvio dopo (lo stato resta «a meta'», e l'impronta dice che il pannello non e'
 * piu' sulla vecchia).
 *
 * <p>Non parte, e lo scrive nel log, se: lo stato dice gia' «fatto» (anche l'installazione lo scrive, perche' genera
 * una password che la webmail non ha mai avuto); il pannello non ha ancora una password, o ne ha una in attesa
 * (un'installazione che decide); MySQL come root non risponde, o non accetta adesso la password del pannello; un
 * account ha gia' una seconda password che non e' nostra; la password compare ancora in un file di Postfix, di
 * Dovecot o della webmail (qualcuno entra ancora con lei: cambiarla lo romperebbe). Gli account dello stesso utente
 * per altri host non si toccano, e il log li nomina.
 *
 * <p>Restano con la vecchia, che dopo non apre piu' niente: le copie di sicurezza (/var/db/mailpanel, gli ambienti di
 * avvio), e un MySQL ripristinato da prima, che riporterebbe anche la vecchia password.
 */
public final class PanelDbPassword {

    private static final Logger LOGGER = Logger.getLogger(PanelDbPassword.class.getName());

    private PanelDbPassword() {}

    /** Lo stato a meta': segue l'impronta SHA-256 (esadecimale) della password vecchia. */
    static final String RETAINED = "retained:";
    /** Lo stato a cose fatte: segue la data UTC. */
    static final String DONE = "done ";

    /** Gli host di un account locale: 127.0.0.1 MySQL lo porta su localhost, e IPv6. */
    static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "::1");

    /** Un account dell'utente del pannello: l'host, e se ha gia' una seconda password. */
    record Account(String host, boolean secondary) {}

    /** MySQL come root. */
    interface Accounts {
        /** Gli account dell'utente; null se MySQL non risponde (o non conosce le password doppie). */
        List<Account> list(String user);
        /** La password nuova, e quella di adesso che resta valida accanto. */
        boolean retain(String host, String user, String password);
        /** Questa password come principale; la seconda, se c'e', resta. */
        boolean setPrimary(String host, String user, String password);
        /** La seconda password tolta. */
        boolean discard(String host, String user);
    }

    /** I file fuori dal pannello. */
    interface Places {
        /** I file dei servizi in cui la password compare (un file che non si legge conta). */
        List<String> usersOf(String password);
        /** Le copie lasciate dagli script vecchi: dove c'e' la vecchia, la nuova. Quelle non riscritte, col motivo. */
        List<String> rewriteCopies(String old, String fresh);
    }

    /** Lo stato, nel file dei segreti di root. */
    interface State {
        String get();
        void set(String value);
    }

    public enum Outcome {
        /** Gia' fatto, o niente da cambiare (pannello non installato). */
        NOTHING,
        /** Cambiata adesso. */
        DONE,
        /** Finita adesso una rotazione rimasta a meta'. */
        RESUMED,
        /** Non si cambia, per una ragione che non passa da sola: il dettaglio la dice. */
        LEFT,
        /** Non adesso (MySQL non risponde, il turno e' di un altro): al prossimo avvio. */
        NOT_NOW,
        /** Qualcosa e' andato storto prima che il pannello adottasse la nuova: tutto com'era. */
        ROLLED_BACK,
        /** A meta': il pannello funziona, il resto lo finisce il prossimo avvio. */
        INCOMPLETE
    }

    public record Result(Outcome outcome, String detail) {}

    static String nz(String s) {
        return s == null ? "" : s;
    }

    static String fingerprint(String password) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** La decisione e il cambio, puri rispetto alle interfacce. */
    static Result run(PendingDbPassword.Store store, PendingDbPassword.Probe probe, Accounts db, Places places, State state,
                      String user, Supplier<String> generator) {
        String mark = nz(state.get());
        if (mark.startsWith(DONE)) return new Result(Outcome.NOTHING, "");
        String current = nz(store.current());
        if (current.isEmpty()) return new Result(Outcome.NOTHING, "the panel has no MySQL password yet");
        if (!nz(store.pending()).isEmpty())
            return new Result(Outcome.NOT_NOW, "a new password of an installation is still waiting to be decided");

        List<Account> all = db.list(user);
        if (all == null) return new Result(Outcome.NOT_NOW, "MySQL does not answer as root, or has no dual passwords (8.0.14+)");
        List<Account> local = all.stream().filter(a -> LOCAL_HOSTS.contains(a.host())).toList();
        List<String> others = all.stream().map(Account::host).filter(h -> !LOCAL_HOSTS.contains(h)).toList();
        if (local.isEmpty()) return new Result(Outcome.LEFT, "the MySQL user " + user + " has no account on this machine");

        if (mark.startsWith(RETAINED)) {
            if (!fingerprint(current).equals(mark.substring(RETAINED.length()))) {
                // Il pannello e' gia' sulla nuova (adottata qui, o dall'avvio con PendingDbPassword): resta il DISCARD.
                return finish(probe, db, state, user, local, others, null, current, Outcome.RESUMED);
            }
            // Ancora sulla vecchia: la nuova non e' mai stata adottata. MySQL torna alla sola vecchia, e si ricomincia.
            if (local.stream().anyMatch(Account::secondary) && !backToOld(db, local, user, current))
                return new Result(Outcome.INCOMPLETE, "an earlier change stopped half way, and MySQL could not be put back"
                        + " to the panel's password alone: the panel keeps working (MySQL accepts it), retried at the next start");
            state.set("");
            all = db.list(user);
            if (all == null) return new Result(Outcome.NOT_NOW, "MySQL does not answer as root");
            local = all.stream().filter(a -> LOCAL_HOSTS.contains(a.host())).toList();
        }

        List<String> withSecond = local.stream().filter(Account::secondary).map(Account::host).toList();
        if (!withSecond.isEmpty())
            return new Result(Outcome.LEFT, "the account(s) " + user + "@" + withSecond + " already have a second password,"
                    + " not set by the panel: left alone");
        PendingDbPassword.Answer now = probe.ask(current);
        if (now != PendingDbPassword.Answer.ACCEPTED)
            return new Result(now == PendingDbPassword.Answer.REJECTED ? Outcome.LEFT : Outcome.NOT_NOW,
                    "MySQL does not accept the panel's password now (" + now + ")");
        List<String> users = places.usersOf(current);
        if (!users.isEmpty())
            return new Result(Outcome.LEFT, "the password is still written in " + users + ": what reads it would stop"
                    + " entering MySQL");

        String fresh = generator.get();
        if (fresh == null || fresh.length() < 24 || fresh.equals(current))
            return new Result(Outcome.NOT_NOW, "no new password");
        String retained = RETAINED + fingerprint(current);
        state.set(retained);
        if (!retained.equals(nz(state.get()))) return new Result(Outcome.NOT_NOW, "the state could not be written");
        store.setPending(fresh);
        if (!fresh.equals(nz(store.pending()))) {
            state.set("");
            return new Result(Outcome.NOT_NOW, "the new password could not be kept aside");
        }

        List<Account> changed = new ArrayList<>();
        for (Account a : local) {
            changed.add(a);   // anche se fallisce: un ALTER a meta' si rimette come gli altri
            if (!db.retain(a.host(), user, fresh))
                return rollBack(store, db, state, user, changed, current, "MySQL refused the new password for " + user + "@" + a.host());
        }
        PendingDbPassword.Answer f = probe.ask(fresh), o = probe.ask(current);
        if (f != PendingDbPassword.Answer.ACCEPTED || o != PendingDbPassword.Answer.ACCEPTED)
            return rollBack(store, db, state, user, changed, current,
                    "after the change MySQL should accept both passwords; new: " + f + ", previous: " + o);

        store.adopt(fresh);
        if (!fresh.equals(nz(store.current()))) {
            store.adopt(current);
            return rollBack(store, db, state, user, changed, current, "the panel could not adopt the new password");
        }
        store.setPending("");
        List<String> notRewritten = places.rewriteCopies(current, fresh);
        Result r = finish(probe, db, state, user, local, others, current, fresh, Outcome.DONE);
        if (!notRewritten.isEmpty())
            return new Result(r.outcome(), r.detail() + "; copies left with the previous password: " + notRewritten);
        return r;
    }

    /** Il DISCARD e le verifiche. old e' null quando non la si conosce piu' (si riprende dopo un arresto). */
    private static Result finish(PendingDbPassword.Probe probe, Accounts db, State state, String user, List<Account> local,
                                 List<String> others, String old, String fresh, Outcome ok) {
        List<String> notDiscarded = new ArrayList<>();
        for (Account a : local) if (!db.discard(a.host(), user)) notDiscarded.add(a.host());
        List<Account> after = db.list(user);
        List<String> stillSecond = after == null ? List.of("?")
                : after.stream().filter(a -> LOCAL_HOSTS.contains(a.host()) && a.secondary()).map(Account::host).toList();
        if (!stillSecond.isEmpty())
            return new Result(Outcome.INCOMPLETE, "the panel uses the new password, but the previous one is still valid on "
                    + user + "@" + stillSecond + (notDiscarded.isEmpty() ? "" : " (DISCARD refused on " + notDiscarded + ")")
                    + ": discarded at the next start");
        PendingDbPassword.Answer f = probe.ask(fresh);
        if (f != PendingDbPassword.Answer.ACCEPTED)
            return new Result(Outcome.INCOMPLETE, "MySQL does not accept the panel's new password after the change (" + f + ")");
        if (old != null) {
            PendingDbPassword.Answer o = probe.ask(old);
            if (o != PendingDbPassword.Answer.REJECTED)
                return new Result(Outcome.INCOMPLETE, "MySQL still answers " + o + " to the previous password");
        }
        state.set(DONE + Instant.now().truncatedTo(ChronoUnit.SECONDS));
        return new Result(ok, "on " + user + "@" + local.stream().map(Account::host).toList()
                + (others.isEmpty() ? "" : "; accounts of the same user for other hosts not touched: " + others));
    }

    /** Ogni account cambiato di nuovo con la sola vecchia; poi via la nuova e lo stato. */
    private static Result rollBack(PendingDbPassword.Store store, Accounts db, State state, String user, List<Account> changed,
                                   String old, String why) {
        if (!backToOld(db, changed, user, old))
            return new Result(Outcome.INCOMPLETE, why + "; and putting MySQL back failed: the panel keeps working with its"
                    + " password (MySQL accepts it), the rest is decided at the next start");
        store.setPending("");
        state.set("");
        return new Result(Outcome.ROLLED_BACK, why + ": MySQL is back as it was, retried at the next start");
    }

    private static boolean backToOld(Accounts db, List<Account> accounts, String user, String old) {
        boolean ok = true;
        for (Account a : accounts) ok &= db.setPrimary(a.host(), user, old) && db.discard(a.host(), user);
        return ok;
    }

    // ===================== Il server vero =====================

    /** Dove la webmail, Postfix e Dovecot scrivono come entrano in MySQL. */
    static final List<Path> SERVICE_DIRS = List.of(Path.of("/usr/local/etc/postfix"), Path.of("/usr/local/etc/dovecot"),
            Path.of(RoundcubeDbUser.ROUNDCUBE_DIR, "config"), Path.of("/usr/local/etc/mail"), Path.of("/usr/local/etc/mailpanel"));
    /**
     * Le copie lasciate dagli script per componente: /usr/local/etc/mail/mysql_password (FullMailStackScript, da cui
     * DovecotConfig la rilegge se non la riceve) e /usr/local/etc/mailpanel/mysql.json (MySQLMailScript). Se hanno la
     * vecchia ricevono la nuova; se hanno altro restano come sono.
     */
    static final List<Path> COPIES = List.of(Path.of("/usr/local/etc/mail/mysql_password"),
            Path.of("/usr/local/etc/mailpanel/mysql.json"));

    static final long MAX_FILE = 2L * 1024 * 1024;

    /**
     * Un nome da copia di sicurezza, che nessun servizio legge (.bak, .orig, .old, ~, .sample, .save, una data in coda,
     * il file temporaneo del pannello): con la vecchia dentro non blocca, perche' dopo il cambio non apre piu' niente.
     */
    static boolean backupName(String name) {
        return name.endsWith(".bak") || name.endsWith(".orig") || name.endsWith(".old") || name.endsWith("~")
                || name.endsWith(".sample") || name.endsWith(".save") || name.endsWith(TEMP_SUFFIX)
                || LegacyNames.pairs("tempSuffixes").stream().anyMatch(p -> name.endsWith(p[0]))
                || name.matches(".*[.-][0-9]{8,}$");
    }

    /** Il file temporaneo che il pannello scrive accanto a quello vero prima di rinominarlo al suo posto. */
    static final String TEMP_SUFFIX = ".daemoxcp-mail.tmp";

    /**
     * I file sotto dirs (fino a tre livelli, senza seguire collegamenti) che contengono la password, tranne le copie e i
     * nomi da copia di sicurezza.
     */
    static List<String> usersOf(List<Path> dirs, List<Path> copies, String password) {
        List<String> out = new ArrayList<>();
        byte[] needle = password.getBytes(StandardCharsets.UTF_8);
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) continue;
            try (Stream<Path> s = Files.walk(dir, 3)) {
                for (Path f : (Iterable<Path>) s::iterator) {
                    if (copies.contains(f) || !Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)
                            || backupName(f.getFileName().toString())) continue;
                    try {
                        if (Files.size(f) > MAX_FILE) continue;
                        if (contains(Files.readAllBytes(f), needle)) out.add(f.toString());
                    } catch (IOException e) {
                        out.add(f + " (cannot be read)");
                    }
                }
            } catch (IOException | RuntimeException e) {
                out.add(dir + " (cannot be read)");
            }
        }
        return out;
    }

    static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }

    /** Le copie con la vecchia riscritte con la nuova, stesso proprietario e permessi; quelle non riscritte. */
    static List<String> rewriteCopies(List<Path> copies, String old, String fresh) {
        List<String> left = new ArrayList<>();
        for (Path f : copies) {
            try {
                if (!Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) continue;
                String text = Files.readString(f, StandardCharsets.UTF_8);
                if (!text.contains(old)) continue;
                RoundcubeDbUser.write(f, text.replace(old, fresh), RoundcubeDbUser.FileState.of(f, text).withoutOthers());
            } catch (IOException | RuntimeException e) {
                left.add(f + " (" + e.getClass().getSimpleName() + ")");
            }
        }
        return left;
    }

    /** Il codice dell'errore di MySQL, mai il messaggio: in un ALTER USER potrebbe ripetere la password. */
    static String errorCode(Shell.Result r) {
        String o = r == null ? "" : r.outputTrim();
        if (o.startsWith("ERROR ")) {
            int sp = o.indexOf(' ', 6);
            return "MySQL error " + (sp > 0 ? o.substring(6, sp) : "?");
        }
        return r != null && r.timedOut() ? "timed out" : "failed";
    }

    static Accounts mysqlAccounts() {
        return new Accounts() {
            @Override public List<Account> list(String user) {
                Shell.Result r = MysqlRoot.rootJdbc(null, SqlCatalog.PDP_ACCOUNTS, user);
                if (!r.success()) {
                    LOGGER.info("[PanelDbPassword] the accounts of " + user + " cannot be read: " + errorCode(r));
                    return null;
                }
                List<Account> out = new ArrayList<>();
                for (String line : r.output().split("\n")) {
                    if (line.isBlank()) continue;
                    String[] c = line.split("\t");
                    if (c.length != 2) return null;
                    out.add(new Account(c[0], "1".equals(c[1].trim())));
                }
                return out;
            }
            @Override public boolean retain(String host, String user, String password) {
                return done("RETAIN", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_RETAIN, user, host, password));
            }
            @Override public boolean setPrimary(String host, String user, String password) {
                return done("back to the previous password", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_SET, user, host, password));
            }
            @Override public boolean discard(String host, String user) {
                return done("DISCARD OLD PASSWORD", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_DISCARD, user, host));
            }
            private boolean done(String what, String host, Shell.Result r) {
                if (r.success()) return true;
                LOGGER.info("[PanelDbPassword] " + what + " on @" + host + ": " + errorCode(r));
                return false;
            }
        };
    }

    static State secretsState() {
        return new State() {
            @Override public String get() { return PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD_ROTATION); }
            @Override public void set(String value) { PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD_ROTATION, value); }
        };
    }

    /**
     * L'installazione ha appena dato al pannello una password nuova, che la webmail non ha mai avuto: non c'e' niente
     * da cambiare.
     */
    public static void markFreshFromInstallation() {
        try {
            secretsState().set(DONE + Instant.now().truncatedTo(ChronoUnit.SECONDS) + " (installation)");
        } catch (RuntimeException e) {
            LOGGER.info("[PanelDbPassword] the state could not be written after the installation: " + e.getClass().getSimpleName());
        }
    }

    /** All'avvio della parte root, dopo RoundcubeDbUser e MailDbUsers. */
    public static Result ensureAtBoot() {
        try {
            if (Main.dbManager == null || !Main.mysqlAvailable) return new Result(Outcome.NOT_NOW, "MySQL not available");
            State state = secretsState();
            if (nz(state.get()).startsWith(DONE)) return new Result(Outcome.NOTHING, "");
            String refusal = PackageQueue.takeForLocks("db-password", I18n.tr("server.dbPassword.rotationTurn"));
            if (refusal != null) {
                LOGGER.info("[PanelDbPassword] not now, another panel process holds the turn: " + refusal);
                return new Result(Outcome.NOT_NOW, refusal);
            }
            Result r;
            try {
                String[] t = PendingDbPassword.mysqlTarget(Main.dbManager);
                r = run(PendingDbPassword.panelStore(Main.dbManager), PendingDbPassword.mysqlProbe(t[0], t[1], t[2]),
                        mysqlAccounts(), new Places() {
                            @Override public List<String> usersOf(String password) { return PanelDbPassword.usersOf(SERVICE_DIRS, COPIES, password); }
                            @Override public List<String> rewriteCopies(String old, String fresh) { return PanelDbPassword.rewriteCopies(COPIES, old, fresh); }
                        }, state, t[2], () -> PanelSecrets.newAlphanumericPassword(32));
            } finally {
                PackageQueue.release("db-password");
            }
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE, RESUMED -> LOGGER.info("[PanelDbPassword] DONE: the password of the panel's MySQL user changed"
                        + (r.outcome() == Outcome.RESUMED ? " (finished after an earlier start)" : "")
                        + ", the previous one no longer opens MySQL; " + r.detail());
                case NOT_NOW -> LOGGER.info("[PanelDbPassword] not now: " + r.detail());
                default -> LOGGER.warning("[PanelDbPassword] " + r.outcome() + ": " + r.detail());
            }
            return r;
        } catch (Throwable t) {
            LOGGER.warning("[PanelDbPassword] failed: " + t.getClass().getName());
            return new Result(Outcome.NOT_NOW, t.getClass().getName());
        }
    }
}
