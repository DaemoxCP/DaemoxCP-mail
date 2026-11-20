package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.SafeNames;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * La home di Dovecot di ogni casella in /var/vmail/dominio/nome/home, non piu' la radice della posta (reperto 217).
 *
 * La posta sta nella radice della casella (mail_location = maildir:/var/vmail/%d/%n) e la home era la stessa cartella.
 * Dovecot nella home scrive i suoi file: la memoria delle risposte automatiche e degli inoltri (.dovecot.lda-dupes, con
 * la cartella dei lucchetti .dovecot.lda-dupes.locks), e con il reperto 214 gli script Sieve dell'utente (sieve/,
 * dovecot.sieve). Maildir++ prende per una cartella di posta tutto cio' che comincia col punto: misurato sulla VM il
 * 10/11/2026, dopo una sola risposta automatica IMAP LIST dava «dovecot», «dovecot.lda-dupes» e
 * «dovecot.lda-dupes.locks», selezionabile, e la webmail li mostrava; aprirla la trasformava in una Maildir vera (cur,
 * new, tmp). La documentazione di Dovecot (2.3 e 2.4, «Home directories for virtual users»): la home non deve essere la
 * cartella della posta con Maildir, «Non-mailbox files may show up as mailboxes»; fra le disposizioni ammesse c'e' la
 * home sotto la posta, «home=/var/vmail/domain/user/home/, mail=/var/vmail/domain/user/». E' questa: la posta non si
 * sposta, si spostano solo i file di Dovecot. maildir_stat_dirs = yes non basta: .dovecot.lda-dupes.locks e' una
 * cartella.
 *
 * Qui, sui server installati prima: si cambia solo il percorso della home in conf.d/auth-sql.conf.ext, se e' quello che
 * il pannello scriveva (2.3 o 2.4), e si portano nella home i file che Dovecot aveva messo nella radice. I file li
 * sposta vmail, non root: e' la sua cartella, e root dentro una cartella di un altro utente seguirebbe i suoi
 * collegamenti. Ordine: prima si copiano nella home (con la configurazione di prima Dovecot usa ancora gli originali),
 * poi la configurazione nuova, doveconf, il ricaricamento e la verifica con doveadm user; se una cosa sola non torna la
 * configurazione torna com'era e le copie si tolgono. Dopo, gli originali si tolgono dalla radice, e la cartella
 * fantasma .dovecot.lda-dupes.locks se non contiene posta; se ne contiene (qualcuno ci ha spostato dei messaggi) resta, e
 * il registro lo dice. Se in radice e in home ci sono due script dell'utente diversi, non si sceglie: restano tutti e due.
 * Al secondo avvio non trova niente da fare.
 */
public final class DovecotHome {

    private static final Logger LOGGER = Logger.getLogger(DovecotHome.class.getName());

    static Path authSql = Path.of("/usr/local/etc/dovecot/conf.d/auth-sql.conf.ext");
    static Path vmail = Path.of("/var/vmail");
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** La cartella della home dentro quella della casella. */
    public static final String DIR = "home";

    /** La home della 2.3 come la scriveva il pannello (args dello userdb static), seguita da uno spazio o dalla fine riga. */
    static final Pattern OLD23 = Pattern.compile("(?m)(\\bhome=/var/vmail/%d/%n)(?=[ \\t]|$)");
    static final String NEW23 = "home=/var/vmail/%d/%n/" + DIR;

    /** La home della 2.4 come la scriveva il pannello (fields dello userdb static), da sola sulla riga. */
    static final Pattern OLD24 = Pattern.compile("(?m)^([ \\t]*home = /var/vmail/%\\{user \\| domain\\}/%\\{user \\| username\\})[ \\t]*$");
    static final String NEW24 = "home = /var/vmail/%{user | domain}/%{user | username}/" + DIR;

    /** Le cartelle fantasma che Maildir++ ricavava dai file di Dovecot nella radice: la piu' profonda e i suoi genitori. */
    static final List<String> PHANTOMS = List.of("dovecot.lda-dupes.locks", "dovecot.lda-dupes", "dovecot");

    /**
     * Il lavoro sui file, eseguito come vmail: $1 la fase, $2 la radice (/var/vmail). Ogni riga che scrive e' una parola
     * in maiuscolo e un percorso. Le cose di Dovecot (la memoria dei duplicati, lo script compilato, il registro degli
     * script) se sono diverse tengono la piu' recente; quelle dell'utente (gli script) se sono diverse restano tutte e due.
     *  prepare: crea la home e ci copia quello che c'e' in radice (gli originali restano, per la configurazione di prima);
     *  undo:    toglie dalla home le copie uguali agli originali, e la home se resta vuota;
     *  finish:  crea la home nelle caselle che hanno gia' la posta, ci sposta quello che e' rimasto in radice, e toglie
     *           la cartella fantasma dei lucchetti se non contiene posta.
     */
    static final String SCRIPT = """
            PATH=/bin:/usr/bin; export PATH
            cd / || exit 1
            umask 077
            phase=$1; root=$2; failed=0
            own='.dovecot.lda-dupes dovecot.svbin dovecot.sieve.log .dovecot.sieve.log'
            user='sieve dovecot.sieve'
            there() { [ -e "$1" ] || [ -L "$1" ]; }
            same() {
              if [ -L "$1" ] || [ -L "$2" ]; then [ -L "$1" ] && [ -L "$2" ] && [ "$(readlink "$1")" = "$(readlink "$2")" ]
              elif [ -d "$1" ] || [ -d "$2" ]; then [ -d "$1" ] && [ -d "$2" ] && diff -r -q "$1" "$2" >/dev/null 2>&1
              else cmp -s "$1" "$2"; fi
            }
            for m in "$root"/*/*; do
              [ -d "$m" ] && [ ! -L "$m" ] && [ ! -L "${m%/*}" ] || continue
              h="$m/home"
              if [ -L "$h" ] || { there "$h" && [ ! -d "$h" ]; }; then echo "CONFLICT $h"; failed=1; continue; fi
              case "$phase" in
              prepare)
                for i in $own $user; do
                  there "$m/$i" || continue
                  mkdir -p "$h" || { echo "FAILED $h"; failed=1; continue 2; }
                  if there "$h/$i"; then echo "BOTH $m/$i"; continue; fi
                  if cp -RPp "$m/$i" "$h/$i"; then echo "COPIED $m/$i"; else echo "FAILED $m/$i"; failed=1; fi
                done ;;
              undo)
                for i in $own $user; do
                  there "$m/$i" && there "$h/$i" && same "$m/$i" "$h/$i" && rm -rf "$h/$i" && echo "UNCOPIED $m/$i"
                done
                [ -d "$h" ] && rmdir "$h" 2>/dev/null ;;
              finish)
                if [ ! -d "$h" ] && { [ -d "$m/cur" ] || [ -f "$m/dovecot-uidlist" ]; }; then
                  mkdir "$h" && echo "CREATED $h" || { echo "FAILED $h"; failed=1; }
                fi
                for i in $own $user; do
                  there "$m/$i" || continue
                  mkdir -p "$h" || { echo "FAILED $h"; failed=1; continue 2; }
                  if ! there "$h/$i"; then
                    if mv "$m/$i" "$h/$i"; then echo "MOVED $m/$i"; else echo "FAILED $m/$i"; failed=1; fi
                  elif same "$m/$i" "$h/$i"; then
                    rm -rf "$m/$i" && echo "MOVED $m/$i"
                  elif [ "$i" = sieve ] || [ "$i" = dovecot.sieve ]; then
                    echo "BOTH_DIFFER $m/$i"
                  elif [ "$m/$i" -nt "$h/$i" ]; then
                    rm -rf "$h/$i" && mv "$m/$i" "$h/$i" && echo "MOVED $m/$i"
                  else
                    rm -rf "$m/$i" && echo "MOVED $m/$i"
                  fi
                done
                p="$m/.dovecot.lda-dupes.locks"
                if [ -d "$p" ] && [ ! -L "$p" ]; then
                  mail=$(cd "$p" && find . -mindepth 1 \\( -type d ! \\( -path ./cur -o -path ./new -o -path ./tmp \\) \\
                      -o -type f \\( -path './cur/*' -o -path './new/*' -o -path './tmp/*' \\) -o ! -type d ! -type f \\) -print | head -n 1)
                  if [ -n "$mail" ]; then echo "PHANTOM_KEPT $p"; else rm -rf "$p" && echo "PHANTOM_REMOVED $p"; fi
                fi ;;
              esac
            done
            exit $failed
            """;

    private DovecotHome() {}

    /** La home di Dovecot di una casella: /var/vmail/dominio/nome/home. */
    public static Path of(String domain, String user) {
        return SafeNames.under(vmail, domain, user, DIR);
    }

    /**
     * conf.d/auth-sql.conf.ext con la home nuova, o null se non c'e' niente da cambiare: gia' fatto, o la home non e'
     * quella che scriveva il pannello, una volta sola (allora non e' sua, e resta com'e'). Funzione pura.
     */
    static String migrated(String conf) {
        if (conf == null) return null;
        String next = once(OLD23, conf, NEW23);
        return next != null ? next : once(OLD24, conf, NEW24);
    }

    private static String once(Pattern old, String conf, String replacement) {
        Matcher m = old.matcher(conf);
        if (!m.find()) return null;
        int start = m.start(1), end = m.end(1);
        if (m.find()) return null;
        String indent = conf.substring(start, end).replaceAll("^([ \\t]*).*$", "$1");
        return conf.substring(0, start) + indent + replacement + conf.substring(end);
    }

    /**
     * Il server usa gia' la home nella sua cartella: per chi crea una casella nuova (ConfigRegeneratorScript), che
     * cosi' la crea subito invece di aspettare il prossimo avvio del pannello.
     */
    public static boolean configured() {
        try {
            return Files.isRegularFile(authSql, LinkOption.NOFOLLOW_LINKS) && usesHome(Files.readString(authSql, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** La configurazione mette gia' la home nella sua cartella (2.3 o 2.4). */
    static boolean usesHome(String conf) {
        return conf != null && (conf.contains(NEW23) || conf.contains(NEW24));
    }

    /** Le righe del lavoro sui file, e se e' andato tutto bene. */
    record Outcome(boolean ok, List<String> lines) {
        List<String> with(String word) {
            List<String> out = new ArrayList<>();
            for (String l : lines) if (l.startsWith(word + " ")) out.add(l.substring(word.length() + 1));
            return out;
        }
    }

    /** Il lavoro sui file come vmail. */
    static Outcome asVmail(String phase) {
        Shell.Result r = Shell.run(Duration.ofSeconds(600), "su", "-m", "vmail", "-c", SCRIPT, "sh", phase, vmail.toString());
        return new Outcome(r.success(), r.outputTrim().isEmpty() ? List.of() : List.of(r.outputTrim().split("\n")));
    }

    /**
     * Quando il pannello scrive le regole di una casella (risposta automatica, inoltro): la sua home, come vmail, se la
     * configurazione la vuole nella sua cartella. Senza, Dovecot la crea da solo alla prima risposta automatica, ma prima
     * scrive nel registro della posta «Error: duplicate db: ... file_dotlock_open(.../home/.dovecot.lda-dupes) failed:
     * No such file or directory» (misurato sulla VM).
     */
    public static void ensureHome(String domain, String user) {
        try {
            if (!SafeNames.domain(domain) || !SafeNames.localPart(user)) return;
            Path home = of(domain, user);
            if (Files.isDirectory(home, LinkOption.NOFOLLOW_LINKS) || !Files.isDirectory(vmail, LinkOption.NOFOLLOW_LINKS)) return;
            if (!Files.isRegularFile(authSql, LinkOption.NOFOLLOW_LINKS) || !usesHome(Files.readString(authSql, StandardCharsets.UTF_8))) return;
            Shell.Result r = Shell.run(Duration.ofSeconds(20), "su", "-m", "vmail", "-c",
                    "PATH=/bin:/usr/bin; cd / && umask 077 && mkdir -p \"$1\"", "sh", home.toString());
            if (!r.success()) LOGGER.warning("[DovecotHome] cannot create " + home + " as vmail: " + first(r.outputTrim()));
        } catch (Exception e) {
            LOGGER.warning("[DovecotHome] cannot create the home of " + user + "@" + domain + ": " + e.getMessage());
        }
    }

    /** All'avvio della parte root. */
    public static void ensureAtBoot() {
        try {
            String problem = ensure();
            if (problem != null) LOGGER.warning("[DovecotHome] " + problem);
        } catch (Throwable t) {
            LOGGER.warning("[DovecotHome] failed: " + t);
        }
    }

    /** Null se non c'era niente da fare o se e' fatto; altrimenti cosa e' rimasto com'era, e perche'. */
    static synchronized String ensure() throws Exception {
        if (!Files.isRegularFile(authSql, LinkOption.NOFOLLOW_LINKS) || !Files.isExecutable(Path.of(DOVECONF))
                || !Files.isDirectory(vmail, LinkOption.NOFOLLOW_LINKS)) return null;
        String current = Files.readString(authSql, StandardCharsets.UTF_8);
        String next = migrated(current);
        if (next == null) {
            // Gia' fatto (o la configurazione l'ha riscritta il pannello col modello nuovo): restano da portare nella
            // home i file rimasti in radice, se ce ne sono.
            if (!usesHome(current)) return null;
            Outcome f = asVmail("finish");
            String told = report(f, false);
            return f.ok() ? null : "NOT_COMPLETE: " + told;
        }
        Outcome prepare = asVmail("prepare");
        if (!prepare.ok()) {
            asVmail("undo");
            return "left as it is: the files of Dovecot could not be copied into the homes ("
                    + String.join("; ", head(prepare.lines())) + ")";
        }
        Path tmp = authSql.resolveSibling(".auth-sql.conf.ext.home");
        Files.copy(authSql, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.move(tmp, authSql, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        if (!Shell.run(Duration.ofSeconds(15), DOVECONF, "-n").success())
            return putBack(current, "doveconf refuses the new home");
        boolean running = Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success();
        String verified = null;
        if (running) {
            if (!Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload").success())
                return putBack(current, "Dovecot did not reload");
            verified = verify();
            if (verified != null && !verified.startsWith("UNVERIFIED")) return putBack(current, verified);
            // I processi di prima finiscono la consegna che hanno in mano con la configurazione di prima.
            Thread.sleep(3000);
        }
        Outcome f = asVmail("finish");
        String told = report(f, true);
        LOGGER.info("[DovecotHome] DONE: every mailbox's Dovecot home in its own folder, " + DIR + "/, no more files of"
                + " Dovecot among the mail folders" + (running ? "; Dovecot reloaded" : "; Dovecot not running, it reads it at the start")
                + (verified == null ? "" : "; not checked with doveadm user, no mailbox answered (" + verified.substring(11) + ")")
                + (told.isEmpty() ? "" : "; " + told));
        return f.ok() ? null : "NOT_COMPLETE: " + told;
    }

    /** Le prime caselle sotto /var/vmail (dominio/nome), come indirizzi. */
    static List<String> candidates(Path root, int max) {
        List<String> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (Stream<Path> domains = Files.list(root)) {
            for (Path d : domains.sorted().toList()) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) continue;
                try (Stream<Path> users = Files.list(d)) {
                    for (Path u : users.sorted().toList()) {
                        String a = u.getFileName() + "@" + d.getFileName();
                        if (Files.isDirectory(u, LinkOption.NOFOLLOW_LINKS) && SafeNames.address(a)) out.add(a);
                        if (out.size() >= max) return out;
                    }
                }
            }
        } catch (IOException e) {
            return out;
        }
        return out;
    }

    /**
     * Dovecot da' la home nuova per una casella vera? Null se si'; «UNVERIFIED ...» se nessuna casella risponde (una
     * cartella rimasta di una casella tolta non e' un utente di Dovecot); altrimenti la home che da'. Riprova per una
     * decina di secondi: subito dopo il ricaricamento il processo di autenticazione puo' non rispondere ancora
     * («auth-master: userdb lookup: Disconnected unexpectedly», visto sulla VM).
     */
    static String verify() throws InterruptedException {
        List<String> mailboxes = candidates(vmail, 5);
        if (mailboxes.isEmpty()) return null;
        String said = "";
        for (int attempt = 0; attempt < 10; attempt++) {
            for (String mailbox : mailboxes) {
                String[] p = mailbox.split("@");
                String expected = of(p[1], p[0]).toString();
                Shell.Result home = Shell.run(Duration.ofSeconds(30), DOVEADM, "user", "-f", "home", "-u", mailbox);
                if (home.success())
                    return home.outputTrim().equals(expected) ? null
                            : "doveadm user -u " + mailbox + " gives the home " + first(home.outputTrim()) + ", not " + expected;
                said = mailbox + ": " + first(home.outputTrim());
            }
            Thread.sleep(1000);
        }
        return "UNVERIFIED " + said;
    }

    /** Cosa ha fatto il lavoro sui file, in una riga per il registro; e le iscrizioni alle cartelle fantasma tolte. */
    private static String report(Outcome f, boolean always) {
        List<String> moved = f.with("MOVED"), removed = f.with("PHANTOM_REMOVED"), kept = f.with("PHANTOM_KEPT"),
                both = f.with("BOTH_DIFFER"), failed = new ArrayList<>(f.with("FAILED"));
        failed.addAll(f.with("CONFLICT"));
        int unsubscribed = 0;
        for (String p : removed) unsubscribed += unsubscribe(Path.of(p).getParent());
        List<String> parts = new ArrayList<>();
        if (!moved.isEmpty()) parts.add(moved.size() + " file(s) of Dovecot moved into the homes");
        if (!f.with("CREATED").isEmpty()) parts.add(f.with("CREATED").size() + " home(s) created");
        if (!removed.isEmpty()) parts.add(removed.size() + " false mail folder(s) .dovecot.lda-dupes.locks removed"
                + (unsubscribed > 0 ? " (" + unsubscribed + " subscription(s) to them removed)" : ""));
        if (!kept.isEmpty()) parts.add("left because it holds mail: " + String.join(", ", head(kept)));
        if (!both.isEmpty()) parts.add("two different copies, both left: " + String.join(", ", head(both)));
        if (!failed.isEmpty()) parts.add("FAILED: " + String.join(", ", head(failed)));
        String told = String.join("; ", parts);
        if (!always && f.ok() && !told.isEmpty()) {
            // Ai riavvii dopo, una cartella con della posta o due script diversi restano: si ricordano, non si rifanno.
            boolean did = !moved.isEmpty() || !removed.isEmpty() || !f.with("CREATED").isEmpty();
            LOGGER.info("[DovecotHome] " + (did ? "DONE: " : "still as they were: ") + told);
        }
        return told;
    }

    /**
     * Le iscrizioni alle cartelle fantasma di una casella, che non esistono piu': si tolgono, perche' la webmail non le
     * mostri vuote. Una cartella vera con lo stesso nome (qualcuno l'ha creata) resta iscritta. Quante ne ha tolte.
     */
    static int unsubscribe(Path mailboxDir) {
        if (mailboxDir == null || mailboxDir.getParent() == null) return 0;
        String address = mailboxDir.getFileName() + "@" + mailboxDir.getParent().getFileName();
        if (!SafeNames.address(address)) return 0;
        Shell.Result subscribed = Shell.run(Duration.ofSeconds(30), DOVEADM, "mailbox", "list", "-s", "-u", address);
        Shell.Result existing = Shell.run(Duration.ofSeconds(30), DOVEADM, "mailbox", "list", "-u", address);
        if (!subscribed.success() || !existing.success()) return 0;
        Set<String> s = new HashSet<>(List.of(subscribed.outputTrim().split("\n")));
        Set<String> e = new HashSet<>(List.of(existing.outputTrim().split("\n")));
        int n = 0;
        for (String name : PHANTOMS)
            if (s.contains(name) && !e.contains(name)
                    && Shell.run(Duration.ofSeconds(30), DOVEADM, "mailbox", "unsubscribe", "-u", address, name).success()) n++;
        return n;
    }

    private static String putBack(String before, String why) throws IOException {
        Files.writeString(authSql, before, StandardCharsets.UTF_8);
        if (Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success())
            Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        asVmail("undo");
        return "ROLLED_BACK: " + why + "; " + authSql + " put back as it was, the copies in the homes removed";
    }

    private static List<String> head(List<String> l) {
        return l.size() <= 5 ? l : l.subList(0, 5);
    }

    private static String first(String s) {
        int i = s.indexOf('\n');
        String t = i < 0 ? s : s.substring(0, i);
        return t.length() > 200 ? t.substring(0, 200) : t;
    }
}
