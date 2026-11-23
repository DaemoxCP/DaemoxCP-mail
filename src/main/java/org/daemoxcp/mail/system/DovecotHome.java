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
 * Dovecot's home of each mailbox in /var/vmail/domain/name/home, no longer the mail root (finding 217).
 *
 * The mail is in the root of the mailbox (mail_location = maildir:/var/vmail/%d/%n) and the home was the same
 * folder. Dovecot writes its own files in the home: the memory of automatic replies and forwards
 * (.dovecot.lda-dupes, with the lock folder .dovecot.lda-dupes.locks), and since finding 214 the user's Sieve
 * scripts (sieve/, dovecot.sieve). Maildir++ takes as a mail folder everything that starts with a dot: measured on
 * the VM on 2026-11-10, after a single automatic reply IMAP LIST gave "dovecot", "dovecot.lda-dupes" and
 * "dovecot.lda-dupes.locks", selectable, and the webmail showed them; opening it turned it into a real Maildir
 * (cur, new, tmp). The Dovecot documentation (2.3 and 2.4, "Home directories for virtual users"): the home must not
 * be the mail folder with Maildir, "Non-mailbox files may show up as mailboxes"; among the allowed layouts there is
 * the home under the mail, "home=/var/vmail/domain/user/home/, mail=/var/vmail/domain/user/". This is the one: the
 * mail does not move, only Dovecot's files move. maildir_stat_dirs = yes is not enough: .dovecot.lda-dupes.locks
 * is a folder.
 *
 * Here, on servers installed earlier: only the home path in conf.d/auth-sql.conf.ext is changed, if it is the one
 * the panel used to write (2.3 or 2.4), and the files Dovecot had put in the root are brought into the home. The
 * files are moved by vmail, not by root: it is its folder, and root inside another user's folder would follow that
 * user's links. Order: first they are copied into the home (with the previous configuration Dovecot still uses the
 * originals), then the new configuration, doveconf, the reload and the check with doveadm user; if a single thing
 * does not add up, the configuration goes back to how it was and the copies are removed. Afterwards the originals
 * are removed from the root, and so is the ghost folder .dovecot.lda-dupes.locks if it contains no mail; if it does
 * (someone moved messages into it) it stays, and the log says so. If the root and the home hold two different user
 * scripts, no choice is made: both stay. At the second startup it finds nothing to do.
 */
public final class DovecotHome {

    private static final Logger LOGGER = Logger.getLogger(DovecotHome.class.getName());

    static Path authSql = Path.of("/usr/local/etc/dovecot/conf.d/auth-sql.conf.ext");
    static Path vmail = Path.of("/var/vmail");
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** The home folder inside the mailbox folder. */
    public static final String DIR = "home";

    /**
     * The 2.3 home as the panel used to write it (args of the static userdb), followed by a space or the end
     * of the line.
     */
    static final Pattern OLD23 = Pattern.compile("(?m)(\\bhome=/var/vmail/%d/%n)(?=[ \\t]|$)");
    static final String NEW23 = "home=/var/vmail/%d/%n/" + DIR;

    /** The 2.4 home as the panel used to write it (fields of the static userdb), alone on its line. */
    static final Pattern OLD24 = Pattern.compile("(?m)^([ \\t]*home = /var/vmail/%\\{user \\| domain\\}/%\\{user \\| username\\})[ \\t]*$");
    static final String NEW24 = "home = /var/vmail/%{user | domain}/%{user | username}/" + DIR;

    /** The ghost folders that Maildir++ derived from Dovecot's files in the root: the deepest one and its parents. */
    static final List<String> PHANTOMS = List.of("dovecot.lda-dupes.locks", "dovecot.lda-dupes", "dovecot");

    /**
     * The job on the files, run as vmail: $1 the phase, $2 the root (/var/vmail). Every line it writes is a word
     * in upper case and a path. Dovecot's things (the duplicates memory, the compiled script, the scripts' log)
     * keep the most recent one if they differ; the user's things (the scripts) both stay if they differ.
     *  prepare: creates the home and copies into it what is in the root (the originals stay, for the previous
     *           configuration);
     *  undo:    removes from the home the copies identical to the originals, and the home if it is left empty;
     *  finish:  creates the home in the mailboxes that already have mail, moves into it what is left in the root,
     *           and removes the ghost lock folder if it contains no mail.
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

    /** Dovecot's home of a mailbox: /var/vmail/domain/name/home. */
    public static Path of(String domain, String user) {
        return SafeNames.under(vmail, domain, user, DIR);
    }

    /**
     * conf.d/auth-sql.conf.ext with the new home, or null if there is nothing to change: already done, or the
     * home is not, exactly once, the one the panel used to write (then it is not the panel's, and it stays as it
     * is). A pure function.
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
     * The server already uses the home in its own folder: for whoever creates a new mailbox
     * (ConfigRegeneratorScript), which in this way creates it right away instead of waiting for the panel's
     * next startup.
     */
    public static boolean configured() {
        try {
            return Files.isRegularFile(authSql, LinkOption.NOFOLLOW_LINKS) && usesHome(Files.readString(authSql, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** The configuration already puts the home in its own folder (2.3 or 2.4). */
    static boolean usesHome(String conf) {
        return conf != null && (conf.contains(NEW23) || conf.contains(NEW24));
    }

    /** The lines of the job on the files, and whether everything went well. */
    record Outcome(boolean ok, List<String> lines) {
        List<String> with(String word) {
            List<String> out = new ArrayList<>();
            for (String l : lines) if (l.startsWith(word + " ")) out.add(l.substring(word.length() + 1));
            return out;
        }
    }

    /** The job on the files, as vmail. */
    static Outcome asVmail(String phase) {
        Shell.Result r = Shell.run(Duration.ofSeconds(600), "su", "-m", "vmail", "-c", SCRIPT, "sh", phase, vmail.toString());
        return new Outcome(r.success(), r.outputTrim().isEmpty() ? List.of() : List.of(r.outputTrim().split("\n")));
    }

    /**
     * When the panel writes a mailbox's rules (automatic reply, forwarding): its home, as vmail, if the
     * configuration wants it in its own folder. Without it, Dovecot creates it by itself at the first automatic
     * reply, but first it writes in the mail log "Error: duplicate db: ...
     * file_dotlock_open(.../home/.dovecot.lda-dupes) failed: No such file or directory" (measured on the VM).
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

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            String problem = ensure();
            if (problem != null) LOGGER.warning("[DovecotHome] " + problem);
        } catch (Throwable t) {
            LOGGER.warning("[DovecotHome] failed: " + t);
        }
    }

    /** Null if there was nothing to do or if it is done; otherwise what was left as it was, and why. */
    static synchronized String ensure() throws Exception {
        if (!Files.isRegularFile(authSql, LinkOption.NOFOLLOW_LINKS) || !Files.isExecutable(Path.of(DOVECONF))
                || !Files.isDirectory(vmail, LinkOption.NOFOLLOW_LINKS)) return null;
        String current = Files.readString(authSql, StandardCharsets.UTF_8);
        String next = migrated(current);
        if (next == null) {
            // Already done (or the panel rewrote the configuration with the new template): what remains is to bring
            // into the home the files left in the root, if there are any.
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
            // The earlier processes finish the delivery they have in hand with the previous configuration.
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

    /** The first mailboxes under /var/vmail (domain/name), as addresses. */
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
     * Does Dovecot give the new home for a real mailbox? Null if yes; "UNVERIFIED ..." if no mailbox answers (a
     * leftover folder of a removed mailbox is not a Dovecot user); otherwise the home it gives. Retries for about
     * ten seconds: right after the reload the authentication process may not answer yet
     * ("auth-master: userdb lookup: Disconnected unexpectedly", seen on the VM).
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

    /** What the job on the files did, in one line for the log; and the removed subscriptions to ghost folders. */
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
            // At later restarts, a folder with mail or two different scripts stay: they are remembered, not redone.
            boolean did = !moved.isEmpty() || !removed.isEmpty() || !f.with("CREATED").isEmpty();
            LOGGER.info("[DovecotHome] " + (did ? "DONE: " : "still as they were: ") + told);
        }
        return told;
    }

    /**
     * A mailbox's subscriptions to the ghost folders, which no longer exist: they are removed, so that the
     * webmail does not show them empty. A real folder with the same name (someone created it) stays subscribed.
     * How many it removed.
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
