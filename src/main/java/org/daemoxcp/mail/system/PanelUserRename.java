package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * All'avvio del servizio: gli utenti di sistema del pannello prendono il nome nuovo (DaemoxCP Mail, 17/11/2026).
 *
 * <p>L'utente e il gruppo della parte web, mailpanel, diventano daemoxcp_mail; il commento suo e quello di sievec
 * dicono il nome nuovo. Si rinominano con pw, che tiene uid e gid: i file della parte web (i segreti che legge, il
 * database SQLite, le pagine, il socket) restano suoi senza toccarne nessuno, perche' il sistema li conosce per
 * numero. PanelUser controlla il commento parola per parola: senza questo passaggio l'utente di prima non sarebbe
 * piu' "del pannello", e la parte web non partirebbe.
 *
 * <p>Si rinomina solo l'utente che il pannello ha creato: nome, commento di prima, gruppo suo, nessun altro membro
 * (PanelUser.problem). Se esiste gia' un utente col nome nuovo, o quello vecchio non e' del pannello, non si tocca
 * niente e lo si dice. Dopo la rinomina si controlla che il nome nuovo abbia lo stesso uid e lo stesso gid di prima,
 * e che nessun gruppo lo citi ancora col nome vecchio; se non torna, si rimette il nome di prima.
 *
 * <p>I nomi e i commenti di prima stanno in legacy-names.json (sezioni "unixUsers" e "unixUserComments").
 */
public final class PanelUserRename {

    private static final Logger LOGGER = Logger.getLogger(PanelUserRename.class.getName());
    private static final Duration T = Duration.ofSeconds(20);

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** pw e i file del sistema, separati per provarli senza toccare gli utenti veri. */
    interface Services {
        /** La riga di pw usershow (formato di master.passwd), o null se l'utente non c'e'. */
        String user(String name);
        /** La riga di pw groupshow (nome:password:gid:membri), o null se il gruppo non c'e'. */
        String group(String name);
        /** Esegue pw con questi argomenti: null se e' andato, altrimenti cosa dice. */
        String pw(String... args);
        /** Le righe di /etc/group. */
        List<String> groups();
        /** La cartella dei crontab degli utenti. */
        Path cronTabs();
    }

    private PanelUserRename() {}

    public static void ensureAtBoot() {
        Services sv = new RealServices();
        for (String[] p : LegacyNames.pairs("unixUsers")) report(rename(p[0], p[1], PanelSeparation.GECOS, sv));
        // Il commento di sievec: l'utente non cambia nome, solo il commento con cui il pannello lo riconosce.
        report(recomment(SieveCompiler.USER, SieveCompiler.COMPILER_USER.gecos(), sv));
    }

    private static void report(Report r) {
        if (r.outcome() == Outcome.NOTHING) return;
        String line = "[PanelUserRename] " + r.outcome() + ": " + r.detail();
        if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
    }

    /** I commenti di prima che oggi sono {@code gecos}. */
    static List<String> oldComments(String gecos) {
        return LegacyNames.oldNamesOf("unixUserComments", gecos);
    }

    static Report rename(String oldName, String newName, String gecos, Services sv) {
        String oldUser = sv.user(oldName);
        if (oldUser == null) return new Report(Outcome.NOTHING, "");
        if (sv.user(newName) != null)
            return new Report(Outcome.LEFT, "both the users " + oldName + " and " + newName + " exist: " + oldName + " left as it is");
        String oldGroup = sv.group(oldName);
        if (oldGroup == null) return new Report(Outcome.LEFT, "the user " + oldName + " has no group of its own: left as it is");
        String[] u = oldUser.split(":", -1);
        if (u.length < 10) return new Report(Outcome.LEFT, "the user " + oldName + " cannot be read");
        // Del pannello: com'era il giorno in cui l'ha creato (il commento di prima o gia' quello di adesso).
        String why = null;
        for (String c : with(oldComments(gecos), gecos)) {
            why = new PanelUser(oldName, c).problem(oldUser, oldGroup);
            if (why == null) break;
        }
        if (why != null) return new Report(Outcome.LEFT, why + ": not renamed");
        if (sv.group(newName) != null)
            return new Report(Outcome.LEFT, "the group " + newName + " already exists: " + oldName + " left as it is");
        String uid = u[2], gid = u[3];

        String problem = sv.pw("groupmod", oldName, "-l", newName);
        if (problem != null) return new Report(Outcome.LEFT, "pw groupmod: " + problem + ": nothing changed");
        problem = sv.pw("usermod", oldName, "-l", newName, "-c", gecos);
        if (problem != null) {
            sv.pw("groupmod", newName, "-l", oldName);
            return new Report(Outcome.ROLLED_BACK, "pw usermod: " + problem + "; the group got its name back");
        }

        // Il controllo: stesso uid, stesso gid, il gruppo suo, e nessun gruppo che lo cita col nome di prima.
        String after = sv.user(newName), afterGroup = sv.group(newName);
        String[] a = after == null ? new String[0] : after.split(":", -1);
        String[] g = afterGroup == null ? new String[0] : afterGroup.split(":", -1);
        String wrong = null;
        if (a.length < 10 || !uid.equals(a[2]) || !gid.equals(a[3])) wrong = "the renamed user has another uid or gid";
        else if (g.length < 4 || !gid.equals(g[2])) wrong = "the renamed group has another gid";
        else if (new PanelUser(newName, gecos).problem(after, afterGroup) != null)
            wrong = new PanelUser(newName, gecos).problem(after, afterGroup);
        if (wrong == null) {
            for (String line : sv.groups()) {
                String[] f = line.split(":", -1);
                if (f.length < 4 || f[3].isEmpty()) continue;
                for (String m : f[3].split(",")) {
                    if (!m.equals(oldName)) continue;
                    // Un gruppo che cita ancora il nome di prima: lo si porta al nome nuovo.
                    String p = sv.pw("groupmod", f[0], "-d", oldName, "-m", newName);
                    if (p != null) wrong = "the group " + f[0] + " still names " + oldName + ": " + p;
                }
            }
        }
        if (wrong != null) {
            sv.pw("usermod", newName, "-l", oldName, "-c", u[7]);
            sv.pw("groupmod", newName, "-l", oldName);
            return new Report(Outcome.ROLLED_BACK, wrong + "; the old names put back");
        }

        // Il crontab dell'utente, se ne ha uno: cron lo cerca col nome.
        String cron = "";
        Path oldTab = sv.cronTabs().resolve(oldName), newTab = sv.cronTabs().resolve(newName);
        try {
            if (Files.exists(oldTab, LinkOption.NOFOLLOW_LINKS) && !Files.exists(newTab, LinkOption.NOFOLLOW_LINKS)) {
                Files.move(oldTab, newTab, StandardCopyOption.ATOMIC_MOVE);
                cron = ", its crontab moved";
            }
        } catch (IOException e) {
            cron = ", its crontab NOT moved (" + e.getMessage() + ")";
        }
        return new Report(Outcome.DONE, "the user and group " + oldName + " are now " + newName + " (uid " + uid
                + ", gid " + gid + ", comment '" + gecos + "')" + cron);
    }

    /** Il commento di un utente del pannello che non cambia nome: se e' uno di prima, diventa quello di adesso. */
    static Report recomment(String name, String gecos, Services sv) {
        String line = sv.user(name);
        if (line == null) return new Report(Outcome.NOTHING, "");
        String[] u = line.split(":", -1);
        if (u.length < 10 || gecos.equals(u[7]) || !oldComments(gecos).contains(u[7])) return new Report(Outcome.NOTHING, "");
        String group = sv.group(name);
        if (group == null || new PanelUser(name, u[7]).problem(line, group) != null)
            return new Report(Outcome.LEFT, "the user " + name + " is not the panel's: comment left as it is");
        String p = sv.pw("usermod", name, "-c", gecos);
        return p == null ? new Report(Outcome.DONE, "the comment of " + name + " is now '" + gecos + "'")
                         : new Report(Outcome.LEFT, "pw usermod " + name + ": " + p);
    }

    private static List<String> with(List<String> list, String last) {
        List<String> out = new ArrayList<>(list);
        out.add(last);
        return out;
    }

    static final class RealServices implements Services {
        @Override public String user(String name) {
            Shell.Result r = Shell.run(T, "pw", "usershow", name);
            return r.success() ? r.outputTrim() : null;
        }
        @Override public String group(String name) {
            Shell.Result r = Shell.run(T, "pw", "groupshow", name);
            return r.success() ? r.outputTrim() : null;
        }
        @Override public String pw(String... args) {
            String[] cmd = new String[args.length + 1];
            cmd[0] = "pw";
            System.arraycopy(args, 0, cmd, 1, args.length);
            Shell.Result r = Shell.run(T, cmd);
            return r.success() ? null : r.outputTrim();
        }
        @Override public List<String> groups() {
            try {
                return Files.readAllLines(Path.of("/etc/group"));
            } catch (IOException e) {
                return List.of();
            }
        }
        @Override public Path cronTabs() { return Path.of("/var/cron/tabs"); }
    }
}
