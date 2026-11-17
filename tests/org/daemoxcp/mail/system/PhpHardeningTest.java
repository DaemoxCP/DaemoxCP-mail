package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * php.ini written when it is missing, and security.limit_extensions = .php in the panel's Roundcube pool (reperto 238).
 * Against a fake php-fpm that, after a reload, sends X-Powered-By unless a php.ini is there, and a fake webmail:
 *  1. the installer writes PhpHardening.INI, which turns off expose_php, display_errors and session upload progress;
 *     the pool the panel writes has the limit;
 *  2. no php.ini (the real server): DONE, the file, the sessions folder and the log prepared, the rotation, X-Powered-By
 *     gone; a pool without the limit: the line added; the second run does nothing;
 *  3. what does not start: a php.ini already there and the pool with the limit or not the panel's; no webmail site; the
 *     webmail not answering;
 *  4. a fault (php-fpm -t refusing, the webmail not answering after the reload, php-fpm not reading the file, a file
 *     not writable): php.ini gone, the rotation gone, the pool as before.
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PhpHardeningTest
 */
public class PhpHardeningTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path INI = Path.of("/fake/php.ini");
    static final Path POOL = Path.of("/fake/php-fpm.d/roundcube.conf");
    static final Path ROT = Path.of("/fake/newsyslog.conf.d/php-errors.conf");
    static final String OLD_POOL = "; " + PanelMarker.WRITTEN + "\n[roundcube]\nuser = roundcube\ngroup = roundcube\n"
            + "listen = /var/run/php-fpm-roundcube.sock\nlisten.mode = 0660\npm = dynamic\npm.max_children = 10\n";

    static class Machine implements PhpHardening.Services {
        final Map<Path, String> files = new HashMap<>();
        boolean iniLoaded = false, up = true, prepared = false;
        String fault;   // "fpm-test", "down-after", "not-read", "write"
        int reloads = 0;

        @Override public String read(Path f) { return files.get(f); }
        @Override public void create(Path f, String t) throws IOException {
            if ("write".equals(fault) && f.equals(INI)) throw new IOException("read-only");
            files.put(f, t);
        }
        @Override public void write(Path f, String t) throws IOException {
            if ("write".equals(fault)) throw new IOException("read-only");
            files.put(f, t);
        }
        @Override public void delete(Path f) { files.remove(f); }
        @Override public void prepare() { prepared = true; }
        @Override public boolean fpmTest() { return !"fpm-test".equals(fault); }
        @Override public void fpmReload() {
            reloads++;
            iniLoaded = files.containsKey(INI) && !"not-read".equals(fault);
            up = !"down-after".equals(fault);
        }
        @Override public List<PhpHardening.Site> sites() { return List.of(new PhpHardening.Site("webmail.example.test", "8443")); }
        @Override public String webmail(PhpHardening.Site s) {
            if (!up) return null;
            return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + (iniLoaded ? "" : "X-Powered-By: PHP/8.4.27\r\n")
                    + "\r\n<input name=\"_user\" id=\"rcmloginuser\">";
        }
        @Override public void pause() { }
    }

    static PhpHardening.Result run(Machine m) { return PhpHardening.run(m, INI, POOL, ROT, 2); }

    static Machine production() {
        Machine m = new Machine();
        m.files.put(POOL, OLD_POOL);
        return m;
    }

    public static void main(String[] args) {
        System.out.println("== 1. What the installer writes");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("php.ini is PhpHardening.INI", installer.contains("<< 'PHPINIEOF'\n" + PhpHardening.INI + "PHPINIEOF\n"));
        for (String line : new String[]{"expose_php = Off", "display_errors = Off", "session.upload_progress.enabled = Off",
                "session.save_path = \"/var/db/mailpanel/php_sessions\"", "allow_url_include = Off", "date.timezone = UTC"})
            check("  " + line, PhpHardening.INI.contains("\n" + line + "\n"));
        check("the panel's pool has security.limit_extensions = .php", RoundcubeUser.poolConf(null).contains("\n" + PhpHardening.LIMIT)
                && PhpHardening.hasLimit(RoundcubeUser.poolConf(null)));
        check("the installer's pool too", installer.contains(PhpHardening.LIMIT));

        System.out.println("\n== 2. The real server: no php.ini, the pool without the limit");
        Machine m = production();
        m.fpmReload();
        check("before: X-Powered-By in the webmail's answer", PhpHardening.poweredBy(m.webmail(null)));
        PhpHardening.Result r = run(m);
        check("DONE (" + r.detail() + ")", r.outcome() == PhpHardening.Outcome.DONE);
        check("  php.ini is INI, the sessions folder and the log prepared", PhpHardening.INI.equals(m.files.get(INI)) && m.prepared);
        check("  the rotation of the log, with its owner", m.files.get(ROT) != null && m.files.get(ROT).contains(RoundcubeUser.phpErrorsRotationLine()));
        check("  the pool: as before plus the limit", m.files.get(POOL).equals(PhpHardening.withLimit(OLD_POOL)) && PhpHardening.hasLimit(m.files.get(POOL)));
        check("  X-Powered-By gone", !PhpHardening.poweredBy(m.webmail(null)));
        int reloads = m.reloads;
        check("  a second run: NOTHING, no reload", run(m).outcome() == PhpHardening.Outcome.NOTHING && m.reloads == reloads);
        Machine poolOnly = production();
        poolOnly.files.put(INI, "[PHP]\nexpose_php = Off\n");
        poolOnly.fpmReload();
        r = run(poolOnly);
        check("php.ini there, the pool without the limit: DONE, php.ini untouched", r.outcome() == PhpHardening.Outcome.DONE
                && poolOnly.files.get(INI).equals("[PHP]\nexpose_php = Off\n") && PhpHardening.hasLimit(poolOnly.files.get(POOL))
                && !poolOnly.files.containsKey(ROT));
        Machine rotThere = production();
        rotThere.files.put(ROT, "# mine\n");
        run(rotThere);
        check("a rotation already there: untouched", rotThere.files.get(ROT).equals("# mine\n"));

        System.out.println("\n== 3. What does not start");
        Machine fine = new Machine();
        fine.files.put(INI, PhpHardening.INI);
        fine.files.put(POOL, RoundcubeUser.poolConf(null));
        check("php.ini there and the pool with the limit: NOTHING", run(fine).outcome() == PhpHardening.Outcome.NOTHING && fine.reloads == 0);
        Machine notOurs = new Machine();
        notOurs.files.put(INI, PhpHardening.INI);
        notOurs.files.put(POOL, "[roundcube]\nuser = roundcube\n");
        check("a pool the panel did not write: NOTHING, untouched", run(notOurs).outcome() == PhpHardening.Outcome.NOTHING
                && notOurs.files.get(POOL).equals("[roundcube]\nuser = roundcube\n"));
        Machine noSite = new Machine() {
            @Override public List<PhpHardening.Site> sites() { return List.of(); }
        };
        noSite.files.put(POOL, OLD_POOL);
        r = run(noSite);
        check("no webmail site: LEFT, nothing written", r.outcome() == PhpHardening.Outcome.LEFT && !noSite.files.containsKey(INI));
        Machine down = production();
        down.up = false;
        r = run(down);
        check("the webmail not answering now: LEFT, nothing written", r.outcome() == PhpHardening.Outcome.LEFT && !down.files.containsKey(INI)
                && down.files.get(POOL).equals(OLD_POOL));

        System.out.println("\n== 4. A fault: everything back");
        for (String fault : new String[]{"fpm-test", "down-after", "not-read", "write"}) {
            Machine x = production();
            x.fpmReload();
            x.fault = fault;
            r = run(x);
            check(fault + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == PhpHardening.Outcome.ROLLED_BACK);
            check("  no php.ini, no rotation, the pool as before", !x.files.containsKey(INI) && !x.files.containsKey(ROT)
                    && x.files.get(POOL).equals(OLD_POOL));
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
