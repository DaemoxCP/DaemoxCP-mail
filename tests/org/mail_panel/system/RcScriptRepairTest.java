package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.function.Function;

/**
 * RcScriptRepair: lo script di avvio scritto dal pannello, coi file dai nomi di prima, in una
 * cartella temporanea. Lo script e' quello vero del server di posta del committente (letto il
 * 31/10/2026, scritto dalla versione dell'11/10), con la firma e il log presi dal codice e dal file
 * di dati invece che scritti qui. sh -n e' quello vero: c'e' su macOS e su FreeBSD.
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RcScriptRepairTest
 */
public class RcScriptRepairTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }

    static final String NEW_LOG = "/var/db/mailpanel/panel.log";
    static final String OLD_LOG = LegacyNames.oldNamesOf("files", NEW_LOG).get(0);

    /**
     * Lo script del server, con @LOG@ al posto del percorso del log e @MARKER@ al posto della firma.
     * Segnaposto che nello script non compaiono: «LOG» c'e' anche in «REQUIRE: LOGIN».
     */
    static final String SERVER_SCRIPT = """
            #!/bin/sh
            #
            # PROVIDE: mailpanel
            # REQUIRE: LOGIN
            # KEYWORD: shutdown
            #
            # @MARKER@. Avvia il pannello in
            # modalita' solo-web (--web): niente menu a schermo, nessun terminale richiesto.
            # Per riavere il menu: service mailpanel stop, poi lancialo a mano senza --web.
            #
            # Abilitazione:  sysrc mailpanel_enable=YES

            . /etc/rc.subr

            name=mailpanel
            rcvar=mailpanel_enable

            load_rc_config $name

            : ${mailpanel_enable:="NO"}
            : ${mailpanel_dir:="/home/panel"}
            : ${mailpanel_java:="/usr/local/openjdk25/bin/java"}
            : ${mailpanel_jar:="/home/panel/freebsd-mail-panel-1.0.jar"}
            : ${mailpanel_opts:=""}
            : ${mailpanel_log:="@LOG@"}

            pidfile="/var/run/${name}.pid"
            procname="${mailpanel_java}"

            start_cmd="${name}_start"
            stop_postcmd="${name}_poststop"

            mailpanel_start()
            {
            	if [ -f "${pidfile}" ] && kill -0 "$(cat "${pidfile}")" 2>/dev/null; then
            		echo "${name}: gia' in esecuzione (pid $(cat ${pidfile}))"
            		return 1
            	fi
            	mkdir -p "$(dirname "${mailpanel_log}")"
            	if [ -f "${mailpanel_log}" ] && [ $(stat -f %z "${mailpanel_log}") -gt 10485760 ]; then
            		mv "${mailpanel_log}" "${mailpanel_log}.1"
            	fi
            	echo "Avvio ${name} (solo web). Registro: ${mailpanel_log}"
            	/usr/sbin/daemon -f -o "${mailpanel_log}" -p "${pidfile}" -t "${name}" \\
            		/bin/sh -c "cd '${mailpanel_dir}' && exec '${mailpanel_java}' ${mailpanel_opts} -jar '${mailpanel_jar}' --web"
            }

            mailpanel_poststop()
            {
            	rm -f "${pidfile}"
            }

            run_rc_command "$1"
            """;

    static String script(String log, boolean ours) {
        return SERVER_SCRIPT.replace("@MARKER@", ours ? RcScriptRepair.MARKER : "Scritto a mano").replace("@LOG@", log);
    }

    static final Function<Path, Shell.Result> SH_N = f -> Shell.run(java.time.Duration.ofSeconds(30), "sh", "-n", f.toString());

    static int checks;

    static final Function<Path, Shell.Result> COUNTING_SH_N = f -> { checks++; return SH_N.apply(f); };

    public static void main(String[] args) throws Exception {
        List<String[]> pairs = LegacyNames.pairs("files");
        check("il file di dati da' un nome di prima per il log (" + OLD_LOG + ")", !OLD_LOG.equals(NEW_LOG) && OLD_LOG.endsWith(".log"));
        check("lo script del server passa sh -n, com'e'", SH_N.apply(write(script(OLD_LOG, true))).success());

        System.out.println("\n== Lo script del server ==");
        Path dir = Files.createTempDirectory("rc-script-repair");
        Path rc = dir.resolve("mailpanel");
        Files.writeString(rc, script(OLD_LOG, true));
        Files.setPosixFilePermissions(rc, PosixFilePermissions.fromString("r-xr-xr-x"));
        RcScriptRepair.Report r = RcScriptRepair.repair(rc, pairs, SH_N);
        System.out.println("        -> " + r.outcome() + ": " + r.detail());
        check("riparato: DONE", r.outcome() == RcScriptRepair.Outcome.DONE);
        check("  il log adesso ha il nome nuovo, e nient'altro e' cambiato",
                Files.readString(rc).equals(script(NEW_LOG, true)));
        check("  coi permessi di prima (r-xr-xr-x)",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(rc)).equals("r-xr-xr-x"));
        check("  e nessun file accanto", List.of(dir.toFile().list()).equals(List.of("mailpanel")));
        check("  e lo script riparato passa sh -n", SH_N.apply(rc).success());

        System.out.println("\n== Il secondo avvio ==");
        checks = 0;
        r = RcScriptRepair.repair(rc, pairs, COUNTING_SH_N);
        check("niente da fare, senza nemmeno sh -n", r.outcome() == RcScriptRepair.Outcome.NOTHING && checks == 0
                && Files.readString(rc).equals(script(NEW_LOG, true)));

        System.out.println("\n== Cose che non si toccano ==");
        Path theirs = dir.resolve("theirs");
        Files.writeString(theirs, script(OLD_LOG, false));
        r = RcScriptRepair.repair(theirs, pairs, SH_N);
        check("uno script col nome vecchio ma senza la firma del pannello: NOT_OURS, com'era",
                r.outcome() == RcScriptRepair.Outcome.NOT_OURS && Files.readString(theirs).equals(script(OLD_LOG, false)));

        Path broken = dir.resolve("broken");
        String brokenText = script(OLD_LOG, true).replace("run_rc_command \"$1\"", "run_rc_command \"$1");
        Files.writeString(broken, brokenText);
        r = RcScriptRepair.repair(broken, pairs, SH_N);
        check("uno script che sh -n rifiuta: REFUSED, com'era, e nessun file accanto",
                r.outcome() == RcScriptRepair.Outcome.REFUSED && Files.readString(broken).equals(brokenText)
                        && !Files.exists(dir.resolve(".broken.panel-new")));

        Path longer = dir.resolve("longer");
        String longerText = script(OLD_LOG + "s", true);
        Files.writeString(longer, longerText);
        r = RcScriptRepair.repair(longer, pairs, SH_N);
        check("un percorso che comincia col nome vecchio ma e' un altro file: NOTHING",
                r.outcome() == RcScriptRepair.Outcome.NOTHING && Files.readString(longer).equals(longerText));

        Path mixed = dir.resolve("mixed");
        String extra = "# " + OLD_LOG + "s: un altro file, non il log\n";
        Files.writeString(mixed, script(OLD_LOG, true) + extra);
        r = RcScriptRepair.repair(mixed, pairs, SH_N);
        check("col log e un percorso piu' lungo che comincia uguale: cambia solo il log",
                r.outcome() == RcScriptRepair.Outcome.DONE && Files.readString(mixed).equals(script(NEW_LOG, true) + extra));

        r = RcScriptRepair.repair(dir.resolve("missing"), pairs, SH_N);
        check("nessuno script: NOTHING", r.outcome() == RcScriptRepair.Outcome.NOTHING);

        System.out.println("\n== Lo script che scrive il pannello oggi ==");
        check("ha la firma che RcScriptRepair riconosce, e il log col nome nuovo",
                Files.readString(Path.of("src/main/java/org/mail_panel/system/UpdateManager.java"))
                        .contains("+ \"# \" + RcScriptRepair.MARKER + \". Avvia il pannello in\\n\""));

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    static Path write(String text) throws Exception {
        Path f = Files.createTempFile("rc-script", "");
        Files.writeString(f, text);
        return f;
    }
}
