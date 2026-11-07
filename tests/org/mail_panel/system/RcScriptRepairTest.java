package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.function.Function;

/**
 * RcScriptRepair: the start script written by the panel, with the files under their old names, in a
 * temporary folder. The script is the real one of the committente's mail server (read on
 * 31/10/2026, written by the 11/10 version, its comments put into English here), with the signature
 * and the log taken from the code and from the data file instead of written here. sh -n is the real
 * one: it is on macOS and on FreeBSD.
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
     * The server's script, with @LOG@ in place of the log path and @MARKER@ in place of the signature.
     * Placeholders that do not appear in the script: "LOG" is also in "REQUIRE: LOGIN".
     */
    static final String SERVER_SCRIPT = """
            #!/bin/sh
            #
            # PROVIDE: mailpanel
            # REQUIRE: LOGIN
            # KEYWORD: shutdown
            #
            # @MARKER@. Starts the panel in
            # web-only mode (--web): no on-screen menu, no terminal needed.
            # To get the menu back: service mailpanel stop, then start it by hand without --web.
            #
            # Enabling:  sysrc mailpanel_enable=YES

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
            		echo "${name}: already running (pid $(cat ${pidfile}))"
            		return 1
            	fi
            	mkdir -p "$(dirname "${mailpanel_log}")"
            	if [ -f "${mailpanel_log}" ] && [ $(stat -f %z "${mailpanel_log}") -gt 10485760 ]; then
            		mv "${mailpanel_log}" "${mailpanel_log}.1"
            	fi
            	echo "Starting ${name} (web only). Log: ${mailpanel_log}"
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
        return SERVER_SCRIPT.replace("@MARKER@", ours ? RcScriptRepair.MARKER : "Written by hand").replace("@LOG@", log);
    }

    static final Function<Path, Shell.Result> SH_N = f -> Shell.run(java.time.Duration.ofSeconds(30), "sh", "-n", f.toString());

    static int checks;

    static final Function<Path, Shell.Result> COUNTING_SH_N = f -> { checks++; return SH_N.apply(f); };

    public static void main(String[] args) throws Exception {
        List<String[]> pairs = LegacyNames.pairs("files");
        check("the data file gives an old name for the log (" + OLD_LOG + ")", !OLD_LOG.equals(NEW_LOG) && OLD_LOG.endsWith(".log"));
        check("the server's script passes sh -n, as it is", SH_N.apply(write(script(OLD_LOG, true))).success());

        System.out.println("\n== The server's script ==");
        Path dir = Files.createTempDirectory("rc-script-repair");
        Path rc = dir.resolve("mailpanel");
        Files.writeString(rc, script(OLD_LOG, true));
        Files.setPosixFilePermissions(rc, PosixFilePermissions.fromString("r-xr-xr-x"));
        RcScriptRepair.Report r = RcScriptRepair.repair(rc, pairs, SH_N);
        System.out.println("        -> " + r.outcome() + ": " + r.detail());
        check("repaired: DONE", r.outcome() == RcScriptRepair.Outcome.DONE);
        check("  the log now has the new name, and nothing else changed",
                Files.readString(rc).equals(script(NEW_LOG, true)));
        check("  with the old permissions (r-xr-xr-x)",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(rc)).equals("r-xr-xr-x"));
        check("  and no file next to it", List.of(dir.toFile().list()).equals(List.of("mailpanel")));
        check("  and the repaired script passes sh -n", SH_N.apply(rc).success());

        System.out.println("\n== The second start ==");
        checks = 0;
        r = RcScriptRepair.repair(rc, pairs, COUNTING_SH_N);
        check("nothing to do, not even sh -n", r.outcome() == RcScriptRepair.Outcome.NOTHING && checks == 0
                && Files.readString(rc).equals(script(NEW_LOG, true)));

        System.out.println("\n== Things that are not touched ==");
        Path theirs = dir.resolve("theirs");
        Files.writeString(theirs, script(OLD_LOG, false));
        r = RcScriptRepair.repair(theirs, pairs, SH_N);
        check("a script with the old name but without the panel's signature: NOT_OURS, as it was",
                r.outcome() == RcScriptRepair.Outcome.NOT_OURS && Files.readString(theirs).equals(script(OLD_LOG, false)));

        Path broken = dir.resolve("broken");
        String brokenText = script(OLD_LOG, true).replace("run_rc_command \"$1\"", "run_rc_command \"$1");
        Files.writeString(broken, brokenText);
        r = RcScriptRepair.repair(broken, pairs, SH_N);
        check("a script sh -n refuses: REFUSED, as it was, and no file next to it",
                r.outcome() == RcScriptRepair.Outcome.REFUSED && Files.readString(broken).equals(brokenText)
                        && !Files.exists(dir.resolve(".broken.panel-new")));

        Path longer = dir.resolve("longer");
        String longerText = script(OLD_LOG + "s", true);
        Files.writeString(longer, longerText);
        r = RcScriptRepair.repair(longer, pairs, SH_N);
        check("a path that starts with the old name but is another file: NOTHING",
                r.outcome() == RcScriptRepair.Outcome.NOTHING && Files.readString(longer).equals(longerText));

        Path mixed = dir.resolve("mixed");
        String extra = "# " + OLD_LOG + "s: another file, not the log\n";
        Files.writeString(mixed, script(OLD_LOG, true) + extra);
        r = RcScriptRepair.repair(mixed, pairs, SH_N);
        check("with the log and a longer path that starts the same: only the log changes",
                r.outcome() == RcScriptRepair.Outcome.DONE && Files.readString(mixed).equals(script(NEW_LOG, true) + extra));

        r = RcScriptRepair.repair(dir.resolve("missing"), pairs, SH_N);
        check("no script: NOTHING", r.outcome() == RcScriptRepair.Outcome.NOTHING);

        System.out.println("\n== The script the panel writes today ==");
        check("it has the signature RcScriptRepair recognises, at the start of its comment",
                Files.readString(Path.of("src/main/java/org/mail_panel/system/UpdateManager.java"))
                        .contains("+ \"# \" + RcScriptRepair.MARKER + \". "));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static Path write(String text) throws Exception {
        Path f = Files.createTempFile("rc-script", "");
        Files.writeString(f, text);
        return f;
    }
}
