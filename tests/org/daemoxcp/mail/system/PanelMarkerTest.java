package org.daemoxcp.mail.system;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * The signatures of the panel's files move to English at start (PanelMarker.migrate), in temporary
 * folders and with a fake nginx that says which folders it includes.
 *
 * The "old" files are built from today's by putting back the old signature taken from the data
 * file: the test writes no old name. After the migration every file must be identical byte for
 * byte to the one today's code writes from scratch, with the same permissions; a second pass must
 * find nothing. The effect on the real services is measured by the test on the VM (findings).
 *
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelMarkerTest
 */
public class PanelMarkerTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final List<String> OLD = LegacyNames.oldNamesOf(PanelMarker.SIGNATURE, PanelMarker.WRITTEN);
    static final String DOVECOT_OLD = LegacyNames.oldNamesOf(PanelMarker.DOVECOT,
            org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE).get(0);

    static final String CONF = WebProtection.configuration("/usr/local/etc/ssl/mail/fullchain.pem",
            "/usr/local/etc/ssl/mail/privkey.pem");
    static final String DOVECOT_CONF = "# Dovecot — " + org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE
            + "\nprotocols = imap pop3 lmtp\n!include conf.d/*.conf\n";

    static String before(String now, String signature) { return now.replace(PanelMarker.WRITTEN, signature); }

    /** A server: fail2ban's folders, two nginx folders and dovecot.conf. */
    static final class Server {
        final Path root, f2b, filter, jail, defaultFolder, otherFolder, dovecot;
        List<String> folders;
        int nginxCalls;

        Server() throws Exception {
            root = Files.createTempDirectory("panel-marker");
            f2b = root.resolve("fail2ban");
            filter = f2b.resolve("filter.d").resolve(WebProtection.FILE_NAME);
            jail = f2b.resolve("jail.d").resolve(WebProtection.FILE_NAME);
            defaultFolder = root.resolve("nginx/conf.d");
            otherFolder = root.resolve("nginx/sites-enabled");
            dovecot = root.resolve("dovecot/dovecot.conf");
            for (Path p : List.of(filter.getParent(), jail.getParent(), defaultFolder, otherFolder, dovecot.getParent()))
                Files.createDirectories(p);
            folders = List.of(defaultFolder.toString());
        }

        void writeOld(boolean conf, boolean f2bFiles, boolean dovecotToo) throws Exception {
            if (conf) write(defaultFolder.resolve(WebProtection.FILE_NAME), before(CONF, OLD.get(OLD.size() - 1)), "rw-r--r--");
            if (f2bFiles) {
                write(filter, before(WebProtection.filter(), OLD.get(0)), "rw-r--r--");
                write(jail, before(WebProtection.jail(), OLD.get(0)), "rw-r-----");
            }
            if (dovecotToo) write(dovecot, DOVECOT_CONF.replace(org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE, DOVECOT_OLD), "rw-r-----");
        }

        void write(Path p, String s, String perms) throws Exception {
            Files.writeString(p, s);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms));
        }

        PanelMarker.Report run() {
            return PanelMarker.migrate(new PanelMarker.Places(f2b, defaultFolder, dovecot), () -> {
                nginxCalls++;
                return folders;
            });
        }

        String read(Path p) throws Exception { return Files.exists(p) ? Files.readString(p) : null; }

        String perms(Path p) throws Exception { return PosixFilePermissions.toString(Files.getPosixFilePermissions(p)); }

        boolean leftovers() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                return s.anyMatch(p -> p.getFileName().toString().endsWith(".daemoxcp-mail.tmp"));
            }
        }

        void close() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== The signatures ==");
        check("three old signatures in the data file (two Italian, the English one before DaemoxCP Mail), today's different from all",
                OLD.size() == 3 && !OLD.contains(PanelMarker.WRITTEN));
        check("today's code signs the three files of the 443",
                CONF.contains(PanelMarker.WRITTEN) && WebProtection.filter().contains(PanelMarker.WRITTEN)
                        && WebProtection.jail().contains(PanelMarker.WRITTEN));

        OUT.println("\n== A server with nothing old ==");
        Server s = new Server();
        PanelMarker.Report r = s.run();
        check("no files: NOTHING, and nginx -T is not run", r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == 0);
        s.write(s.defaultFolder.resolve(WebProtection.FILE_NAME), CONF, "rw-r--r--");
        s.write(s.filter, WebProtection.filter(), "rw-r--r--");
        s.write(s.jail, WebProtection.jail(), "rw-r-----");
        s.write(s.dovecot, DOVECOT_CONF, "rw-r-----");
        r = s.run();
        check("files already with today's signature: NOTHING, and nginx -T is not run",
                r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == 0);
        s.close();

        OUT.println("\n== A server installed before: the signatures change ==");
        s = new Server();
        s.writeOld(true, true, true);
        String jailBefore = s.read(s.jail);
        r = s.run();
        check("outcome DONE: " + r.detail(), r.outcome() == PanelMarker.Outcome.DONE);
        check("the nginx file is the one the panel writes today",
                CONF.equals(s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME))));
        check("filter and jail are today's", WebProtection.filter().equals(s.read(s.filter))
                && WebProtection.jail().equals(s.read(s.jail)));
        check("dovecot.conf has today's signature, and the rest as it was", DOVECOT_CONF.equals(s.read(s.dovecot)));
        check("  and only the signature line changes", PanelMarker.withoutComments(jailBefore).equals(PanelMarker.withoutComments(s.read(s.jail))));
        check("the permissions stay (jail 0640, filter 0644, dovecot.conf 0640)",
                "rw-r-----".equals(s.perms(s.jail)) && "rw-r--r--".equals(s.perms(s.filter)) && "rw-r-----".equals(s.perms(s.dovecot)));
        check("no temporary file left", !s.leftovers());
        int calls = s.nginxCalls;
        r = s.run();
        check("a second time: NOTHING, and nginx -T is not run", r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == calls);
        s.close();

        OUT.println("\n== The nginx file where nginx says it is ==");
        s = new Server();
        s.writeOld(false, true, false);
        s.write(s.otherFolder.resolve(WebProtection.FILE_NAME), before(CONF, OLD.get(1)), "rw-r--r--");
        s.folders = List.of(s.otherFolder.toString());
        r = s.run();
        check("in another included folder: DONE and the file is today's",
                r.outcome() == PanelMarker.Outcome.DONE && CONF.equals(s.read(s.otherFolder.resolve(WebProtection.FILE_NAME))));
        s.close();

        s = new Server();
        Path elsewhere = s.root.resolve("nginx/sites-available/" + WebProtection.FILE_NAME);
        Files.createDirectories(elsewhere.getParent());
        s.write(elsewhere, before(CONF, OLD.get(1)), "rw-r--r--");
        Files.createSymbolicLink(s.defaultFolder.resolve(WebProtection.FILE_NAME), elsewhere);
        r = s.run();
        check("a link is followed: the file it points to changes, the link stays",
                r.outcome() == PanelMarker.Outcome.DONE && CONF.equals(s.read(elsewhere))
                        && Files.isSymbolicLink(s.defaultFolder.resolve(WebProtection.FILE_NAME)));
        s.close();

        OUT.println("\n== When something goes wrong ==");
        s = new Server();
        s.writeOld(true, true, true);
        s.folders = null;
        String filterBefore = s.read(s.filter);
        r = s.run();
        check("nginx -T fails: NGINX_UNREADABLE, the 443 is not touched", r.outcome() == PanelMarker.Outcome.NGINX_UNREADABLE
                && filterBefore.equals(s.read(s.filter)) && s.read(s.jail).contains(OLD.get(0)));
        check("  but dovecot.conf, which does not depend on nginx, is", DOVECOT_CONF.equals(s.read(s.dovecot)));
        s.folders = List.of(s.defaultFolder.toString());
        r = s.run();
        check("  and at the next start, with nginx answering, the rest is done", r.outcome() == PanelMarker.Outcome.DONE
                && WebProtection.jail().equals(s.read(s.jail)) && CONF.equals(s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME))));
        s.close();

        s = new Server();
        s.writeOld(true, true, false);
        // nginx's temporary file cannot be created: in its place there is a full folder.
        Path blocker = s.defaultFolder.resolve("." + WebProtection.FILE_NAME + ".daemoxcp-mail.tmp");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("x"), "x");
        r = s.run();
        check("the nginx file cannot be written: PARTIAL, and filter and jail keep the old signature",
                r.outcome() == PanelMarker.Outcome.PARTIAL && s.read(s.filter).contains(OLD.get(0)) && s.read(s.jail).contains(OLD.get(0)));
        check("  (so at the next start everything is tried again: " + r.detail() + ")", s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME)).contains(OLD.get(OLD.size() - 1)));
        Files.delete(blocker.resolve("x"));
        Files.delete(blocker);
        r = s.run();
        check("  and with the obstacle removed it goes to the end", r.outcome() == PanelMarker.Outcome.DONE && WebProtection.jail().equals(s.read(s.jail)));
        s.close();

        s = new Server();
        String odd = "# " + OLD.get(0) + ".\n[" + WebProtection.NAME + "]\nenabled = true\nlogpath = /var/log/" + OLD.get(0) + "\n";
        s.write(s.jail, odd, "rw-r-----");
        s.write(s.defaultFolder.resolve(WebProtection.FILE_NAME), CONF, "rw-r--r--");
        r = s.run();
        String after = s.read(s.jail);
        check("the signature changes only in comment lines: the comment line yes, the other no",
                r.outcome() == PanelMarker.Outcome.DONE && after.startsWith("# " + PanelMarker.WRITTEN + ".\n")
                        && after.contains("logpath = /var/log/" + OLD.get(0) + "\n"));
        s.close();

        s = new Server();
        s.write(s.jail, "# my file\n[" + WebProtection.NAME + "]\nenabled = true\n", "rw-r-----");
        s.write(s.dovecot, "# my dovecot\nprotocols = imap\n", "rw-r-----");
        r = s.run();
        check("files without a signature (written by hand): NOTHING, they are not touched", r.outcome() == PanelMarker.Outcome.NOTHING
                && s.read(s.jail).startsWith("# my file") && s.read(s.dovecot).startsWith("# my dovecot"));
        s.close();

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
