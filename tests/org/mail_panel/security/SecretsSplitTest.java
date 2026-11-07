package org.mail_panel.security;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Properties;

/**
 * The panel secrets split in two files: the web part of the panel will
 * run as the user mailpanel and must not read the MySQL root password nor the webmail's MySQL password.
 *
 *  1. the move done at start by root: the two root-only secrets leave panel-secrets.properties for
 *     root-secrets.properties (0600), the others stay, and the second time nothing moves; a different
 *     value already in the root file wins;
 *  2. every secret goes to its own file when it is generated or written;
 *  3. as root on the VM (-De2e.vm=yes): with the separation on, a write by root gives the panel file and
 *     its lock back to the web user, the folder becomes 0750 root:<web user>, and the root file stays
 *     root's. The web user here is "nobody", which exists everywhere.
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.SecretsSplitTest
 */
public class SecretsSplitTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Properties read(Path f) throws Exception {
        Properties p = new Properties();
        if (Files.exists(f)) try (Reader r = Files.newBufferedReader(f, StandardCharsets.UTF_8)) { p.load(r); }
        return p;
    }

    static String mode(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    static String owner(Path p) throws Exception {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class);
        return a.owner().getName() + ":" + a.group().getName();
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("secrets-split").resolve("mail-panel");
        PanelSecrets.dir = dir;
        PanelSecrets.reset();
        Path web = dir.resolve("panel-secrets.properties"), root = dir.resolve("root-secrets.properties");

        System.out.println("== 1. The move at start ==");
        PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD, "Panel-Pass-1");
        // A server installed before the split: the root secrets are in the panel file.
        PanelSecrets.WEB.update(p -> {
            p.setProperty(PanelSecrets.MYSQL_ROOT_PASSWORD, "Root-Pass-1!#");
            p.setProperty(PanelSecrets.ROUNDCUBE_DB_PASSWORD, "Webmail-Pass-1");
            return p;
        });
        List<String> moved = PanelSecrets.splitRootSecrets();
        check("both root secrets moved (" + moved + ")", moved.size() == 2);
        check("  they are in the root file, with their values", "Root-Pass-1!#".equals(read(root).getProperty(PanelSecrets.MYSQL_ROOT_PASSWORD))
                && "Webmail-Pass-1".equals(read(root).getProperty(PanelSecrets.ROUNDCUBE_DB_PASSWORD)));
        check("  and no longer in the panel file", !read(web).containsKey(PanelSecrets.MYSQL_ROOT_PASSWORD)
                && !read(web).containsKey(PanelSecrets.ROUNDCUBE_DB_PASSWORD));
        check("  the panel's own secrets stay where they were", "Panel-Pass-1".equals(read(web).getProperty(PanelSecrets.MYSQL_PASSWORD)));
        check("  the root file is 0600", mode(root).equals("rw-------"));
        check("reading goes to the right file", "Root-Pass-1!#".equals(PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD))
                && "Panel-Pass-1".equals(PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD)));
        check("the second time nothing moves", PanelSecrets.splitRootSecrets().isEmpty());

        PanelSecrets.WEB.update(p -> { p.setProperty(PanelSecrets.MYSQL_ROOT_PASSWORD, "Stale-In-Panel"); return p; });
        moved = PanelSecrets.splitRootSecrets();
        check("a different value already in the root file wins", "Root-Pass-1!#".equals(read(root).getProperty(PanelSecrets.MYSQL_ROOT_PASSWORD))
                && !read(web).containsKey(PanelSecrets.MYSQL_ROOT_PASSWORD) && moved.equals(List.of(PanelSecrets.MYSQL_ROOT_PASSWORD)));

        System.out.println("\n== 2. Every secret to its own file ==");
        PanelSecrets.setText(PanelSecrets.MYSQL_ROOT_PASSWORD, "");
        PanelSecrets.setText(PanelSecrets.ROUNDCUBE_DB_PASSWORD, "");
        String generated = PanelSecrets.ensureMysqlRootPassword();
        check("a new root password is generated into the root file", generated.equals(read(root).getProperty(PanelSecrets.MYSQL_ROOT_PASSWORD))
                && !read(web).containsKey(PanelSecrets.MYSQL_ROOT_PASSWORD));
        String webmail = PanelSecrets.ensureRoundcubeDbPassword();
        check("and the webmail's MySQL password too", webmail.equals(read(root).getProperty(PanelSecrets.ROUNDCUBE_DB_PASSWORD)));
        PanelSecrets.ensureKeys();
        check("the panel's keys go to the panel file", read(web).containsKey("data_key") && !read(root).containsKey("data_key"));
        check("location() of a secret names its file", PanelSecrets.location(PanelSecrets.MYSQL_ROOT_PASSWORD).equals(root.toString())
                && PanelSecrets.location(PanelSecrets.MYSQL_PASSWORD).equals(web.toString()));

        if ("yes".equals(System.getProperty("e2e.vm")) && "root".equals(System.getProperty("user.name"))) {
            System.out.println("\n== 3. With the separation on, as root ==");
            PanelSecrets.setWebOwner("nobody");
            try {
                PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD, "Panel-Pass-2");
                check("the panel file goes back to the web user (" + owner(web) + ")", owner(web).equals("nobody:nobody") && mode(web).equals("rw-------"));
                check("  and so does its lock (" + owner(dir.resolve("panel-secrets.lock")) + ")", owner(dir.resolve("panel-secrets.lock")).equals("nobody:nobody"));
                check("the folder is 0750 root:<web user> (" + mode(dir) + " " + owner(dir) + ")", mode(dir).equals("rwxr-x---") && owner(dir).equals("root:nobody"));
                PanelSecrets.setText(PanelSecrets.MYSQL_ROOT_PASSWORD, "Root-Pass-3");
                check("the root file stays root's, 0600 (" + owner(root) + ")", owner(root).startsWith("root:") && mode(root).equals("rw-------"));
            } finally {
                PanelSecrets.setWebOwner(null);
            }
        } else {
            System.out.println("\n  (part 3 skipped: it changes owners, turned on with -De2e.vm=yes as root on the VM)");
        }

        org.mail_panel.util.Shell.run("rm", "-rf", dir.getParent().toString());
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
