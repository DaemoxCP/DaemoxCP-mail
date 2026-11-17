package org.daemoxcp.mail.security;

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
 * run as the user daemoxcp_mail and must not read the MySQL root password nor the webmail's MySQL password.
 *
 *  1. the move done at start by root: the two root-only secrets leave panel-secrets.properties for
 *     root-secrets.properties (0600), the others stay, and the second time nothing moves; a different
 *     value already in the root file wins;
 *  2. every secret goes to its own file when it is generated or written;
 *  3. as root on the VM (-De2e.vm=yes): with the separation on (the folder and the panel file in the
 *     web part's group, as PanelSeparation leaves them) a write by root keeps the panel file 0640
 *     root:daemoxcp_mail, readable by the web part and never writable by it, and the folder 0750; the lock
 *     and the root file stay 0600 root. The group daemoxcp_mail is created if missing, and removed after.
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.SecretsSplitTest
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
            String g = PanelSecrets.WEB_GROUP;
            boolean created = !org.daemoxcp.mail.util.Shell.run("pw", "groupshow", g).success()
                    && org.daemoxcp.mail.util.Shell.run("pw", "groupadd", g).success();
            try {
                // What PanelSeparation.prepareFiles does.
                org.daemoxcp.mail.util.Shell.run("chgrp", g, dir.toString(), web.toString());
                org.daemoxcp.mail.util.Shell.run("chmod", "750", dir.toString());
                org.daemoxcp.mail.util.Shell.run("chmod", "640", web.toString());
                PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD, "Panel-Pass-2");
                check("a rewrite keeps the panel file 0640 root:" + g + " (" + mode(web) + " " + owner(web) + ")",
                        owner(web).equals("root:" + g) && mode(web).equals("rw-r-----")
                        && "Panel-Pass-2".equals(read(web).getProperty(PanelSecrets.MYSQL_PASSWORD)));
                check("  its lock stays root's, 0600 (" + mode(dir.resolve("panel-secrets.lock")) + " " + owner(dir.resolve("panel-secrets.lock")) + ")",
                        owner(dir.resolve("panel-secrets.lock")).startsWith("root:") && mode(dir.resolve("panel-secrets.lock")).equals("rw-------"));
                check("the folder stays 0750 root:" + g + " (" + mode(dir) + " " + owner(dir) + ")", mode(dir).equals("rwxr-x---") && owner(dir).equals("root:" + g));
                PanelSecrets.setText(PanelSecrets.MYSQL_ROOT_PASSWORD, "Root-Pass-3");
                check("the root file stays root's, 0600 (" + owner(root) + " " + mode(root) + ")",
                        owner(root).startsWith("root:") && !owner(root).endsWith(":" + g) && mode(root).equals("rw-------"));
            } finally {
                if (created) org.daemoxcp.mail.util.Shell.run("pw", "groupdel", g);
            }
        } else {
            System.out.println("\n  (part 3 skipped: it changes owners, turned on with -De2e.vm=yes as root on the VM)");
        }

        org.daemoxcp.mail.util.Shell.run("rm", "-rf", dir.getParent().toString());
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
