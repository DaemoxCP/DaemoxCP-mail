package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import org.mail_panel.i18n.I18n;
import org.mail_panel.scripts.DovecotConfig;

/**
 * Users' Sieve scripts in their mail folder, the panel's rules before them (reperto 214).
 *
 * Before, the panel's rules and the users' scripts were the same file under /var/mail/sieve, owned by root:
 * ManageSieve, the webmail's filters and doveadm sieve could save nothing ("mkdir_parents_chgrp(/var/mail/sieve/...)
 * failed: Permission denied"), measured on the VM on 2.3 and 2.4.
 *
 *  1. What the panel writes from now on, 2.3 and 2.4: the panel's rules as a "before" script from /var/mail/sieve, the
 *     users' scripts in ~/sieve, the active one ~/dovecot.sieve WITHOUT a dot (with the mail in the mailbox's root,
 *     Maildir++ took ~/.dovecot.sieve for a mail folder and deliveries with fileinto failed, measured).
 *  2. The migration of servers installed before: the exact block the panel wrote, 2.3 or 2.4, becomes the new one, the
 *     rest of the file untouched; done, hand-written or twice: nothing.
 *  3. A ManageSieve link under /var/mail/sieve (made by hand) is seen, so the migration leaves it; a panel file is not.
 *  4. The mailbox to try doveadm sieve list on, from /var/vmail.
 */
public class SieveStorageTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        System.out.println("== 1. What the panel writes ==");
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("2.3: the panel's rules as sieve_before, the users' scripts in ~/sieve, active ~/dovecot.sieve",
                fragment.contains("  sieve_before = /var/mail/sieve/%d/%n/.dovecot.sieve\n")
                && fragment.contains("  sieve = file:~/sieve;active=~/dovecot.sieve\n"));
        check("  no more sieve = /var/mail/sieve/... nor sieve_dir", !fragment.contains("sieve = /var/mail/sieve/%d/%n/.dovecot.sieve")
                && !fragment.contains("sieve_dir"));
        String master24 = DovecotConfig.file24().stream().filter(f -> f.path().equals("conf.d/10-master.conf")).findFirst().get().content();
        check("2.4: a before script for the panel's rules, the personal storage in ~/sieve, active ~/dovecot.sieve",
                master24.contains(DovecotConfig.SIEVE24) && master24.contains("type = before")
                && master24.contains("path = ~/sieve\n") && master24.contains("active_path = ~/dovecot.sieve\n"));
        check("  no more the personal storage under /var/mail/sieve", !master24.contains(SieveStorage.OLD24)
                && !master24.contains("active_path = /var/mail/sieve"));
        check("the active script has no dot in front, in both (Maildir++ would take it for a folder)",
                !fragment.contains("active=~/.") && !master24.contains("active_path = ~/."));

        System.out.println("\n== 2. The migration ==");
        String before23 = "service managesieve {\n}\n\nplugin {\n" + SieveStorage.OLD23
                + "  sieve_global_dir = /var/mail/sieve/global/\n  sieve_extensions = +fileinto +vacation\n}\n";
        String after23 = SieveStorage.migrated(before23);
        System.out.println(after23 == null ? "    null" : after23.trim().replaceAll("(?m)^", "    "));
        check("2.3: the panel's block becomes the new one, the rest untouched", after23 != null
                && after23.equals(before23.replace(SieveStorage.OLD23, DovecotConfig.SIEVE23.stripTrailing() + "\n"))
                && after23.contains("sieve_global_dir = /var/mail/sieve/global/") && after23.contains("sieve_extensions = +fileinto +vacation"));
        String before24 = "protocol lmtp {\n  mail_plugins {\n    sieve = yes\n  }\n}\n\n" + SieveStorage.OLD24
                + "\nsieve_script global {\n  type = global\n  driver = file\n  path = /var/mail/sieve/global/\n}\n";
        String after24 = SieveStorage.migrated(before24);
        check("2.4: the panel's personal block becomes the panel's before block and the personal one in ~/sieve",
                after24 != null && after24.equals(before24.replace(SieveStorage.OLD24, DovecotConfig.SIEVE24))
                && after24.contains("sieve_script global {"));
        check("already done: nothing", SieveStorage.migrated(after23) == null && SieveStorage.migrated(after24) == null);
        check("  a block written by hand (another path): nothing", SieveStorage.migrated(before23.replace("%d/%n/.dovecot.sieve", "%u/main.sieve")) == null);
        check("  the panel's block twice (not the panel's file): nothing", SieveStorage.migrated(before23 + before23) == null);
        check("  no file: nothing", SieveStorage.migrated(null) == null);

        System.out.println("\n== 3. ManageSieve links made by hand ==");
        Path root = Files.createTempDirectory("sieve-storage-test");
        try {
            Path panel = Files.createDirectories(root.resolve("sieve/example.test/alice"));
            Files.writeString(panel.resolve(".dovecot.sieve"), "keep;\n");
            check("a panel's rule (a file): not a link", SieveStorage.manageSieveLinks(root.resolve("sieve")).isEmpty());
            Path hand = Files.createDirectories(root.resolve("sieve/example.test/bob"));
            Files.writeString(hand.resolve("mine.sieve"), "keep;\n");
            Files.createSymbolicLink(hand.resolve(".dovecot.sieve"), Path.of("mine.sieve"));
            check("a ManageSieve link: seen, so the migration leaves it", SieveStorage.manageSieveLinks(root.resolve("sieve"))
                    .equals(java.util.List.of(hand.resolve(".dovecot.sieve"))));
            check("  no folder: none", SieveStorage.manageSieveLinks(root.resolve("none")).isEmpty());

            System.out.println("\n== 4. The mailbox to try ==");
            Path vmail = Files.createDirectories(root.resolve("vmail"));
            check("no mailbox: none", SieveStorage.someMailbox(vmail) == null && SieveStorage.someMailbox(root.resolve("x")) == null);
            Files.createDirectories(vmail.resolve("example.test/carol"));
            Files.createDirectories(vmail.resolve("bad name/x"));
            check("the first one, as an address: " + SieveStorage.someMailbox(vmail), "carol@example.test".equals(SieveStorage.someMailbox(vmail)));
        } finally {
            new ProcessBuilder("rm", "-rf", root.toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
