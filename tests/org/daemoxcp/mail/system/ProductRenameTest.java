package org.daemoxcp.mail.system;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * The files only the panel reads move to today's names at the first start (ProductRename.moveFiles), and the old
 * folders whose today's name is already another folder pour their files into it (ProductRename.mergeFolders):
 * /usr/local/etc/mailpanel, where the MySQL-only script left mysql.json, and /usr/local/etc/mail-panel, the secrets,
 * both become /usr/local/etc/daemoxcp-mail. In temporary folders, with the pairs given by the test.
 *
 * It runs anywhere (it calls nothing):
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.ProductRenameTest
 */
public class ProductRenameTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== The data file ==");
        List<String[]> merged = LegacyNames.pairs("mergedFolders");
        check("mergedFolders: /usr/local/etc/mailpanel into today's secrets folder",
                merged.size() == 1 && merged.get(0)[0].equals("/usr/local/etc/mailpanel")
                        && merged.get(0)[1].equals("/usr/local/etc/" + Product.SLUG));
        check("  and today's folder is the one productFiles gives to the secrets",
                LegacyNames.pairs("productFiles").stream().anyMatch(p -> p[1].equals(merged.get(0)[1])));

        Path root = Files.createTempDirectory("product-rename-test");

        OUT.println("\n== The secrets moved, then the old MySQL folder poured into them ==");
        Path secretsOld = Files.createDirectories(root.resolve("etc/mail-panel"));
        Files.writeString(secretsOld.resolve("panel-secrets.properties"), "k=v\n");
        Path mysqlOld = Files.createDirectories(root.resolve("etc/mailpanel"));
        Path json = Files.writeString(mysqlOld.resolve("mysql.json"), "{\"host\": \"127.0.0.1\"}\n");
        Files.setPosixFilePermissions(json, PosixFilePermissions.fromString("rw-------"));
        Path today = root.resolve("etc/daemoxcp-mail");
        ProductRename.moveFiles(List.<String[]>of(new String[] {secretsOld.toString(), today.toString()}));
        ProductRename.mergeFolders(List.<String[]>of(new String[] {mysqlOld.toString(), today.toString()}));
        check("the secrets are in today's folder",
                "k=v\n".equals(read(today.resolve("panel-secrets.properties"))) && !Files.exists(secretsOld));
        check("mysql.json is next to them, same content and permissions (0600)",
                "{\"host\": \"127.0.0.1\"}\n".equals(read(today.resolve("mysql.json")))
                        && PosixFilePermissions.toString(Files.getPosixFilePermissions(today.resolve("mysql.json"))).equals("rw-------"));
        check("the old MySQL folder, now empty, is gone", !Files.exists(mysqlOld));

        OUT.println("\n== The second start ==");
        ProductRename.mergeFolders(List.<String[]>of(new String[] {mysqlOld.toString(), today.toString()}));
        check("nothing to do, nothing changes", !Files.exists(mysqlOld) && Files.exists(today.resolve("mysql.json")));

        OUT.println("\n== A file already there under today's name ==");
        Files.createDirectories(mysqlOld);
        Files.writeString(mysqlOld.resolve("mysql.json"), "older\n");
        Files.writeString(mysqlOld.resolve("notes.txt"), "n\n");
        ProductRename.mergeFolders(List.<String[]>of(new String[] {mysqlOld.toString(), today.toString()}));
        check("today's file is not overwritten, the old one stays where it is",
                "{\"host\": \"127.0.0.1\"}\n".equals(read(today.resolve("mysql.json"))) && "older\n".equals(read(mysqlOld.resolve("mysql.json"))));
        check("  the other file moves, and the old folder stays (it is not empty)",
                "n\n".equals(read(today.resolve("notes.txt"))) && Files.isDirectory(mysqlOld));

        OUT.println("\n== Today's folder not there yet ==");
        Path lonely = Files.createDirectories(root.resolve("etc/lonely-old"));
        Files.writeString(lonely.resolve("mysql.json"), "x\n");
        Path missing = root.resolve("etc/not-there");
        ProductRename.mergeFolders(List.<String[]>of(new String[] {lonely.toString(), missing.toString()}));
        check("nothing moves and today's folder is not created (PanelSecrets gives it its permissions)",
                Files.exists(lonely.resolve("mysql.json")) && !Files.exists(missing));

        OUT.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    static String read(Path p) throws Exception { return Files.exists(p) ? Files.readString(p) : null; }
}
