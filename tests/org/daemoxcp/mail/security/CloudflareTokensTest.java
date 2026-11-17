package org.daemoxcp.mail.security;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Cloudflare API tokens encrypted in the database (CloudflareTokens): before, cloudflare_accounts.api_token held them in
 * clear, so every copy of the database had a key that writes the DNS records of every zone of the account.
 *  1. sealed with DataCrypto (AES-256-GCM, a random nonce each time: the same token never gives the same value), and
 *     read back the same; a value in clear (written before the migration) is read as it is; a sealed value that
 *     cannot be decrypted (another secrets file) gives "", never the sealed text;
 *  2. the boot migration: tokens in clear sealed, row by row, only if the row still has the value read (a row changed
 *     meanwhile stays to whoever changed it, PARTIAL); sealed rows and empty ones untouched; a second start has
 *     nothing to do;
 *  3. the panel's own code: MailDatabase seals on every write (new account, new token, the legacy token) and opens on
 *     the one read (mapCloudflareAccount); the boot migration is called by the root part.
 * The secrets go to a temporary folder (-Ddaemoxcp.mail.secrets.dir is set here, before PanelSecrets loads): never the
 * real file of the machine it runs on.
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.CloudflareTokensTest
 */
public class CloudflareTokensTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The table as a map id -> stored value, with a hook to change a row between the read and the write. */
    static class Table implements CloudflareTokens.Rows {
        final Map<Integer, String> rows = new LinkedHashMap<>();
        Runnable meanwhile = () -> {};
        int writes = 0;

        @Override public List<CloudflareTokens.Row> all() {
            List<CloudflareTokens.Row> out = new ArrayList<>();
            rows.forEach((id, v) -> out.add(new CloudflareTokens.Row(id, v)));
            return out;
        }

        @Override public boolean replace(int id, String before, String sealed) {
            meanwhile.run();
            if (!before.equals(rows.get(id))) return false;
            rows.put(id, sealed);
            writes++;
            return true;
        }
    }

    public static void main(String[] args) throws Exception {
        Path secrets = Files.createTempDirectory("cloudflare-tokens-test");
        System.setProperty("daemoxcp.mail.secrets.dir", secrets.toString());
        check("the secrets in a temporary folder, not the machine's (" + PanelSecrets.dir + ")",
                PanelSecrets.dir.equals(secrets));

        String token = "AbCdEf0123456789-AbCdEf0123456789_xyz12";
        System.out.println("\n== 1. Sealed and read back");
        String a = CloudflareTokens.seal(token), b = CloudflareTokens.seal(token);
        check("sealed: not the token, and the token is not inside it", !a.equals(token) && !a.contains(token)
                && CloudflareTokens.isSealed(a));
        check("the same token sealed twice gives two different values (random nonce)", !a.equals(b));
        check("read back the same, both", token.equals(CloudflareTokens.open(1, a)) && token.equals(CloudflareTokens.open(1, b)));
        check("a token in clear (written before the migration) is read as it is", token.equals(CloudflareTokens.open(1, token)));
        check("null stays null", CloudflareTokens.open(1, null) == null && CloudflareTokens.seal(null) == null);
        String tampered = a.substring(0, a.length() - 4) + (a.endsWith("AAAA") ? "BBBB" : "AAAA");
        check("a sealed value that does not decrypt: \"\", never the sealed text", CloudflareTokens.open(1, tampered).isEmpty());

        System.out.println("\n== 2. The boot migration");
        Table t = new Table();
        t.rows.put(1, token);
        t.rows.put(2, CloudflareTokens.seal("already-sealed-token-000000000000000000"));
        t.rows.put(3, "second-token-in-clear-0000000000000000000");
        t.rows.put(4, "");
        String sealedBefore = t.rows.get(2);
        CloudflareTokens.Report r = CloudflareTokens.migrate(t);
        System.out.println("    -> " + r.outcome() + ": " + r.detail());
        check("DONE, the two in clear sealed", r.outcome() == CloudflareTokens.Outcome.DONE && t.writes == 2
                && CloudflareTokens.isSealed(t.rows.get(1)) && CloudflareTokens.isSealed(t.rows.get(3)));
        check("  and they read back the same", token.equals(CloudflareTokens.open(1, t.rows.get(1)))
                && "second-token-in-clear-0000000000000000000".equals(CloudflareTokens.open(3, t.rows.get(3))));
        check("  the one already sealed untouched, the empty one untouched", sealedBefore.equals(t.rows.get(2)) && "".equals(t.rows.get(4)));
        check("  no token in the report", !r.detail().contains(token) && r.detail().contains("[1, 3]"));
        t.writes = 0;
        r = CloudflareTokens.migrate(t);
        check("a second start: NOTHING, no write", r.outcome() == CloudflareTokens.Outcome.NOTHING && t.writes == 0);

        Table changed = new Table();
        changed.rows.put(7, token);
        changed.meanwhile = () -> changed.rows.put(7, "changed-by-the-administrator-meanwhile0");
        r = CloudflareTokens.migrate(changed);
        System.out.println("    -> " + r.outcome() + ": " + r.detail());
        check("a row changed between the read and the write: PARTIAL, the row stays to whoever changed it",
                r.outcome() == CloudflareTokens.Outcome.PARTIAL && "changed-by-the-administrator-meanwhile0".equals(changed.rows.get(7)));

        System.out.println("\n== 3. The panel's own code");
        String db = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/database/MailDatabase.java"));
        check("a new account: sealed", db.contains("stmt.setString(3, org.daemoxcp.mail.security.CloudflareTokens.seal(apiToken));"));
        check("a new token: sealed", db.contains("stmt.setString(1, org.daemoxcp.mail.security.CloudflareTokens.seal(newToken));"));
        check("the legacy token: sealed", db.contains("ins.setString(2, org.daemoxcp.mail.security.CloudflareTokens.seal(legacyToken));"));
        check("read: opened", db.contains("a.apiToken = org.daemoxcp.mail.security.CloudflareTokens.open(a.id, rs.getString(\"api_token\"));"));
        check("no other read of the column into an account", db.split("rs.getString\\(\"api_token\"\\)", -1).length - 1 == 2);
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int managers = server.indexOf("private void initializeManagers()");
        int call = server.indexOf("CloudflareTokens.ensureAtBoot(Main.mailDatabase)");
        check("the boot migration is called where the root part starts its managers", managers > 0 && call > managers
                && call < server.indexOf("private ", managers + 30));

        try (var w = Files.walk(secrets)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
