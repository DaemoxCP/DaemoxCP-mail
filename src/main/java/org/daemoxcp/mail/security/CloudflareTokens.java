package org.daemoxcp.mail.security;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * The Cloudflare API tokens encrypted in the database, not in plaintext.
 *
 * A Cloudflare token writes the DNS records of all the zones of the account: whoever reads it can hijack the mail of
 * every domain. It was in plaintext in cloudflare_accounts.api_token, so in every copy of the database (mysqldump,
 * the backups, a boot environment copied elsewhere). Now it is encrypted like the other data the panel has to read
 * back (DataCrypto: AES-256-GCM, a random nonce for every encryption, the key only in the secrets file): whoever has
 * the database without that file does not have the token. It is read and written only by the root part (RootGate
 * forwards /api/cloudflare, /api/dns, /api/autodns to it), which reads the key.
 *
 * The tokens already written in plaintext are encrypted by ensureAtBoot, one per row, with the update conditioned on
 * the previous value: if someone changed it in the meantime, that row stays theirs. A plaintext value that arrives
 * before the migration is still read as it is, so nothing stops working halfway.
 */
public final class CloudflareTokens {

    private static final Logger LOGGER = Logger.getLogger(CloudflareTokens.class.getName());

    /** How DataCrypto marks an encrypted value. */
    static final String SEALED_PREFIX = "v1:";

    private CloudflareTokens() {}

    /** The token to write into the database. */
    public static String seal(String token) {
        return token == null ? null : DataCrypto.encrypt(token);
    }

    /**
     * The token read from the database: if encrypted it is decrypted, if in plaintext (written before the migration)
     * it is used as it is. An encrypted value that cannot be decrypted (the secrets file changed) gives "" and this is
     * said in the log: Cloudflare would only answer "invalid token", without saying why.
     */
    public static String open(int accountId, String stored) {
        if (stored == null || !isSealed(stored)) return stored;
        String plain = DataCrypto.decryptOrEmpty(stored);
        if (plain.isEmpty())
            LOGGER.warning("[CloudflareTokens] the token of Cloudflare account " + accountId
                    + " cannot be decrypted (was the panel's secrets file replaced?): enter it again on the Cloudflare page");
        return plain;
    }

    static boolean isSealed(String stored) {
        return stored != null && stored.startsWith(SEALED_PREFIX);
    }

    enum Outcome { NOTHING, DONE, PARTIAL }

    record Report(Outcome outcome, String detail) {}

    record Row(int id, String stored) {}

    /** The rows of the table: in production MySQL, in the tests a list. */
    interface Rows {
        List<Row> all() throws Exception;

        /** Writes sealed only if the row still has the value before; true if it wrote it. */
        boolean replace(int id, String before, String sealed) throws Exception;
    }

    static Report migrate(Rows rows) throws Exception {
        List<Integer> done = new ArrayList<>(), left = new ArrayList<>();
        for (Row r : rows.all()) {
            if (r.stored() == null || r.stored().isEmpty() || isSealed(r.stored())) continue;
            String sealed = seal(r.stored());
            // Before writing it, the proof that it reads back the same: a lost token cannot be recovered from here.
            if (!r.stored().equals(DataCrypto.decryptOrEmpty(sealed)) || !rows.replace(r.id(), r.stored(), sealed)) {
                left.add(r.id());
                continue;
            }
            done.add(r.id());
        }
        if (done.isEmpty() && left.isEmpty()) return new Report(Outcome.NOTHING, "");
        String detail = (done.isEmpty() ? "" : "encrypted the token of Cloudflare accounts " + done)
                + (left.isEmpty() ? "" : (done.isEmpty() ? "" : "; ") + "left in clear (changed meanwhile or not readable back): " + left);
        return new Report(left.isEmpty() ? Outcome.DONE : Outcome.PARTIAL, detail);
    }

    public static void ensureAtBoot(org.daemoxcp.mail.database.MailDatabase db) {
        try {
            Report r = migrate(new Rows() {
                @Override public List<Row> all() throws Exception {
                    List<Row> out = new ArrayList<>();
                    for (String[] x : db.cloudflareStoredTokens()) out.add(new Row(Integer.parseInt(x[0]), x[1]));
                    return out;
                }
                @Override public boolean replace(int id, String before, String sealed) throws Exception {
                    return db.replaceCloudflareStoredToken(id, before, sealed);
                }
            });
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[CloudflareTokens] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[CloudflareTokens] failed: " + t);
        }
    }
}
