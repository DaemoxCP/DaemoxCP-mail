package org.daemoxcp.mail.security;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * I token API di Cloudflare cifrati nel database, non in chiaro.
 *
 * Un token di Cloudflare scrive i record DNS di tutte le zone dell'account: chi lo legge puo' dirottare la posta di
 * ogni dominio. Stava in chiaro in cloudflare_accounts.api_token, quindi in ogni copia del database (mysqldump, i
 * backup, un boot environment copiato altrove). Ora si cifra come gli altri dati che il pannello deve rileggere
 * (DataCrypto: AES-256-GCM, un nonce casuale per ogni cifratura, la chiave solo nel file dei segreti): chi ha il
 * database senza quel file non ha il token. Lo legge e lo scrive solo la parte root (RootGate inoltra a lei
 * /api/cloudflare, /api/dns, /api/autodns), che la chiave la legge.
 *
 * I token gia' scritti in chiaro li cifra ensureAtBoot, uno per riga, con l'aggiornamento condizionato al valore di
 * prima: se intanto qualcuno lo ha cambiato, quella riga resta a lui. Un valore in chiaro che arriva prima della
 * migrazione si legge ancora com'e', cosi' niente smette di funzionare a meta'.
 */
public final class CloudflareTokens {

    private static final Logger LOGGER = Logger.getLogger(CloudflareTokens.class.getName());

    /** Come DataCrypto marca un valore cifrato. */
    static final String SEALED_PREFIX = "v1:";

    private CloudflareTokens() {}

    /** Il token da scrivere nel database. */
    public static String seal(String token) {
        return token == null ? null : DataCrypto.encrypt(token);
    }

    /**
     * Il token letto dal database: cifrato si decifra, in chiaro (scritto prima della migrazione) si usa com'e'. Un
     * valore cifrato che non si decifra (il file dei segreti cambiato) da' "" e lo si dice nel registro: Cloudflare
     * risponderebbe solo «token non valido», senza dire perche'.
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

    /** Le righe della tabella: in produzione MySQL, nelle prove una lista. */
    interface Rows {
        List<Row> all() throws Exception;

        /** Scrive sealed solo se la riga ha ancora il valore before; vero se l'ha scritto. */
        boolean replace(int id, String before, String sealed) throws Exception;
    }

    static Report migrate(Rows rows) throws Exception {
        List<Integer> done = new ArrayList<>(), left = new ArrayList<>();
        for (Row r : rows.all()) {
            if (r.stored() == null || r.stored().isEmpty() || isSealed(r.stored())) continue;
            String sealed = seal(r.stored());
            // Prima di scriverlo, la prova che si rilegge uguale: un token perso non si recupera da qui.
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
