package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * All'avvio: i record DNS che il pannello ha creato su Cloudflare prima del 30/10/2026 hanno il commento in italiano
 * («Creato dal pannello di posta»); prendono quello in inglese che il pannello scrive da allora (reperto 211). Il
 * committente: «quando aggiunge un record, non usi l'italiano nei commenti ... ma sempre e comunque l'inglese».
 *
 * Solo nelle zone dei domini del pannello che hanno un account Cloudflare, una volta per zona anche se piu' domini ci
 * stanno. Cambia solo il commento (CloudflareManager.renameLegacyComments): il DNS resta com'e'. In un thread suo, cosi'
 * un Cloudflare lento non ferma l'avvio. Al secondo avvio non trova niente e non scrive niente: una lettura per zona.
 */
public final class CloudflareCommentsEnglish {

    private static final Logger LOGGER = Logger.getLogger(CloudflareCommentsEnglish.class.getName());

    private CloudflareCommentsEnglish() {}

    public static void ensureAtBoot(CloudflareManager cloudflare, MailDatabase database) {
        if (cloudflare == null || database == null) return;
        Thread t = new Thread(() -> run(cloudflare, database), "cloudflare-comments-english");
        t.setDaemon(true);
        t.start();
    }

    /** Le zone (id -> nome, col token del loro account) e per ognuna i commenti rinominati. Quanti in tutto. */
    static int run(CloudflareManager cloudflare, MailDatabase database) {
        int total = 0;
        try {
            Map<String, String[]> zones = new LinkedHashMap<>();
            for (MailDatabase.Domain d : database.getDomains()) {
                MailDatabase.CloudflareAccount account = cloudflare.getAccountForDomain(d.id);
                if (account == null || account.apiToken == null || account.apiToken.isBlank()) continue;
                CloudflareManager.ZoneLookup zone = cloudflare.findZone(account.apiToken, d.domain);
                if (!zone.found) continue;
                zones.putIfAbsent(zone.zoneId, new String[]{zone.zoneName, account.apiToken});
            }
            for (Map.Entry<String, String[]> z : zones.entrySet()) {
                int n = cloudflare.renameLegacyComments(z.getValue()[1], z.getKey());
                if (n < 0) LOGGER.warning("[CloudflareComments] zone " + z.getValue()[0]
                        + ": Cloudflare did not answer as expected; the comments are tried again at the next start");
                else if (n > 0) {
                    LOGGER.info("[CloudflareComments] zone " + z.getValue()[0] + ": " + n
                            + " records with the Italian comment of before now say \"" + CloudflareManager.RECORD_COMMENT + "\"");
                    total += n;
                }
            }
        } catch (Exception e) {
            LOGGER.warning("[CloudflareComments] " + e.getMessage());
        }
        return total;
    }
}
