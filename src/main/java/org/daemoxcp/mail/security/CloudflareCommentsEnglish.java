package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * At startup: the DNS records that the panel created on Cloudflare before 2026-10-30 have the comment in Italian
 * (`Creato dal pannello di posta`, "Created by the mail panel"); they get the English one that the panel has written
 * since then (finding 211). The owner: "when you add a record, do not use Italian in the comments ... but always and
 * in any case English".
 *
 * Only in the zones of the panel's domains that have a Cloudflare account, once per zone even if several domains are
 * in it. Only the comment changes (CloudflareManager.renameLegacyComments): DNS stays as it is. In a thread of its
 * own, so that a slow Cloudflare does not hold up startup. On the second start it finds nothing and writes nothing:
 * one read per zone.
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

    /** The zones (id -> name, with the token of their account) and for each one the renamed comments. How many in all. */
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
                            + " records with a comment of before now say \"" + CloudflareManager.RECORD_COMMENT + "\"");
                    total += n;
                }
            }
        } catch (Exception e) {
            LOGGER.warning("[CloudflareComments] " + e.getMessage());
        }
        return total;
    }
}
