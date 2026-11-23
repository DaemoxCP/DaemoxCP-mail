package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.AutoDns;
import org.daemoxcp.mail.security.CloudflareManager;
import org.daemoxcp.mail.security.DkimManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Everything a domain needs, with one button.
 *
 * Why it exists. A newly added domain needs eight things: the DKIM keys and their
 * record, SPF, a mailbox for the reports, DMARC, the name for the clients' automatic
 * configuration, the two SRVs, the name for MTA-STS, and a certificate covering those
 * names. Doing them by hand one by one, every time, means forgetting one -- and which one was
 * forgotten is not discovered right away: it is discovered when mail starts ending up in spam.
 *
 * Every step in here NEVER overwrites anything. That is why this sequence can be launched
 * without fear even on a domain already half configured: it finds what is already there,
 * leaves it where it is, and adds only what is missing. On a domain used elsewhere -- a
 * website with its mail managed by another provider -- it does not touch the existing SPF, it
 * shows it and stops on that line.
 *
 * The destination of the DMARC reports is not asked for: it is copied from another domain
 * already configured. Whoever has already decided where they want the reports should not have
 * to decide again for every domain; and if there is no precedent to copy from, that step is
 * skipped, saying so.
 */
public class DomainSetup {

    private DomainSetup() {}

    public static JSONObject run(int domainId) { return run(domainId, null); }

    /**
     * @param job where to write the progress as it happens.
     *
     * It is needed because this sequence includes waiting for DNS propagation and can last
     * minutes. If the HTTP request were kept open, the browser would receive the proxy's error
     * page while on the server the job carries on -- and an unknown state on a
     * production certificate is the antechamber of damage.
     */
    public static JSONObject run(int domainId, UpdateManager.Job job) {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        try {
            MailDatabase.Domain d = find(domainId);
            if (d == null) return r.put("success", false).put("error", I18n.tr("server.cfgdom.notFound"));
            r.put("domain", d.domain);
            if (job != null) job.write("=== " + I18n.tr("server.cfgdom.title", java.util.Map.of("d", String.valueOf(d.domain))) + " ===");

            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));

            // Every step also as a log line, with its reason: before, they were only in the JSON at the end, and the
            // log of a job that stopped halfway said only how many steps were in order (finding 250).
            final UpdateManager.Job log = job;
            java.util.function.Consumer<JSONObject> put = e -> {
                steps.put(e);
                if (log != null) log.write(e.optString("title") + ": "
                        + (e.optBoolean("ok", false) ? I18n.tr("server.cfgdom.done") : I18n.tr("server.um.x.failedF"))
                        + " \u2014 " + e.optString("messageText"));
            };

            // 1. DKIM: the key and its record.
            put.accept(dkim(d));

            // 2. SPF.
            put.accept(reduce("SPF", auto.create(domainId, "spf", "")));

            // 3. The reports mailbox, with the destination copied from another domain.
            String target = existingReportDestination();
            JSONObject deliveryState = auto.reportDelivery(d);
            if (deliveryState.optBoolean("exists", false))
                put.accept(entry(I18n.tr("server.cfgdom.reportBox"), true, I18n.tr("server.cfgdom.boxPresent", java.util.Map.of("kind", String.valueOf(deliveryState.optString("type"))))));
            else if (target == null)
                put.accept(entry(I18n.tr("server.cfgdom.reportBox"), false,
                        I18n.tr("server.cfgdom.boxNoSource")));
            else
                put.accept(reduce(I18n.tr("server.cfgdom.reportBox"), auto.createReportAlias(domainId, target)));

            // 4. DMARC, always in monitoring mode: it is tightened after reading the reports.
            put.accept(reduce("DMARC (p=none)", auto.create(domainId, "dmarc", "none")));

            // 5. The records that help the clients.
            for (String[] o : new String[][] {
                    {"autoconfig", "Autoconfig (Thunderbird)"},
                    {"srv_imaps", "server.cfgdom.srvIn"},
                    {"srv_submission", "server.cfgdom.srvOut"} })
                put.accept(reduce(I18n.tr(o[1]), auto.createOptional(domainId, o[0])));

            // 6. MTA-STS: the whole chain, for this domain, from the nginx include to the
            //    TXT record.
            //
            // Here there used to be three steps written separately -- the mta-sts name, the
            // certificate, the TXT record -- and it was a second version of the same sequence. It
            // had already diverged, in three points that were correct in the original:
            //
            //   - the certificate was RE-ISSUED at every press, without checking whether the names
            //     were already covered: a Let's Encrypt issuance burned every time, out of the
            //     five allowed per week for the same set of names;
            //   - the Cloudflare proxy was never turned off, so the name could stay
            //     behind the orange cloud and answer 526;
            //   - the policy was tested an instant after creating the CNAME, when
            //     no resolver can know it yet: the TXT record was never published.
            //
            // DNS, nginx and certificate do not work separately if you want MTA-STS: it is
            // a single chain and must be run from a single place. Two implementations of the
            // same thing always diverge, and the one that is pressed rarely falls behind
            // without anyone noticing.
            if (job != null) job.write("--- MTA-STS: " + I18n.tr("server.cfgdom.stsChain") + " ---");
            JSONArray mtasts = MtaStsSetup.asEntries(MtaStsSetup.run(job, d.domain));
            for (int i = 0; i < mtasts.length(); i++) steps.put(mtasts.get(i));

            int succeeded = 0;
            for (int i = 0; i < steps.length(); i++)
                if (steps.getJSONObject(i).optBoolean("ok", false)) succeeded++;

            return r.put("success", true).put("steps", steps)
                    .put("succeeded", succeeded).put("total", steps.length())
                    .put("note", I18n.tr("server.cfgdom.summary", java.util.Map.of("ok", String.valueOf(succeeded), "tot", String.valueOf(steps.length()))));
        } catch (Exception e) {
            return r.put("success", false).put("steps", steps)
                    .put("error", I18n.tr("server.cfgdom.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("DomainSetup", e))));
        }
    }

    /*
     * ===================================================================
     * Before starting: the domain's Cloudflare account
     * ===================================================================
     */

    /**
     * Ready, or why not; and the account assigned here, if the domain did not have one.
     *
     * Without a Cloudflare account that sees the domain's zone, "Set up everything" publishes nothing: before, it
     * started anyway, generated the DKIM key, changed nginx, stopped halfway and ended in green, "Setup completed" with
     * one step out of ten (finding 250, on the clean VM following the guide). Now it is checked before touching
     * anything. And the link between domain and account, which the guide did not mention, is made automatically when
     * only one panel account sees the zone: that is the case of whoever follows the guide, one account and its domains.
     */
    public record CloudflareChoice(boolean ready, String error, MailDatabase.CloudflareAccount assigned) {
        static CloudflareChoice no(String error) { return new CloudflareChoice(false, error, null); }
    }

    /** The zone that an account's token sees for the domain (CloudflareManager.findZone, or a test). */
    interface ZoneCheck { CloudflareManager.ZoneLookup find(MailDatabase.CloudflareAccount a); }

    static CloudflareChoice choose(String domain, MailDatabase.CloudflareAccount current,
                                   List<MailDatabase.CloudflareAccount> accounts, ZoneCheck zones) {
        if (current != null) {
            CloudflareManager.ZoneLookup zl = zones.find(current);
            if (zl != null && zl.found) return new CloudflareChoice(true, null, null);
            return CloudflareChoice.no(I18n.tr("server.cfgdom.cfZoneNotSeen", java.util.Map.of("a", String.valueOf(current.label),
                    "d", domain, "e", withoutFinalStop(zl == null ? I18n.tr("server.cfgdom.noAnswer") : zl.error))));
        }
        if (accounts == null || accounts.isEmpty())
            return CloudflareChoice.no(I18n.tr("server.cfgdom.cfNone", java.util.Map.of("d", domain)));
        List<MailDatabase.CloudflareAccount> seeing = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        for (MailDatabase.CloudflareAccount a : accounts) {
            labels.add(String.valueOf(a.label));
            CloudflareManager.ZoneLookup zl = zones.find(a);
            if (zl != null && zl.found) seeing.add(a);
        }
        if (seeing.size() == 1) return new CloudflareChoice(true, null, seeing.get(0));
        if (seeing.isEmpty())
            return CloudflareChoice.no(I18n.tr("server.cfgdom.cfNoneSees", java.util.Map.of("d", domain, "list", String.join(", ", labels))));
        List<String> which = new ArrayList<>();
        for (MailDatabase.CloudflareAccount a : seeing) which.add(String.valueOf(a.label));
        return CloudflareChoice.no(I18n.tr("server.cfgdom.cfSeveral", java.util.Map.of("d", domain, "list", String.join(", ", which))));
    }

    /** The reason without the final full stop: the sentence that contains it adds its own ("... after.. On Cloudflare"). */
    static String withoutFinalStop(String reason) {
        String r = String.valueOf(reason).trim();
        while (r.endsWith(".")) r = r.substring(0, r.length() - 1);
        return r;
    }

    /**
     * The real check: the domain's account, the panel's accounts, and the zone requested from Cloudflare with
     * the token of each one.
     */
    public static CloudflareChoice cloudflareFor(int domainId) {
        try {
            MailDatabase.Domain d = find(domainId);
            if (d == null) return CloudflareChoice.no(I18n.tr("server.cfgdom.notFound"));
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            CloudflareChoice c = choose(d.domain, cf.getAccountForDomain(d.id), cf.listAccounts(),
                    a -> cf.findZone(a.apiToken, d.domain));
            if (c.assigned() != null && !cf.assignDomain(d.id, c.assigned().id))
                return CloudflareChoice.no(I18n.tr("server.operationFailed"));
            return c;
        } catch (Exception e) {
            return CloudflareChoice.no(I18n.tr("server.cfgdom.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("DomainSetup", e))));
        }
    }

    /*
     * ===================================================================
     * The individual steps
     * ===================================================================
     */

    /** The DKIM key and its record, signing only with a published key: DkimManager.ensurePublished. */
    private static JSONObject dkim(MailDatabase.Domain d) {
        try {
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            MailDatabase.CloudflareAccount acct = cf.getAccountForDomain(d.id);
            if (acct == null)
                return entry("DKIM", false, I18n.tr("server.cfgdom.dkimNoCf", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cf.findZone(acct.apiToken, d.domain);
            if (!zl.found)
                return entry("DKIM", false, I18n.tr("server.cfgdom.dkimNoZone", java.util.Map.of("err", String.valueOf(zl.error))));

            DkimManager dk = new DkimManager(Main.mailDatabase);
            dk.setCloudflareManager(cf);
            // A zone that cannot be read throws ZoneReadException: it ends up in the catch, and nothing is created.
            DkimManager.RecordStep st = DkimManager.ensurePublished(cf, acct.apiToken, zl.zoneId, d.domain,
                    d.dkimSelector, d.dkimPublicKey, dk::newKey, k -> dk.install(d.id, d.domain, k));
            return entry("DKIM", st.ok(), st.message());
        } catch (Exception e) {
            return entry("DKIM", false, I18n.tr("server.cfgdom.dkimError", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("DomainSetup", e))));
        }
    }

    /**
     * Where the DMARC reports of the other domains end up.
     *
     * We look at an existing dmarc@ alias and reuse its destination: whoever has already
     * decided where they want the reports should not have to decide again for every domain.
     */
    public static String existingReportDestination() {
        try {
            for (MailDatabase.Domain d : Main.mailDatabase.getDomains())
                for (MailDatabase.Alias a : Main.mailDatabase.getAliases(d.id))
                    if (a.source != null && a.source.equalsIgnoreCase("dmarc@" + d.domain)
                            && a.destination != null && !a.destination.isBlank())
                        return a.destination.trim();
        } catch (Exception ignore) {}
        return null;
    }

    private static MailDatabase.Domain find(int id) throws Exception {
        for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) if (d.id == id) return d;
        return null;
    }

    /** Reduces the outcome of an operation to a readable line. */
    private static JSONObject reduce(String title, JSONObject e) {
        boolean ok = e.optBoolean("success", false);
        String msg = ok ? e.optString("note", I18n.tr("server.cfgdom.done"))
                        : e.optString("error", I18n.tr("server.cfgdom.failed"));
        // "Already exists" is not a failure: it is the rule that protects what was there.
        if (!ok && (e.optBoolean("alreadyExists", false) || e.optBoolean("unchanged", false)))
            return entry(title, true, msg);
        return entry(title, ok, msg);
    }

    private static JSONObject entry(String title, boolean ok, String message) {
        return new JSONObject().put("title", title).put("ok", ok)
                .put("messageText", message == null ? "" : message);
    }
}
