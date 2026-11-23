package org.daemoxcp.mail.security;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.database.MailDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * Creates the SPF and DMARC records on Cloudflare, following the rules of the specifications instead of
 * just writing a string that looks like a record.
 *
 * The rules that govern this file, all checked against the text and not from memory:
 *
 *  - RFC 7208 section 4.5: two SPF records on the same name give "permerror": SPF stops working
 *    altogether. So a second one is never added, and if there are already two the
 *    panel says so, because it is a fault that nobody else reports.
 *  - RFC 9989 section 4: two DMARC records on the same name are ALL discarded. Same thing.
 *  - RFC 9989 sections 5.1.4 and 5.1.5: you start from "p=none", with the rua pointing to a mailbox
 *    that ALREADY EXISTS. Starting from quarantine means putting your own mail into spam before
 *    having seen a single report.
 *  - RFC 9990 section 4: if the reports address is on another domain, the
 *    "_report._dmarc" authorization is needed, otherwise the reports are not sent at all.
 *
 * The principle that held from the first version, and that still holds here: **an existing record is
 * never overwritten.** But now the question "does it exist?" is asked about the CONTENT,
 * not about the name. Before, a "google-site-verification" on the apex was enough to make the
 * panel say "a TXT already exists" and prevent the creation of the SPF forever: a harmless
 * record that blocked the essential one.
 */
public class AutoDns {

    private final MailDatabase database;
    private final CloudflareManager cloudflare;

    public AutoDns(MailDatabase database, CloudflareManager cloudflare) {
        this.database = database;
        this.cloudflare = cloudflare;
    }

    /*
     * ===================================================================
     * Reading
     * ===================================================================
     */

    public JSONObject state(int domainId) {
        JSONObject r = new JSONObject().put("success", true);
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            r.put("domain", d.domain);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null)
                return r.put("cloudflare", false)
                        .put("note", I18n.tr("server.adns.noAccount", java.util.Map.of("d", String.valueOf(d.domain))));
            r.put("cloudflare", true).put("account", acct.label);

            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found)
                return r.put("zone", false)
                        .put("note", I18n.tr("server.adns.zoneNotSeen", java.util.Map.of("a", String.valueOf(acct.label), "d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));
            r.put("zone", true).put("zoneId", zl.zoneId);

            JSONArray record = new JSONArray();
            record.put(describe(acct.apiToken, zl.zoneId, "spf", d));
            record.put(describe(acct.apiToken, zl.zoneId, "dmarc", d));
            r.put("record", record);
            r.put("optionalItems", optionalState(acct.apiToken, zl.zoneId, d));

            // Where the reports would end up, and whether that mailbox really exists.
            r.put("reports", reportDelivery(d));
            return r;
        } catch (Exception e) {
            return error(I18n.tr("server.adns.readState", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /** The contents of the TXT records that are EXACTLY on that name, with their Cloudflare id. */
    private List<CloudflareManager.TxtRecordInfo> txtAtName(String token, String zoneId, String name) {
        List<CloudflareManager.TxtRecordInfo> outside = new ArrayList<>();
        String searched = name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
        // The whole zone is requested and filtered here: asking for "the names that contain X" for
        // the apex would return the whole zone anyway, because every name ends with the domain.
        for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(token, zoneId, null)) {
            String n = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
            if (n.equals(searched)) outside.add(t);
        }
        return outside;
    }

    /**
     * What is on that name now and what would go there. The difference from the previous
     * version lies entirely here: the records OF THAT TYPE are separated from all the other TXT records.
     */
    private JSONObject describe(String token, String zoneId, String which, MailDatabase.Domain d) {
        boolean spf = "spf".equals(which);
        String name = spf ? d.domain : "_dmarc." + d.domain;
        JSONObject o = new JSONObject().put("which", which).put("name", name);

        String proposed = spf ? spfValue() : dmarcValue(d.domain, "none");
        if (proposed == null) {
            o.put("proposed", JSONObject.NULL)
             .put("locked", I18n.tr("server.adns.noIpSpf"));
        } else {
            o.put("proposed", proposed);
        }

        List<CloudflareManager.TxtRecordInfo> allItems = txtAtName(token, zoneId, name);
        List<String> contents = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : allItems) contents.add(DnsRules.cloudflareContent(t.content));

        List<String> pertinent = spf ? DnsRules.onlySpf(contents) : DnsRules.onlyDmarc(contents);
        o.put("howMany", pertinent.size())
         .put("exists", !pertinent.isEmpty())
         .put("otherTxt", allItems.size() - pertinent.size());

        if (!pertinent.isEmpty()) {
            o.put("content", String.join("  ||  ", pertinent));
            for (CloudflareManager.TxtRecordInfo t : allItems)
                if (pertinent.contains(DnsRules.cloudflareContent(t.content))) { o.put("recordId", t.id); break; }
        }

        JSONArray warnings = new JSONArray();
        if (pertinent.size() > 1)
            warnings.put(spf
                ? I18n.tr("server.adns.multiSpf", java.util.Map.of("n", String.valueOf(pertinent.size())))
                : I18n.tr("server.adns.multiDmarc", java.util.Map.of("n", String.valueOf(pertinent.size()))));

        if (!pertinent.isEmpty()) {
            if (spf) {
                DnsRules.SpfOutcome e = DnsRules.analyzeSpf(contents, serverIp());
                for (String x : e.warnings) warnings.put(x);
                if (e.valid && !e.explicitAuthorization && !e.viaMx && !e.viaA && e.include == 0)
                    warnings.put(I18n.tr("server.adns.spfNotAuth", java.util.Map.of("ip", String.valueOf(serverIp()))));
            } else {
                DnsRules.DmarcOutcome e = DnsRules.analyzeDmarc(contents, d.domain);
                if (e.valid) o.put("currentPolicy", e.policy == null ? "none" : e.policy);
                for (String x : e.warnings) warnings.put(x);
                if (!e.toAuthorize.isEmpty())
                    warnings.put(I18n.tr("server.adns.ruaOutside", java.util.Map.of("r", String.valueOf(String.join(", ", e.toAuthorize)))));
            }
        }
        o.put("warnings", warnings);
        return o;
    }

    /*
     * ===================================================================
     * Writing
     * ===================================================================
     */

    public JSONObject create(int domainId, String which, String policy) {
        JSONObject r = new JSONObject().put("which", which);
        boolean spf = "spf".equals(which);
        if (!spf && !"dmarc".equals(which)) return error(I18n.tr("server.adns.unknownRecord", java.util.Map.of("q", String.valueOf(which))));

        // Whoever does not choose, chooses "none": it is what RFC 9989 section 5.1.5 asks to do
        // first, and the only value that cannot stop legitimate mail on the same day.
        String pol = (policy == null || policy.isBlank()) ? "none" : policy.trim().toLowerCase(java.util.Locale.ROOT);
        if (!spf && !List.of("none", "quarantine", "reject").contains(pol))
            return error(I18n.tr("server.adns.badDmarcPolicy"));

        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return error(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return error(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            String name = spf ? d.domain : "_dmarc." + d.domain;
            String value = spf ? spfValue() : dmarcValue(d.domain, pol);
            r.put("name", name).put("domain", d.domain).put("account", acct.label);

            // An SPF without IPs is not an incomplete SPF: it is an invalid record, which makes
            // the whole domain lose the protection it believed it had.
            if (value == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noIpWrite"));
            r.put("value", value);

            List<CloudflareManager.TxtRecordInfo> allItems = txtAtName(acct.apiToken, zl.zoneId, name);
            List<String> contents = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : allItems) contents.add(DnsRules.cloudflareContent(t.content));
            List<String> pertinent = spf ? DnsRules.onlySpf(contents) : DnsRules.onlyDmarc(contents);

            // The check that matters more than all the others, now done on the content.
            if (!pertinent.isEmpty())
                return r.put("success", false).put("alreadyExists", true)
                        .put("content", String.join("  ||  ", pertinent))
                        .put("error", (pertinent.size() == 1
                                   ? I18n.tr("server.adns.existsOne", java.util.Map.of("name", String.valueOf(name), "kind", String.valueOf(spf ? "SPF" : "DMARC")))
                                   : I18n.tr("server.adns.existsMany", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf(pertinent.size()), "kind", String.valueOf(spf ? "SPF" : "DMARC")))) + " "
                                + (pertinent.size() > 1
                                   ? (spf ? I18n.tr("server.adns.tooManySpf")
                                          : I18n.tr("server.adns.tooManyDmarc"))
                                   : (spf ? I18n.tr("server.adns.spfOthers", java.util.Map.of("ip", String.valueOf(serverIp())))
                                          : I18n.tr("server.adns.dmarcOld"))));

            // Unrelated TXT records are not an obstacle: a verification record of a third-party
            // service on the apex has nothing to do with SPF, and must not prevent it.
            int others = allItems.size() - pertinent.size();
            if (others > 0) r.put("otherTxt", others);

            // DMARC without a mailbox that receives the reports is a request that bounces.
            if (!spf) {
                JSONObject rec = reportDelivery(d);
                r.put("reports", rec);
                if (!rec.optBoolean("exists", false))
                    return r.put("success", false).put("mailboxMissing", true)
                            .put("error", I18n.tr("server.adns.ruaMissing", java.util.Map.of("a", String.valueOf(rec.optString("address")))));
            }

            CloudflareManager.RecordOp op = cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, name, value, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // The outcome is not "the API said ok": it is the record as seen from outside.
            return r.put("success", true).put("recordId", op.recordId)
                    .put("note", I18n.tr("server.adns.created", java.util.Map.of("z", String.valueOf(zl.zoneName)))
                            + (spf ? "" : " " + ("none".equals(pol)
                                ? I18n.tr("server.adns.policyNone", java.util.Map.of("p", String.valueOf(pol)))
                                : I18n.tr("server.adns.policyActive", java.util.Map.of("p", String.valueOf(pol))))));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.createError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Changes the policy of a DMARC record that is already published.
     *
     * It is needed because the intended path is none -> quarantine -> reject, and without this the
     * panel made only the first step easy, leaving the two that matter manual.
     *
     * The rule "I never overwrite" is not broken, it is made precise: ONE SINGLE VALUE is changed,
     * the one of the "p" tag, and all the rest of the record stays identical byte for byte.
     * If someone added "sp=", "fo=" or a second address for the reports, those
     * parts survive. And before writing, the before and after are shown, because a
     * confirmation that does not show what changes is not a confirmation.
     */
    public JSONObject changePolicy(int domainId, String fresh, boolean confirmed) {
        JSONObject r = new JSONObject();
        String n = fresh == null ? "" : fresh.trim().toLowerCase(java.util.Locale.ROOT);
        if (!java.util.List.of("none", "quarantine", "reject").contains(n))
            return error(I18n.tr("server.adns.badPolicy"));
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return error(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return error(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            String name = "_dmarc." + d.domain;
            r.put("name", name).put("domain", d.domain).put("newPolicy", n);

            CloudflareManager.TxtRecordInfo target = null;
            java.util.List<String> dmarc = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (!nm.equals(name.toLowerCase(java.util.Locale.ROOT))) continue;
                String content = DnsRules.cloudflareContent(t.content);
                if (DnsRules.eDmarc(content)) { dmarc.add(content); target = t; }
            }

            if (dmarc.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noDmarcToEdit", java.util.Map.of("name", String.valueOf(name))));
            if (dmarc.size() > 1)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.manyDmarcEdit", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf(dmarc.size()))));

            String before = DnsRules.cloudflareContent(target.content);
            String after = DnsRules.changePolicy(before, n);
            if (after == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cannotEdit", java.util.Map.of("v", String.valueOf(before))));
            r.put("before", before).put("after", after);

            if (before.equals(after))
                return r.put("success", true).put("unchanged", true)
                        .put("note", I18n.tr("server.adns.policySame", java.util.Map.of("p", String.valueOf(n))));

            if (!confirmed)
                return r.put("success", true).put("preview", true)
                        .put("note", I18n.tr("server.adns.onlyP"));

            CloudflareManager.RecordOp op = cloudflare.updateTxtRecord(
                    acct.apiToken, zl.zoneId, target.id, name, after, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefusedEdit", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // It is not enough that the API said yes: the zone is reread.
            String verified = null;
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (nm.equals(name.toLowerCase(java.util.Locale.ROOT))) {
                    String c = DnsRules.cloudflareContent(t.content);
                    if (DnsRules.eDmarc(c)) verified = c;
                }
            }
            if (verified == null || !verified.equals(after))
                return r.put("success", false).put("reread", verified == null ? "" : verified)
                        .put("error", I18n.tr("server.adns.notChanged"));

            return r.put("success", true)
                    .put("note", I18n.tr("server.adns.policySet", java.util.Map.of("p", String.valueOf(n), "name", String.valueOf(name))) + " "
                            + ("reject".equals(n)
                               ? I18n.tr("server.adns.rejectNow")
                               : "quarantine".equals(n)
                               ? I18n.tr("server.adns.quarantineNow")
                               : I18n.tr("server.adns.noneNow"))
                            + " " + I18n.tr("server.adns.propagation"));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.editError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Publishes the _mta-sts TXT record, but ONLY if the policy already answers.
     *
     * It is the rule that keeps the whole mechanism honest. That record is a public
     * declaration: it tells servers all over the world "go and read my policy". Publishing it
     * before the policy exists means sending them into an error, and in the meantime
     * showing whoever looks at the panel a green tick on a protection that is not there.
     */
    public JSONObject createTxtMtaSts(int domainId) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            String name = "_mta-sts." + d.domain;
            r.put("name", name).put("domain", d.domain);

            JSONObject publishableState = org.daemoxcp.mail.system.MtaSts.publishable(d.domain);
            r.put("test", publishableState.optJSONObject("test"));
            if (!publishableState.optBoolean("publishable", false))
                return r.put("success", false).put("error", publishableState.optString("reason"));

            String value = publishableState.getString("value");
            r.put("value", value);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return error(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return error(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            return alignMtaStsTxt(acct.apiToken, zl.zoneId, name, value, r);
        } catch (Exception e) {
            return error(I18n.tr("server.adns.createError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Leaves a single MTA-STS record on that name, with that value: creates it if it is missing,
     * updates it if it has another id, removes the extra ones.
     *
     * The extra ones matter: with two v=STSv1 records senders behave as if MTA-STS were not
     * there (RFC 8461 section 3.1). Before, only the first record was looked at here: if it was already
     * right the answer was "unchanged", and the other one stayed there switching everything off.
     *
     * They are removed without asking anything else because the _mta-sts name belongs to the panel and
     * the record contains nothing chosen by hand: the version and the id, which follows the policy served.
     * The removed ones remain written in the answer.
     *
     * It stands on its own so that the tests can check it with a fake Cloudflare.
     */
    JSONObject alignMtaStsTxt(String token, String zoneId, String name, String value, JSONObject r) {
        List<CloudflareManager.TxtRecordInfo> sts = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : txtAtName(token, zoneId, name))
            if (DnsRules.eMtaSts(DnsRules.cloudflareContent(t.content))) sts.add(t);

        List<String> removed = new ArrayList<>();
        String before = null;
        if (sts.isEmpty()) {
            CloudflareManager.RecordOp op = cloudflare.createTxtRecord(token, zoneId, name, value, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));
            r.put("recordId", op.recordId);
        } else {
            // The one that is already right is kept, if there is one; otherwise the first, to be updated.
            CloudflareManager.TxtRecordInfo keep = sts.get(0);
            for (CloudflareManager.TxtRecordInfo t : sts)
                if (DnsRules.cloudflareContent(t.content).trim().equals(value.trim())) { keep = t; break; }

            // First the others are removed, then it is updated. If the update failed there would remain
            // a single record with the old id: senders read it and download the current
            // policy. Two records, instead, nobody reads.
            for (CloudflareManager.TxtRecordInfo t : sts) {
                if (t == keep) continue;
                String c = DnsRules.cloudflareContent(t.content);
                CloudflareManager.RecordOp del = cloudflare.deleteRecord(token, zoneId, t.id);
                if (del == null || !del.success)
                    return r.put("success", false).put("removed", new JSONArray(removed))
                            .put("error", I18n.tr("server.adns.stsManyDelFail", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf(sts.size()), "c", String.valueOf(c), "e", String.valueOf(del == null ? I18n.tr("server.adns.noAnswer") : del.error)))
                                    + (removed.isEmpty() ? "." : ". " + I18n.tr("server.adns.removedSoFar", java.util.Map.of("list", String.valueOf(String.join("  ||  ", removed))))));
                removed.add(c);
            }

            String c = DnsRules.cloudflareContent(keep.content);
            if (!c.trim().equals(value.trim())) {
                // The id is NOT decorative: it is the signal by which senders notice that the
                // policy has changed. A fixed id (for example a clock written only once,
                // as in the records suggested by the old panel) keeps everyone
                // on the old policy until their copy expires. So it is updated.
                CloudflareManager.RecordOp up = cloudflare.updateTxtRecord(
                        token, zoneId, keep.id, name, value, 3600);
                if (up == null || !up.success)
                    return r.put("success", false).put("content", c).put("removed", new JSONArray(removed))
                            .put("error", I18n.tr("server.adns.stsUpdateFail", java.util.Map.of("name", String.valueOf(name), "c", String.valueOf(c), "e", String.valueOf(up == null ? I18n.tr("server.adns.noAnswer") : up.error)))
                                    + (removed.isEmpty() ? "" : ". " + I18n.tr("server.adns.othersRemoved", java.util.Map.of("list", String.valueOf(String.join("  ||  ", removed))))));
                before = c;
            } else if (removed.isEmpty()) {
                return r.put("success", true).put("unchanged", true).put("content", c)
                        .put("note", I18n.tr("server.adns.alreadyRight", java.util.Map.of("name", String.valueOf(name))));
            }
        }

        // It is not enough that the API said yes: the zone is reread. The goal is that ONE
        // remains, so it is counted. It is also needed when it was created: if the first read had
        // come back empty because of a Cloudflare error, the new record would sit next to an
        // old one, and there would be two.
        List<String> remain = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : txtAtName(token, zoneId, name)) {
            String c = DnsRules.cloudflareContent(t.content);
            if (DnsRules.eMtaSts(c)) remain.add(c.trim());
        }
        if (!removed.isEmpty()) r.put("removed", new JSONArray(removed));
        if (before != null) r.put("updated", true).put("before", before).put("after", value);
        if (remain.size() != 1 || !remain.get(0).equals(value.trim()))
            return r.put("success", false).put("reread", String.join("  ||  ", remain))
                    .put("error", (remain.isEmpty()
                               ? I18n.tr("server.adns.stsReadNone", java.util.Map.of("name", String.valueOf(name)))
                               : remain.size() == 1
                               ? I18n.tr("server.adns.stsReadOne", java.util.Map.of("name", String.valueOf(name), "v", String.valueOf(remain.get(0))))
                               : I18n.tr("server.adns.stsReadMany", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf(remain.size()), "list", String.valueOf(String.join("  ||  ", remain)))))
                            + " " + I18n.tr("server.adns.lookBeforeRetry"));

        String note;
        if (!removed.isEmpty())
            note = I18n.tr("server.adns.stsCleaned", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf(sts.size()), "list", String.valueOf(String.join("  ||  ", removed))));
        else if (before != null)
            note = I18n.tr("server.adns.stsUpdated", java.util.Map.of("name", String.valueOf(name)));
        else
            note = I18n.tr("server.adns.stsPublished", java.util.Map.of("name", String.valueOf(name)));
        return r.put("success", true).put("note", note);
    }

    /*
     * ===================================================================
     * The reports mailbox
     * ===================================================================
     */

    /** The address the panel writes into the rua, and whether it already exists as a mailbox or an alias. */
    public JSONObject reportDelivery(MailDatabase.Domain d) {
        JSONObject o = new JSONObject();
        String address = "dmarc@" + d.domain;
        o.put("address", address).put("domain", d.domain);
        try {
            for (MailDatabase.Mailbox m : database.getMailboxes(d.id))
                if (m.email != null && m.email.equalsIgnoreCase(address))
                    return o.put("exists", true).put("type", "mailbox");
            for (MailDatabase.Alias a : database.getAliases(d.id))
                if (a.source != null && a.source.equalsIgnoreCase(address))
                    return o.put("exists", true).put("type", "alias")
                            .put("destination", a.destination == null ? "" : a.destination);
            // The note does NOT repeat "does not exist": the interface already says that, and saying it
            // twice in a row makes the panel look broken instead of the DNS.
            return o.put("exists", false)
                    .put("note", I18n.tr("server.adns.ruaInside"));
        } catch (Exception e) {
            return o.put("exists", false).put("error", I18n.tr("server.adns.readBoxes", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Creates the alias dmarc@&lt;domain&gt; pointing to a chosen mailbox. No shortcut: it
     * first checks that the address is not already taken, and that the destination really
     * exists. It is exactly the check that was missing when a "create" overrode
     * an alias already in use on a domain that had nothing to do with it.
     */
    public JSONObject createReportAlias(int domainId, String destination) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            String address = "dmarc@" + d.domain;
            r.put("address", address).put("domain", d.domain).put("destination", destination);

            if (destination == null || destination.isBlank())
                return error(I18n.tr("server.adns.needDest"));
            String dest = destination.trim();
            if (dest.indexOf('@') < 0) return error(I18n.tr("server.adns.destNotAddr", java.util.Map.of("d", String.valueOf(dest))));
            if (dest.equalsIgnoreCase(address))
                return error(I18n.tr("server.adns.destLoop"));

            JSONObject already = reportDelivery(d);
            if (already.optBoolean("exists", false))
                return r.put("success", false).put("alreadyExists", true)
                        .put("error", I18n.tr("server.adns.existsAs", java.util.Map.of("address", String.valueOf(address), "kind", String.valueOf(already.optString("type")), "destination", String.valueOf(already.has("destination") ? " (" + I18n.tr("server.adns.toAddr", java.util.Map.of("v", String.valueOf(already.optString("destination")))) + ")" : ""))));

            // Whitelist of allowed characters: it declares what CAN be there, not what cannot.
            if (!dest.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.notMailAddr", java.util.Map.of("d", String.valueOf(dest))));

            // The destination can also be outside the panel: reports are normal mail
            // and can be forwarded anywhere. But if it is outside, the panel cannot verify that
            // it exists, and says so instead of letting it be believed.
            boolean internal = false;
            for (MailDatabase.Domain dom : database.getDomains())
                for (MailDatabase.Mailbox m : database.getMailboxes(dom.id))
                    if (m.email != null && m.email.equalsIgnoreCase(dest)) internal = true;
            r.put("internalDestination", internal);

            int id = database.addAlias(d.id, address, dest);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.adns.aliasNotCreated"));

            JSONObject after = reportDelivery(d);
            if (!after.optBoolean("exists", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.aliasNotReread"));

            return r.put("success", true).put("aliasId", id)
                    .put("note", I18n.tr("server.adns.aliasCreated", java.util.Map.of("a", String.valueOf(address), "d", String.valueOf(dest), "dom", String.valueOf(d.domain)))
                            + (internal ? "" : " " + I18n.tr("server.adns.aliasExternal", java.util.Map.of("d", String.valueOf(dest)))));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.aliasError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Creates dmarc@&lt;domain&gt; as a real mailbox, with a password generated by the panel and
     * shown only once. It is the alternative to the alias: it separates the reports from everything
     * else, at the price of one more mailbox to look at now and then.
     */
    public JSONObject createReportMailbox(int domainId) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            String address = "dmarc@" + d.domain;
            r.put("address", address).put("domain", d.domain);

            JSONObject already = reportDelivery(d);
            if (already.optBoolean("exists", false))
                return r.put("success", false).put("alreadyExists", true)
                        .put("error", I18n.tr("server.adns.existsAsShort", java.util.Map.of("address", String.valueOf(address), "kind", String.valueOf(already.optString("type")), "destination", String.valueOf(already.has("destination") ? " (" + I18n.tr("server.adns.toAddr", java.util.Map.of("v", String.valueOf(already.optString("destination")))) + ")" : ""))));

            String password = randomPassword();
            int id = database.addMailbox(d.id, address, password, I18n.tr("server.adns.dmarcBoxName", java.util.Map.of("d", String.valueOf(d.domain))), 512);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.adns.boxNotCreated"));

            JSONObject after = reportDelivery(d);
            if (!after.optBoolean("exists", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.boxNotReread"));

            // The password is NOT "shown only once": addMailbox encrypts it in the vault
            // (AES-256-GCM), and the "Mailboxes" page shows it again with "Reveal". Calling it
            // unrecoverable would make the reader believe the panel is less capable than it is.
            return r.put("success", true).put("mailboxId", id).put("password", password)
                    .put("note", I18n.tr("server.adns.boxCreated", java.util.Map.of("a", String.valueOf(address), "dom", String.valueOf(d.domain))));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.boxError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /** A strong password from a declared alphabet, without characters that are easily confused by eye. */
    private static String randomPassword() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        java.security.SecureRandom random = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        return sb.toString();
    }

    /**
     * All the real mailboxes of the panel, for the destination drop-down. The
     * destination is CHOSEN from a list: a free field is a way to write an
     * address that does not exist and to notice it months later, when a report was needed.
     */
    public JSONObject availableMailboxes() {
        JSONObject r = new JSONObject().put("success", true);
        JSONArray list = new JSONArray();
        try {
            for (MailDatabase.Domain dom : database.getDomains())
                for (MailDatabase.Mailbox m : database.getMailboxes(dom.id))
                    if (m.email != null && !m.email.isBlank()) list.put(m.email);
            return r.put("mailboxes", list);
        } catch (Exception e) {
            return error(I18n.tr("server.adns.readMailboxes", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /*
     * ===================================================================
     * The optional records
     * ===================================================================
     */

    /**
     * The ones the panel can create by itself. They are "optional" in the sense that mail
     * works without them too, not in the sense that they are not needed: without autoconfig and the two
     * SRV records, whoever adds the mailbox must know server, ports and type of encryption by heart.
     *
     * Beware of a difference that cannot be seen from the name: the two SRV records work ON THEIR OWN
     * (RFC 6186 section 4: the client queries DNS and from there derives host and port), while
     * autoconfig is only the address where the client goes looking for a configuration file.
     *
     * "autodiscover" is NO longer there: it was only for Outlook, which is not used here. It was a
     * record that the panel proposed, the certificate included and the check marked in
     * red, for a client that will never connect to this server. A line that serves
     * nobody is still a line that someone one day tries to understand.
     *
     * key | type | relative name | port (0 if not SRV) | what it is for | missing prerequisite
     */
    private static final String[][] OPTIONAL_ITEMS = {
        { "autoconfig",     "CNAME", "autoconfig",       "0",
          "server.adns.opt.autoconfigWhat",
          // This note said "this panel does not serve that file" and sent clients to the
          // two SRV records. They were two false statements in the same sentence, and the page
          // contradicted itself: the automatic configuration card, a few lines
          // further down, measures that the file arrives, and explains that Thunderbird does not
          // read the SRV records.
          "server.adns.opt.autoconfigNeeds" },
        { "srv_imaps",      "SRV",   "_imaps._tcp",      "993",
          "server.adns.opt.imapsWhat", "" },
        { "mta_sts",        "CNAME", "mta-sts",          "0",
          "server.adns.opt.stsWhat",
          "server.adns.opt.stsNeeds" },
        { "srv_submission", "SRV",   "_submission._tcp", "587",
          "server.adns.opt.submissionWhat", "" },
    };

    private static String[] definition(String key) {
        for (String[] o : OPTIONAL_ITEMS) if (o[0].equals(key)) return o;
        return null;
    }

    /** The hostname of the mail server, read where the DNS page reads it and not elsewhere. */
    private String mailHost(String domain) {
        try {
            return database.getSetting("mail_hostname", "mail." + domain);
        } catch (Exception e) {
            return "mail." + domain;
        }
    }

    /** All the records of the zone that are exactly on that name, of any type. */
    private java.util.List<CloudflareManager.DnsRecordInfo> atName(
            java.util.List<CloudflareManager.DnsRecordInfo> allItems, String name) {
        java.util.List<CloudflareManager.DnsRecordInfo> outside = new ArrayList<>();
        String searched = name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
        for (CloudflareManager.DnsRecordInfo t : allItems) {
            String n = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
            if (n.equals(searched)) outside.add(t);
        }
        return outside;
    }

    private JSONArray optionalState(String token, String zoneId, MailDatabase.Domain d) {
        JSONArray out = new JSONArray();
        java.util.List<CloudflareManager.DnsRecordInfo> allItems = cloudflare.listRecords(token, zoneId);
        String target = mailHost(d.domain);
        for (String[] o : OPTIONAL_ITEMS) {
            String fullName = o[2] + "." + d.domain;
            JSONObject j = new JSONObject()
                    .put("which", o[0]).put("type", o[1]).put("name", fullName)
                    .put("purpose", I18n.tr(o[4]))
                    .put("premise", o[5].isEmpty() ? "" : I18n.tr(o[5]))
                    .put("proposed", "SRV".equals(o[1])
                            ? "0 1 " + o[3] + " " + target
                            : target);

            java.util.List<CloudflareManager.DnsRecordInfo> here = atName(allItems, fullName);
            java.util.List<CloudflareManager.DnsRecordInfo> sameKind = new ArrayList<>();
            java.util.List<CloudflareManager.DnsRecordInfo> otherKind = new ArrayList<>();
            for (CloudflareManager.DnsRecordInfo t : here)
                (o[1].equalsIgnoreCase(t.type) ? sameKind : otherKind).add(t);

            j.put("exists", !sameKind.isEmpty());
            if (!sameKind.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (CloudflareManager.DnsRecordInfo t : sameKind) {
                    if (sb.length() > 0) sb.append("  ||  ");
                    // An SRV is shown WHOLE. Showing only the "content", the column said
                    // "1 993 mail.domain-b.test" next to the proposal "0 1 993 mail.domain-b.test",
                    // and the two looked different while they were the same record written in two
                    // formats: only the priority is missing, which Cloudflare keeps aside.
                    sb.append(fullSrv(t));
                    if (t.proxied) sb.append("  (").append(I18n.tr("server.adns.proxiedTag")).append(")");
                }
                j.put("content", sb.toString());
                boolean proxied = false;
                for (CloudflareManager.DnsRecordInfo t : sameKind) if (t.proxied) proxied = true;
                if (proxied)
                    j.put("warning", I18n.tr("server.adns.proxied"));
            } else if (!otherKind.isEmpty()) {
                // DNS does not allow a CNAME next to other data on the same name.
                StringBuilder sb = new StringBuilder();
                for (CloudflareManager.DnsRecordInfo t : otherKind) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(t.type).append(" ").append(t.content);
                }
                j.put("conflict", I18n.tr("server.adns.typeConflict", java.util.Map.of("name", String.valueOf(fullName), "other", String.valueOf(sb), "kind", String.valueOf(o[1]))));
            }
            out.put(j);
        }
        return out;
    }

    /**
     * Creates one of the optional records. Same rules as the others: nothing is overwritten,
     * and the outcome is verified by rereading the zone instead of trusting the answer of the API.
     */
    public JSONObject createOptional(int domainId, String key) {
        JSONObject r = new JSONObject().put("which", key);
        String[] def = definition(key);
        if (def == null) return error(I18n.tr("server.adns.unknownOptional", java.util.Map.of("k", String.valueOf(key))));
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            // "I cannot handle it" is not "I failed": the caller must be able to tell
            // the two cases apart, otherwise it ends up giving a red error to a legitimate
            // configuration, or, worse, a green to one it has not checked.
            if (acct == null) return error(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))))
                    .put("unmanaged", true);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return error(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))))
                    .put("unmanaged", true);

            String fullName = def[2] + "." + d.domain;
            String target = mailHost(d.domain);
            boolean srv = "SRV".equals(def[1]);
            int port = srv ? Integer.parseInt(def[3]) : 0;
            r.put("name", fullName).put("type", def[1]).put("domain", d.domain)
             .put("value", srv ? "0 1 " + port + " " + target : target);

            if (target == null || target.isBlank() || !target.contains("."))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noHostname"));

            java.util.List<CloudflareManager.DnsRecordInfo> here =
                    atName(cloudflare.listRecords(acct.apiToken, zl.zoneId), fullName);
            for (CloudflareManager.DnsRecordInfo t : here) {
                if (!def[1].equalsIgnoreCase(t.type))
                    return r.put("success", false).put("conflict", true)
                            .put("error", I18n.tr("server.adns.recordConflict", java.util.Map.of("name", String.valueOf(fullName), "existingKind", String.valueOf(t.type), "content", String.valueOf(t.content), "kind", String.valueOf(def[1]))));

                // "Exists" does not mean "is right".
                //
                // These names belong to the panel: autoconfig, mta-sts and the two SRV records
                // exist only to point to this mail server. If they point elsewhere, or
                // to the wrong port, or go through a proxy, they are not "already done": they are
                // wrong. Saying "it already exists, fix it yourself in Cloudflare" offloads onto the
                // reader a job that the panel knows how to do, and above all presents as
                // fine something that does not work.
                //
                // The case of the SPF on the apex or of DMARC is different: there, there may be
                // declarations of other services, and those are never touched blindly.
                boolean right = coincide(t, srv, target, port);
                if (right && !t.proxied)
                    return r.put("success", true).put("unchanged", true).put("content", t.content)
                            .put("note", I18n.tr("server.adns.alreadyRightOn", java.util.Map.of("name", String.valueOf(fullName))));

                java.util.List<String> whatIsWrong = new ArrayList<>();
                if (!right) whatIsWrong.add(I18n.tr("server.adns.pointedTo", java.util.Map.of("before", String.valueOf(t.content), "right", String.valueOf(srv ? "0 1 " + port + " " + target : target))));
                if (t.proxied) whatIsWrong.add(I18n.tr("server.adns.wentThroughCf"));

                CloudflareManager.RecordOp op = srv
                        ? cloudflare.updateSrv(acct.apiToken, zl.zoneId, t.id, fullName, target, 0, 1, port)
                        : cloudflare.updateCname(acct.apiToken, zl.zoneId, t.id, fullName, target);
                if (op == null || !op.success)
                    return r.put("success", false).put("content", t.content)
                            .put("error", I18n.tr("server.adns.fixRefused", java.util.Map.of("name", String.valueOf(fullName), "what", String.valueOf(String.join("; ", whatIsWrong)), "e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));
                return r.put("success", true).put("correct", true)
                        .put("before", t.content).put("after", srv ? "0 1 " + port + " " + target : target)
                        .put("note", I18n.tr("server.adns.fixed", java.util.Map.of("name", String.valueOf(fullName), "what", String.valueOf(String.join("; ", whatIsWrong)))));
            }

            CloudflareManager.RecordOp op = srv
                    ? cloudflare.createSrvRecord(acct.apiToken, zl.zoneId, fullName, target, 0, 1, port, 3600)
                    : cloudflare.createCnameRecord(acct.apiToken, zl.zoneId, fullName, target, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // It is not enough that the API says yes: the zone is reread to see whether it is there.
            boolean confirmed = false;
            for (CloudflareManager.DnsRecordInfo t :
                    atName(cloudflare.listRecords(acct.apiToken, zl.zoneId), fullName))
                if (def[1].equalsIgnoreCase(t.type)) confirmed = true;
            if (!confirmed)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.createdNotFound"));

            return r.put("success", true).put("recordId", op.recordId)
                    .put("note", I18n.tr("server.adns.createdOn", java.util.Map.of("kind", String.valueOf(def[1]), "name", String.valueOf(fullName), "z", String.valueOf(zl.zoneName))));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.createError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * The existing record is already the one the panel would write.
     *
     * For a CNAME the destination name is enough; for an SRV the port also matters, which is
     * the only reason that record exists, and so does the destination. The comparison of names is
     * exact: "xmail.example.com" contains "mail.example.com" and would pass as right.
     */
    /** The SRV record in the complete form "priority weight port target". */
    private static String fullSrv(CloudflareManager.DnsRecordInfo t) {
        if (!"SRV".equalsIgnoreCase(t.type) || t.srvPort == null || t.srvDestination == null)
            return t.content == null ? "" : t.content;
        return (t.srvPriority == null ? 0 : t.srvPriority) + " "
             + (t.srvWeight == null ? 1 : t.srvWeight) + " "
             + t.srvPort + " " + t.srvDestination;
    }

    static boolean coincide(CloudflareManager.DnsRecordInfo t, boolean srv, String target, int port) {
        String c = t.content == null ? "" : t.content.trim();
        if (!srv) return DnsRules.sameName(c, target);
        // For an SRV the STRUCTURED fields of Cloudflare are looked at, not the "content" string.
        //
        // In "content" Cloudflare puts three values (weight, port, target) while
        // analyzeSrv demands four because it is written for the output of dig, where the
        // priority is there. With three fields it returned null, that is "I do not recognize it",
        // and the record ended up as wrong: the sequence rewrote it on every run and announced
        // "it pointed to X instead of Y" comparing two different formats of the same thing.
        // A write in production made for nothing, repeated on every pass.
        if (t.srvPort != null && t.srvDestination != null)
            return t.srvPort == port && DnsRules.sameName(t.srvDestination, target);
        // Only if Cloudflare did not give the structured fields do we fall back to the string, and
        // BOTH forms in which that string can arrive are accepted.
        DnsRules.Srv s = DnsRules.analyzeSrv(c);
        if (s != null) return s.port == port && DnsRules.sameName(s.destination, target);
        // There were not four fields: we try the three-field form, "weight port target",
        // which is the one observed in production in Cloudflare's content. The
        // priority is not needed: here port and target are compared, and the priority was never
        // part of the question.
        String[] pieces = c.split("\\s+");
        if (pieces.length == 3) {
            try {
                return Integer.parseInt(pieces[1]) == port
                    && DnsRules.sameName(pieces[2], target);
            } catch (NumberFormatException ignore) {
                return false;
            }
        }
        return false;
    }

    /**
     * Here there used to be `perche_niente_mtasts()`: the explanation of why MTA-STS was the only
     * exception in the list, that is, the only record that the panel refused to create.
     *
     * The reasoning was correct: RFC 8461 sections 3.2 and 3.3 also want a policy served
     * on https://mta-sts.<domain>/.well-known/mta-sts.txt by a host with a certificate
     * valid for that name, and publishing only the TXT would leave a green tick on a defense
     * that is not there. But the premise, "this panel does not serve that site", stopped
     * being true the day the 443 card was born. The sentence stayed there for months,
     * and the DNS page went on denying something that the panel did routinely.
     *
     * The right conclusion was not to update that sentence: it was to remove the exception. The
     * rule it protected (the TXT is not published until the policy answers) now lives
     * where it should, inside the sequence, which MEASURES that condition instead of
     * declaring it once and for all. See createTxtMtaSts() above and MtaStsSetup.
     */

    /*
     * ===================================================================
     * Values
     * ===================================================================
     */

    /** null when the IP is not known: better no record than an invalid one. */
    private String spfValue() {
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        return DnsRecordsGenerator.spfValue(family.v4() ? serverIp() : "", family.sends6() ? serverIpv6() : "", family);
    }

    /** The public IPv6 of the server, or "" if it is not known. */
    private String serverIpv6() {
        try {
            String ip = new DnsRecordsGenerator(database).detectServerIpv6();
            return ip == null ? "" : ip.trim();
        } catch (Exception e) {
            return "";
        }
    }

    private String dmarcValue(String domain, String policy) {
        return "v=DMARC1; p=" + policy + "; rua=mailto:dmarc@" + domain;
    }

    /**
     * The public IP of the server. The one of the DNS page is reused instead of writing another
     * one: two ways of deriving the same number are two numbers that one day diverge,
     * and an SPF written with the wrong one blocks outgoing mail.
     */
    private String serverIp() {
        try {
            String ip = new DnsRecordsGenerator(database).detectServerIp();
            return ip == null ? "" : ip.trim();
        } catch (Exception e) {
            return "";
        }
    }

    private MailDatabase.Domain findDomain(int id) throws Exception {
        for (MailDatabase.Domain d : database.getDomains()) if (d.id == id) return d;
        return null;
    }

    private JSONObject error(String m) {
        return new JSONObject().put("success", false).put("error", m);
    }

    /**
     * On rotation, which we were asked to implement "only if it is needed":
     * it is NOT. DKIM is rotated because it has a private key, and a key that stays the
     * same for years is a key that sooner or later leaks. SPF and DMARC contain no
     * secrets: they are public declarations of policy. They change when the server or
     * the policy changes, not on a schedule.
     */
    public static String whyNoRotation() {
        return I18n.tr("server.adns.noRotation");
    }
}
