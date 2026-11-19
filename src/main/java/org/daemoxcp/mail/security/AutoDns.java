package org.daemoxcp.mail.security;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.database.MailDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * Crea su Cloudflare i record SPF e DMARC, rispettando le regole delle specifiche invece di
 * limitarsi a scrivere una stringa che somiglia a un record.
 *
 * Le regole che governano questo file, tutte verificate sul testo e non a memoria:
 *
 *  - RFC 7208 §4.5 — due record SPF sullo stesso nome danno "permerror": SPF non funziona
 *    piu' del tutto. Quindi non se ne aggiunge mai un secondo, e se ce ne sono gia' due il
 *    pannello lo dice, perche' e' un guasto che nessun altro segnala.
 *  - RFC 9989 §4 — due record DMARC sullo stesso nome vengono scartati TUTTI. Stessa cosa.
 *  - RFC 9989 §5.1.4 e §5.1.5 — si comincia da "p=none", con il rua che punta a una casella
 *    che ESISTE GIA'. Partire da quarantine significa mettere in spam la propria posta prima
 *    di aver visto un solo rapporto.
 *  - RFC 9990 §4 — se l'indirizzo dei rapporti sta su un altro dominio, serve
 *    l'autorizzazione "_report._dmarc", altrimenti i rapporti non partono affatto.
 *
 * Il principio che restava valido dalla prima versione, e che qui vale ancora: **non si
 * sovrascrive mai un record esistente.** Ma ora la domanda "esiste?" e' posta sul CONTENUTO,
 * non sul nome. Prima bastava un "google-site-verification" sull'apice per far dire al
 * pannello "esiste gia' un TXT" e impedire per sempre la creazione dell'SPF: un record
 * innocuo che bloccava quello indispensabile.
 */
public class AutoDns {

    private final MailDatabase database;
    private final CloudflareManager cloudflare;

    public AutoDns(MailDatabase database, CloudflareManager cloudflare) {
        this.database = database;
        this.cloudflare = cloudflare;
    }

    /* ===================================================================
     * Lettura
     * =================================================================== */

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

            // Dove finirebbero i rapporti, e se quella cassetta esiste davvero.
            r.put("reports", reportDelivery(d));
            return r;
        } catch (Exception e) {
            return error(I18n.tr("server.adns.readState", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /** I contenuti dei TXT che stanno ESATTAMENTE su quel nome, con il loro id Cloudflare. */
    private List<CloudflareManager.TxtRecordInfo> txtAtName(String token, String zoneId, String name) {
        List<CloudflareManager.TxtRecordInfo> outside = new ArrayList<>();
        String searched = name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
        // Si chiede tutta la zona e si filtra qui: chiedere "i nomi che contengono X" per
        // l'apice restituirebbe comunque l'intera zona, perche' ogni nome finisce col dominio.
        for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(token, zoneId, null)) {
            String n = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
            if (n.equals(searched)) outside.add(t);
        }
        return outside;
    }

    /**
     * Cosa c'e' adesso su quel nome e cosa ci andrebbe. La differenza con la versione
     * precedente sta tutta qui: si separano i record DI QUEL TIPO da tutti gli altri TXT.
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

    /* ===================================================================
     * Scrittura
     * =================================================================== */

    public JSONObject create(int domainId, String which, String policy) {
        JSONObject r = new JSONObject().put("which", which);
        boolean spf = "spf".equals(which);
        if (!spf && !"dmarc".equals(which)) return error(I18n.tr("server.adns.unknownRecord", java.util.Map.of("q", String.valueOf(which))));

        // Chi non sceglie, sceglie "none": e' quello che RFC 9989 §5.1.5 chiede di fare per
        // primo, e l'unico valore che non puo' fermare posta legittima il giorno stesso.
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

            // Un SPF senza IP non e' un SPF incompleto: e' un record invalido, che fa perdere
            // a tutto il dominio la protezione che credeva di avere.
            if (value == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noIpWrite"));
            r.put("value", value);

            List<CloudflareManager.TxtRecordInfo> allItems = txtAtName(acct.apiToken, zl.zoneId, name);
            List<String> contents = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : allItems) contents.add(DnsRules.cloudflareContent(t.content));
            List<String> pertinent = spf ? DnsRules.onlySpf(contents) : DnsRules.onlyDmarc(contents);

            // Il controllo che vale piu' di tutti gli altri, ora fatto sul contenuto.
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

            // I TXT non pertinenti non sono un ostacolo: un record di verifica di un servizio
            // terzo sull'apice non ha nulla a che vedere con l'SPF, e non deve impedirlo.
            int others = allItems.size() - pertinent.size();
            if (others > 0) r.put("otherTxt", others);

            // DMARC senza una casella che riceva i rapporti e' una richiesta che rimbalza.
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

            // L'esito non e' "l'API ha detto ok": e' il record che si vede da fuori.
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
     * Cambia la politica di un record DMARC gia' pubblicato.
     *
     * Serve perche' il percorso previsto e' none -> quarantine -> reject, e senza questo il
     * pannello rendeva facile solo il primo passo, lasciando manuali i due che contano.
     *
     * La regola "non sovrascrivo mai" non viene infranta, viene precisata: si cambia UN SOLO
     * VALORE, quello del tag "p", e tutto il resto del record resta identico byte per byte.
     * Se qualcuno ci ha aggiunto "sp=", "fo=" o un secondo indirizzo nei rapporti, quelle
     * parti sopravvivono. E prima di scrivere si mostra il prima e il dopo, perche' una
     * conferma che non fa vedere cosa cambia non e' una conferma.
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

            // Non basta che l'API abbia detto di si': si rilegge la zona.
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
     * Pubblica il record TXT _mta-sts, ma SOLO se la politica risponde gia'.
     *
     * E' la regola che tiene onesto tutto il meccanismo. Quel record e' una dichiarazione
     * pubblica: dice ai server di tutto il mondo "vai a leggere la mia politica". Pubblicarlo
     * prima che la politica esista significa mandarli contro un errore, e nel frattempo
     * mostrare a chi guarda il pannello una spunta verde su una protezione che non c'e'.
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
     * Lascia su quel nome un solo record MTA-STS, con quel valore: lo crea se manca, lo
     * aggiorna se ha un altro id, toglie quelli in piu'.
     *
     * Quelli in piu' contano: con due record v=STSv1 i mittenti fanno come se MTA-STS non ci
     * fosse (RFC 8461 §3.1). Prima qui si guardava il primo record: se era gia' giusto la
     * risposta era "invariato", e l'altro restava li' a spegnere tutto.
     *
     * Si tolgono senza chiedere altro perche' il nome _mta-sts e' del pannello e il record non
     * contiene niente di scelto a mano: la versione e l'id, che segue la politica servita.
     * Quelli tolti restano scritti nella risposta.
     *
     * Sta da sola perche' le prove la verifichino con un Cloudflare finto.
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
            // Si tiene quello gia' giusto, se c'e'; se no il primo, da aggiornare.
            CloudflareManager.TxtRecordInfo keep = sts.get(0);
            for (CloudflareManager.TxtRecordInfo t : sts)
                if (DnsRules.cloudflareContent(t.content).trim().equals(value.trim())) { keep = t; break; }

            // Prima si tolgono gli altri, poi si aggiorna. Se l'aggiornamento fallisse resterebbe
            // un record solo con l'id vecchio: i mittenti lo leggono e scaricano la politica di
            // adesso. Due record, invece, non li legge nessuno.
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
                // L'id NON e' decorativo: e' il segnale con cui i mittenti si accorgono che la
                // politica e' cambiata. Un id fermo — per esempio un orologio scritto una volta
                // sola, com'era nei record suggeriti dal vecchio pannello — fa restare tutti
                // sulla politica vecchia finche' non scade la loro copia. Quindi si aggiorna.
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

        // Non basta che l'API abbia detto di si': si rilegge la zona. Lo scopo e' che ne resti
        // UNO, quindi lo si conta. Serve anche quando si e' creato: se la prima lettura fosse
        // tornata vuota per un errore di Cloudflare, il record nuovo starebbe accanto a uno
        // vecchio, e sarebbero due.
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

    /* ===================================================================
     * La cassetta dei rapporti
     * =================================================================== */

    /** L'indirizzo che il pannello scrive nel rua, e se esiste gia' come casella o alias. */
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
            // La nota NON ripete "non esiste": quello lo dice gia' l'interfaccia, e ripeterlo
            // due volte di fila fa sembrare rotto il pannello invece del DNS.
            return o.put("exists", false)
                    .put("note", I18n.tr("server.adns.ruaInside"));
        } catch (Exception e) {
            return o.put("exists", false).put("error", I18n.tr("server.adns.readBoxes", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /**
     * Crea l'alias dmarc@&lt;dominio&gt; verso una casella scelta. Nessuna scorciatoia: si
     * verifica prima che l'indirizzo non sia gia' occupato, e che la destinazione esista
     * davvero. E' esattamente il controllo che era mancato quando un "crea" ha scavalcato
     * un alias gia' in uso su un dominio che non c'entrava niente.
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

            // Whitelist di caratteri ammessi: si dichiara cosa PUO' esserci, non cosa non puo'.
            if (!dest.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.notMailAddr", java.util.Map.of("d", String.valueOf(dest))));

            // La destinazione puo' anche stare fuori dal pannello: i rapporti sono posta normale
            // e si inoltrano ovunque. Ma se sta fuori, il pannello non puo' verificare che
            // esista, e lo dice invece di lasciarlo credere.
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
     * Crea dmarc@&lt;dominio&gt; come casella vera, con una password generata dal pannello e
     * mostrata una volta sola. E' l'alternativa all'alias: separa i rapporti da tutto il
     * resto, al prezzo di una casella in piu' da guardare ogni tanto.
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

            // La password NON e' "mostrata una volta sola": addMailbox la cifra nel vault
            // (AES-256-GCM), e la pagina Caselle la rivede con "Rivela". Dirla irrecuperabile
            // sarebbe far credere a chi legge che il pannello sia meno capace di com'e'.
            return r.put("success", true).put("mailboxId", id).put("password", password)
                    .put("note", I18n.tr("server.adns.boxCreated", java.util.Map.of("a", String.valueOf(address), "dom", String.valueOf(d.domain))));
        } catch (Exception e) {
            return error(I18n.tr("server.adns.boxError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("AutoDns", e))));
        }
    }

    /** Password robusta da un alfabeto dichiarato, senza caratteri che si confondono a occhio. */
    private static String randomPassword() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        java.security.SecureRandom random = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        return sb.toString();
    }

    /**
     * Tutte le caselle vere del pannello, per la tendina della destinazione. La
     * destinazione si SCEGLIE da un elenco: un campo libero e' un modo per scrivere un
     * indirizzo che non esiste e accorgersene mesi dopo, quando serviva un rapporto.
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

    /* ===================================================================
     * I record opzionali
     * =================================================================== */

    /**
     * Quelli che il pannello sa creare da solo. Sono "opzionali" nel senso che la posta
     * funziona anche senza, non nel senso che non servano: senza autoconfig e i due SRV,
     * chi aggiunge la casella deve sapere a memoria server, porte e tipo di cifratura.
     *
     * Attenzione a una differenza che non si vede dal nome: i due SRV funzionano DA SOLI
     * (RFC 6186 §4: il client interroga il DNS e da li' ricava host e porta), mentre
     * autoconfig e' solo l'indirizzo a cui il client va a cercare un file di configurazione.
     *
     * "autodiscover" NON c'e' piu': serviva solo a Outlook, che qui non si usa. Era un
     * record che il pannello proponeva, il certificato includeva e la verifica segnava in
     * rosso, per un client che non entrera' mai in questo server. Una riga che non serve a
     * nessuno e' comunque una riga che qualcuno un giorno cerca di capire.
     *
     * chiave | tipo | nome relativo | porta (0 se non SRV) | a cosa serve | premessa mancante
     */
    private static final String[][] OPTIONAL_ITEMS = {
        { "autoconfig",     "CNAME", "autoconfig",       "0",
          "server.adns.opt.autoconfigWhat",
          // Questa nota diceva "questo pannello quel file non lo serve" e mandava i client sui
          // due SRV. Erano due affermazioni false nello stesso periodo, e la pagina si
          // contraddiceva da sola: la scheda della configurazione automatica, poche righe piu'
          // giu', misura che il file arriva — e spiega che Thunderbird gli SRV non li legge.
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

    /** L'hostname del server di posta, letto dove lo legge la pagina DNS e non altrove. */
    private String mailHost(String domain) {
        try {
            return database.getSetting("mail_hostname", "mail." + domain);
        } catch (Exception e) {
            return "mail." + domain;
        }
    }

    /** Tutti i record della zona che stanno esattamente su quel nome, di qualunque tipo. */
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
                    // Un SRV si mostra INTERO. Mostrando il solo "content" la colonna diceva
                    // "1 993 mail.domain-b.test" accanto alla proposta "0 1 993 mail.domain-b.test",
                    // e le due sembravano diverse mentre erano lo stesso record scritto in due
                    // formati: manca solo la priorita', che Cloudflare tiene da parte.
                    sb.append(fullSrv(t));
                    if (t.proxied) sb.append("  (").append(I18n.tr("server.adns.proxiedTag")).append(")");
                }
                j.put("content", sb.toString());
                boolean proxied = false;
                for (CloudflareManager.DnsRecordInfo t : sameKind) if (t.proxied) proxied = true;
                if (proxied)
                    j.put("warning", I18n.tr("server.adns.proxied"));
            } else if (!otherKind.isEmpty()) {
                // Il DNS non ammette un CNAME accanto ad altri dati sullo stesso nome.
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
     * Crea uno dei record opzionali. Stesse regole degli altri: non si sovrascrive niente,
     * e l'esito si verifica rileggendo la zona invece di fidarsi della risposta dell'API.
     */
    public JSONObject createOptional(int domainId, String key) {
        JSONObject r = new JSONObject().put("which", key);
        String[] def = definition(key);
        if (def == null) return error(I18n.tr("server.adns.unknownOptional", java.util.Map.of("k", String.valueOf(key))));
        try {
            MailDatabase.Domain d = findDomain(domainId);
            if (d == null) return error(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            // "non posso occuparmene" non e' "ho fallito": chi chiama deve poter distinguere
            // i due casi, altrimenti finisce per dare un errore rosso a una configurazione
            // legittima — o, peggio, per dare un verde a una che non ha controllato.
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

                // "Esiste" non vuol dire "e' giusto".
                //
                // Questi nomi appartengono al pannello: autoconfig, mta-sts e i due SRV
                // esistono solo per puntare a questo server di posta. Se puntano altrove, o
                // sulla porta sbagliata, o passano da un proxy, non sono "gia' fatti": sono
                // sbagliati. Dire "esiste gia', correggilo tu in Cloudflare" scarica su chi
                // legge un lavoro che il pannello sa fare, e soprattutto presenta come a
                // posto una cosa che non funziona.
                //
                // Diverso e' il caso dell'SPF sull'apice o del DMARC: li' possono esserci
                // dichiarazioni di altri servizi, e quelli non si toccano mai alla cieca.
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

            // Non basta che l'API dica di si': si rilegge la zona e si guarda se c'e'.
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
     * Il record esistente e' gia' quello che il pannello scriverebbe.
     *
     * Per un CNAME basta il nome di destinazione; per un SRV contano anche la porta, che e'
     * l'unica ragione per cui quel record esiste, e la destinazione. Il confronto sui nomi e'
     * esatto: "xmail.esempio.it" contiene "mail.esempio.it" e passerebbe per giusto.
     */
    /** Il record SRV nella forma completa "priorita' peso porta destinazione". */
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
        // Per un SRV si guardano i campi STRUTTURATI di Cloudflare, non la stringa "content".
        //
        // In "content" Cloudflare mette tre valori — peso, porta, destinazione — mentre
        // analyzeSrv ne pretende quattro perche' e' scritta per l'uscita di dig, dove la
        // priorita' c'e'. Con tre campi tornava null, cioe' "non lo riconosco", e il record
        // finiva per sbagliato: la sequenza lo riscriveva a ogni esecuzione e annunciava
        // "puntava a X invece che a Y" confrontando due formati diversi della stessa cosa.
        // Una scrittura in produzione fatta per niente, ripetuta a ogni passaggio.
        if (t.srvPort != null && t.srvDestination != null)
            return t.srvPort == port && DnsRules.sameName(t.srvDestination, target);
        // Solo se Cloudflare non desse i campi strutturati si torna alla stringa, e si
        // accettano ENTRAMBE le forme in cui quella stringa puo' arrivare.
        DnsRules.Srv s = DnsRules.analyzeSrv(c);
        if (s != null) return s.port == port && DnsRules.sameName(s.destination, target);
        // Quattro campi non ce n'erano: proviamo la forma a tre, "peso porta destinazione",
        // che e' quella osservata in produzione nel content di Cloudflare. Non serve la
        // priorita': qui si confrontano porta e destinazione, e la priorita' non e' mai
        // stata parte della domanda.
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
     * Qui c'era perche_niente_mtasts(): la spiegazione del perche' MTA-STS fosse l'unica
     * eccezione dell'elenco, cioe' l'unico record che il pannello si rifiutava di creare.
     *
     * Il ragionamento era corretto — RFC 8461 §3.2 e §3.3 vogliono anche una politica servita
     * su https://mta-sts.<dominio>/.well-known/mta-sts.txt da un host con un certificato
     * valido per quel nome, e pubblicare il solo TXT lascerebbe una spunta verde su una difesa
     * che non c'e'. Ma la premessa, "questo pannello quel sito non lo serve", ha smesso di
     * essere vera il giorno in cui e' nata la scheda della 443. La frase e' rimasta li' mesi,
     * e la pagina DNS ha continuato a negare una cosa che il pannello faceva di routine.
     *
     * La conclusione giusta non era aggiornare quella frase: era togliere l'eccezione. La
     * regola che proteggeva — il TXT non si pubblica finche' la politica non risponde — vive
     * adesso dove deve, dentro la sequenza, che quella condizione la MISURA invece di
     * dichiararla una volta per tutte. Vedi createTxtMtaSts() qui sopra e MtaStsSetup.
     */

    /* ===================================================================
     * Valori
     * =================================================================== */

    /** null quando l'IP non si conosce: meglio nessun record che uno invalido. */
    private String spfValue() {
        org.daemoxcp.mail.system.IpFamily.Family family = org.daemoxcp.mail.system.IpFamily.effective();
        return DnsRecordsGenerator.spfValue(family.v4() ? serverIp() : "", family.sends6() ? serverIpv6() : "", family);
    }

    /** L'IPv6 pubblico del server, o "" se non lo si conosce. */
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
     * L'IP pubblico del server. Si riusa quello della pagina DNS invece di scriverne un
     * altro: due modi di ricavare lo stesso numero sono due numeri che un giorno divergono,
     * e un SPF scritto con quello sbagliato blocca la posta in uscita.
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
     * Sulla rotazione, che e' stato chiesto di implementare "solo se ce n'e' bisogno":
     * NON ce n'e'. DKIM si ruota perche' ha una chiave privata, e una chiave che resta la
     * stessa per anni e' una chiave che prima o poi trapela. SPF e DMARC non contengono
     * segreti: sono dichiarazioni pubbliche di politica. Cambiano quando cambia il server o
     * la politica, non a scadenza.
     */
    public static String whyNoRotation() {
        return I18n.tr("server.adns.noRotation");
    }
}
