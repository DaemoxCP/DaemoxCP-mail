package org.mail_panel.security;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

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

    public JSONObject stato(int domainId) {
        JSONObject r = new JSONObject().put("success", true);
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            r.put("dominio", d.domain);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null)
                return r.put("cloudflare", false)
                        .put("nota", I18n.tr("server.adns.noAccount", java.util.Map.of("d", String.valueOf(d.domain))));
            r.put("cloudflare", true).put("account", acct.label);

            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found)
                return r.put("zona", false)
                        .put("nota", I18n.tr("server.adns.zoneNotSeen", java.util.Map.of("a", String.valueOf(acct.label), "d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));
            r.put("zona", true).put("zoneId", zl.zoneId);

            JSONArray record = new JSONArray();
            record.put(descrivi(acct.apiToken, zl.zoneId, "spf", d));
            record.put(descrivi(acct.apiToken, zl.zoneId, "dmarc", d));
            r.put("record", record);
            r.put("opzionali", statoOpzionali(acct.apiToken, zl.zoneId, d));

            // Dove finirebbero i rapporti, e se quella cassetta esiste davvero.
            r.put("rapporti", recapitoRapporti(d));
            return r;
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.readState", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /** I contenuti dei TXT che stanno ESATTAMENTE su quel nome, con il loro id Cloudflare. */
    private List<CloudflareManager.TxtRecordInfo> txtAlNome(String token, String zoneId, String nome) {
        List<CloudflareManager.TxtRecordInfo> fuori = new ArrayList<>();
        String cercato = nome.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
        // Si chiede tutta la zona e si filtra qui: chiedere "i nomi che contengono X" per
        // l'apice restituirebbe comunque l'intera zona, perche' ogni nome finisce col dominio.
        for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(token, zoneId, null)) {
            String n = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
            if (n.equals(cercato)) fuori.add(t);
        }
        return fuori;
    }

    /**
     * Cosa c'e' adesso su quel nome e cosa ci andrebbe. La differenza con la versione
     * precedente sta tutta qui: si separano i record DI QUEL TIPO da tutti gli altri TXT.
     */
    private JSONObject descrivi(String token, String zoneId, String quale, MailDatabase.Domain d) {
        boolean spf = "spf".equals(quale);
        String nome = spf ? d.domain : "_dmarc." + d.domain;
        JSONObject o = new JSONObject().put("quale", quale).put("nome", nome);

        String proposto = spf ? valoreSpf() : valoreDmarc(d.domain, "none");
        if (proposto == null) {
            o.put("proposto", JSONObject.NULL)
             .put("bloccato", I18n.tr("server.adns.noIpSpf"));
        } else {
            o.put("proposto", proposto);
        }

        List<CloudflareManager.TxtRecordInfo> tutti = txtAlNome(token, zoneId, nome);
        List<String> contenuti = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : tutti) contenuti.add(DnsRules.contenutoCloudflare(t.content));

        List<String> pertinenti = spf ? DnsRules.soloSpf(contenuti) : DnsRules.soloDmarc(contenuti);
        o.put("quanti", pertinenti.size())
         .put("esiste", !pertinenti.isEmpty())
         .put("altriTxt", tutti.size() - pertinenti.size());

        if (!pertinenti.isEmpty()) {
            o.put("contenuto", String.join("  ||  ", pertinenti));
            for (CloudflareManager.TxtRecordInfo t : tutti)
                if (pertinenti.contains(DnsRules.contenutoCloudflare(t.content))) { o.put("recordId", t.id); break; }
        }

        JSONArray avvisi = new JSONArray();
        if (pertinenti.size() > 1)
            avvisi.put(spf
                ? I18n.tr("server.adns.multiSpf", java.util.Map.of("n", String.valueOf(pertinenti.size())))
                : I18n.tr("server.adns.multiDmarc", java.util.Map.of("n", String.valueOf(pertinenti.size()))));

        if (!pertinenti.isEmpty()) {
            if (spf) {
                DnsRules.EsitoSpf e = DnsRules.analizzaSpf(contenuti, ipDelServer());
                for (String x : e.avvisi) avvisi.put(x);
                if (e.valido && !e.autorizzaEsplicito && !e.viaMx && !e.viaA && e.include == 0)
                    avvisi.put(I18n.tr("server.adns.spfNotAuth", java.util.Map.of("ip", String.valueOf(ipDelServer()))));
            } else {
                DnsRules.EsitoDmarc e = DnsRules.analizzaDmarc(contenuti, d.domain);
                if (e.valido) o.put("politicaAttuale", e.politica == null ? "none" : e.politica);
                for (String x : e.avvisi) avvisi.put(x);
                if (!e.daAutorizzare.isEmpty())
                    avvisi.put(I18n.tr("server.adns.ruaOutside", java.util.Map.of("r", String.valueOf(String.join(", ", e.daAutorizzare)))));
            }
        }
        o.put("avvisi", avvisi);
        return o;
    }

    /* ===================================================================
     * Scrittura
     * =================================================================== */

    public JSONObject crea(int domainId, String quale, String politica) {
        JSONObject r = new JSONObject().put("quale", quale);
        boolean spf = "spf".equals(quale);
        if (!spf && !"dmarc".equals(quale)) return errore(I18n.tr("server.adns.unknownRecord", java.util.Map.of("q", String.valueOf(quale))));

        // Chi non sceglie, sceglie "none": e' quello che RFC 9989 §5.1.5 chiede di fare per
        // primo, e l'unico valore che non puo' fermare posta legittima il giorno stesso.
        String pol = (politica == null || politica.isBlank()) ? "none" : politica.trim().toLowerCase(java.util.Locale.ROOT);
        if (!spf && !List.of("none", "quarantine", "reject").contains(pol))
            return errore(I18n.tr("server.adns.badDmarcPolicy"));

        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            String nome = spf ? d.domain : "_dmarc." + d.domain;
            String valore = spf ? valoreSpf() : valoreDmarc(d.domain, pol);
            r.put("nome", nome).put("dominio", d.domain).put("account", acct.label);

            // Un SPF senza IP non e' un SPF incompleto: e' un record invalido, che fa perdere
            // a tutto il dominio la protezione che credeva di avere.
            if (valore == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noIpWrite"));
            r.put("valore", valore);

            List<CloudflareManager.TxtRecordInfo> tutti = txtAlNome(acct.apiToken, zl.zoneId, nome);
            List<String> contenuti = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : tutti) contenuti.add(DnsRules.contenutoCloudflare(t.content));
            List<String> pertinenti = spf ? DnsRules.soloSpf(contenuti) : DnsRules.soloDmarc(contenuti);

            // Il controllo che vale piu' di tutti gli altri, ora fatto sul contenuto.
            if (!pertinenti.isEmpty())
                return r.put("success", false).put("esisteGia", true)
                        .put("contenuto", String.join("  ||  ", pertinenti))
                        .put("error", (pertinenti.size() == 1
                                   ? I18n.tr("server.adns.existsOne", java.util.Map.of("nome", String.valueOf(nome), "tipo", String.valueOf(spf ? "SPF" : "DMARC")))
                                   : I18n.tr("server.adns.existsMany", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf(pertinenti.size()), "tipo", String.valueOf(spf ? "SPF" : "DMARC")))) + " "
                                + (pertinenti.size() > 1
                                   ? (spf ? I18n.tr("server.adns.tooManySpf")
                                          : I18n.tr("server.adns.tooManyDmarc"))
                                   : (spf ? I18n.tr("server.adns.spfOthers", java.util.Map.of("ip", String.valueOf(ipDelServer())))
                                          : I18n.tr("server.adns.dmarcOld"))));

            // I TXT non pertinenti non sono un ostacolo: un record di verifica di un servizio
            // terzo sull'apice non ha nulla a che vedere con l'SPF, e non deve impedirlo.
            int altri = tutti.size() - pertinenti.size();
            if (altri > 0) r.put("altriTxt", altri);

            // DMARC senza una casella che riceva i rapporti e' una richiesta che rimbalza.
            if (!spf) {
                JSONObject rec = recapitoRapporti(d);
                r.put("rapporti", rec);
                if (!rec.optBoolean("esiste", false))
                    return r.put("success", false).put("mancaCasella", true)
                            .put("error", I18n.tr("server.adns.ruaMissing", java.util.Map.of("a", String.valueOf(rec.optString("indirizzo")))));
            }

            CloudflareManager.RecordOp op = cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, nome, valore, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // L'esito non e' "l'API ha detto ok": e' il record che si vede da fuori.
            return r.put("success", true).put("recordId", op.recordId)
                    .put("nota", I18n.tr("server.adns.created", java.util.Map.of("z", String.valueOf(zl.zoneName)))
                            + (spf ? "" : " " + ("none".equals(pol)
                                ? I18n.tr("server.adns.policyNone", java.util.Map.of("p", String.valueOf(pol)))
                                : I18n.tr("server.adns.policyActive", java.util.Map.of("p", String.valueOf(pol))))));
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.createError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
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
    public JSONObject cambiaPolitica(int domainId, String nuova, boolean confermato) {
        JSONObject r = new JSONObject();
        String n = nuova == null ? "" : nuova.trim().toLowerCase(java.util.Locale.ROOT);
        if (!java.util.List.of("none", "quarantine", "reject").contains(n))
            return errore(I18n.tr("server.adns.badPolicy"));
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            String nome = "_dmarc." + d.domain;
            r.put("nome", nome).put("dominio", d.domain).put("nuovaPolitica", n);

            CloudflareManager.TxtRecordInfo bersaglio = null;
            java.util.List<String> dmarc = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (!nm.equals(nome.toLowerCase(java.util.Locale.ROOT))) continue;
                String contenuto = DnsRules.contenutoCloudflare(t.content);
                if (DnsRules.eDmarc(contenuto)) { dmarc.add(contenuto); bersaglio = t; }
            }

            if (dmarc.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noDmarcToEdit", java.util.Map.of("nome", String.valueOf(nome))));
            if (dmarc.size() > 1)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.manyDmarcEdit", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf(dmarc.size()))));

            String prima = DnsRules.contenutoCloudflare(bersaglio.content);
            String dopo = DnsRules.cambiaPolitica(prima, n);
            if (dopo == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cannotEdit", java.util.Map.of("v", String.valueOf(prima))));
            r.put("prima", prima).put("dopo", dopo);

            if (prima.equals(dopo))
                return r.put("success", true).put("invariato", true)
                        .put("nota", I18n.tr("server.adns.policySame", java.util.Map.of("p", String.valueOf(n))));

            if (!confermato)
                return r.put("success", true).put("anteprima", true)
                        .put("nota", I18n.tr("server.adns.onlyP"));

            CloudflareManager.RecordOp op = cloudflare.updateTxtRecord(
                    acct.apiToken, zl.zoneId, bersaglio.id, nome, dopo, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefusedEdit", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // Non basta che l'API abbia detto di si': si rilegge la zona.
            String verificato = null;
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (nm.equals(nome.toLowerCase(java.util.Locale.ROOT))) {
                    String c = DnsRules.contenutoCloudflare(t.content);
                    if (DnsRules.eDmarc(c)) verificato = c;
                }
            }
            if (verificato == null || !verificato.equals(dopo))
                return r.put("success", false).put("riletto", verificato == null ? "" : verificato)
                        .put("error", I18n.tr("server.adns.notChanged"));

            return r.put("success", true)
                    .put("nota", I18n.tr("server.adns.policySet", java.util.Map.of("p", String.valueOf(n), "nome", String.valueOf(nome))) + " "
                            + ("reject".equals(n)
                               ? I18n.tr("server.adns.rejectNow")
                               : "quarantine".equals(n)
                               ? I18n.tr("server.adns.quarantineNow")
                               : I18n.tr("server.adns.noneNow"))
                            + " " + I18n.tr("server.adns.propagation"));
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.editError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
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
    public JSONObject creaTxtMtaSts(int domainId) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            String nome = "_mta-sts." + d.domain;
            r.put("nome", nome).put("dominio", d.domain);

            JSONObject pubb = org.mail_panel.system.MtaSts.pubblicabile(d.domain);
            r.put("prova", pubb.optJSONObject("prova"));
            if (!pubb.optBoolean("pubblicabile", false))
                return r.put("success", false).put("error", pubb.optString("motivo"));

            String valore = pubb.getString("valore");
            r.put("valore", valore);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))));
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))));

            return allineaTxtMtaSts(acct.apiToken, zl.zoneId, nome, valore, r);
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.createError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
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
    JSONObject allineaTxtMtaSts(String token, String zoneId, String nome, String valore, JSONObject r) {
        List<CloudflareManager.TxtRecordInfo> sts = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : txtAlNome(token, zoneId, nome))
            if (DnsRules.eMtaSts(DnsRules.contenutoCloudflare(t.content))) sts.add(t);

        List<String> tolti = new ArrayList<>();
        String prima = null;
        if (sts.isEmpty()) {
            CloudflareManager.RecordOp op = cloudflare.createTxtRecord(token, zoneId, nome, valore, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));
            r.put("recordId", op.recordId);
        } else {
            // Si tiene quello gia' giusto, se c'e'; se no il primo, da aggiornare.
            CloudflareManager.TxtRecordInfo tieni = sts.get(0);
            for (CloudflareManager.TxtRecordInfo t : sts)
                if (DnsRules.contenutoCloudflare(t.content).trim().equals(valore.trim())) { tieni = t; break; }

            // Prima si tolgono gli altri, poi si aggiorna. Se l'aggiornamento fallisse resterebbe
            // un record solo con l'id vecchio: i mittenti lo leggono e scaricano la politica di
            // adesso. Due record, invece, non li legge nessuno.
            for (CloudflareManager.TxtRecordInfo t : sts) {
                if (t == tieni) continue;
                String c = DnsRules.contenutoCloudflare(t.content);
                CloudflareManager.RecordOp del = cloudflare.deleteRecord(token, zoneId, t.id);
                if (del == null || !del.success)
                    return r.put("success", false).put("tolti", new JSONArray(tolti))
                            .put("error", I18n.tr("server.adns.stsManyDelFail", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf(sts.size()), "c", String.valueOf(c), "e", String.valueOf(del == null ? I18n.tr("server.adns.noAnswer") : del.error)))
                                    + (tolti.isEmpty() ? "." : ". " + I18n.tr("server.adns.removedSoFar", java.util.Map.of("elenco", String.valueOf(String.join("  ||  ", tolti))))));
                tolti.add(c);
            }

            String c = DnsRules.contenutoCloudflare(tieni.content);
            if (!c.trim().equals(valore.trim())) {
                // L'id NON e' decorativo: e' il segnale con cui i mittenti si accorgono che la
                // politica e' cambiata. Un id fermo — per esempio un orologio scritto una volta
                // sola, com'era nei record suggeriti dal vecchio pannello — fa restare tutti
                // sulla politica vecchia finche' non scade la loro copia. Quindi si aggiorna.
                CloudflareManager.RecordOp up = cloudflare.updateTxtRecord(
                        token, zoneId, tieni.id, nome, valore, 3600);
                if (up == null || !up.success)
                    return r.put("success", false).put("contenuto", c).put("tolti", new JSONArray(tolti))
                            .put("error", I18n.tr("server.adns.stsUpdateFail", java.util.Map.of("nome", String.valueOf(nome), "c", String.valueOf(c), "e", String.valueOf(up == null ? I18n.tr("server.adns.noAnswer") : up.error)))
                                    + (tolti.isEmpty() ? "" : ". " + I18n.tr("server.adns.othersRemoved", java.util.Map.of("elenco", String.valueOf(String.join("  ||  ", tolti))))));
                prima = c;
            } else if (tolti.isEmpty()) {
                return r.put("success", true).put("invariato", true).put("contenuto", c)
                        .put("nota", I18n.tr("server.adns.alreadyRight", java.util.Map.of("nome", String.valueOf(nome))));
            }
        }

        // Non basta che l'API abbia detto di si': si rilegge la zona. Lo scopo e' che ne resti
        // UNO, quindi lo si conta. Serve anche quando si e' creato: se la prima lettura fosse
        // tornata vuota per un errore di Cloudflare, il record nuovo starebbe accanto a uno
        // vecchio, e sarebbero due.
        List<String> restano = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : txtAlNome(token, zoneId, nome)) {
            String c = DnsRules.contenutoCloudflare(t.content);
            if (DnsRules.eMtaSts(c)) restano.add(c.trim());
        }
        if (!tolti.isEmpty()) r.put("tolti", new JSONArray(tolti));
        if (prima != null) r.put("aggiornato", true).put("prima", prima).put("dopo", valore);
        if (restano.size() != 1 || !restano.get(0).equals(valore.trim()))
            return r.put("success", false).put("riletto", String.join("  ||  ", restano))
                    .put("error", (restano.isEmpty()
                               ? I18n.tr("server.adns.stsReadNone", java.util.Map.of("nome", String.valueOf(nome)))
                               : restano.size() == 1
                               ? I18n.tr("server.adns.stsReadOne", java.util.Map.of("nome", String.valueOf(nome), "v", String.valueOf(restano.get(0))))
                               : I18n.tr("server.adns.stsReadMany", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf(restano.size()), "elenco", String.valueOf(String.join("  ||  ", restano)))))
                            + " " + I18n.tr("server.adns.lookBeforeRetry"));

        String nota;
        if (!tolti.isEmpty())
            nota = I18n.tr("server.adns.stsCleaned", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf(sts.size()), "elenco", String.valueOf(String.join("  ||  ", tolti))));
        else if (prima != null)
            nota = I18n.tr("server.adns.stsUpdated", java.util.Map.of("nome", String.valueOf(nome)));
        else
            nota = I18n.tr("server.adns.stsPublished", java.util.Map.of("nome", String.valueOf(nome)));
        return r.put("success", true).put("nota", nota);
    }

    /* ===================================================================
     * La cassetta dei rapporti
     * =================================================================== */

    /** L'indirizzo che il pannello scrive nel rua, e se esiste gia' come casella o alias. */
    public JSONObject recapitoRapporti(MailDatabase.Domain d) {
        JSONObject o = new JSONObject();
        String indirizzo = "dmarc@" + d.domain;
        o.put("indirizzo", indirizzo).put("dominio", d.domain);
        try {
            for (MailDatabase.Mailbox m : database.getMailboxes(d.id))
                if (m.email != null && m.email.equalsIgnoreCase(indirizzo))
                    return o.put("esiste", true).put("tipo", "casella");
            for (MailDatabase.Alias a : database.getAliases(d.id))
                if (a.source != null && a.source.equalsIgnoreCase(indirizzo))
                    return o.put("esiste", true).put("tipo", "alias")
                            .put("verso", a.destination == null ? "" : a.destination);
            // La nota NON ripete "non esiste": quello lo dice gia' l'interfaccia, e ripeterlo
            // due volte di fila fa sembrare rotto il pannello invece del DNS.
            return o.put("esiste", false)
                    .put("nota", I18n.tr("server.adns.ruaInside"));
        } catch (Exception e) {
            return o.put("esiste", false).put("errore", I18n.tr("server.adns.readBoxes", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Crea l'alias dmarc@&lt;dominio&gt; verso una casella scelta. Nessuna scorciatoia: si
     * verifica prima che l'indirizzo non sia gia' occupato, e che la destinazione esista
     * davvero. E' esattamente il controllo che era mancato quando un "crea" ha scavalcato
     * un alias gia' in uso su un dominio che non c'entrava niente.
     */
    public JSONObject creaAliasRapporti(int domainId, String destinazione) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            String indirizzo = "dmarc@" + d.domain;
            r.put("indirizzo", indirizzo).put("dominio", d.domain).put("verso", destinazione);

            if (destinazione == null || destinazione.isBlank())
                return errore(I18n.tr("server.adns.needDest"));
            String dest = destinazione.trim();
            if (dest.indexOf('@') < 0) return errore(I18n.tr("server.adns.destNotAddr", java.util.Map.of("d", String.valueOf(dest))));
            if (dest.equalsIgnoreCase(indirizzo))
                return errore(I18n.tr("server.adns.destLoop"));

            JSONObject gia = recapitoRapporti(d);
            if (gia.optBoolean("esiste", false))
                return r.put("success", false).put("esisteGia", true)
                        .put("error", I18n.tr("server.adns.existsAs", java.util.Map.of("indirizzo", String.valueOf(indirizzo), "tipo", String.valueOf(gia.optString("tipo")), "verso", String.valueOf(gia.has("verso") ? " (" + I18n.tr("server.adns.toAddr", java.util.Map.of("v", String.valueOf(gia.optString("verso")))) + ")" : ""))));

            // Whitelist di caratteri ammessi: si dichiara cosa PUO' esserci, non cosa non puo'.
            if (!dest.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.notMailAddr", java.util.Map.of("d", String.valueOf(dest))));

            // La destinazione puo' anche stare fuori dal pannello: i rapporti sono posta normale
            // e si inoltrano ovunque. Ma se sta fuori, il pannello non puo' verificare che
            // esista, e lo dice invece di lasciarlo credere.
            boolean interna = false;
            for (MailDatabase.Domain dom : database.getDomains())
                for (MailDatabase.Mailbox m : database.getMailboxes(dom.id))
                    if (m.email != null && m.email.equalsIgnoreCase(dest)) interna = true;
            r.put("destinazioneInterna", interna);

            int id = database.addAlias(d.id, indirizzo, dest);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.adns.aliasNotCreated"));

            JSONObject dopo = recapitoRapporti(d);
            if (!dopo.optBoolean("esiste", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.aliasNotReread"));

            return r.put("success", true).put("aliasId", id)
                    .put("nota", I18n.tr("server.adns.aliasCreated", java.util.Map.of("a", String.valueOf(indirizzo), "d", String.valueOf(dest), "dom", String.valueOf(d.domain)))
                            + (interna ? "" : " " + I18n.tr("server.adns.aliasExternal", java.util.Map.of("d", String.valueOf(dest)))));
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.aliasError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Crea dmarc@&lt;dominio&gt; come casella vera, con una password generata dal pannello e
     * mostrata una volta sola. E' l'alternativa all'alias: separa i rapporti da tutto il
     * resto, al prezzo di una casella in piu' da guardare ogni tanto.
     */
    public JSONObject creaCasellaRapporti(int domainId) {
        JSONObject r = new JSONObject();
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            String indirizzo = "dmarc@" + d.domain;
            r.put("indirizzo", indirizzo).put("dominio", d.domain);

            JSONObject gia = recapitoRapporti(d);
            if (gia.optBoolean("esiste", false))
                return r.put("success", false).put("esisteGia", true)
                        .put("error", I18n.tr("server.adns.existsAsShort", java.util.Map.of("indirizzo", String.valueOf(indirizzo), "tipo", String.valueOf(gia.optString("tipo")), "verso", String.valueOf(gia.has("verso") ? " (" + I18n.tr("server.adns.toAddr", java.util.Map.of("v", String.valueOf(gia.optString("verso")))) + ")" : ""))));

            String password = passwordCasuale();
            int id = database.addMailbox(d.id, indirizzo, password, I18n.tr("server.adns.dmarcBoxName", java.util.Map.of("d", String.valueOf(d.domain))), 512);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.adns.boxNotCreated"));

            JSONObject dopo = recapitoRapporti(d);
            if (!dopo.optBoolean("esiste", false))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.boxNotReread"));

            // La password NON e' "mostrata una volta sola": addMailbox la cifra nel vault
            // (AES-256-GCM), e la pagina Caselle la rivede con "Rivela". Dirla irrecuperabile
            // sarebbe far credere a chi legge che il pannello sia meno capace di com'e'.
            return r.put("success", true).put("mailboxId", id).put("password", password)
                    .put("nota", I18n.tr("server.adns.boxCreated", java.util.Map.of("a", String.valueOf(indirizzo), "dom", String.valueOf(d.domain))));
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.boxError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /** Password robusta da un alfabeto dichiarato, senza caratteri che si confondono a occhio. */
    private static String passwordCasuale() {
        String alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 24; i++) sb.append(alfabeto.charAt(rnd.nextInt(alfabeto.length())));
        return sb.toString();
    }

    /**
     * Tutte le caselle vere del pannello, per la tendina della destinazione. La
     * destinazione si SCEGLIE da un elenco: un campo libero e' un modo per scrivere un
     * indirizzo che non esiste e accorgersene mesi dopo, quando serviva un rapporto.
     */
    public JSONObject caselleDisponibili() {
        JSONObject r = new JSONObject().put("success", true);
        JSONArray elenco = new JSONArray();
        try {
            for (MailDatabase.Domain dom : database.getDomains())
                for (MailDatabase.Mailbox m : database.getMailboxes(dom.id))
                    if (m.email != null && !m.email.isBlank()) elenco.put(m.email);
            return r.put("caselle", elenco);
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.readMailboxes", java.util.Map.of("m", String.valueOf(e.getMessage()))));
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
    private static final String[][] OPZIONALI = {
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

    private static String[] definizione(String chiave) {
        for (String[] o : OPZIONALI) if (o[0].equals(chiave)) return o;
        return null;
    }

    /** L'hostname del server di posta, letto dove lo legge la pagina DNS e non altrove. */
    private String hostDiPosta(String dominio) {
        try {
            return database.getSetting("mail_hostname", "mail." + dominio);
        } catch (Exception e) {
            return "mail." + dominio;
        }
    }

    /** Tutti i record della zona che stanno esattamente su quel nome, di qualunque tipo. */
    private java.util.List<CloudflareManager.DnsRecordInfo> alNome(
            java.util.List<CloudflareManager.DnsRecordInfo> tutti, String nome) {
        java.util.List<CloudflareManager.DnsRecordInfo> fuori = new ArrayList<>();
        String cercato = nome.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
        for (CloudflareManager.DnsRecordInfo t : tutti) {
            String n = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
            if (n.equals(cercato)) fuori.add(t);
        }
        return fuori;
    }

    private JSONArray statoOpzionali(String token, String zoneId, MailDatabase.Domain d) {
        JSONArray out = new JSONArray();
        java.util.List<CloudflareManager.DnsRecordInfo> tutti = cloudflare.listRecords(token, zoneId);
        String bersaglio = hostDiPosta(d.domain);
        for (String[] o : OPZIONALI) {
            String nomePieno = o[2] + "." + d.domain;
            JSONObject j = new JSONObject()
                    .put("quale", o[0]).put("tipo", o[1]).put("nome", nomePieno)
                    .put("aCosaServe", I18n.tr(o[4]))
                    .put("premessa", o[5].isEmpty() ? "" : I18n.tr(o[5]))
                    .put("proposto", "SRV".equals(o[1])
                            ? "0 1 " + o[3] + " " + bersaglio
                            : bersaglio);

            java.util.List<CloudflareManager.DnsRecordInfo> qui = alNome(tutti, nomePieno);
            java.util.List<CloudflareManager.DnsRecordInfo> stessoTipo = new ArrayList<>();
            java.util.List<CloudflareManager.DnsRecordInfo> altroTipo = new ArrayList<>();
            for (CloudflareManager.DnsRecordInfo t : qui)
                (o[1].equalsIgnoreCase(t.type) ? stessoTipo : altroTipo).add(t);

            j.put("esiste", !stessoTipo.isEmpty());
            if (!stessoTipo.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (CloudflareManager.DnsRecordInfo t : stessoTipo) {
                    if (sb.length() > 0) sb.append("  ||  ");
                    // Un SRV si mostra INTERO. Mostrando il solo "content" la colonna diceva
                    // "1 993 mail.domain-b.test" accanto alla proposta "0 1 993 mail.domain-b.test",
                    // e le due sembravano diverse mentre erano lo stesso record scritto in due
                    // formati: manca solo la priorita', che Cloudflare tiene da parte.
                    sb.append(srvIntero(t));
                    if (t.proxied) sb.append("  (proxato)");
                }
                j.put("contenuto", sb.toString());
                boolean proxato = false;
                for (CloudflareManager.DnsRecordInfo t : stessoTipo) if (t.proxied) proxato = true;
                if (proxato)
                    j.put("avviso", I18n.tr("server.adns.proxied"));
            } else if (!altroTipo.isEmpty()) {
                // Il DNS non ammette un CNAME accanto ad altri dati sullo stesso nome.
                StringBuilder sb = new StringBuilder();
                for (CloudflareManager.DnsRecordInfo t : altroTipo) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(t.type).append(" ").append(t.content);
                }
                j.put("conflitto", I18n.tr("server.adns.typeConflict", java.util.Map.of("nome", String.valueOf(nomePieno), "altro", String.valueOf(sb), "tipo", String.valueOf(o[1]))));
            }
            out.put(j);
        }
        return out;
    }

    /**
     * Crea uno dei record opzionali. Stesse regole degli altri: non si sovrascrive niente,
     * e l'esito si verifica rileggendo la zona invece di fidarsi della risposta dell'API.
     */
    public JSONObject creaOpzionale(int domainId, String chiave) {
        JSONObject r = new JSONObject().put("quale", chiave);
        String[] def = definizione(chiave);
        if (def == null) return errore(I18n.tr("server.adns.unknownOptional", java.util.Map.of("k", String.valueOf(chiave))));
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore(I18n.tr("server.adns.domainNotFound"));
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            // "non posso occuparmene" non e' "ho fallito": chi chiama deve poter distinguere
            // i due casi, altrimenti finisce per dare un errore rosso a una configurazione
            // legittima — o, peggio, per dare un verde a una che non ha controllato.
            if (acct == null) return errore(I18n.tr("server.adns.noAccountFor", java.util.Map.of("d", String.valueOf(d.domain))))
                    .put("nonGestito", true);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore(I18n.tr("server.adns.zoneNotVisible", java.util.Map.of("d", String.valueOf(d.domain), "e", String.valueOf(zl.error))))
                    .put("nonGestito", true);

            String nomePieno = def[2] + "." + d.domain;
            String bersaglio = hostDiPosta(d.domain);
            boolean srv = "SRV".equals(def[1]);
            int porta = srv ? Integer.parseInt(def[3]) : 0;
            r.put("nome", nomePieno).put("tipo", def[1]).put("dominio", d.domain)
             .put("valore", srv ? "0 1 " + porta + " " + bersaglio : bersaglio);

            if (bersaglio == null || bersaglio.isBlank() || !bersaglio.contains("."))
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.noHostname"));

            java.util.List<CloudflareManager.DnsRecordInfo> qui =
                    alNome(cloudflare.listRecords(acct.apiToken, zl.zoneId), nomePieno);
            for (CloudflareManager.DnsRecordInfo t : qui) {
                if (!def[1].equalsIgnoreCase(t.type))
                    return r.put("success", false).put("conflitto", true)
                            .put("error", I18n.tr("server.adns.recordConflict", java.util.Map.of("nome", String.valueOf(nomePieno), "tipoEsistente", String.valueOf(t.type), "contenuto", String.valueOf(t.content), "tipo", String.valueOf(def[1]))));

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
                boolean giusto = coincide(t, srv, bersaglio, porta);
                if (giusto && !t.proxied)
                    return r.put("success", true).put("invariato", true).put("contenuto", t.content)
                            .put("nota", I18n.tr("server.adns.alreadyRightOn", java.util.Map.of("nome", String.valueOf(nomePieno))));

                java.util.List<String> cosaNonVa = new ArrayList<>();
                if (!giusto) cosaNonVa.add(I18n.tr("server.adns.pointedTo", java.util.Map.of("prima", String.valueOf(t.content), "giusto", String.valueOf(srv ? "0 1 " + porta + " " + bersaglio : bersaglio))));
                if (t.proxied) cosaNonVa.add(I18n.tr("server.adns.wentThroughCf"));

                CloudflareManager.RecordOp op = srv
                        ? cloudflare.aggiornaSrv(acct.apiToken, zl.zoneId, t.id, nomePieno, bersaglio, 0, 1, porta)
                        : cloudflare.aggiornaCname(acct.apiToken, zl.zoneId, t.id, nomePieno, bersaglio);
                if (op == null || !op.success)
                    return r.put("success", false).put("contenuto", t.content)
                            .put("error", I18n.tr("server.adns.fixRefused", java.util.Map.of("nome", String.valueOf(nomePieno), "cosa", String.valueOf(String.join("; ", cosaNonVa)), "e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));
                return r.put("success", true).put("corretto", true)
                        .put("prima", t.content).put("dopo", srv ? "0 1 " + porta + " " + bersaglio : bersaglio)
                        .put("nota", I18n.tr("server.adns.fixed", java.util.Map.of("nome", String.valueOf(nomePieno), "cosa", String.valueOf(String.join("; ", cosaNonVa)))));
            }

            CloudflareManager.RecordOp op = srv
                    ? cloudflare.createSrvRecord(acct.apiToken, zl.zoneId, nomePieno, bersaglio, 0, 1, porta, 3600)
                    : cloudflare.createCnameRecord(acct.apiToken, zl.zoneId, nomePieno, bersaglio, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.cfRefused", java.util.Map.of("e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error))));

            // Non basta che l'API dica di si': si rilegge la zona e si guarda se c'e'.
            boolean confermato = false;
            for (CloudflareManager.DnsRecordInfo t :
                    alNome(cloudflare.listRecords(acct.apiToken, zl.zoneId), nomePieno))
                if (def[1].equalsIgnoreCase(t.type)) confermato = true;
            if (!confermato)
                return r.put("success", false)
                        .put("error", I18n.tr("server.adns.createdNotFound"));

            return r.put("success", true).put("recordId", op.recordId)
                    .put("nota", I18n.tr("server.adns.createdOn", java.util.Map.of("tipo", String.valueOf(def[1]), "nome", String.valueOf(nomePieno), "z", String.valueOf(zl.zoneName))));
        } catch (Exception e) {
            return errore(I18n.tr("server.adns.createError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
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
    private static String srvIntero(CloudflareManager.DnsRecordInfo t) {
        if (!"SRV".equalsIgnoreCase(t.type) || t.srvPorta == null || t.srvDestinazione == null)
            return t.content == null ? "" : t.content;
        return (t.srvPriorita == null ? 0 : t.srvPriorita) + " "
             + (t.srvPeso == null ? 1 : t.srvPeso) + " "
             + t.srvPorta + " " + t.srvDestinazione;
    }

    static boolean coincide(CloudflareManager.DnsRecordInfo t, boolean srv, String bersaglio, int porta) {
        String c = t.content == null ? "" : t.content.trim();
        if (!srv) return DnsRules.stessoNome(c, bersaglio);
        // Per un SRV si guardano i campi STRUTTURATI di Cloudflare, non la stringa "content".
        //
        // In "content" Cloudflare mette tre valori — peso, porta, destinazione — mentre
        // analizzaSrv ne pretende quattro perche' e' scritta per l'uscita di dig, dove la
        // priorita' c'e'. Con tre campi tornava null, cioe' "non lo riconosco", e il record
        // finiva per sbagliato: la sequenza lo riscriveva a ogni esecuzione e annunciava
        // "puntava a X invece che a Y" confrontando due formati diversi della stessa cosa.
        // Una scrittura in produzione fatta per niente, ripetuta a ogni passaggio.
        if (t.srvPorta != null && t.srvDestinazione != null)
            return t.srvPorta == porta && DnsRules.stessoNome(t.srvDestinazione, bersaglio);
        // Solo se Cloudflare non desse i campi strutturati si torna alla stringa, e si
        // accettano ENTRAMBE le forme in cui quella stringa puo' arrivare.
        DnsRules.Srv s = DnsRules.analizzaSrv(c);
        if (s != null) return s.porta == porta && DnsRules.stessoNome(s.destinazione, bersaglio);
        // Quattro campi non ce n'erano: proviamo la forma a tre, "peso porta destinazione",
        // che e' quella osservata in produzione nel content di Cloudflare. Non serve la
        // priorita': qui si confrontano porta e destinazione, e la priorita' non e' mai
        // stata parte della domanda.
        String[] pezzi = c.split("\\s+");
        if (pezzi.length == 3) {
            try {
                return Integer.parseInt(pezzi[1]) == porta
                    && DnsRules.stessoNome(pezzi[2], bersaglio);
            } catch (NumberFormatException ignora) {
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
     * dichiararla una volta per tutte. Vedi creaTxtMtaSts() qui sopra e MtaStsSetup.
     */

    /* ===================================================================
     * Valori
     * =================================================================== */

    /** null quando l'IP non si conosce: meglio nessun record che uno invalido. */
    private String valoreSpf() {
        String ip = ipDelServer();
        if (ip == null || ip.isBlank()) return null;
        return "v=spf1 ip4:" + ip + " mx -all";
    }

    private String valoreDmarc(String dominio, String politica) {
        return "v=DMARC1; p=" + politica + "; rua=mailto:dmarc@" + dominio;
    }

    /**
     * L'IP pubblico del server. Si riusa quello della pagina DNS invece di scriverne un
     * altro: due modi di ricavare lo stesso numero sono due numeri che un giorno divergono,
     * e un SPF scritto con quello sbagliato blocca la posta in uscita.
     */
    private String ipDelServer() {
        try {
            String ip = new DnsRecordsGenerator(database).detectServerIp();
            return ip == null ? "" : ip.trim();
        } catch (Exception e) {
            return "";
        }
    }

    private MailDatabase.Domain trovaDominio(int id) throws Exception {
        for (MailDatabase.Domain d : database.getDomains()) if (d.id == id) return d;
        return null;
    }

    private JSONObject errore(String m) {
        return new JSONObject().put("success", false).put("error", m);
    }

    /**
     * Sulla rotazione, che e' stato chiesto di implementare "solo se ce n'e' bisogno":
     * NON ce n'e'. DKIM si ruota perche' ha una chiave privata, e una chiave che resta la
     * stessa per anni e' una chiave che prima o poi trapela. SPF e DMARC non contengono
     * segreti: sono dichiarazioni pubbliche di politica. Cambiano quando cambia il server o
     * la politica, non a scadenza.
     */
    public static String perche_niente_rotazione() {
        return I18n.tr("server.adns.noRotation");
    }
}
