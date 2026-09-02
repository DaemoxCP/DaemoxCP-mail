package org.mail_panel.security;

import org.json.JSONArray;
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
            if (d == null) return errore("dominio non trovato");
            r.put("dominio", d.domain);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null)
                return r.put("cloudflare", false)
                        .put("nota", "Nessun account Cloudflare assegnato a " + d.domain + ": senza, il pannello "
                                + "non puo' scrivere record. Assegnane uno nella scheda Account Cloudflare.");
            r.put("cloudflare", true).put("account", acct.label);

            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found)
                return r.put("zona", false)
                        .put("nota", "L'account Cloudflare \"" + acct.label + "\" non vede la zona " + d.domain
                                + ": " + zl.error);
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
            return errore("non riesco a leggere lo stato: " + e.getMessage());
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
             .put("bloccato", "Il pannello non riesce a determinare l'IP pubblico del server, e un SPF "
                     + "senza indirizzo (\"v=spf1 ip4: mx -all\") e' sintatticamente invalido: verrebbe "
                     + "scartato in blocco. Prima va risolto l'IP nella pagina DNS.");
        } else {
            o.put("proposto", proposto);
        }

        List<CloudflareManager.TxtRecordInfo> tutti = txtAlNome(token, zoneId, nome);
        List<String> contenuti = new ArrayList<>();
        for (CloudflareManager.TxtRecordInfo t : tutti) contenuti.add(RegoleDns.contenutoCloudflare(t.content));

        List<String> pertinenti = spf ? RegoleDns.soloSpf(contenuti) : RegoleDns.soloDmarc(contenuti);
        o.put("quanti", pertinenti.size())
         .put("esiste", !pertinenti.isEmpty())
         .put("altriTxt", tutti.size() - pertinenti.size());

        if (!pertinenti.isEmpty()) {
            o.put("contenuto", String.join("  ||  ", pertinenti));
            for (CloudflareManager.TxtRecordInfo t : tutti)
                if (pertinenti.contains(RegoleDns.contenutoCloudflare(t.content))) { o.put("recordId", t.id); break; }
        }

        JSONArray avvisi = new JSONArray();
        if (pertinenti.size() > 1)
            avvisi.put(spf
                ? "Ci sono " + pertinenti.size() + " record SPF sullo stesso nome: RFC 7208 §4.5 dice che il "
                  + "risultato e' \"permerror\", cioe' SPF non funziona affatto. Vanno uniti in uno solo."
                : "Ci sono " + pertinenti.size() + " record DMARC sullo stesso nome: RFC 9989 li scarta TUTTI. "
                  + "La politica non e' \"la prima delle due\": non c'e'.");

        if (!pertinenti.isEmpty()) {
            if (spf) {
                RegoleDns.EsitoSpf e = RegoleDns.analizzaSpf(contenuti, ipDelServer());
                for (String x : e.avvisi) avvisi.put(x);
                if (e.valido && !e.autorizzaEsplicito && !e.viaMx && !e.viaA && e.include == 0)
                    avvisi.put("L'SPF esistente non autorizza questo server: non contiene ne' l'IP "
                             + ipDelServer() + ", ne' un meccanismo \"mx\" o \"a\".");
            } else {
                RegoleDns.EsitoDmarc e = RegoleDns.analizzaDmarc(contenuti, d.domain);
                if (e.valido) o.put("politicaAttuale", e.politica == null ? "none" : e.politica);
                for (String x : e.avvisi) avvisi.put(x);
                if (!e.daAutorizzare.isEmpty())
                    avvisi.put("Il rua punta fuori dominio: senza il record "
                             + String.join(", ", e.daAutorizzare) + " (RFC 9990 §4) i rapporti non partono.");
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
        if (!spf && !"dmarc".equals(quale)) return errore("record sconosciuto: " + quale);

        // Chi non sceglie, sceglie "none": e' quello che RFC 9989 §5.1.5 chiede di fare per
        // primo, e l'unico valore che non puo' fermare posta legittima il giorno stesso.
        String pol = (politica == null || politica.isBlank()) ? "none" : politica.trim().toLowerCase(java.util.Locale.ROOT);
        if (!spf && !List.of("none", "quarantine", "reject").contains(pol))
            return errore("politica DMARC non valida: deve essere none, quarantine o reject");

        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore("dominio non trovato");
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore("nessun account Cloudflare assegnato a " + d.domain);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore("la zona " + d.domain + " non e' visibile: " + zl.error);

            String nome = spf ? d.domain : "_dmarc." + d.domain;
            String valore = spf ? valoreSpf() : valoreDmarc(d.domain, pol);
            r.put("nome", nome).put("dominio", d.domain).put("account", acct.label);

            // Un SPF senza IP non e' un SPF incompleto: e' un record invalido, che fa perdere
            // a tutto il dominio la protezione che credeva di avere.
            if (valore == null)
                return r.put("success", false)
                        .put("error", "Non riesco a determinare l'IP pubblico del server. Scrivere "
                                + "\"v=spf1 ip4: mx -all\" produrrebbe un record invalido, che i destinatari "
                                + "scartano in blocco: meglio nessun SPF che uno rotto. Risolvi prima l'IP "
                                + "nella pagina DNS.");
            r.put("valore", valore);

            List<CloudflareManager.TxtRecordInfo> tutti = txtAlNome(acct.apiToken, zl.zoneId, nome);
            List<String> contenuti = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : tutti) contenuti.add(RegoleDns.contenutoCloudflare(t.content));
            List<String> pertinenti = spf ? RegoleDns.soloSpf(contenuti) : RegoleDns.soloDmarc(contenuti);

            // Il controllo che vale piu' di tutti gli altri, ora fatto sul contenuto.
            if (!pertinenti.isEmpty())
                return r.put("success", false).put("esisteGia", true)
                        .put("contenuto", String.join("  ||  ", pertinenti))
                        .put("error", "Su " + nome + " esiste gia' "
                                + (pertinenti.size() == 1 ? "un record " : pertinenti.size() + " record ")
                                + (spf ? "SPF" : "DMARC") + ": NON lo sovrascrivo. "
                                + (pertinenti.size() > 1
                                   ? (spf ? "Anzi, sono gia' troppi: due SPF danno \"permerror\" e SPF smette "
                                          + "di funzionare (RFC 7208 §4.5). Vanno uniti in uno solo."
                                          : "Anzi, sono gia' troppi: con due record DMARC vengono scartati "
                                          + "entrambi (RFC 9989). Ne va lasciato uno solo.")
                                   : (spf ? "Un SPF esistente puo' autorizzare altri servizi a spedire per questo "
                                          + "dominio (newsletter, gestionali): sostituirlo li farebbe smettere di "
                                          + "funzionare, e te ne accorgeresti giorni dopo. Guardalo in Cloudflare e, "
                                          + "se serve, aggiungi \"ip4:" + ipDelServer() + "\" a quello che c'e' gia'."
                                          : "Guardalo in Cloudflare: se e' un DMARC vecchio, modificalo li'.")));

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
                            .put("error", "Il record direbbe di mandare i rapporti a " + rec.optString("indirizzo")
                                    + ", che pero' non esiste: ne' casella ne' alias. RFC 9989 §5.1.4 fa creare "
                                    + "prima la cassetta e poi il record, e per un motivo pratico: pubblicato il "
                                    + "DMARC, i rapporti cominciano ad arrivare subito e rimbalzerebbero tutti. "
                                    + "Crea prima l'alias qui sotto, poi torna a creare il DMARC.");
            }

            CloudflareManager.RecordOp op = cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, nome, valore, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", "Cloudflare ha rifiutato: " + (op == null ? "nessuna risposta" : op.error));

            // L'esito non e' "l'API ha detto ok": e' il record che si vede da fuori.
            return r.put("success", true).put("recordId", op.recordId)
                    .put("nota", "Record creato in Cloudflare (zona " + zl.zoneName + "). La propagazione "
                            + "richiede di solito pochi minuti: premi Verifica nella pagina DNS fra qualche "
                            + "minuto per vederlo dall'esterno."
                            + (spf ? "" : " La politica e' \"p=" + pol + "\"" + ("none".equals(pol)
                                ? ": non blocca nulla, serve a far arrivare i rapporti e vedere chi spedisce "
                                  + "a nome tuo prima di decidere. Si irrigidisce dopo, a rapporti letti."
                                : ". Ricorda che questa politica agisce da subito sulla posta.")));
        } catch (Exception e) {
            return errore("errore durante la creazione: " + e.getMessage());
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
            return errore("politica non valida: deve essere none, quarantine o reject");
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore("dominio non trovato");
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore("nessun account Cloudflare assegnato a " + d.domain);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore("la zona " + d.domain + " non e' visibile: " + zl.error);

            String nome = "_dmarc." + d.domain;
            r.put("nome", nome).put("dominio", d.domain).put("nuovaPolitica", n);

            CloudflareManager.TxtRecordInfo bersaglio = null;
            java.util.List<String> dmarc = new ArrayList<>();
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (!nm.equals(nome.toLowerCase(java.util.Locale.ROOT))) continue;
                String contenuto = RegoleDns.contenutoCloudflare(t.content);
                if (RegoleDns.eDmarc(contenuto)) { dmarc.add(contenuto); bersaglio = t; }
            }

            if (dmarc.isEmpty())
                return r.put("success", false)
                        .put("error", "Su " + nome + " non c'e' nessun record DMARC da modificare: "
                                + "va prima creato.");
            if (dmarc.size() > 1)
                return r.put("success", false)
                        .put("error", "Su " + nome + " ci sono " + dmarc.size() + " record DMARC. Con due "
                                + "record vengono scartati entrambi (RFC 9989) e non saprei nemmeno quale "
                                + "modificare: prima va lasciato uno solo.");

            String prima = RegoleDns.contenutoCloudflare(bersaglio.content);
            String dopo = RegoleDns.cambiaPolitica(prima, n);
            if (dopo == null)
                return r.put("success", false)
                        .put("error", "Non riesco a modificare quel record senza rischiare di rovinarlo: "
                                + "va cambiato a mano in Cloudflare. Contenuto attuale: " + prima);
            r.put("prima", prima).put("dopo", dopo);

            if (prima.equals(dopo))
                return r.put("success", true).put("invariato", true)
                        .put("nota", "La politica era gia' \"p=" + n + "\": non ho toccato niente.");

            if (!confermato)
                return r.put("success", true).put("anteprima", true)
                        .put("nota", "Cambia solo il valore di \"p\". Tutto il resto del record resta "
                                + "come sta.");

            CloudflareManager.RecordOp op = cloudflare.updateTxtRecord(
                    acct.apiToken, zl.zoneId, bersaglio.id, nome, dopo, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", "Cloudflare ha rifiutato la modifica: "
                                + (op == null ? "nessuna risposta" : op.error));

            // Non basta che l'API abbia detto di si': si rilegge la zona.
            String verificato = null;
            for (CloudflareManager.TxtRecordInfo t : cloudflare.listTxtRecordsContaining(acct.apiToken, zl.zoneId, null)) {
                String nm = t.name == null ? "" : t.name.toLowerCase(java.util.Locale.ROOT).replaceAll("\\.$", "");
                if (nm.equals(nome.toLowerCase(java.util.Locale.ROOT))) {
                    String c = RegoleDns.contenutoCloudflare(t.content);
                    if (RegoleDns.eDmarc(c)) verificato = c;
                }
            }
            if (verificato == null || !verificato.equals(dopo))
                return r.put("success", false).put("riletto", verificato == null ? "" : verificato)
                        .put("error", "Cloudflare ha accettato la modifica, ma rileggendo la zona il record "
                                + "non risulta cambiato. Guardalo in Cloudflare prima di riprovare.");

            return r.put("success", true)
                    .put("nota", "Politica portata a \"p=" + n + "\" su " + nome + ". "
                            + ("reject".equals(n)
                               ? "Da ora la posta che non si autentica a nome di questo dominio viene "
                                 + "rifiutata: se qualche servizio tuo non era autorizzato, smette di "
                                 + "essere consegnato. Guarda i rapporti nei prossimi giorni."
                               : "quarantine".equals(n)
                               ? "Da ora la posta che non si autentica finisce in spam. E' il passo "
                                 + "intermedio: se nei rapporti non compaiono sorprese, poi si passa a reject."
                               : "Torni in sola osservazione: nessuna posta viene bloccata.")
                            + " La propagazione richiede di solito pochi minuti.");
        } catch (Exception e) {
            return errore("errore durante la modifica: " + e.getMessage());
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
            if (d == null) return errore("dominio non trovato");
            String nome = "_mta-sts." + d.domain;
            r.put("nome", nome).put("dominio", d.domain);

            JSONObject pubb = org.mail_panel.system.MtaSts.pubblicabile(d.domain);
            r.put("prova", pubb.optJSONObject("prova"));
            if (!pubb.optBoolean("pubblicabile", false))
                return r.put("success", false).put("error", pubb.optString("motivo"));

            String valore = pubb.getString("valore");
            r.put("valore", valore);

            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            if (acct == null) return errore("nessun account Cloudflare assegnato a " + d.domain);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore("la zona " + d.domain + " non e' visibile: " + zl.error);

            for (CloudflareManager.TxtRecordInfo t : txtAlNome(acct.apiToken, zl.zoneId, nome)) {
                String c = RegoleDns.contenutoCloudflare(t.content);
                if (!c.toLowerCase(java.util.Locale.ROOT).startsWith("v=stsv1")) continue;
                if (c.trim().equals(valore.trim()))
                    return r.put("success", true).put("invariato", true).put("contenuto", c)
                            .put("nota", "Il record su " + nome + " e' gia' quello giusto.");

                // L'id NON e' decorativo: e' il segnale con cui i mittenti si accorgono che la
                // politica e' cambiata. Un id fermo — per esempio un orologio scritto una volta
                // sola, com'era nei record suggeriti dal vecchio pannello — fa restare tutti
                // sulla politica vecchia finche' non scade la loro copia. Quindi si aggiorna.
                CloudflareManager.RecordOp up = cloudflare.updateTxtRecord(
                        acct.apiToken, zl.zoneId, t.id, nome, valore, 3600);
                if (up == null || !up.success)
                    return r.put("success", false).put("contenuto", c)
                            .put("error", "Su " + nome + " c'e' un record MTA-STS con un id diverso ("
                                    + c + ") e Cloudflare ha rifiutato l'aggiornamento: "
                                    + (up == null ? "nessuna risposta" : up.error));
                return r.put("success", true).put("aggiornato", true)
                        .put("prima", c).put("dopo", valore)
                        .put("nota", "Record MTA-STS aggiornato su " + nome + ": l'id ora segue il "
                                + "contenuto della politica, quindi i mittenti si accorgeranno delle "
                                + "modifiche future invece di restare sulla copia vecchia.");
            }

            CloudflareManager.RecordOp op =
                    cloudflare.createTxtRecord(acct.apiToken, zl.zoneId, nome, valore, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", "Cloudflare ha rifiutato: " + (op == null ? "nessuna risposta" : op.error));

            return r.put("success", true).put("recordId", op.recordId)
                    .put("nota", "Record MTA-STS pubblicato su " + nome + ". La politica e' gia' "
                            + "raggiungibile, quindi la dichiarazione e' mantenuta fin da subito.");
        } catch (Exception e) {
            return errore("errore durante la creazione: " + e.getMessage());
        }
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
                    .put("nota", "Siccome l'indirizzo dei rapporti resta dentro il dominio stesso, non "
                            + "serve alcun record di autorizzazione (RFC 9990 §4): basta che sia "
                            + "recapitabile da qualche parte.");
        } catch (Exception e) {
            return o.put("esiste", false).put("errore", "non riesco a leggere caselle e alias: " + e.getMessage());
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
            if (d == null) return errore("dominio non trovato");
            String indirizzo = "dmarc@" + d.domain;
            r.put("indirizzo", indirizzo).put("dominio", d.domain).put("verso", destinazione);

            if (destinazione == null || destinazione.isBlank())
                return errore("Serve la casella a cui recapitare i rapporti.");
            String dest = destinazione.trim();
            if (dest.indexOf('@') < 0) return errore("La destinazione non e' un indirizzo: " + dest);
            if (dest.equalsIgnoreCase(indirizzo))
                return errore("La destinazione coincide con l'alias stesso: si creerebbe un giro chiuso.");

            JSONObject gia = recapitoRapporti(d);
            if (gia.optBoolean("esiste", false))
                return r.put("success", false).put("esisteGia", true)
                        .put("error", indirizzo + " esiste gia' come " + gia.optString("tipo")
                                + (gia.has("verso") ? " (verso " + gia.optString("verso") + ")" : "")
                                + ": non lo tocco. Se va cambiato, si modifica dalla pagina Alias.");

            // Whitelist di caratteri ammessi: si dichiara cosa PUO' esserci, non cosa non puo'.
            if (!dest.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$"))
                return r.put("success", false)
                        .put("error", "\"" + dest + "\" non ha la forma di un indirizzo di posta.");

            // La destinazione puo' anche stare fuori dal pannello: i rapporti sono posta normale
            // e si inoltrano ovunque. Ma se sta fuori, il pannello non puo' verificare che
            // esista, e lo dice invece di lasciarlo credere.
            boolean interna = false;
            for (MailDatabase.Domain dom : database.getDomains())
                for (MailDatabase.Mailbox m : database.getMailboxes(dom.id))
                    if (m.email != null && m.email.equalsIgnoreCase(dest)) interna = true;
            r.put("destinazioneInterna", interna);

            int id = database.addAlias(d.id, indirizzo, dest);
            if (id <= 0) return r.put("success", false).put("error", "Il database non ha creato l'alias.");

            JSONObject dopo = recapitoRapporti(d);
            if (!dopo.optBoolean("esiste", false))
                return r.put("success", false)
                        .put("error", "L'alias risulta creato ma non lo rileggo: controlla la pagina Alias.");

            return r.put("success", true).put("aliasId", id)
                    .put("nota", "Alias creato: " + indirizzo + " → " + dest + ". Ora il DMARC di " + d.domain
                            + " puo' essere pubblicato, e i rapporti arriveranno li'."
                            + (interna ? "" : " Attenzione: " + dest + " non e' una casella di questo pannello, "
                                    + "quindi non ho modo di verificare che esista. Se l'indirizzo fosse "
                                    + "sbagliato, i rapporti si perderebbero senza alcun segnale."));
        } catch (Exception e) {
            return errore("errore durante la creazione dell'alias: " + e.getMessage());
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
            if (d == null) return errore("dominio non trovato");
            String indirizzo = "dmarc@" + d.domain;
            r.put("indirizzo", indirizzo).put("dominio", d.domain);

            JSONObject gia = recapitoRapporti(d);
            if (gia.optBoolean("esiste", false))
                return r.put("success", false).put("esisteGia", true)
                        .put("error", indirizzo + " esiste gia' come " + gia.optString("tipo")
                                + (gia.has("verso") ? " (verso " + gia.optString("verso") + ")" : "")
                                + ": non lo tocco.");

            String password = passwordCasuale();
            int id = database.addMailbox(d.id, indirizzo, password, "Rapporti DMARC " + d.domain, 512);
            if (id <= 0) return r.put("success", false).put("error", "Il database non ha creato la casella.");

            JSONObject dopo = recapitoRapporti(d);
            if (!dopo.optBoolean("esiste", false))
                return r.put("success", false)
                        .put("error", "La casella risulta creata ma non la rileggo: controlla la pagina Caselle.");

            // La password NON e' "mostrata una volta sola": addMailbox la cifra nel vault
            // (AES-256-GCM), e la pagina Caselle la rivede con "Rivela". Dirla irrecuperabile
            // sarebbe far credere a chi legge che il pannello sia meno capace di com'e'.
            return r.put("success", true).put("mailboxId", id).put("password", password)
                    .put("nota", "Casella creata: " + indirizzo + ", quota 512 MB. La password resta "
                            + "disponibile: il pannello la conserva cifrata nel suo vault, e la rivedi "
                            + "quando vuoi da Caselle → Modifica → Rivela. Ora il DMARC di " + d.domain
                            + " puo' essere pubblicato.");
        } catch (Exception e) {
            return errore("errore durante la creazione della casella: " + e.getMessage());
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
            return errore("non riesco a leggere le caselle: " + e.getMessage());
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
          "L'indirizzo a cui Thunderbird va a cercare le impostazioni gia' pronte.",
          // Questa nota diceva "questo pannello quel file non lo serve" e mandava i client sui
          // due SRV. Erano due affermazioni false nello stesso periodo, e la pagina si
          // contraddiceva da sola: la scheda della configurazione automatica, poche righe piu'
          // giu', misura che il file arriva — e spiega che Thunderbird gli SRV non li legge.
          "Il record da solo non basta: perche' serva, su quel nome deve rispondere il file di "
          + "configurazione (/mail/config-v1.1.xml). Il pannello lo serve: la scheda \"Configurazione "
          + "automatica dei client\" qui sotto lo scarica davvero e dice se arriva. Non contare sui "
          + "due SRV per Thunderbird: non li legge (e' scritto nella stessa scheda)." },
        { "srv_imaps",      "SRV",   "_imaps._tcp",      "993",
          "Dice ai client dove prendere la posta in arrivo (IMAP su TLS, porta 993). Funziona da solo: "
          + "il client interroga il DNS e ricava host e porta senza altro (RFC 6186 §4).", "" },
        { "mta_sts",        "CNAME", "mta-sts",          "0",
          "L'indirizzo su cui i server mittenti vanno a leggere la politica MTA-STS.",
          "Da solo non fa niente: serve anche che il pannello serva la politica su quel nome (si "
          + "configura da qui sotto) e che il certificato copra mta-sts.<dominio>. Il record TXT "
          + "che dichiara la politica si crea DOPO, e solo quando la politica risponde davvero." },
        { "srv_submission", "SRV",   "_submission._tcp", "587",
          "Dice ai client dove consegnare la posta in uscita (submission, porta 587). Funziona da solo, "
          + "come quello sopra.", "" },
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
                    .put("aCosaServe", o[4])
                    .put("premessa", o[5])
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
                    sb.append(t.content);
                    if (t.proxied) sb.append("  (proxato)");
                }
                j.put("contenuto", sb.toString());
                boolean proxato = false;
                for (CloudflareManager.DnsRecordInfo t : stessoTipo) if (t.proxied) proxato = true;
                if (proxato)
                    j.put("avviso", "Il record e' proxato da Cloudflare (nuvola arancione): cosi' non "
                            + "risponde piu' con l'host, ma con gli indirizzi di Cloudflare, e il client "
                            + "di posta non trova il server. Va messo su \"Solo DNS\".");
            } else if (!altroTipo.isEmpty()) {
                // Il DNS non ammette un CNAME accanto ad altri dati sullo stesso nome.
                StringBuilder sb = new StringBuilder();
                for (CloudflareManager.DnsRecordInfo t : altroTipo) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(t.type).append(" ").append(t.content);
                }
                j.put("conflitto", "Su " + nomePieno + " c'e' gia' un record di tipo diverso (" + sb
                        + "). Un " + o[1] + " non puo' convivere con altri dati sullo stesso nome: "
                        + "prima va deciso quale dei due deve restare.");
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
        if (def == null) return errore("record opzionale sconosciuto: " + chiave);
        try {
            MailDatabase.Domain d = trovaDominio(domainId);
            if (d == null) return errore("dominio non trovato");
            MailDatabase.CloudflareAccount acct = cloudflare.getAccountForDomain(domainId);
            // "non posso occuparmene" non e' "ho fallito": chi chiama deve poter distinguere
            // i due casi, altrimenti finisce per dare un errore rosso a una configurazione
            // legittima — o, peggio, per dare un verde a una che non ha controllato.
            if (acct == null) return errore("nessun account Cloudflare assegnato a " + d.domain)
                    .put("nonGestito", true);
            CloudflareManager.ZoneLookup zl = cloudflare.findZone(acct.apiToken, d.domain);
            if (!zl.found) return errore("la zona " + d.domain + " non e' visibile: " + zl.error)
                    .put("nonGestito", true);

            String nomePieno = def[2] + "." + d.domain;
            String bersaglio = hostDiPosta(d.domain);
            boolean srv = "SRV".equals(def[1]);
            int porta = srv ? Integer.parseInt(def[3]) : 0;
            r.put("nome", nomePieno).put("tipo", def[1]).put("dominio", d.domain)
             .put("valore", srv ? "0 1 " + porta + " " + bersaglio : bersaglio);

            if (bersaglio == null || bersaglio.isBlank() || !bersaglio.contains("."))
                return r.put("success", false)
                        .put("error", "L'hostname del server di posta non e' configurato: senza, il record "
                                + "punterebbe nel vuoto. Impostalo prima nelle impostazioni del pannello.");

            java.util.List<CloudflareManager.DnsRecordInfo> qui =
                    alNome(cloudflare.listRecords(acct.apiToken, zl.zoneId), nomePieno);
            for (CloudflareManager.DnsRecordInfo t : qui) {
                if (!def[1].equalsIgnoreCase(t.type))
                    return r.put("success", false).put("conflitto", true)
                            .put("error", "Su " + nomePieno + " c'e' gia' un record " + t.type + " ("
                                    + t.content + "). Un " + def[1] + " non puo' stare sullo stesso nome "
                                    + "insieme ad altri dati: prima va deciso quale dei due deve restare.");

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
                            .put("nota", "Su " + nomePieno + " il record e' gia' quello giusto.");

                java.util.List<String> cosaNonVa = new ArrayList<>();
                if (!giusto) cosaNonVa.add("puntava a \"" + t.content + "\" invece che a \""
                        + (srv ? "0 1 " + porta + " " + bersaglio : bersaglio) + "\"");
                if (t.proxied) cosaNonVa.add("passava da Cloudflare invece di puntare dritto al server");

                CloudflareManager.RecordOp op = srv
                        ? cloudflare.aggiornaSrv(acct.apiToken, zl.zoneId, t.id, nomePieno, bersaglio, 0, 1, porta)
                        : cloudflare.aggiornaCname(acct.apiToken, zl.zoneId, t.id, nomePieno, bersaglio);
                if (op == null || !op.success)
                    return r.put("success", false).put("contenuto", t.content)
                            .put("error", "Su " + nomePieno + " il record non e' giusto ("
                                    + String.join("; ", cosaNonVa) + ") e Cloudflare ha rifiutato la "
                                    + "correzione: " + (op == null ? "nessuna risposta" : op.error));
                return r.put("success", true).put("corretto", true)
                        .put("prima", t.content).put("dopo", srv ? "0 1 " + porta + " " + bersaglio : bersaglio)
                        .put("nota", "Corretto " + nomePieno + ": " + String.join("; ", cosaNonVa) + ".");
            }

            CloudflareManager.RecordOp op = srv
                    ? cloudflare.createSrvRecord(acct.apiToken, zl.zoneId, nomePieno, bersaglio, 0, 1, porta, 3600)
                    : cloudflare.createCnameRecord(acct.apiToken, zl.zoneId, nomePieno, bersaglio, 3600);
            if (op == null || !op.success)
                return r.put("success", false)
                        .put("error", "Cloudflare ha rifiutato: " + (op == null ? "nessuna risposta" : op.error));

            // Non basta che l'API dica di si': si rilegge la zona e si guarda se c'e'.
            boolean confermato = false;
            for (CloudflareManager.DnsRecordInfo t :
                    alNome(cloudflare.listRecords(acct.apiToken, zl.zoneId), nomePieno))
                if (def[1].equalsIgnoreCase(t.type)) confermato = true;
            if (!confermato)
                return r.put("success", false)
                        .put("error", "Cloudflare ha risposto che il record e' stato creato, ma rileggendo "
                                + "la zona non lo trovo. Guarda in Cloudflare prima di riprovare.");

            return r.put("success", true).put("recordId", op.recordId)
                    .put("nota", "Record " + def[1] + " creato su " + nomePieno + " (zona " + zl.zoneName
                            + "). La propagazione richiede di solito pochi minuti.");
        } catch (Exception e) {
            return errore("errore durante la creazione: " + e.getMessage());
        }
    }

    /**
     * Il record esistente e' gia' quello che il pannello scriverebbe.
     *
     * Per un CNAME basta il nome di destinazione; per un SRV contano anche la porta, che e'
     * l'unica ragione per cui quel record esiste, e la destinazione. Il confronto sui nomi e'
     * esatto: "xmail.esempio.it" contiene "mail.esempio.it" e passerebbe per giusto.
     */
    private boolean coincide(CloudflareManager.DnsRecordInfo t, boolean srv, String bersaglio, int porta) {
        String c = t.content == null ? "" : t.content.trim();
        if (!srv) return RegoleDns.stessoNome(c, bersaglio);
        RegoleDns.Srv s = RegoleDns.analizzaSrv(c);
        return s != null && s.porta == porta && RegoleDns.stessoNome(s.destinazione, bersaglio);
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
     * dichiararla una volta per tutte. Vedi creaTxtMtaSts() qui sopra e AttivaMtaSts.
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
        return "SPF e DMARC non contengono chiavi: sono dichiarazioni pubbliche di politica. "
             + "Si cambiano quando cambia il server o la politica, non a scadenza. Per questo il "
             + "pannello non offre una rotazione: sarebbe una manutenzione finta, e ogni cambio "
             + "automatico di SPF e' un'occasione per fermare la posta.";
    }
}
