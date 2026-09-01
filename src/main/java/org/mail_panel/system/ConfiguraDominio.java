package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AutoDns;
import org.mail_panel.security.CloudflareManager;
import org.mail_panel.security.DkimManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Tutto quello che serve a un dominio, con un pulsante.
 *
 * Perche' esiste. Un dominio appena aggiunto ha bisogno di otto cose: le chiavi DKIM e il
 * loro record, SPF, una cassetta per i rapporti, DMARC, il nome per la configurazione
 * automatica dei client, i due SRV, il nome per MTA-STS, e un certificato che copra quei
 * nomi. Farle a mano una per una, ogni volta, significa dimenticarne una — e quale si e'
 * dimenticata non si scopre subito: si scopre quando la posta comincia a finire nello spam.
 *
 * Ogni passo qui dentro NON sovrascrive mai niente. E' la ragione per cui questa sequenza si
 * puo' lanciare senza paura anche su un dominio gia' configurato a meta': trova cio' che c'e'
 * gia', lo lascia dov'e', e aggiunge solo cio' che manca. Su un dominio usato altrove — un
 * sito con la sua posta gestita da un altro fornitore — non tocca l'SPF esistente, lo mostra
 * e si ferma su quella riga.
 *
 * La destinazione dei rapporti DMARC non viene chiesta: si copia da un altro dominio gia'
 * configurato. Chi ha gia' deciso dove vuole i rapporti non deve deciderlo di nuovo a ogni
 * dominio; e se non c'e' un precedente da cui copiare, quel passo si salta dicendolo.
 */
public class ConfiguraDominio {

    private ConfiguraDominio() {}

    public static JSONObject esegui(int domainId) { return esegui(domainId, null); }

    /**
     * @param job dove scrivere l'avanzamento mentre accade.
     *
     * Serve perche' questa sequenza include l'attesa della propagazione DNS e puo' durare
     * minuti. Tenendo aperta la richiesta HTTP, il browser riceverebbe la pagina di errore
     * del proxy mentre sul server il lavoro continua — e uno stato sconosciuto su un
     * certificato di produzione e' l'anticamera del danno.
     */
    public static JSONObject esegui(int domainId, UpdateManager.Job job) {
        JSONObject r = new JSONObject();
        JSONArray passi = new JSONArray();
        try {
            MailDatabase.Domain d = trova(domainId);
            if (d == null) return r.put("success", false).put("error", "dominio non trovato");
            r.put("dominio", d.domain);
            if (job != null) job.scrivi("=== Configurazione di " + d.domain + " ===");

            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));

            // 1. DKIM: la chiave e il suo record.
            passi.put(dkim(d));

            // 2. SPF.
            passi.put(riduci("SPF", auto.crea(domainId, "spf", "")));

            // 3. La cassetta dei rapporti, con la destinazione copiata da un altro dominio.
            String verso = destinazioneRapportiEsistente();
            JSONObject cassetta = auto.recapitoRapporti(d);
            if (cassetta.optBoolean("esiste", false))
                passi.put(voce("Cassetta dei rapporti", true, "gia' presente ("
                        + cassetta.optString("tipo") + ")"));
            else if (verso == null)
                passi.put(voce("Cassetta dei rapporti", false,
                        "Non c'e' nessun altro dominio da cui copiare la destinazione dei rapporti. "
                      + "Scegli una volta dove vuoi riceverli, nella scheda qui sopra: dal prossimo "
                      + "dominio in poi la copio da sola."));
            else
                passi.put(riduci("Cassetta dei rapporti", auto.creaAliasRapporti(domainId, verso)));

            // 4. DMARC, sempre in osservazione: si stringe dopo aver letto i rapporti.
            passi.put(riduci("DMARC (p=none)", auto.crea(domainId, "dmarc", "none")));

            // 5. I record che aiutano i client.
            for (String[] o : new String[][] {
                    {"autoconfig", "Autoconfig (Thunderbird)"},
                    {"srv_imaps", "SRV posta in arrivo"},
                    {"srv_submission", "SRV posta in uscita"} })
                passi.put(riduci(o[1], auto.creaOpzionale(domainId, o[0])));

            // 6. MTA-STS: tutta la catena, per questo dominio, dall'include di nginx al
            //    record TXT.
            //
            // Qui prima c'erano tre passi scritti a parte — il nome mta-sts, il certificato,
            // il record TXT — ed era una seconda versione della stessa sequenza. Aveva gia'
            // divergito, in tre punti che nell'originale erano corretti:
            //
            //   - il certificato veniva RIEMESSO a ogni pressione, senza guardare se i nomi
            //     fossero gia' coperti: un'emissione Let's Encrypt bruciata ogni volta, su
            //     cinque concesse a settimana per lo stesso insieme di nomi;
            //   - il proxy Cloudflare non veniva mai spento, quindi il nome poteva restare
            //     dietro la nuvola arancione e rispondere 526;
            //   - la politica veniva provata un istante dopo aver creato il CNAME, quando
            //     nessun resolver puo' ancora saperlo: il record TXT non si pubblicava mai.
            //
            // DNS, nginx e certificato non funzionano separatamente se si vuole MTA-STS: e'
            // una catena sola e va eseguita da un posto solo. Due implementazioni della
            // stessa cosa divergono sempre, e quella che si preme di rado resta indietro
            // senza che nessuno se ne accorga.
            if (job != null) job.scrivi("--- MTA-STS: nginx, CNAME, proxy, certificato, politica, TXT ---");
            JSONArray mtasts = AttivaMtaSts.comeVoci(AttivaMtaSts.esegui(job, d.domain));
            for (int i = 0; i < mtasts.length(); i++) passi.put(mtasts.get(i));

            int riusciti = 0;
            for (int i = 0; i < passi.length(); i++)
                if (passi.getJSONObject(i).optBoolean("ok", false)) riusciti++;

            return r.put("success", true).put("passi", passi)
                    .put("riusciti", riusciti).put("totale", passi.length())
                    .put("nota", riusciti + " passi su " + passi.length() + " a posto. Dove ha creato "
                            + "un record, la sequenza ha gia' aspettato che il DNS propagasse prima di "
                            + "provare la politica, quindi questo e' un esito e non una fotografia a "
                            + "meta'. Le righe rosse spiegano cosa manca — di solito e' qualcosa che "
                            + "esiste gia' e che il pannello non sovrascrive apposta.");
        } catch (Exception e) {
            return r.put("success", false).put("passi", passi)
                    .put("error", "errore durante la configurazione: " + e.getMessage());
        }
    }

    /* ===================================================================
     * I singoli passi
     * =================================================================== */

    private static JSONObject dkim(MailDatabase.Domain d) {
        try {
            if (d.dkimSelector != null && !d.dkimSelector.isBlank()
                    && d.dkimPublicKey != null && !d.dkimPublicKey.isBlank())
                return voce("DKIM", true, "chiave gia' presente (selector " + d.dkimSelector + ")");

            DkimManager dk = new DkimManager(Main.mailDatabase);
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            dk.setCloudflareManager(cf);
            DkimManager.DkimResult res = dk.generateDkimKeys(d.id, d.domain, "mail");
            if (!res.success)
                return voce("DKIM", false, "non sono riuscito a generare la chiave: " + res.error);

            // La chiave senza il record in DNS non serve a niente: chi riceve non puo'
            // verificare la firma, e la posta parte firmata da nessuno.
            MailDatabase.CloudflareAccount acct = cf.getAccountForDomain(d.id);
            if (acct == null)
                return voce("DKIM", false, "chiave generata, ma nessun account Cloudflare e' collegato a "
                        + d.domain + ": il record va pubblicato a mano.");
            CloudflareManager.ZoneLookup zl = cf.findZone(acct.apiToken, d.domain);
            if (!zl.found)
                return voce("DKIM", false, "chiave generata, ma la zona non e' visibile: " + zl.error);

            String nome = res.selector + "._domainkey." + d.domain;
            for (CloudflareManager.TxtRecordInfo t :
                    cf.listTxtRecordsContaining(acct.apiToken, zl.zoneId, nome))
                if (t.name != null && t.name.equalsIgnoreCase(nome))
                    return voce("DKIM", false, "chiave generata, ma su " + nome + " esiste gia' un "
                            + "record: non lo sovrascrivo. Guardalo in Cloudflare.");

            CloudflareManager.RecordOp op = cf.createTxtRecord(acct.apiToken, zl.zoneId, nome,
                    "v=DKIM1; k=rsa; p=" + res.publicKey, 3600);
            return op != null && op.success
                    ? voce("DKIM", true, "chiave generata e record pubblicato su " + nome)
                    : voce("DKIM", false, "chiave generata, ma Cloudflare ha rifiutato il record: "
                            + (op == null ? "nessuna risposta" : op.error));
        } catch (Exception e) {
            return voce("DKIM", false, "errore: " + e.getMessage());
        }
    }

    /**
     * Dove finiscono i rapporti DMARC degli altri domini.
     *
     * Si guarda un alias dmarc@ gia' esistente e si riusa la sua destinazione: chi ha gia'
     * deciso dove vuole i rapporti non deve deciderlo di nuovo a ogni dominio.
     */
    public static String destinazioneRapportiEsistente() {
        try {
            for (MailDatabase.Domain d : Main.mailDatabase.getDomains())
                for (MailDatabase.Alias a : Main.mailDatabase.getAliases(d.id))
                    if (a.source != null && a.source.equalsIgnoreCase("dmarc@" + d.domain)
                            && a.destination != null && !a.destination.isBlank())
                        return a.destination.trim();
        } catch (Exception ignore) {}
        return null;
    }

    private static MailDatabase.Domain trova(int id) throws Exception {
        for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) if (d.id == id) return d;
        return null;
    }

    /** Riduce l'esito di un'operazione a una riga leggibile. */
    private static JSONObject riduci(String titolo, JSONObject e) {
        boolean ok = e.optBoolean("success", false);
        String msg = ok ? e.optString("nota", "fatto")
                        : e.optString("error", "non riuscito");
        // "Esiste gia'" non e' un fallimento: e' la regola che protegge cio' che c'era.
        if (!ok && (e.optBoolean("esisteGia", false) || e.optBoolean("invariato", false)))
            return voce(titolo, true, msg);
        return voce(titolo, ok, msg);
    }

    private static JSONObject voce(String titolo, boolean ok, String messaggio) {
        return new JSONObject().put("titolo", titolo).put("ok", ok)
                .put("messaggio", messaggio == null ? "" : messaggio);
    }
}
