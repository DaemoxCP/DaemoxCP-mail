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
public class DomainSetup {

    private DomainSetup() {}

    public static JSONObject run(int domainId) { return run(domainId, null); }

    /**
     * @param job dove scrivere l'avanzamento mentre accade.
     *
     * Serve perche' questa sequenza include l'attesa della propagazione DNS e puo' durare
     * minuti. Tenendo aperta la richiesta HTTP, il browser riceverebbe la pagina di errore
     * del proxy mentre sul server il lavoro continua — e uno stato sconosciuto su un
     * certificato di produzione e' l'anticamera del danno.
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

            // Ogni passo anche come riga del registro, col suo motivo: prima stavano solo nel JSON in fondo, e il
            // registro di un lavoro andato a meta' diceva soltanto quanti passi erano in ordine (reperto 250).
            final UpdateManager.Job log = job;
            java.util.function.Consumer<JSONObject> put = e -> {
                steps.put(e);
                if (log != null) log.write(e.optString("title") + ": "
                        + (e.optBoolean("ok", false) ? I18n.tr("server.cfgdom.done") : I18n.tr("server.um.x.failedF"))
                        + " \u2014 " + e.optString("messageText"));
            };

            // 1. DKIM: la chiave e il suo record.
            put.accept(dkim(d));

            // 2. SPF.
            put.accept(reduce("SPF", auto.create(domainId, "spf", "")));

            // 3. La cassetta dei rapporti, con la destinazione copiata da un altro dominio.
            String target = existingReportDestination();
            JSONObject deliveryState = auto.reportDelivery(d);
            if (deliveryState.optBoolean("exists", false))
                put.accept(entry(I18n.tr("server.cfgdom.reportBox"), true, I18n.tr("server.cfgdom.boxPresent", java.util.Map.of("kind", String.valueOf(deliveryState.optString("type"))))));
            else if (target == null)
                put.accept(entry(I18n.tr("server.cfgdom.reportBox"), false,
                        I18n.tr("server.cfgdom.boxNoSource")));
            else
                put.accept(reduce(I18n.tr("server.cfgdom.reportBox"), auto.createReportAlias(domainId, target)));

            // 4. DMARC, sempre in osservazione: si stringe dopo aver letto i rapporti.
            put.accept(reduce("DMARC (p=none)", auto.create(domainId, "dmarc", "none")));

            // 5. I record che aiutano i client.
            for (String[] o : new String[][] {
                    {"autoconfig", "Autoconfig (Thunderbird)"},
                    {"srv_imaps", "server.cfgdom.srvIn"},
                    {"srv_submission", "server.cfgdom.srvOut"} })
                put.accept(reduce(I18n.tr(o[1]), auto.createOptional(domainId, o[0])));

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
                    .put("error", I18n.tr("server.cfgdom.error", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /* ===================================================================
     * Prima di cominciare: l'account Cloudflare del dominio
     * =================================================================== */

    /**
     * Pronto, o perche' no; e l'account assegnato qui, se il dominio non ne aveva uno.
     *
     * Senza un account Cloudflare che veda la zona del dominio «Set up everything» non pubblica niente: prima partiva
     * lo stesso, generava la chiave DKIM, cambiava nginx, si fermava a meta' e finiva in verde, «Setup completed» con un
     * passo su dieci (reperto 250, sulla VM pulita seguendo la guida). Ora si controlla prima di toccare qualunque cosa.
     * E il collegamento fra dominio e account, che la guida non nominava, si fa da solo quando un solo account del
     * pannello vede la zona: e' il caso di chi segue la guida, un account e i suoi domini.
     */
    public record CloudflareChoice(boolean ready, String error, MailDatabase.CloudflareAccount assigned) {
        static CloudflareChoice no(String error) { return new CloudflareChoice(false, error, null); }
    }

    /** La zona che il token di un account vede per il dominio (CloudflareManager.findZone, o una prova). */
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

    /** Il motivo senza il punto finale: la frase che lo contiene ne mette uno suo («... after.. On Cloudflare»). */
    static String withoutFinalStop(String reason) {
        String r = String.valueOf(reason).trim();
        while (r.endsWith(".")) r = r.substring(0, r.length() - 1);
        return r;
    }

    /** Il controllo vero: account del dominio, account del pannello, e la zona chiesta a Cloudflare col token di ognuno. */
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
            return CloudflareChoice.no(I18n.tr("server.cfgdom.error", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /* ===================================================================
     * I singoli passi
     * =================================================================== */

    /** La chiave DKIM e il suo record, firmando solo con una chiave pubblicata: DkimManager.ensurePublished. */
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
            // Una zona che non si legge lancia ZoneReadException: finisce nel catch, e non si crea niente.
            DkimManager.RecordStep st = DkimManager.ensurePublished(cf, acct.apiToken, zl.zoneId, d.domain,
                    d.dkimSelector, d.dkimPublicKey, dk::newKey, k -> dk.install(d.id, d.domain, k));
            return entry("DKIM", st.ok(), st.message());
        } catch (Exception e) {
            return entry("DKIM", false, I18n.tr("server.cfgdom.dkimError", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Dove finiscono i rapporti DMARC degli altri domini.
     *
     * Si guarda un alias dmarc@ gia' esistente e si riusa la sua destinazione: chi ha gia'
     * deciso dove vuole i rapporti non deve deciderlo di nuovo a ogni dominio.
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

    /** Riduce l'esito di un'operazione a una riga leggibile. */
    private static JSONObject reduce(String title, JSONObject e) {
        boolean ok = e.optBoolean("success", false);
        String msg = ok ? e.optString("note", I18n.tr("server.cfgdom.done"))
                        : e.optString("error", I18n.tr("server.cfgdom.failed"));
        // "Esiste gia'" non e' un fallimento: e' la regola che protegge cio' che c'era.
        if (!ok && (e.optBoolean("alreadyExists", false) || e.optBoolean("unchanged", false)))
            return entry(title, true, msg);
        return entry(title, ok, msg);
    }

    private static JSONObject entry(String title, boolean ok, String message) {
        return new JSONObject().put("title", title).put("ok", ok)
                .put("messageText", message == null ? "" : message);
    }
}
