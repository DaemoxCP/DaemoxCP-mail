package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AcmeManager;
import org.mail_panel.security.AutoDns;
import org.mail_panel.security.CloudflareManager;
import org.mail_panel.security.RegoleDns;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * MTA-STS acceso con un pulsante solo.
 *
 * Perche' esiste. Attivare MTA-STS richiede sette cose fatte NELL'ORDINE GIUSTO: la riga di
 * include in nginx, la configurazione della 443, la jail, un CNAME per dominio, un
 * certificato che copra quei nomi, la verifica che la politica risponda, e solo alla fine il
 * record TXT. Farle fare a mano una per una significa sbagliare l'ordine — come e' successo
 * a me, che ho chiesto di provare con curl un nome che il passo dopo doveva ancora creare.
 *
 * L'ordine non e' un dettaglio di comodita': ogni passo e' il presupposto del successivo. Il
 * TXT pubblicato prima che la politica risponda e' una dichiarazione pubblica non mantenuta;
 * il certificato emesso prima del CNAME non puo' validare il nome; la configurazione scritta
 * prima dell'include finisce in un file che nginx non legge.
 *
 * Quindi la sequenza la conosce il pannello, che sa anche a che punto e' e riparte da li'.
 * Ogni passo verifica il proprio esito prima che cominci il successivo, e al primo che
 * fallisce ci si ferma spiegando cosa manca: proseguire dopo un fallimento vorrebbe dire
 * costruire sul vuoto.
 */
public class AttivaMtaSts {

    private AttivaMtaSts() {}

    public static class Passo {
        public String chiave, titolo, dettaglio, stato, motivo;
        public JSONObject json() {
            return new JSONObject().put("chiave", chiave).put("titolo", titolo)
                    .put("dettaglio", dettaglio == null ? "" : dettaglio)
                    .put("stato", stato).put("motivo", motivo == null ? "" : motivo);
        }
    }

    private static Passo passo(String c, String t, String d, String s, String m) {
        Passo p = new Passo();
        p.chiave = c; p.titolo = t; p.dettaglio = d; p.stato = s; p.motivo = m;
        return p;
    }

    /* ===================================================================
     * A che punto siamo
     * =================================================================== */

    public static JSONObject piano() {
        JSONObject r = new JSONObject().put("success", true);
        List<Passo> passi = new ArrayList<>();

        // 1-2-3: la superficie sulla 443
        JSONObject web = ProtezioneWeb.stato();
        JSONObject inc = web.optJSONObject("include");
        boolean includeOk = inc != null && inc.optBoolean("ok", false);
        passi.add(passo("include", "nginx legge una cartella di configurazioni aggiuntive",
                inc == null ? "" : inc.optString("motivo", ""),
                includeOk ? "fatto" : "da fare", null));
        passi.add(passo("config443", "La 443 serve i due file e nient'altro",
                web.optString("file", ""),
                web.optBoolean("installato", false) ? "fatto" : "da fare", null));
        passi.add(passo("jail", "Jail fail2ban sul log della 443", "",
                jailAttiva() ? "fatto" : "da fare", null));

        // 4 e 4-bis: i CNAME. Una sola lettura della zona per entrambi i passi, cosi' non
        // possono contraddirsi come e' successo con domain-d.test.
        List<EsameNome> esami = esaminaCname();
        // Se l'esame non copre tutti i domini vuol dire che si e' fermato per un guasto:
        // senza questa riga le liste resterebbero vuote e il piano direbbe "tutti a posto"
        // proprio perche' non ha guardato niente. E' l'errore che sto togliendo dal pannello:
        // non deve tornare dalla porta di servizio.
        int quantiDomini = domini().size();
        List<String> assenti = new ArrayList<>(), storti = new ArrayList<>(),
                     proxati = new ArrayList<>(), ciechi = new ArrayList<>(),
                     inPropagazione = new ArrayList<>();
        for (EsameNome e : esami) {
            switch (e.stato) {
                case ASSENTE -> assenti.add(e.dominio + " (" + e.motivo + ")");
                case CIECO -> ciechi.add(e.dominio + " (" + e.motivo + ")");
                case DA_CORREGGERE -> {
                    if (e.motivo.contains("Cloudflare")) proxati.add(e.dominio);
                    else storti.add(e.dominio + " (" + e.motivo + ")");
                }
                case GIUSTO -> { if (!e.risolve) inPropagazione.add(e.dominio); }
            }
        }
        if (esami.size() < quantiDomini)
            ciechi.add((quantiDomini - esami.size()) + " domini non esaminati: non sono riuscito "
                     + "a leggerne l'elenco o a interrogare Cloudflare");
        List<String> guaiCname = new ArrayList<>(assenti); guaiCname.addAll(storti);
        String dettCname;
        if (!guaiCname.isEmpty()) dettCname = "da sistemare: " + String.join("; ", guaiCname);
        else if (!ciechi.isEmpty()) dettCname = "non verificabili: " + String.join("; ", ciechi);
        else if (!inPropagazione.isEmpty())
            dettCname = "creati, in attesa di propagazione: " + String.join(", ", inPropagazione);
        else dettCname = "tutti presenti e giusti";
        passi.add(passo("cname", "Un CNAME mta-sts per ogni dominio", dettCname,
                !guaiCname.isEmpty() ? "da fare" : (ciechi.isEmpty() ? "fatto" : "incerto"),
                ciechi.isEmpty() ? null
                    : "Su questi domini il pannello non arriva al DNS: se la politica risponde "
                    + "lo dira' la prova qui sotto, che e' una verifica vera. Ma \"non ho potuto "
                    + "controllare\" non e' \"va tutto bene\", quindi non lo segno come fatto."));

        // 4-bis: i record che devono puntare DRITTI al server
        boolean cieco = !ciechi.isEmpty();
        passi.add(passo("proxy", "I nomi mta-sts puntano dritti al server",
                !proxati.isEmpty() ? "passano da Cloudflare: " + String.join(", ", proxati)
                        : (cieco ? "verificato solo sui domini che il pannello vede"
                                 : "nessuno passa da Cloudflare"),
                !proxati.isEmpty() ? "da fare" : (cieco ? "incerto" : "fatto"),
                proxati.isEmpty() ? null
                    : "Con il proxy acceso chi legge la policy parla con Cloudflare, che deve a sua "
                    + "volta validare il certificato del tuo server: un secondo pezzo che deve "
                    + "funzionare, e che quando non funziona risponde 526 senza dire cosa manchi. "
                    + "Il pannello li rimette su \"Solo DNS\"."));

        // 5: il certificato
        List<String> nomiServiti = nomiDaCoprire();
        List<String> scoperti = new ArrayList<>();
        for (String n : nomiServiti) if (!certificatoCopre(n)) scoperti.add(n);
        List<String> esclusi = dominiSuAltroAccount();
        passi.add(passo("certificato", "Il certificato copre i nomi mta-sts",
                scoperti.isEmpty() ? "tutti coperti" : "scoperti: " + String.join(", ", scoperti),
                scoperti.isEmpty() ? "fatto" : "da fare",
                esclusi.isEmpty() ? null
                    : "Questi domini stanno su un altro account Cloudflare e non possono entrare nello "
                    + "stesso certificato, perche' acme.sh valida tutti i nomi con un solo token: "
                    + String.join(", ", esclusi)));

        // 6-7: la prova e il record
        List<String> nonRisponde = new ArrayList<>(), senzaTxt = new ArrayList<>();
        for (String d : domini()) {
            if (!MtaSts.provaPubblica(d).optBoolean("ok", false)) nonRisponde.add(d);
            else if (!txtCorretto(d)) senzaTxt.add(d);
        }
        passi.add(passo("prova", "La politica risponde da fuori",
                nonRisponde.isEmpty() ? "risponde per tutti"
                                      : "non risponde per: " + String.join(", ", nonRisponde),
                nonRisponde.isEmpty() ? "fatto" : "da fare", null));
        passi.add(passo("txt", "Il record _mta-sts e' pubblicato",
                senzaTxt.isEmpty() && nonRisponde.isEmpty() ? "tutti pubblicati"
                        : (senzaTxt.isEmpty() ? "in attesa dei passi precedenti"
                                              : "mancano: " + String.join(", ", senzaTxt)),
                (nonRisponde.isEmpty() && senzaTxt.isEmpty()) ? "fatto" : "da fare", null));

        JSONArray a = new JSONArray();
        int daFare = 0;
        for (Passo p : passi) { a.put(p.json()); if ("da fare".equals(p.stato)) daFare++; }
        r.put("passi", a).put("daFare", daFare);
        r.put("completo", daFare == 0);
        r.put("nota", daFare == 0
                ? "MTA-STS e' attivo su tutti i domini che il pannello puo' coprire."
                : daFare + (daFare == 1 ? " passo manca" : " passi mancano") + ". Il pulsante li esegue "
                  + "nell'ordine e si ferma al primo che non riesce.");
        return r;
    }

    /* ===================================================================
     * L'esecuzione
     * =================================================================== */

    public static JSONObject esegui() { return esegui(null); }

    /**
     * @param job se presente, l'avanzamento viene scritto li' mentre accade.
     *
     * L'emissione del certificato dura piu' del limite di tempo di un proxy: tenendo aperta
     * la richiesta HTTP, il browser riceve una pagina di errore mentre sul server
     * l'operazione continua. Chi guarda non sa piu' cosa sia successo — e uno stato
     * sconosciuto su un certificato di produzione e' l'anticamera del danno.
     */
    public static JSONObject esegui(UpdateManager.Job job) {
        JSONObject r = new JSONObject();
        JSONArray fatti = new JSONArray();
        if (job != null) job.scrivi("=== Attivazione MTA-STS ===");

        // 1. include
        JSONObject web = ProtezioneWeb.stato();
        JSONObject inc = web.optJSONObject("include");
        if (inc == null || !inc.optBoolean("ok", false)) {
            JSONObject e = ProtezioneWeb.aggiungiInclude();
            fatti.put(esito("include", "Riga di include in nginx", e));
            if (job != null) job.scrivi("[1/7] include in nginx: " + (e.optBoolean("success", false) ? "fatto" : "FALLITO"));
            if (!e.optBoolean("success", false)) return fermati(r, fatti,
                    "Senza la riga di include, la configurazione della 443 finirebbe in un file che "
                  + "nginx non legge: mi fermo qui.");
        } else fatti.put(gia("include", "Riga di include in nginx"));

        // 2. la 443
        if (!ProtezioneWeb.stato().optBoolean("installato", false)) {
            JSONObject e = ProtezioneWeb.installa("", "");
            fatti.put(esito("config443", "Configurazione della 443", e));
            if (job != null) job.scrivi("[2/7] configurazione 443: " + (e.optBoolean("success", false) ? "fatta" : "FALLITA"));
            if (!e.optBoolean("success", false)) return fermati(r, fatti,
                    "Senza la 443 configurata la politica non puo' rispondere: mi fermo.");
        } else fatti.put(gia("config443", "Configurazione della 443"));

        // 3. la jail
        if (!jailAttiva()) {
            JSONObject e = ProtezioneWeb.installaJail();
            fatti.put(esito("jail", "Jail fail2ban", e));
            // Una jail mancante non impedisce a MTA-STS di funzionare: si annota e si prosegue.
        } else fatti.put(gia("jail", "Jail fail2ban"));

        // 4. i CNAME
        JSONArray cname = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                // Prima qui c'era una scorciatoia: se "mta-sts.<dominio>" RISPONDEVA, il record
                // si dava per fatto. Ma rispondere non vuol dire esistere: un jolly "*.dominio"
                // fa rispondere qualunque nome. Su domain-d.test era esattamente cosi' — il nome
                // rispondeva grazie al jolly, dietro Cloudflare, e la politica tornava 526.
                // creaOpzionale guarda il record col nome ESATTO dentro la zona, corregge quelli
                // sbagliati o dietro proxy e crea quelli mancanti: e' lui che deve decidere.
                JSONObject e = auto.creaOpzionale(d.id, "mta_sts");
                if (e.optBoolean("nonGestito", false)) {
                    // Dominio non su Cloudflare: non e' un errore, ma nemmeno una conferma.
                    boolean risponde = risolve("mta-sts." + d.domain);
                    cname.put(nota(d.domain, risponde,
                            risponde ? "il nome risponde, ma il dominio non e' su Cloudflare: non posso "
                                     + "verificare che il record punti a questo server. Lo conferma "
                                     + "semmai la prova della politica qui sotto."
                                     : "il nome non risponde e il dominio non e' su Cloudflare: "
                                     + "il CNAME va creato a mano dove sta il DNS di questo dominio."));
                    continue;
                }
                cname.put(nota(d.domain, e.optBoolean("success", false),
                        e.optString("nota", e.optString("error", ""))));
            }
        } catch (Exception e) {
            cname.put(nota("", false, "errore: " + e.getMessage()));
        }
        fatti.put(new JSONObject().put("chiave", "cname").put("titolo", "CNAME mta-sts")
                .put("dettaglio", cname));
        if (job != null) { job.avanza(4, 7); job.scrivi("[4/7] CNAME mta-sts: " + cname.length() + " domini esaminati"); }

        // 4-bis. I nomi mta-sts devono puntare dritti al server.
        // Ogni dominio riporta COSA HO VISTO. Prima questo passo diceva "era gia' a posto"
        // ogni volta che non aveva FATTO nulla — compreso quando non aveva VISTO nulla:
        // account assente, zona non trovata, API muta. "Non ho potuto controllare"
        // travestito da "va tutto bene" e' il modo piu' rapido per prendere una decisione
        // sbagliata: qui, pubblicare un record MTA-STS su un nome che passa da Cloudflare.
        JSONArray proxy = new JSONArray();
        int sistemati = 0, dritti = 0, ciechi = 0;
        try {
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, "non collegato a Cloudflare: non posso "
                            + "controllare se il nome passa dal proxy"));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, "zona non trovata su Cloudflare: non posso "
                            + "controllare se il nome passa dal proxy"));
                    continue;
                }
                String nome = ("mta-sts." + d.domain).toLowerCase(Locale.ROOT);
                java.util.List<CloudflareManager.DnsRecordInfo> tutti =
                        cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, "Cloudflare non ha restituito nessun record "
                            + "per questa zona: non posso controllare, e una lista vuota non "
                            + "vuol dire che vada tutto bene"));
                    continue;
                }
                boolean visto = false;
                for (CloudflareManager.DnsRecordInfo t : tutti) {
                    if (t.name == null || !t.name.toLowerCase(Locale.ROOT).equals(nome)) continue;
                    visto = true;
                    if (!t.proxied) {
                        dritti++;
                        proxy.put(nota(d.domain, true, "il record " + t.type
                                + " punta dritto al server (Solo DNS)"));
                        continue;
                    }
                    CloudflareManager.RecordOp op = cf.impostaProxy(a.apiToken, zl.zoneId, t.id, false);
                    boolean fatto = op != null && op.success;
                    if (fatto) sistemati++;
                    proxy.put(nota(d.domain, fatto,
                            fatto ? "il record " + t.type + " era dietro Cloudflare (nuvola "
                                    + "arancione), l'ho messo su Solo DNS"
                                  : "il record " + t.type + " e' dietro Cloudflare e non sono "
                                    + "riuscito a toglierlo: "
                                    + (op == null ? "nessuna risposta" : op.error)));
                }
                if (!visto) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, "nessun record chiamato " + nome
                            + " nella zona: il CNAME non e' stato creato o sta in un'altra zona"));
                }
            }
        } catch (Exception e) {
            ciechi++;
            proxy.put(nota("", false, "errore nel controllo: " + e.getMessage()));
        }
        fatti.put(new JSONObject().put("chiave", "proxy")
                .put("titolo", "I nomi mta-sts puntano dritti al server")
                .put("dettaglio", proxy));
        if (job != null) job.scrivi("[4b/7] Proxy: " + dritti + " gia' dritti, "
                + sistemati + " sistemati, " + ciechi + " non verificabili");

        // 5. il certificato
        List<String> nomi = nomiDaCoprire();
        List<String> scoperti = new ArrayList<>();
        for (String n : nomi) if (!certificatoCopre(n)) scoperti.add(n);
        if (!scoperti.isEmpty()) {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            String host = MtaSts.hostDiPosta();

            // La guardia "scoperti.isEmpty()" qui sopra evita di riemettere quando i nomi
            // ci sono gia': Let's Encrypt concede 5 emissioni a settimana per lo stesso
            // insieme di nomi, e un pulsante che riemette a ogni pressione consuma quel
            // margine lasciando senza rinnovo proprio quando servirebbe.
            if (job != null) { job.avanza(5, 7); job.scrivi("[5/7] Emetto il certificato con "
                    + nomi.size() + " nomi (" + scoperti.size()
                    + " mancano da quello in uso). Puo' richiedere un minuto..."); }
            AcmeManager.CertificateResult cr = acme.emettiConNomi(host, nomi);
            // "Emissione fallita" da solo non serve a nessuno: la ragione vera sta nell'uscita
            // di acme.sh — un dominio che il token non copre, un limite di Let's Encrypt, una
            // zona non visibile. Senza quella riga non si diagnostica niente.
            String dettaglio = cr.output == null ? "" : cr.output.trim();
            if (dettaglio.length() > 4000) dettaglio = dettaglio.substring(dettaglio.length() - 4000);
            JSONObject e = new JSONObject().put("success", cr.success)
                    .put("nota", cr.message).put("error", cr.message);
            JSONObject riga = esito("certificato", "Certificato con i nomi mta-sts", e);
            riga.put("nomi", new JSONArray(nomi));
            // L'uscita si mostra SEMPRE, non solo quando fallisce. Buttarla via quando il
            // comando "riesce" toglie la prova proprio nel caso peggiore: quello in cui
            // riesce ma non ha fatto quello che credevamo.
            riga.put("uscita", dettaglio);
            fatti.put(riga);
            if (job != null) {
                job.scrivi("--- uscita di acme.sh ---");
                for (String r2 : dettaglio.split("\n")) job.scrivi("  " + r2);
                job.scrivi("--- fine uscita ---");
            }
            if (!cr.success) return fermati(r, fatti,
                    "Senza un certificato che copra mta-sts.<dominio>, chi va a leggere la politica si "
                  + "ferma all'errore TLS. Mi fermo prima di pubblicare il record.");
        } else fatti.put(gia("certificato", "Certificato con i nomi mta-sts"));

        // 6-7. la prova e il record, dominio per dominio
        JSONArray finali = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : Main.mailDatabase.getDomains()) {
                JSONObject prova = MtaSts.provaPubblica(d.domain);
                if (!prova.optBoolean("ok", false)) {
                    finali.put(nota(d.domain, false, "la politica non risponde ancora: "
                            + prova.optString("errore", "") + " Il record TXT NON viene pubblicato: "
                            + "sarebbe una dichiarazione che non mantieni."));
                    continue;
                }
                // Non si salta piu' quando il record c'e': va controllato che l'id corrisponda
                // alla politica servita. I record creati dal vecchio pannello hanno un id fisso
                // che non cambierebbe mai.
                JSONObject e = auto.creaTxtMtaSts(d.id);
                finali.put(nota(d.domain, e.optBoolean("success", false),
                        e.optString("nota", e.optString("error", ""))));
            }
        } catch (Exception e) {
            finali.put(nota("", false, "errore: " + e.getMessage()));
        }
        if (job != null) { job.avanza(7, 7); job.scrivi("[6-7/7] Prova della politica e record TXT: "
                + finali.length() + " domini esaminati"); }
        fatti.put(new JSONObject().put("chiave", "txt").put("titolo", "Prova della politica e record TXT")
                .put("dettaglio", finali));

        return r.put("success", true).put("passi", fatti)
                .put("nota", "Sequenza completata. Premi di nuovo Stato per vedere com'e' rimasta: i "
                        + "record DNS appena creati possono metterci qualche minuto a propagarsi, quindi "
                        + "un dominio che ora risulta \"non risponde\" puo' sistemarsi da solo.");
    }

    private static JSONObject fermati(JSONObject r, JSONArray fatti, String perche) {
        return r.put("success", false).put("passi", fatti).put("error", perche);
    }

    private static JSONObject esito(String chiave, String titolo, JSONObject e) {
        return new JSONObject().put("chiave", chiave).put("titolo", titolo)
                .put("ok", e.optBoolean("success", false))
                .put("messaggio", e.optString("nota", e.optString("error", "")));
    }

    private static JSONObject gia(String chiave, String titolo) {
        return new JSONObject().put("chiave", chiave).put("titolo", titolo)
                .put("ok", true).put("messaggio", "era gia' a posto");
    }

    private static JSONObject nota(String dominio, boolean ok, String messaggio) {
        return new JSONObject().put("dominio", dominio).put("ok", ok).put("messaggio", messaggio);
    }

    /* ===================================================================
     * Misure
     * =================================================================== */

    private static List<String> domini() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }

    /** I nomi che il certificato deve coprire: l'hostname piu' mta-sts e autoconfig dei domini. */
    public static List<String> nomiDaCoprire() {
        LinkedHashSet<String> n = new LinkedHashSet<>();
        List<String> esclusi = dominiSuAltroAccount();
        for (String d : domini()) {
            if (esclusi.contains(d)) continue;
            n.add("mta-sts." + d);
            n.add("autoconfig." + d);
        }
        return new ArrayList<>(n);
    }

    /**
     * I domini che stanno su un account Cloudflare diverso da quello del certificato.
     *
     * Non e' pignoleria: acme.sh valida tutti i nomi di un certificato con un solo token, e
     * un nome che non si riesce a validare fa fallire l'emissione INTERA. Escluderli prima
     * significa ottenere un certificato valido per gli altri, invece di nessun certificato.
     */
    public static List<String> dominiSuAltroAccount() {
        List<String> fuori = new ArrayList<>();
        try {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            var certAcct = acme.accountDelCertificato(MtaSts.hostDiPosta());
            if (certAcct == null) return fuori;
            for (var d : Main.mailDatabase.getDomains()) {
                var a = acme.accountDi(d.id);
                if (a == null || a.id != certAcct.id) fuori.add(d.domain);
            }
        } catch (Exception ignore) {}
        return fuori;
    }

    private static boolean certificatoCopre(String nome) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            // Una sola implementazione della lettura dei nomi, condivisa con AcmeManager:
            // due letture separate finiscono per divergere, e una delle due sbaglia in silenzio.
            for (String n : AcmeManager.nomiDaSubjectAltName(out))
                if (n.equalsIgnoreCase(nome)) return true;
        } catch (Exception ignore) {}
        return false;
    }

    /**
     * Cosa il pannello sa DAVVERO del nome mta-sts di un dominio.
     *
     * Prima c'erano due controlli separati — "il nome risolve?" e "il record e' proxato?" —
     * e tutti e due rispondevano "va bene" quando non avevano visto niente. Su domain-d.test
     * questo ha prodotto la contraddizione: il piano diceva "CNAME presente" perche' il nome
     * rispondeva (grazie a un jolly della zona), mentre nella zona non esisteva alcun record
     * con quel nome. Una sola domanda, una sola risposta, e un valore apposta per "non lo so".
     */
    public enum StatoNome { GIUSTO, DA_CORREGGERE, ASSENTE, CIECO }

    public static final class EsameNome {
        public final String dominio; public final StatoNome stato;
        public final String motivo; public final boolean risolve;
        EsameNome(String d, StatoNome s, String m, boolean r) {
            dominio = d; stato = s; motivo = m; risolve = r;
        }
    }

    public static List<EsameNome> esaminaCname() {
        List<EsameNome> out = new ArrayList<>();
        CloudflareManager cf;
        List<MailDatabase.Domain> domini;
        try {
            cf = new CloudflareManager(Main.mailDatabase);
            domini = Main.mailDatabase.getDomains();
        } catch (Exception e) {
            // Nessun dominio esaminato: chi chiama vede una lista vuota, non un falso "a posto".
            return out;
        }
        for (MailDatabase.Domain d : domini) {
            String pieno = "mta-sts." + d.domain;
            boolean risolve = risolve(pieno);
            try {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    out.add(new EsameNome(d.domain, StatoNome.CIECO,
                            "non e' collegato a un account Cloudflare: il record non lo posso "
                            + "ne' vedere ne' creare", risolve));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    out.add(new EsameNome(d.domain, StatoNome.CIECO,
                            "la zona non e' visibile con questo token Cloudflare", risolve));
                    continue;
                }
                List<CloudflareManager.DnsRecordInfo> tutti = cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    out.add(new EsameNome(d.domain, StatoNome.CIECO,
                            "Cloudflare non ha restituito nessun record per la zona: una lista "
                            + "vuota non vuol dire che vada tutto bene", risolve));
                    continue;
                }
                CloudflareManager.DnsRecordInfo trovato = null;
                String cercato = pieno.toLowerCase(Locale.ROOT);
                for (CloudflareManager.DnsRecordInfo t : tutti)
                    if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(cercato)) {
                        trovato = t; break;
                    }
                if (trovato == null) {
                    out.add(new EsameNome(d.domain, StatoNome.ASSENTE,
                            "nella zona non c'e' nessun record con questo nome"
                            + (risolve ? ", eppure il nome risponde: quasi certamente c'e' un "
                                       + "jolly (*." + d.domain + ") che risponde al posto suo"
                                       : ""), risolve));
                    continue;
                }
                String bersaglio = Main.mailDatabase.getSetting("mail_hostname", "mail." + d.domain);
                List<String> male = new ArrayList<>();
                if (!"CNAME".equalsIgnoreCase(trovato.type))
                    male.add("e' un record " + trovato.type + " invece di un CNAME");
                else if (!RegoleDns.stessoNome(trovato.content, bersaglio))
                    male.add("punta a \"" + trovato.content + "\" invece che a \"" + bersaglio + "\"");
                if (trovato.proxied)
                    male.add("passa da Cloudflare invece di puntare dritto al server");
                out.add(male.isEmpty()
                        ? new EsameNome(d.domain, StatoNome.GIUSTO, "punta dritto a " + bersaglio, risolve)
                        : new EsameNome(d.domain, StatoNome.DA_CORREGGERE, String.join("; ", male), risolve));
            } catch (Exception e) {
                out.add(new EsameNome(d.domain, StatoNome.CIECO,
                        "errore nel controllo: " + e.getMessage(), risolve));
            }
        }
        return out;
    }


    private static boolean risolve(String nome) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", nome);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return !out.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Il record c'e' ED E' QUELLO GIUSTO.
     *
     * Non basta che esista: l'id deve corrispondere alla politica servita, altrimenti i
     * mittenti non si accorgeranno delle modifiche future. I record suggeriti dal vecchio
     * pannello hanno un id fisso — un orologio scritto una volta sola — che non cambierebbe
     * mai. Un piano che li desse per "fatti" nasconderebbe proprio la cosa da sistemare.
     */
    private static boolean txtCorretto(String dominio) {
        try {
            String host = MtaSts.hostDiPosta();
            String modo = MtaSts.modoCorrente();
            String atteso = MtaSts.recordTxt(MtaSts.politica(host, modo, MtaSts.maxAgeConsigliato(modo)));

            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "TXT", "_mta-sts." + dominio);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            for (String riga : org.mail_panel.security.RegoleDns.recordTxt(out))
                if (riga.trim().equals(atteso.trim())) return true;
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean jailAttiva() {
        try {
            ProcessBuilder pb = new ProcessBuilder("fail2ban-client", "status", "mailpanel-pubblico");
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
