package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MTA-STS acceso con un pulsante solo.
 *
 * Perche' esiste. Attivare MTA-STS richiede otto cose fatte NELL'ORDINE GIUSTO: la riga di
 * include in nginx, la configurazione della 443, la jail, un CNAME per dominio, che quel
 * CNAME punti DRITTO al server e non passi da un proxy, un certificato che copra quei nomi,
 * la verifica che la politica risponda, e solo alla fine il record TXT. Farle fare a mano
 * una per una significa sbagliare l'ordine — come e' successo
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

    /**
     * Quanto la sequenza aspetta, al massimo, che un record DNS appena creato diventi visibile.
     *
     * Non e' un numero scelto a sentimento: un resolver che ha gia' in cache la risposta
     * precedente la tiene per il TTL di quella risposta, e su un jolly Cloudflare quel TTL
     * misurato vale 300 secondi. Sotto i cinque minuti l'attesa non servirebbe a niente; sei
     * lasciano il margine perche' la cache scada davvero.
     */
    private static final long ATTESA_MAX_MS = 6 * 60 * 1000L;

    /**
     * Ogni quanto si riprova. Trenta secondi perche' la JVM tiene in cache le risoluzioni
     * riuscite per trenta secondi: riprovare piu' spesso vorrebbe dire rileggere la propria
     * cache e credere di aver interrogato il DNS.
     */
    private static final long ATTESA_INTERVALLO_MS = 30 * 1000L;

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
        passi.add(passo("include", I18n.tr("server.sts.stepInclude"),
                inc == null ? "" : inc.optString("motivo", ""),
                includeOk ? "fatto" : "da fare", null));
        passi.add(passo("config443", I18n.tr("server.sts.step443"),
                web.optString("file", ""),
                web.optBoolean("installato", false) ? "fatto" : "da fare", null));
        passi.add(passo("jail", I18n.tr("server.sts.stepJail"), "",
                jailAttiva() ? "fatto" : "da fare", null));

        // 4 e 4-bis: i CNAME. Una sola lettura della zona per entrambi i passi, cosi' non
        // possono contraddirsi come e' successo con domain-d.test.
        List<EsameNome> esami = esaminaCname();
        // Se l'esame non copre tutti i domini vuol dire che si e' fermato per un guasto:
        // senza questa riga le liste resterebbero vuote e il piano direbbe "tutti a posto"
        // proprio perche' non ha guardato niente. E' l'errore che sto togliendo dal pannello:
        // non deve tornare dalla porta di servizio.
        int quantiDomini = domini().size();
        Ripartizione rip = ripartisci(esami);
        List<String> assenti = rip.assenti, storti = rip.storti, proxati = rip.proxati,
                     ciechi = rip.ciechi, inPropagazione = rip.inPropagazione;
        boolean proxyDaJolly = rip.proxyDaJolly;
        if (esami.size() < quantiDomini)
            ciechi.add(I18n.tr("server.sts.notExamined", java.util.Map.of("n", String.valueOf((quantiDomini - esami.size())))));
        List<String> guaiCname = new ArrayList<>(assenti); guaiCname.addAll(storti);
        String dettCname;
        if (!guaiCname.isEmpty()) dettCname = I18n.tr("server.sts.toFix", java.util.Map.of("elenco", String.valueOf(String.join("; ", guaiCname))));
        else if (!ciechi.isEmpty()) dettCname = I18n.tr("server.sts.unverifiable", java.util.Map.of("elenco", String.valueOf(String.join("; ", ciechi))));
        else if (!inPropagazione.isEmpty())
            dettCname = I18n.tr("server.sts.propagating", java.util.Map.of("elenco", String.valueOf(String.join(", ", inPropagazione))));
        else if (!proxati.isEmpty())
            dettCname = I18n.tr("server.sts.allPresentProxy");
        else dettCname = I18n.tr("server.sts.allPresentOk");
        passi.add(passo("cname", I18n.tr("server.sts.stepCname"), dettCname,
                !guaiCname.isEmpty() ? "da fare" : (ciechi.isEmpty() ? "fatto" : "incerto"),
                ciechi.isEmpty() ? null
                    : I18n.tr("server.sts.blindDns")));

        // 4-bis: i record che devono puntare DRITTI al server
        boolean cieco = !ciechi.isEmpty();
        passi.add(passo("proxy", I18n.tr("server.sts.stepProxy"),
                !proxati.isEmpty() ? I18n.tr("server.sts.viaCf", java.util.Map.of("elenco", String.valueOf(String.join(", ", proxati))))
                        : (cieco ? I18n.tr("server.sts.checkedVisible")
                                 : I18n.tr("server.sts.noneViaCf")),
                !proxati.isEmpty() ? "da fare" : (cieco ? "incerto" : "fatto"),
                proxati.isEmpty() ? null
                    : I18n.tr("server.sts.proxyWhy")
                    + (proxyDaJolly
                        ? " " + I18n.tr("server.sts.wildcardWhy")
                        : "")));

        // 5: il certificato
        List<String> nomiServiti = nomiDaCoprire();
        List<String> scoperti = new ArrayList<>();
        for (String n : nomiServiti) if (!certificatoCopre(n)) scoperti.add(n);
        List<String> esclusi = dominiSuAltroAccount();
        passi.add(passo("certificato", I18n.tr("server.sts.stepCert"),
                scoperti.isEmpty() ? I18n.tr("server.sts.allCovered") : I18n.tr("server.sts.uncovered", java.util.Map.of("elenco", String.valueOf(String.join(", ", scoperti)))),
                scoperti.isEmpty() ? "fatto" : "da fare",
                esclusi.isEmpty() ? null
                    : I18n.tr("server.sts.otherAccount", java.util.Map.of("elenco", String.valueOf(String.join(", ", esclusi))))));

        // 6-7: la prova e il record
        List<EsameTxt> esamiTxt = new ArrayList<>();
        for (String d : domini()) {
            boolean risponde = MtaSts.provaPubblica(d).optBoolean("ok", false);
            // Il TXT si legge SEMPRE, e soprattutto quando la politica NON risponde: e' proprio
            // quella la combinazione da scoprire, un record gia' pubblicato che manda i mittenti
            // del mondo contro un errore. Prima qui c'era un "else if" e a quel ramo non si
            // arrivava mai: su domain-d.test il pannello scriveva "in attesa dei passi precedenti"
            // mentre il record era pubblicato, con un id vecchio, e la politica dava 526. Cieco
            // esattamente sulla cosa che questa scheda esiste per sorvegliare.
            esamiTxt.add(new EsameTxt(d, risponde, leggiTxt(d)));
        }
        passi.addAll(passiProvaETxt(esamiTxt, txtAtteso()));

        JSONArray a = new JSONArray();
        int daFare = 0, incerti = 0;
        for (Passo p : passi) {
            a.put(p.json());
            if ("da fare".equals(p.stato)) daFare++;
            else if ("incerto".equals(p.stato)) incerti++;
        }
        r.put("passi", a).put("daFare", daFare).put("incerti", incerti);
        // "completo" accende la spunta verde e fa sparire il pulsante, quindi non puo' bastare
        // che non ci sia niente DA FARE: serve anche che non sia rimasto niente da VERIFICARE.
        // Con la sola condizione daFare==0, un passo "incerto" — cioe' uno che il pannello non
        // ha potuto controllare — sarebbe bastato da solo a dichiarare "attivo su tutti i domini".
        boolean completo = daFare == 0 && incerti == 0;
        r.put("completo", completo);
        String quantiIncerti = incerti == 1 ? I18n.tr("server.sts.steps.one") : I18n.tr("server.sts.steps.other", java.util.Map.of("n", String.valueOf(incerti)));
        r.put("nota", completo
                ? I18n.tr("server.sts.complete")
                : daFare == 0
                  ? I18n.tr("server.sts.onlyUncertain", java.util.Map.of("passi", String.valueOf(quantiIncerti)))
                  : (daFare == 1 ? I18n.tr("server.sts.missing.one") : I18n.tr("server.sts.missing.other", java.util.Map.of("n", String.valueOf(daFare))))
                    + (incerti > 0 ? ", " + I18n.tr("server.sts.plusUncertain", java.util.Map.of("passi", String.valueOf(quantiIncerti))) : "")
                    + ". " + I18n.tr("server.sts.buttonRuns"));
        return r;
    }

    /** Cosa si e' visto di un dominio per i passi della prova e del record. */
    static final class EsameTxt {
        final String dominio; final boolean risponde; final LetturaTxt txt;
        EsameTxt(String dominio, boolean risponde, LetturaTxt txt) {
            this.dominio = dominio; this.risponde = risponde; this.txt = txt;
        }
    }

    /**
     * I passi "prova" e "txt" del piano, da cio' che si e' visto dominio per dominio. E' qui
     * che il passo del record diventa "fatto", e sta da solo perche' le prove lo verifichino
     * con letture costruite, senza DNS e senza la politica vera: due record v=STSv1 non
     * devono poterlo far diventare "fatto".
     */
    static List<Passo> passiProvaETxt(List<EsameTxt> esami, String atteso) {
        List<String> nonRisponde = new ArrayList<>(), senzaTxt = new ArrayList<>(),
                     nonMantenuti = new ArrayList<>(), txtIgnoti = new ArrayList<>(),
                     troppi = new ArrayList<>();
        for (EsameTxt e : esami) {
            String d = e.dominio;
            LetturaTxt txt = e.txt;
            if (!e.risponde) {
                nonRisponde.add(d);
                // Anche con piu' record: se uno e' scritto male, i mittenti che lo scartano
                // contano solo l'altro, e quello li manda contro la politica che non risponde.
                if (txt.esito == EsitoTxt.PRESENTE || txt.esito == EsitoTxt.TROPPI)
                    nonMantenuti.add(d + " -> " + String.join("  ||  ", txt.valori));
                continue;
            }
            switch (txt.esito) {
                case NON_CHIESTO -> txtIgnoti.add(d + " (" + txt.motivo + ")");
                case ASSENTE -> senzaTxt.add(d);
                case TROPPI -> troppi.add(d + " (" + txt.valori.size() + " record: "
                        + String.join("  ||  ", txt.valori) + ")");
                case PRESENTE -> {
                    if (!atteso.equals(txt.contenuto)) senzaTxt.add(d + " " + I18n.tr("server.sts.idToUpdate"));
                }
            }
        }
        List<Passo> passi = new ArrayList<>();
        passi.add(passo("prova", I18n.tr("server.sts.stepTest"),
                nonRisponde.isEmpty()
                    ? I18n.tr("server.sts.answersAll")
                    : I18n.tr("server.sts.noAnswerFor", java.util.Map.of("elenco", String.valueOf(String.join(", ", nonRisponde)))),
                nonRisponde.isEmpty() ? "fatto" : "da fare", null));

        String dettTxt, statoTxt, motivoTxt = null;
        if (!nonMantenuti.isEmpty()) {
            dettTxt = I18n.tr("server.sts.notKept", java.util.Map.of("elenco", String.valueOf(String.join("; ", nonMantenuti))));
            statoTxt = "da fare";
            motivoTxt = I18n.tr("server.sts.notKeptWhy");
        } else if (!troppi.isEmpty()) {
            dettTxt = I18n.tr("server.sts.moreThanOne", java.util.Map.of("elenco", String.valueOf(String.join(", ", troppi))));
            statoTxt = "da fare";
            motivoTxt = I18n.tr("server.sts.moreThanOneWhy");
        } else if (!txtIgnoti.isEmpty()) {
            dettTxt = "non so se c'e' per: " + String.join(", ", txtIgnoti);
            statoTxt = "incerto";
            motivoTxt = I18n.tr("server.sts.notMarkedDone");
        } else if (!nonRisponde.isEmpty()) {
            dettTxt = I18n.tr("server.sts.waitingPrev"); statoTxt = "da fare";
        } else if (!senzaTxt.isEmpty()) {
            dettTxt = I18n.tr("server.sts.missingList", java.util.Map.of("elenco", String.valueOf(String.join(", ", senzaTxt)))); statoTxt = "da fare";
        } else {
            dettTxt = I18n.tr("server.sts.allPublished"); statoTxt = "fatto";
        }
        passi.add(passo("txt", I18n.tr("server.sts.stepTxt"), dettTxt, statoTxt, motivoTxt));
        return passi;
    }

    /**
     * Come i domini esaminati si distribuiscono fra i passi del piano.
     *
     * Sta in un metodo suo, staccato da piano(), per una ragione precisa: e' QUI che sono nati
     * i falsi verdi. Un dominio senza record che rispondeva grazie a un jolly proxato non
     * entrava nel conto del proxy, e il passo diceva "nessuno passa da Cloudflare"; un record
     * insieme SBAGLIATO e PROXATO finiva nel solo conto del proxy — perche' la classificazione
     * cercava la parola "Cloudflare" dentro una frase scritta per un essere umano — e il passo
     * dei CNAME dichiarava "tutti presenti e giusti" un record che puntava altrove.
     *
     * Dentro piano(), che per esistere ha bisogno del database e di Cloudflare, questa logica
     * non si poteva provare con un test. Una logica che nessun test puo' raggiungere e' una
     * logica che nessuno controlla: qui infatti non la controllava nessuno.
     */
    static final class Ripartizione {
        final List<String> assenti = new ArrayList<>(), storti = new ArrayList<>(),
                           proxati = new ArrayList<>(), ciechi = new ArrayList<>(),
                           inPropagazione = new ArrayList<>();
        boolean proxyDaJolly;
    }

    static Ripartizione ripartisci(List<EsameNome> esami) {
        Ripartizione r = new Ripartizione();
        for (EsameNome e : esami) {
            // Il proxy si conta per conto suo, da un booleano: un record puo' essere insieme
            // sbagliato E proxato, e i due fatti devono comparire tutti e due, nei due passi
            // a cui appartengono.
            if (e.passaDalProxy) {
                boolean daJolly = e.stato == StatoNome.ASSENTE;
                if (daJolly) r.proxyDaJolly = true;
                r.proxati.add(e.dominio + (daJolly
                        ? " " + I18n.tr("server.sts.wildcardAnswers", java.util.Map.of("d", String.valueOf(e.dominio))) : ""));
            }
            switch (e.stato) {
                case ASSENTE -> r.assenti.add(e.dominio + " (" + e.motivo + ")");
                case CIECO -> r.ciechi.add(e.dominio + " (" + e.motivo + ")");
                case DA_CORREGGERE -> {
                    if (e.contenutoSbagliato) r.storti.add(e.dominio + " (" + e.motivo + ")");
                }
                case GIUSTO -> { if (!e.risolve) r.inPropagazione.add(e.dominio); }
            }
        }
        return r;
    }

    /**
     * Il tempo, passato da fuori.
     *
     * Serve solo perche' l'attesa qui sotto possa essere provata: incollata a Thread.sleep e
     * a System.currentTimeMillis, un test avrebbe dovuto aspettare sei minuti veri per
     * esercitarla, cioe' non l'avrebbe esercitata mai.
     */
    interface Orologio {
        long adesso();
        void dormi(long ms) throws InterruptedException;
    }

    static final Orologio OROLOGIO_VERO = new Orologio() {
        public long adesso() { return System.currentTimeMillis(); }
        public void dormi(long ms) throws InterruptedException { Thread.sleep(ms); }
    };

    /**
     * Aspetta che i domini indicati rispondano, e restituisce quelli che non ce l'hanno fatta.
     *
     * Tre proprieta' che devono valere, e che il test verifica una per una: si prova SUBITO
     * prima di dormire (se rispondono gia', non si aspetta un istante); si smette appena la
     * lista si svuota; e si smette comunque alla scadenza, perche' un ciclo di attesa senza
     * un'uscita garantita, dentro un pannello di produzione, e' un blocco che non finisce piu'.
     */
    static List<String> attendiPropagazione(List<String> domini,
                                            java.util.function.Predicate<String> risponde,
                                            Orologio orologio, long maxMs, long intervalloMs,
                                            java.util.function.Consumer<String> log) {
        List<String> restano = new ArrayList<>(domini);
        long scadenza = orologio.adesso() + maxMs;
        while (true) {
            restano.removeIf(risponde);
            if (restano.isEmpty() || orologio.adesso() >= scadenza) break;
            log.accept("    " + I18n.tr("server.sts.stillNotAnswering", java.util.Map.of("elenco", String.valueOf(String.join(", ", restano)), "s", String.valueOf((intervalloMs / 1000)))));
            try {
                orologio.dormi(intervalloMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log.accept("    " + I18n.tr("server.sts.waitInterrupted"));
                break;
            }
        }
        return restano;
    }

    /* ===================================================================
     * L'esecuzione
     * =================================================================== */

    public static JSONObject esegui() { return esegui(null, null); }

    public static JSONObject esegui(UpdateManager.Job job) { return esegui(job, null); }

    /**
     * I domini su cui la sequenza deve agire.
     *
     * Un elenco vuoto NON e' "nessun dominio da fare": vuol dire che il nome chiesto non
     * esiste, e chi chiama deve accorgersene invece di vedere una sequenza che "riesce"
     * senza aver toccato niente.
     */
    private static List<MailDatabase.Domain> dominiDaToccare(String soloDominio) throws Exception {
        return filtra(Main.mailDatabase.getDomains(), soloDominio);
    }

    /**
     * Il filtro vero e proprio, separato dalla lettura del database perche' possa essere
     * provato: dentro dominiDaToccare sarebbe raggiungibile solo con un database vivo, e un
     * test che non arriva alla riga che deve verificare non verifica niente.
     *
     * Il confronto e' senza distinzione di maiuscole perche' i nomi di dominio non ne hanno,
     * ed e' ESATTO: "ake.net" non deve trovare "domain-d.test".
     */
    static List<MailDatabase.Domain> filtra(List<MailDatabase.Domain> tutti, String soloDominio) {
        List<MailDatabase.Domain> out = new ArrayList<>();
        if (tutti == null) return out;
        for (MailDatabase.Domain d : tutti)
            if (soloDominio == null || (d != null && soloDominio.equalsIgnoreCase(d.domain)))
                out.add(d);
        return out;
    }

    /**
     * @param job se presente, l'avanzamento viene scritto li' mentre accade.
     * @param soloDominio se presente, i passi per dominio toccano solo quello. I primi tre —
     *        include di nginx, 443, jail — restano globali perche' quella superficie e' una
     *        sola per tutti i domini, e installarla e' idempotente. Il certificato resta
     *        globale per una ragione piu' seria, spiegata al suo passo.
     *
     * L'emissione del certificato dura piu' del limite di tempo di un proxy: tenendo aperta
     * la richiesta HTTP, il browser riceve una pagina di errore mentre sul server
     * l'operazione continua. Chi guarda non sa piu' cosa sia successo — e uno stato
     * sconosciuto su un certificato di produzione e' l'anticamera del danno.
     */
    public static JSONObject esegui(UpdateManager.Job job, String soloDominio) {
        JSONObject r = new JSONObject();
        JSONArray fatti = new JSONArray();
        if (job != null) job.scrivi("=== " + I18n.tr("server.sts.jobTitle") + " ==="
                + (soloDominio == null ? "" : " " + I18n.tr("server.sts.onlyDomain", java.util.Map.of("d", String.valueOf(soloDominio)))));

        // Un nome che non corrisponde a nessun dominio non deve produrre una sequenza che
        // "riesce": i cicli per dominio girerebbero a vuoto, nessun passo fallirebbe, e
        // l'esito direbbe che e' andato tutto bene senza che sia stato toccato niente. E'
        // il falso successo piu' silenzioso di tutti, e va fermato qui.
        if (soloDominio != null) {
            try {
                if (dominiDaToccare(soloDominio).isEmpty())
                    return fermati(r, fatti, I18n.tr("server.sts.notPanelDomain", java.util.Map.of("d", String.valueOf(soloDominio))));
            } catch (Exception e) {
                return fermati(r, fatti, I18n.tr("server.sts.domainsUnreadable", java.util.Map.of("m", String.valueOf(e.getMessage()))));
            }
        }

        // 1. include
        JSONObject web = ProtezioneWeb.stato();
        JSONObject inc = web.optJSONObject("include");
        if (inc == null || !inc.optBoolean("ok", false)) {
            JSONObject e = ProtezioneWeb.aggiungiInclude();
            fatti.put(esito("include", I18n.tr("server.sts.includeTitle"), e));
            if (job != null) job.scrivi("[1/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.includeOk") : I18n.tr("server.sts.includeFail")));
            if (!e.optBoolean("success", false)) return fermati(r, fatti,
                    I18n.tr("server.sts.noIncludeStop"));
        } else fatti.put(gia("include", I18n.tr("server.sts.includeTitle")));

        // 2. la 443
        if (!ProtezioneWeb.stato().optBoolean("installato", false)) {
            JSONObject e = ProtezioneWeb.installa("", "");
            fatti.put(esito("config443", I18n.tr("server.sts.config443Title"), e));
            if (job != null) job.scrivi("[2/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.c443Ok") : I18n.tr("server.sts.c443Fail")));
            if (!e.optBoolean("success", false)) return fermati(r, fatti,
                    I18n.tr("server.sts.no443Stop"));
        } else fatti.put(gia("config443", I18n.tr("server.sts.config443Title")));

        // 3. la jail
        if (!jailAttiva()) {
            JSONObject e = ProtezioneWeb.installaJail();
            fatti.put(esito("jail", "Jail fail2ban", e));
            // Una jail mancante non impedisce a MTA-STS di funzionare: si annota e si prosegue.
        } else fatti.put(gia("jail", "Jail fail2ban"));

        // 4. i CNAME
        //
        // I domini in cui qualcosa CAMBIA davvero si segnano: sono gli unici per cui, piu'
        // avanti, ha senso aspettare la propagazione. Dove non e' cambiato niente non c'e'
        // niente da propagare, e un'attesa sarebbe solo tempo tolto a chi guarda.
        LinkedHashSet<String> appenaCambiati = new LinkedHashSet<>();
        JSONArray cname = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : dominiDaToccare(soloDominio)) {
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
                            risponde ? I18n.tr("server.sts.answersNoCf")
                                     : I18n.tr("server.sts.noAnswerNoCf")));
                    continue;
                }
                if (e.optBoolean("success", false) && !e.optBoolean("invariato", false))
                    appenaCambiati.add(d.domain);
                cname.put(nota(d.domain, e.optBoolean("success", false),
                        e.optString("nota", e.optString("error", ""))));
            }
        } catch (Exception e) {
            cname.put(nota("", false, I18n.tr("server.sts.error", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        fatti.put(new JSONObject().put("chiave", "cname").put("titolo", "CNAME mta-sts")
                .put("dettaglio", cname));
        if (job != null) { job.avanza(4, 8); job.scrivi("[4/8] " + I18n.tr("server.sts.cnameExamined", java.util.Map.of("n", String.valueOf(cname.length())))); }

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
            for (MailDatabase.Domain d : dominiDaToccare(soloDominio)) {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, I18n.tr("server.sts.notLinkedCf")));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, I18n.tr("server.sts.zoneNotFoundCf")));
                    continue;
                }
                String nome = ("mta-sts." + d.domain).toLowerCase(Locale.ROOT);
                java.util.List<CloudflareManager.DnsRecordInfo> tutti =
                        cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, I18n.tr("server.sts.emptyZone")));
                    continue;
                }
                boolean visto = false;
                for (CloudflareManager.DnsRecordInfo t : tutti) {
                    if (t.name == null || !t.name.toLowerCase(Locale.ROOT).equals(nome)) continue;
                    visto = true;
                    if (!t.proxied) {
                        dritti++;
                        proxy.put(nota(d.domain, true, I18n.tr("server.sts.pointsStraight", java.util.Map.of("tipo", String.valueOf(t.type)))));
                        continue;
                    }
                    CloudflareManager.RecordOp op = cf.impostaProxy(a.apiToken, zl.zoneId, t.id, false);
                    boolean fatto = op != null && op.success;
                    if (fatto) { sistemati++; appenaCambiati.add(d.domain); }
                    proxy.put(nota(d.domain, fatto,
                            fatto ? I18n.tr("server.sts.proxyRemoved", java.util.Map.of("tipo", String.valueOf(t.type)))
                                  : I18n.tr("server.sts.proxyNotRemoved", java.util.Map.of("tipo", String.valueOf(t.type), "e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error)))));
                }
                if (!visto) {
                    ciechi++;
                    proxy.put(nota(d.domain, false, I18n.tr("server.sts.noRecordNamed", java.util.Map.of("nome", String.valueOf(nome)))));
                }
            }
        } catch (Exception e) {
            ciechi++;
            proxy.put(nota("", false, I18n.tr("server.sts.checkError", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        fatti.put(new JSONObject().put("chiave", "proxy")
                .put("titolo", I18n.tr("server.sts.stepProxy"))
                .put("dettaglio", proxy));
        if (job != null) job.scrivi("[5/8] " + I18n.tr("server.sts.proxySummary", java.util.Map.of("d", String.valueOf(dritti), "s", String.valueOf(sistemati), "c", String.valueOf(ciechi))));

        // 5. il certificato
        //
        // Questo passo NON rispetta il filtro per dominio, ed e' voluto: il certificato e'
        // uno solo e "--issue --force" RIDEFINISCE l'insieme dei nomi. Emetterlo con i soli
        // nomi del dominio corrente cancellerebbe dal certificato i mta-sts.* e autoconfig.*
        // di tutti gli altri — e con i record MTA-STS gia' pubblicati, quella e' posta
        // rifiutata. Si guardano sempre tutti i nomi, si emette solo se ne manca qualcuno.
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
            if (job != null) { job.avanza(6, 8); job.scrivi("[6/8] " + I18n.tr("server.sts.issuingCert", java.util.Map.of("n", String.valueOf(nomi.size()), "m", String.valueOf(scoperti.size())))); }
            AcmeManager.CertificateResult cr = acme.emettiConNomi(host, nomi);
            // "Emissione fallita" da solo non serve a nessuno: la ragione vera sta nell'uscita
            // di acme.sh — un dominio che il token non copre, un limite di Let's Encrypt, una
            // zona non visibile. Senza quella riga non si diagnostica niente.
            String dettaglio = cr.output == null ? "" : cr.output.trim();
            if (dettaglio.length() > 4000) dettaglio = dettaglio.substring(dettaglio.length() - 4000);
            JSONObject e = new JSONObject().put("success", cr.success)
                    .put("nota", cr.message).put("error", cr.message);
            JSONObject riga = esito("certificato", I18n.tr("server.sts.certTitle"), e);
            riga.put("nomi", new JSONArray(nomi));
            // L'uscita si mostra SEMPRE, non solo quando fallisce. Buttarla via quando il
            // comando "riesce" toglie la prova proprio nel caso peggiore: quello in cui
            // riesce ma non ha fatto quello che credevamo.
            riga.put("uscita", dettaglio);
            fatti.put(riga);
            if (job != null) {
                job.scrivi("--- " + I18n.tr("server.sts.acmeOutput") + " ---");
                for (String r2 : dettaglio.split("\n")) job.scrivi("  " + r2);
                job.scrivi("--- " + I18n.tr("server.sts.outputEnd") + " ---");
            }
            if (!cr.success) return fermati(r, fatti,
                    I18n.tr("server.sts.noCertStop"));
        } else fatti.put(gia("certificato", I18n.tr("server.sts.certTitle")));

        // 6-bis. L'attesa della propagazione, e solo dove serve.
        //
        // Un record DNS appena creato non e' visibile subito: chi ha in cache la risposta
        // precedente la tiene per il suo TTL. Su un nome coperto da un jolly Cloudflare quel
        // TTL vale 300 secondi, quindi la politica puo' restare irraggiungibile per cinque
        // minuti dopo che il CNAME e' stato creato. Provando subito, la sequenza si fermerebbe
        // sempre un passo prima della fine e lascerebbe a chi guarda il compito di ripremere
        // piu' tardi — cioe' esattamente il lavoro a mano che questo pulsante esiste per
        // togliere, e per giunta senza dire quanto tardi.
        //
        // Quindi si aspetta. Ma solo per i domini in cui qualcosa e' cambiato, si prova subito
        // prima di dormire, e si smette appena rispondono: un'attesa che non finisce mai
        // quando l'esito e' gia' buono e' un difetto tanto quanto non aspettare.
        if (!appenaCambiati.isEmpty()) {
            if (job != null) job.scrivi("[7/8] " + I18n.tr("server.sts.waitingDns", java.util.Map.of("n", String.valueOf(appenaCambiati.size()), "min", String.valueOf((ATTESA_MAX_MS / 60000)))));
            List<String> restano = attendiPropagazione(
                    new ArrayList<>(appenaCambiati),
                    dom -> MtaSts.provaPubblica(dom).optBoolean("ok", false),
                    OROLOGIO_VERO, ATTESA_MAX_MS, ATTESA_INTERVALLO_MS,
                    riga -> { if (job != null) job.scrivi(riga); });
            if (job != null) job.scrivi(restano.isEmpty()
                    ? "    " + I18n.tr("server.sts.allAnswer")
                    : "    " + I18n.tr("server.sts.stillNot", java.util.Map.of("elenco", String.valueOf(String.join(", ", restano)))));
        }

        // 6-7. la prova e il record, dominio per dominio
        JSONArray finali = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : dominiDaToccare(soloDominio)) {
                JSONObject prova = MtaSts.provaPubblica(d.domain);
                if (!prova.optBoolean("ok", false)) {
                    finali.put(nota(d.domain, false, I18n.tr("server.sts.policyNotYet", java.util.Map.of("e", String.valueOf(prova.optString("errore", ""))))));
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
            finali.put(nota("", false, I18n.tr("server.sts.error", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        if (job != null) { job.avanza(8, 8); job.scrivi("[7-8/8] " + I18n.tr("server.sts.finalExamined", java.util.Map.of("n", String.valueOf(finali.length())))); }
        fatti.put(new JSONObject().put("chiave", "txt").put("titolo", I18n.tr("server.sts.finalTitle"))
                .put("dettaglio", finali));

        return r.put("success", true).put("passi", fatti)
                .put("nota", I18n.tr("server.sts.sequenceDone"));
    }

    /**
     * L'esito della sequenza tradotto nelle righe che la pagina DNS gia' sa disegnare
     * ({titolo, ok, messaggio}).
     *
     * La traduzione sta QUI e non nella pagina DNS perche' le forme che escono da esegui()
     * sono di questa classe: se le conoscesse anche chi chiama, ogni cambiamento qui dentro
     * andrebbe ricordato la' — ed e' cosi' che due pezzi di codice cominciano a divergere.
     *
     * Un passo interrotto non sparisce: se la sequenza si e' fermata, l'ultima riga dice
     * perche'. Un elenco di passi riusciti che si interrompe senza spiegazioni sarebbe la
     * cosa peggiore da mostrare, perche' somiglia a un successo.
     */
    public static JSONArray comeVoci(JSONObject esito) {
        JSONArray voci = new JSONArray();
        JSONArray passi = esito.optJSONArray("passi");
        for (int i = 0; passi != null && i < passi.length(); i++) {
            JSONObject p = passi.optJSONObject(i);
            if (p == null) continue;
            String titolo = p.optString("titolo", p.optString("chiave", "passo"));
            JSONArray dett = p.optJSONArray("dettaglio");
            if (dett == null) {
                voci.put(new JSONObject().put("titolo", titolo)
                        .put("ok", p.optBoolean("ok", false))
                        .put("messaggio", p.optString("messaggio", "")));
                continue;
            }
            // Un passo per dominio: riuscito solo se lo sono tutte le righe, e il messaggio
            // le riporta tutte. Riassumerlo in "fatto" perderebbe l'unica riga che spiega.
            boolean tutte = dett.length() > 0;
            List<String> righe = new ArrayList<>();
            for (int j = 0; j < dett.length(); j++) {
                JSONObject x = dett.optJSONObject(j);
                if (x == null) continue;
                if (!x.optBoolean("ok", false)) tutte = false;
                String dom = x.optString("dominio", "");
                righe.add((dom.isEmpty() ? "" : dom + ": ") + x.optString("messaggio", ""));
            }
            voci.put(new JSONObject().put("titolo", titolo).put("ok", tutte)
                    .put("messaggio", String.join(" | ", righe)));
        }
        if (!esito.optBoolean("success", false) && !esito.optString("error", "").isEmpty())
            voci.put(new JSONObject().put("titolo", I18n.tr("server.sts.interrupted")).put("ok", false)
                    .put("messaggio", esito.getString("error")));
        return voci;
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
                .put("ok", true).put("messaggio", I18n.tr("server.sts.alreadyOk"));
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
        /**
         * Il nome risponde ATTRAVERSO Cloudflare: o il record esplicito e' proxato, o il
         * record manca e a rispondere e' un jolly proxato. Nei due casi l'effetto e' lo
         * stesso — chi legge la politica non parla mai con il server — ma il rimedio no,
         * e per questo il fatto viaggia come booleano invece che dentro una frase.
         *
         * Prima il piano ricavava questa informazione cercando la parola "Cloudflare" nel
         * motivo. Un record insieme SBAGLIATO e PROXATO finiva cosi' nel solo conto del
         * proxy, e il passo dei CNAME dichiarava "tutti presenti e giusti" un record che
         * puntava altrove. Una classificazione si calcola dove stanno i fatti, non
         * rileggendo il testo scritto per un essere umano.
         */
        public final boolean passaDalProxy;
        /** Il record c'e' ma il contenuto e' sbagliato: tipo errato o destinazione errata. */
        public final boolean contenutoSbagliato;
        EsameNome(String d, StatoNome s, String m, boolean r) { this(d, s, m, r, false, false); }
        EsameNome(String d, StatoNome s, String m, boolean r, boolean proxy, boolean storto) {
            dominio = d; stato = s; motivo = m; risolve = r;
            passaDalProxy = proxy; contenutoSbagliato = storto;
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
                            I18n.tr("server.sts.blindNoAccount"), risolve));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    out.add(new EsameNome(d.domain, StatoNome.CIECO,
                            I18n.tr("server.sts.blindZone"), risolve));
                    continue;
                }
                List<CloudflareManager.DnsRecordInfo> tutti = cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    out.add(new EsameNome(d.domain, StatoNome.CIECO,
                            I18n.tr("server.sts.blindEmpty"), risolve));
                    continue;
                }
                CloudflareManager.DnsRecordInfo trovato = null;
                String cercato = pieno.toLowerCase(Locale.ROOT);
                for (CloudflareManager.DnsRecordInfo t : tutti)
                    if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(cercato)) {
                        trovato = t; break;
                    }
                if (trovato == null) {
                    // "Quasi certamente c'e' un jolly" era una supposizione, scritta mentre la
                    // lista completa dei record della zona era gia' in mano. Il jolly si guarda.
                    // E la differenza pesa: un jolly DIETRO PROXY non e' solo il motivo per cui
                    // il nome risponde, e' il motivo per cui risponde 526 — un fatto che il
                    // passo del proxy deve sapere, e che una supposizione non gli puo' dare.
                    CloudflareManager.DnsRecordInfo jolly = null;
                    String nomeJolly = ("*." + d.domain).toLowerCase(Locale.ROOT);
                    for (CloudflareManager.DnsRecordInfo t : tutti)
                        if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(nomeJolly)) {
                            jolly = t; break;
                        }
                    String perche;
                    if (jolly != null)
                        // Niente parentesi qui dentro: questo motivo viene mostrato gia' dentro
                        // una parentesi, e due livelli annidati si leggono male.
                        perche = ", " + (jolly.proxied
                                ? I18n.tr("server.sts.wildcardProxied", java.util.Map.of("d", String.valueOf(d.domain), "tipo", String.valueOf(jolly.type), "v", String.valueOf(jolly.content)))
                                : I18n.tr("server.sts.wildcardStraight", java.util.Map.of("d", String.valueOf(d.domain), "tipo", String.valueOf(jolly.type), "v", String.valueOf(jolly.content))));
                    else if (risolve)
                        perche = ", " + I18n.tr("server.sts.answersFromOutside", java.util.Map.of("d", String.valueOf(d.domain)));
                    else perche = "";
                    out.add(new EsameNome(d.domain, StatoNome.ASSENTE,
                            I18n.tr("server.sts.noRecordInZone") + perche, risolve,
                            jolly != null && jolly.proxied, false));
                    continue;
                }
                String bersaglio = Main.mailDatabase.getSetting("mail_hostname", "mail." + d.domain);
                List<String> male = new ArrayList<>();
                boolean storto = false;
                if (!"CNAME".equalsIgnoreCase(trovato.type)) {
                    male.add(I18n.tr("server.sts.notCname", java.util.Map.of("tipo", String.valueOf(trovato.type))));
                    storto = true;
                } else if (!RegoleDns.stessoNome(trovato.content, bersaglio)) {
                    male.add(I18n.tr("server.sts.pointsElsewhere", java.util.Map.of("v", String.valueOf(trovato.content), "b", String.valueOf(bersaglio))));
                    storto = true;
                }
                if (trovato.proxied)
                    male.add(I18n.tr("server.sts.viaCfInstead"));
                out.add(male.isEmpty()
                        ? new EsameNome(d.domain, StatoNome.GIUSTO, I18n.tr("server.sts.pointsStraightTo", java.util.Map.of("b", String.valueOf(bersaglio))), risolve)
                        : new EsameNome(d.domain, StatoNome.DA_CORREGGERE, String.join("; ", male),
                                        risolve, trovato.proxied, storto));
            } catch (Exception e) {
                out.add(new EsameNome(d.domain, StatoNome.CIECO,
                        I18n.tr("server.sts.checkError", java.util.Map.of("m", String.valueOf(e.getMessage()))), risolve));
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
     * Cosa dice il DNS del record _mta-sts, con un valore apposta per "non l'ho chiesto".
     *
     * Prima questa lettura era un booleano solo — "il record c'e' ed e' quello giusto?" — e
     * rispondeva NO in tre casi diversissimi: record assente, record presente con un id
     * vecchio, e interrogazione DNS fallita. Il piano non poteva distinguerli, e infatti il
     * secondo caso — l'unico pericoloso, perche' e' una dichiarazione pubblica gia' in aria —
     * spariva. Tre risposte diverse vogliono tre valori diversi.
     *
     * NON_CHIESTO vuol dire "non lo so": dig che non parte, un DNS che non risponde, oppure un
     * DNS che risponde con un errore (SERVFAIL, REFUSED) invece che con il contenuto del nome.
     *
     * TROPPI vuol dire piu' di un record v=STSv1 sullo stesso nome: per i mittenti e' come non
     * averne nessuno (RFC 8461 §3.1, vedi RegoleDns.soloMtaSts). Prima si leggeva il primo e si
     * diceva PRESENTE, e il passo poteva risultare fatto su un MTA-STS che nessuno usa.
     *
     * E' pubblica perche' la stessa lettura serve alla pagina DNS: due letture dello stesso
     * record sono due letture che un giorno rispondono in modo diverso.
     */
    public enum EsitoTxt { PRESENTE, ASSENTE, TROPPI, NON_CHIESTO }

    public static final class LetturaTxt {
        public final EsitoTxt esito;
        /** Con PRESENTE, il record. Altrimenti vuoto, anche con TROPPI: li' "il" record non c'e'. */
        public final String contenuto;
        /** Tutti i record v=STSv1 trovati: uno con PRESENTE, piu' d'uno con TROPPI. */
        public final List<String> valori;
        /**
         * Con NON_CHIESTO, il perche': "il DNS risponde SERVFAIL" e "nessun DNS risponde"
         * portano a cercare il guasto in posti diversi.
         */
        public final String motivo;

        private LetturaTxt(EsitoTxt esito, List<String> valori, String motivo) {
            this.esito = esito;
            this.valori = List.copyOf(valori);
            this.contenuto = esito == EsitoTxt.PRESENTE ? valori.get(0) : "";
            this.motivo = motivo;
        }
    }

    /** Dai record v=STSv1 del nome: nessuno, uno solo, o troppi. */
    private static LetturaTxt trovati(List<String> sts) {
        EsitoTxt e = sts.isEmpty() ? EsitoTxt.ASSENTE
                   : sts.size() == 1 ? EsitoTxt.PRESENTE : EsitoTxt.TROPPI;
        return new LetturaTxt(e, sts, "");
    }

    private static LetturaTxt ignoto(String motivo) {
        return new LetturaTxt(EsitoTxt.NON_CHIESTO, List.of(), motivo);
    }

    public static LetturaTxt leggiTxt(String dominio) {
        try {
            // Senza +short: serve lo stato della risposta. Con +short un SERVFAIL (una zona
            // rotta, un DNSSEC che non torna) esce con 0 e non stampa niente, esattamente come un
            // nome senza record: il piano leggeva "assente" e proponeva di pubblicare un record
            // che forse c'e' gia'.
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+answer",
                    "TXT", "_mta-sts." + dominio);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return interpretaTxt(p.waitFor(), out);
        } catch (Exception e) {
            // dig che non c'e' o non parte: non ho chiesto niente a nessuno.
            return ignoto(I18n.tr("server.sts.digNoStart"));
        }
    }

    // ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55131"
    private static final Pattern STATO_DIG = Pattern.compile("->>HEADER<<-.*\\bstatus:\\s*([A-Z]+)");
    // "_mta-sts.domain-d.test.  3600  IN  TXT  "v=STSv1; id=..."": nome, TTL e classe, poi il tipo
    private static final Pattern RIGA_TXT = Pattern.compile("^\\S+\\s+(?:\\d+\\s+)?(?:IN\\s+)?TXT\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    /**
     * Cosa vuol dire l'uscita di "dig +noall +comments +answer TXT _mta-sts.<dominio>": il
     * codice con cui dig e' uscito e cio' che ha stampato. Sta da sola perche' le prove la
     * verifichino con uscite di dig registrate, senza bisogno di un DNS raggiungibile; e'
     * pubblica perche' la usano anche le prove della pagina DNS, che stanno in un altro pacchetto.
     *
     * Lo stato della risposta decide prima del contenuto:
     *   NOERROR  -> il nome c'e': si contano i suoi record v=STSv1. Nessuno e' ASSENTE, uno
     *               e' PRESENTE, piu' d'uno e' TROPPI;
     *   NXDOMAIN -> il nome non esiste: ASSENTE;
     *   un altro stato (SERVFAIL, REFUSED...) o nessuno -> il DNS non ha detto che cosa c'e':
     *   NON_CHIESTO.
     */
    public static LetturaTxt interpretaTxt(int uscitaDig, String stampato) {
        // dig torna 0 anche quando il nome non esiste: un'uscita diversa da zero vuol dire
        // che non ho CHIESTO, non che la risposta sia "niente". Sono cose opposte.
        if (uscitaDig == 9) return ignoto(I18n.tr("server.sts.noDnsAnswers"));
        if (uscitaDig != 0 || stampato == null) return ignoto(I18n.tr("server.sts.digExit", java.util.Map.of("c", String.valueOf(uscitaDig))));
        Matcher stato = STATO_DIG.matcher(stampato);
        String s = stato.find() ? stato.group(1) : "";
        if (s.equals("NXDOMAIN")) return trovati(List.of());
        if (s.isEmpty()) return ignoto(I18n.tr("server.sts.digNoStatus"));
        if (!s.equals("NOERROR")) return ignoto(I18n.tr("server.sts.dnsAnswers", java.util.Map.of("s", String.valueOf(s))));
        // Tutti i TXT del nome, non il primo che va bene: il conto dei record v=STSv1 e' parte
        // della risposta.
        List<String> txt = new ArrayList<>();
        for (String riga : stampato.split("\n")) {
            String t = riga.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            Matcher m = RIGA_TXT.matcher(t);          // un CNAME davanti al TXT si salta
            if (m.matches()) txt.addAll(RegoleDns.recordTxt(m.group(1)));
        }
        return trovati(RegoleDns.soloMtaSts(txt));
    }

    /**
     * Il record TXT che questo pannello scriverebbe adesso.
     *
     * Non basta che il record esista: l'id deve corrispondere alla politica servita, altrimenti
     * i mittenti non si accorgeranno delle modifiche future. I record creati dal vecchio
     * pannello hanno un id fisso — un orologio scritto una volta sola — che non cambierebbe
     * mai. Un piano che li desse per "fatti" nasconderebbe proprio la cosa da sistemare.
     */
    private static String txtAtteso() {
        // Non si ricalcola qui: lo sa MtaSts, che e' anche chi serve la politica. Tre punti
        // che compongono la stessa stringa sono tre stringhe che un giorno divergono — ed e'
        // gia' successo, con l'id da orologio del riepilogo DNS.
        return MtaSts.recordTxtCorrente();
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
