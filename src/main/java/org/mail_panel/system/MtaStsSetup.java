package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.security.AcmeManager;
import org.mail_panel.security.AutoDns;
import org.mail_panel.security.CloudflareManager;
import org.mail_panel.security.DnsRules;
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
public class MtaStsSetup {

    private MtaStsSetup() {}

    /**
     * Quanto la sequenza aspetta, al massimo, che un record DNS appena creato diventi visibile.
     *
     * Non e' un numero scelto a sentimento: un resolver che ha gia' in cache la risposta
     * precedente la tiene per il TTL di quella risposta, e su un jolly Cloudflare quel TTL
     * measured vale 300 secondi. Sotto i cinque minuti l'attesa non servirebbe a niente; sei
     * lasciano il margine perche' la cache scada davvero.
     */
    private static final long MAX_WAIT_MS = 6 * 60 * 1000L;

    /**
     * Ogni quanto si riprova. Trenta secondi perche' la JVM tiene in cache le risoluzioni
     * riuscite per trenta secondi: riprovare piu' spesso vorrebbe dire rileggere la propria
     * cache e credere di aver interrogato il DNS.
     */
    private static final long WAIT_INTERVAL_MS = 30 * 1000L;

    public static class Step {
        public String key, title, detail, state, reason;
        public JSONObject json() {
            return new JSONObject().put("chiave", key).put("titolo", title)
                    .put("dettaglio", detail == null ? "" : detail)
                    .put("stato", state).put("reason", reason == null ? "" : reason);
        }
    }

    private static Step step(String c, String t, String d, String s, String m) {
        Step p = new Step();
        p.key = c; p.title = t; p.detail = d; p.state = s; p.reason = m;
        return p;
    }

    /* ===================================================================
     * A che punto siamo
     * =================================================================== */

    public static JSONObject plan() {
        JSONObject r = new JSONObject().put("success", true);
        List<Step> steps = new ArrayList<>();

        // 1-2-3: la superficie sulla 443
        JSONObject web = WebProtection.state();
        JSONObject inclusion = web.optJSONObject("include");
        boolean includeOk = inclusion != null && inclusion.optBoolean("ok", false);
        steps.add(step("include", I18n.tr("server.sts.stepInclude"),
                inclusion == null ? "" : inclusion.optString("reason", ""),
                includeOk ? "fatto" : "da fare", null));
        steps.add(step("config443", I18n.tr("server.sts.step443"),
                web.optString("file", ""),
                web.optBoolean("installato", false) ? "fatto" : "da fare", null));
        steps.add(step("jail", I18n.tr("server.sts.stepJail"), "",
                jailActive() ? "fatto" : "da fare", null));

        // 4 e 4-bis: i CNAME. Una sola lettura della zona per entrambi i passi, cosi' non
        // possono contraddirsi come e' successo con domain-d.test.
        List<NameReview> reviews = reviewCname();
        // Se l'esame non copre tutti i domini vuol dire che si e' fermato per un guasto:
        // senza questa riga le liste resterebbero vuote e il piano direbbe "tutti a posto"
        // proprio perche' non ha guardato niente. E' l'errore che sto togliendo dal pannello:
        // non deve tornare dalla porta di servizio.
        int domainCount = domains().size();
        Breakdown rip = split(reviews);
        List<String> absent = rip.absent, crooked = rip.crooked, proxied = rip.proxied,
                     blindOnes = rip.blind, propagating = rip.propagating;
        boolean proxyDaJolly = rip.proxyDaJolly;
        if (reviews.size() < domainCount)
            blindOnes.add(I18n.tr("server.sts.notExamined", java.util.Map.of("n", String.valueOf((domainCount - reviews.size())))));
        List<String> cnameTroubles = new ArrayList<>(absent); cnameTroubles.addAll(crooked);
        String cnameDetail;
        if (!cnameTroubles.isEmpty()) cnameDetail = I18n.tr("server.sts.toFix", java.util.Map.of("elenco", String.valueOf(String.join("; ", cnameTroubles))));
        else if (!blindOnes.isEmpty()) cnameDetail = I18n.tr("server.sts.unverifiable", java.util.Map.of("elenco", String.valueOf(String.join("; ", blindOnes))));
        else if (!propagating.isEmpty())
            cnameDetail = I18n.tr("server.sts.propagating", java.util.Map.of("elenco", String.valueOf(String.join(", ", propagating))));
        else if (!proxied.isEmpty())
            cnameDetail = I18n.tr("server.sts.allPresentProxy");
        else cnameDetail = I18n.tr("server.sts.allPresentOk");
        steps.add(step("cname", I18n.tr("server.sts.stepCname"), cnameDetail,
                !cnameTroubles.isEmpty() ? "da fare" : (blindOnes.isEmpty() ? "fatto" : "incerto"),
                blindOnes.isEmpty() ? null
                    : I18n.tr("server.sts.blindDns")));

        // 4-bis: i record che devono puntare DRITTI al server
        boolean blind = !blindOnes.isEmpty();
        steps.add(step("proxy", I18n.tr("server.sts.stepProxy"),
                !proxied.isEmpty() ? I18n.tr("server.sts.viaCf", java.util.Map.of("elenco", String.valueOf(String.join(", ", proxied))))
                        : (blind ? I18n.tr("server.sts.checkedVisible")
                                 : I18n.tr("server.sts.noneViaCf")),
                !proxied.isEmpty() ? "da fare" : (blind ? "incerto" : "fatto"),
                proxied.isEmpty() ? null
                    : I18n.tr("server.sts.proxyWhy")
                    + (proxyDaJolly
                        ? " " + I18n.tr("server.sts.wildcardWhy")
                        : "")));

        // 5: il certificato
        List<String> servedNames = namesToCover();
        List<String> uncovered = new ArrayList<>();
        for (String n : servedNames) if (!certificateCovers(n)) uncovered.add(n);
        List<String> excluded = domainsOnOtherAccount();
        steps.add(step("certificato", I18n.tr("server.sts.stepCert"),
                uncovered.isEmpty() ? I18n.tr("server.sts.allCovered") : I18n.tr("server.sts.uncovered", java.util.Map.of("elenco", String.valueOf(String.join(", ", uncovered)))),
                uncovered.isEmpty() ? "fatto" : "da fare",
                excluded.isEmpty() ? null
                    : I18n.tr("server.sts.otherAccount", java.util.Map.of("elenco", String.valueOf(String.join(", ", excluded))))));

        // 6-7: la prova e il record
        List<TxtReview> txtReviews = new ArrayList<>();
        for (String d : domains()) {
            boolean answers = MtaSts.publicTest(d).optBoolean("ok", false);
            // Il TXT si legge SEMPRE, e soprattutto quando la politica NON risponde: e' proprio
            // quella la combinazione da scoprire, un record gia' pubblicato che manda i mittenti
            // del mondo contro un errore. Prima qui c'era un "else if" e a quel ramo non si
            // arrivava mai: su domain-d.test il pannello scriveva "in attesa dei passi precedenti"
            // mentre il record era pubblicato, con un id vecchio, e la politica dava 526. Cieco
            // esattamente sulla cosa che questa scheda esiste per sorvegliare.
            txtReviews.add(new TxtReview(d, answers, readTxt(d)));
        }
        steps.addAll(testAndTxtSteps(txtReviews, expectedTxt()));

        JSONArray a = new JSONArray();
        int daFare = 0, uncertain = 0;
        for (Step p : steps) {
            a.put(p.json());
            if ("da fare".equals(p.state)) daFare++;
            else if ("incerto".equals(p.state)) uncertain++;
        }
        r.put("passi", a).put("daFare", daFare).put("incerti", uncertain);
        // "completo" accende la spunta verde e fa sparire il pulsante, quindi non puo' bastare
        // che non ci sia niente DA FARE: serve anche che non sia rimasto niente da VERIFICARE.
        // Con la sola condizione daFare==0, un passo "incerto" — cioe' uno che il pannello non
        // ha potuto controllare — sarebbe bastato da solo a dichiarare "attivo su tutti i domini".
        boolean complete = daFare == 0 && uncertain == 0;
        r.put("completo", complete);
        String uncertainCount = uncertain == 1 ? I18n.tr("server.sts.steps.one") : I18n.tr("server.sts.steps.other", java.util.Map.of("n", String.valueOf(uncertain)));
        r.put("nota", complete
                ? I18n.tr("server.sts.complete")
                : daFare == 0
                  ? I18n.tr("server.sts.onlyUncertain", java.util.Map.of("passi", String.valueOf(uncertainCount)))
                  : (daFare == 1 ? I18n.tr("server.sts.missing.one") : I18n.tr("server.sts.missing.other", java.util.Map.of("n", String.valueOf(daFare))))
                    + (uncertain > 0 ? ", " + I18n.tr("server.sts.plusUncertain", java.util.Map.of("passi", String.valueOf(uncertainCount))) : "")
                    + ". " + I18n.tr("server.sts.buttonRuns"));
        return r;
    }

    /** Cosa si e' visto di un dominio per i passi della prova e del record. */
    static final class TxtReview {
        final String domain; final boolean answers; final TxtReading txt;
        TxtReview(String domain, boolean answers, TxtReading txt) {
            this.domain = domain; this.answers = answers; this.txt = txt;
        }
    }

    /**
     * I passi "prova" e "txt" del piano, da cio' che si e' visto dominio per dominio. E' qui
     * che il passo del record diventa "fatto", e sta da solo perche' le prove lo verifichino
     * con letture costruite, senza DNS e senza la politica vera: due record v=STSv1 non
     * devono poterlo far diventare "fatto".
     */
    static List<Step> testAndTxtSteps(List<TxtReview> reviews, String expected) {
        List<String> notAnswering = new ArrayList<>(), withoutTxt = new ArrayList<>(),
                     unmaintained = new ArrayList<>(), unknownTxt = new ArrayList<>(),
                     tooMany = new ArrayList<>();
        for (TxtReview e : reviews) {
            String d = e.domain;
            TxtReading txt = e.txt;
            if (!e.answers) {
                notAnswering.add(d);
                // Anche con piu' record: se uno e' scritto male, i mittenti che lo scartano
                // contano solo l'altro, e quello li manda contro la politica che non risponde.
                if (txt.outcome == TxtOutcome.PRESENTE || txt.outcome == TxtOutcome.TROPPI)
                    unmaintained.add(d + " -> " + String.join("  ||  ", txt.values));
                continue;
            }
            switch (txt.outcome) {
                case NON_CHIESTO -> unknownTxt.add(d + " (" + txt.reason + ")");
                case ASSENTE -> withoutTxt.add(d);
                case TROPPI -> tooMany.add(d + " (" + txt.values.size() + " record: "
                        + String.join("  ||  ", txt.values) + ")");
                case PRESENTE -> {
                    if (!expected.equals(txt.content)) withoutTxt.add(d + " " + I18n.tr("server.sts.idToUpdate"));
                }
            }
        }
        List<Step> steps = new ArrayList<>();
        steps.add(step("prova", I18n.tr("server.sts.stepTest"),
                notAnswering.isEmpty()
                    ? I18n.tr("server.sts.answersAll")
                    : I18n.tr("server.sts.noAnswerFor", java.util.Map.of("elenco", String.valueOf(String.join(", ", notAnswering)))),
                notAnswering.isEmpty() ? "fatto" : "da fare", null));

        String txtDetail, txtState, txtReason = null;
        if (!unmaintained.isEmpty()) {
            txtDetail = I18n.tr("server.sts.notKept", java.util.Map.of("elenco", String.valueOf(String.join("; ", unmaintained))));
            txtState = "da fare";
            txtReason = I18n.tr("server.sts.notKeptWhy");
        } else if (!tooMany.isEmpty()) {
            txtDetail = I18n.tr("server.sts.moreThanOne", java.util.Map.of("elenco", String.valueOf(String.join(", ", tooMany))));
            txtState = "da fare";
            txtReason = I18n.tr("server.sts.moreThanOneWhy");
        } else if (!unknownTxt.isEmpty()) {
            txtDetail = "non so se c'e' per: " + String.join(", ", unknownTxt);
            txtState = "incerto";
            txtReason = I18n.tr("server.sts.notMarkedDone");
        } else if (!notAnswering.isEmpty()) {
            txtDetail = I18n.tr("server.sts.waitingPrev"); txtState = "da fare";
        } else if (!withoutTxt.isEmpty()) {
            txtDetail = I18n.tr("server.sts.missingList", java.util.Map.of("elenco", String.valueOf(String.join(", ", withoutTxt)))); txtState = "da fare";
        } else {
            txtDetail = I18n.tr("server.sts.allPublished"); txtState = "fatto";
        }
        steps.add(step("txt", I18n.tr("server.sts.stepTxt"), txtDetail, txtState, txtReason));
        return steps;
    }

    /**
     * Come i domini esaminati si distribuiscono fra i passi del piano.
     *
     * Sta in un metodo suo, staccato da plan(), per una ragione precisa: e' QUI che sono nati
     * i falsi verdi. Un dominio senza record che rispondeva grazie a un jolly proxato non
     * entrava nel conto del proxy, e il passo diceva "nessuno passa da Cloudflare"; un record
     * insieme SBAGLIATO e PROXATO finiva nel solo conto del proxy — perche' la classificazione
     * cercava la parola "Cloudflare" dentro una frase scritta per un essere umano — e il passo
     * dei CNAME dichiarava "tutti presenti e giusti" un record che puntava altrove.
     *
     * Dentro plan(), che per esistere ha bisogno del database e di Cloudflare, questa logica
     * non si poteva provare con un test. Una logica che nessun test puo' raggiungere e' una
     * logica che nessuno controlla: qui infatti non la controllava nessuno.
     */
    static final class Breakdown {
        final List<String> absent = new ArrayList<>(), crooked = new ArrayList<>(),
                           proxied = new ArrayList<>(), blind = new ArrayList<>(),
                           propagating = new ArrayList<>();
        boolean proxyDaJolly;
    }

    static Breakdown split(List<NameReview> reviews) {
        Breakdown r = new Breakdown();
        for (NameReview e : reviews) {
            // Il proxy si conta per conto suo, da un booleano: un record puo' essere insieme
            // sbagliato E proxato, e i due fatti devono comparire tutti e due, nei due passi
            // a cui appartengono.
            if (e.goesThroughProxy) {
                boolean daJolly = e.state == NameState.ASSENTE;
                if (daJolly) r.proxyDaJolly = true;
                r.proxied.add(e.domain + (daJolly
                        ? " " + I18n.tr("server.sts.wildcardAnswers", java.util.Map.of("d", String.valueOf(e.domain))) : ""));
            }
            switch (e.state) {
                case ASSENTE -> r.absent.add(e.domain + " (" + e.reason + ")");
                case CIECO -> r.blind.add(e.domain + " (" + e.reason + ")");
                case DA_CORREGGERE -> {
                    if (e.wrongContent) r.crooked.add(e.domain + " (" + e.reason + ")");
                }
                case GIUSTO -> { if (!e.resolves) r.propagating.add(e.domain); }
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
    interface Clock {
        long now();
        void sleep(long ms) throws InterruptedException;
    }

    static final Clock REAL_CLOCK = new Clock() {
        public long now() { return System.currentTimeMillis(); }
        public void sleep(long ms) throws InterruptedException { Thread.sleep(ms); }
    };

    /**
     * Aspetta che i domini indicati rispondano, e restituisce quelli che non ce l'hanno fatta.
     *
     * Tre proprieta' che devono valere, e che il test verifica una per una: si prova SUBITO
     * prima di dormire (se rispondono gia', non si aspetta un istante); si smette appena la
     * lista si svuota; e si smette comunque alla scadenza, perche' un ciclo di attesa senza
     * un'uscita garantita, dentro un pannello di produzione, e' un blocco che non finisce piu'.
     */
    static List<String> waitForPropagation(List<String> domains,
                                            java.util.function.Predicate<String> answers,
                                            Clock clock, long maxMs, long intervalMs,
                                            java.util.function.Consumer<String> log) {
        List<String> remain = new ArrayList<>(domains);
        long expiry = clock.now() + maxMs;
        while (true) {
            remain.removeIf(answers);
            if (remain.isEmpty() || clock.now() >= expiry) break;
            log.accept("    " + I18n.tr("server.sts.stillNotAnswering", java.util.Map.of("elenco", String.valueOf(String.join(", ", remain)), "s", String.valueOf((intervalMs / 1000)))));
            try {
                clock.sleep(intervalMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log.accept("    " + I18n.tr("server.sts.waitInterrupted"));
                break;
            }
        }
        return remain;
    }

    /* ===================================================================
     * L'esecuzione
     * =================================================================== */

    public static JSONObject run() { return run(null, null); }

    public static JSONObject run(UpdateManager.Job job) { return run(job, null); }

    /**
     * I domini su cui la sequenza deve agire.
     *
     * Un elenco vuoto NON e' "nessun dominio da fare": vuol dire che il nome chiesto non
     * esiste, e chi chiama deve accorgersene invece di vedere una sequenza che "riesce"
     * senza aver toccato niente.
     */
    private static List<MailDatabase.Domain> domainsToTouch(String domainOnly) throws Exception {
        return filter(Main.mailDatabase.getDomains(), domainOnly);
    }

    /**
     * Il filtro vero e proprio, separato dalla lettura del database perche' possa essere
     * provato: dentro domainsToTouch sarebbe raggiungibile solo con un database vivo, e un
     * test che non arriva alla riga che deve verificare non verifica niente.
     *
     * Il confronto e' senza distinzione di maiuscole perche' i nomi di dominio non ne hanno,
     * ed e' ESATTO: "ake.net" non deve trovare "domain-d.test".
     */
    static List<MailDatabase.Domain> filter(List<MailDatabase.Domain> tutti, String domainOnly) {
        List<MailDatabase.Domain> out = new ArrayList<>();
        if (tutti == null) return out;
        for (MailDatabase.Domain d : tutti)
            if (domainOnly == null || (d != null && domainOnly.equalsIgnoreCase(d.domain)))
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
    public static JSONObject run(UpdateManager.Job job, String domainOnly) {
        JSONObject r = new JSONObject();
        JSONArray doneOnes = new JSONArray();
        if (job != null) job.write("=== " + I18n.tr("server.sts.jobTitle") + " ==="
                + (domainOnly == null ? "" : " " + I18n.tr("server.sts.onlyDomain", java.util.Map.of("d", String.valueOf(domainOnly)))));

        // Un nome che non corrisponde a nessun dominio non deve produrre una sequenza che
        // "riesce": i cicli per dominio girerebbero a vuoto, nessun passo fallirebbe, e
        // l'esito direbbe che e' andato tutto bene senza che sia stato toccato niente. E'
        // il falso successo piu' silenzioso di tutti, e va fermato qui.
        if (domainOnly != null) {
            try {
                if (domainsToTouch(domainOnly).isEmpty())
                    return stopped(r, doneOnes, I18n.tr("server.sts.notPanelDomain", java.util.Map.of("d", String.valueOf(domainOnly))));
            } catch (Exception e) {
                return stopped(r, doneOnes, I18n.tr("server.sts.domainsUnreadable", java.util.Map.of("m", String.valueOf(e.getMessage()))));
            }
        }

        // 1. include
        JSONObject web = WebProtection.state();
        JSONObject inclusion = web.optJSONObject("include");
        if (inclusion == null || !inclusion.optBoolean("ok", false)) {
            JSONObject e = WebProtection.addInclude();
            doneOnes.put(outcome("include", I18n.tr("server.sts.includeTitle"), e));
            if (job != null) job.write("[1/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.includeOk") : I18n.tr("server.sts.includeFail")));
            if (!e.optBoolean("success", false)) return stopped(r, doneOnes,
                    I18n.tr("server.sts.noIncludeStop"));
        } else doneOnes.put(already("include", I18n.tr("server.sts.includeTitle")));

        // 2. la 443
        if (!WebProtection.state().optBoolean("installato", false)) {
            JSONObject e = WebProtection.install("", "");
            doneOnes.put(outcome("config443", I18n.tr("server.sts.config443Title"), e));
            if (job != null) job.write("[2/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.c443Ok") : I18n.tr("server.sts.c443Fail")));
            if (!e.optBoolean("success", false)) return stopped(r, doneOnes,
                    I18n.tr("server.sts.no443Stop"));
        } else doneOnes.put(already("config443", I18n.tr("server.sts.config443Title")));

        // 3. la jail
        if (!jailActive()) {
            JSONObject e = WebProtection.installJail();
            doneOnes.put(outcome("jail", "Jail fail2ban", e));
            // Una jail mancante non impedisce a MTA-STS di funzionare: si annota e si prosegue.
        } else doneOnes.put(already("jail", "Jail fail2ban"));

        // 4. i CNAME
        //
        // I domini in cui qualcosa CAMBIA davvero si segnano: sono gli unici per cui, piu'
        // avanti, ha senso aspettare la propagazione. Dove non e' cambiato niente non c'e'
        // niente da propagare, e un'attesa sarebbe solo tempo tolto a chi guarda.
        LinkedHashSet<String> justChanged = new LinkedHashSet<>();
        JSONArray cname = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                // Prima qui c'era una scorciatoia: se "mta-sts.<dominio>" RISPONDEVA, il record
                // si dava per fatto. Ma rispondere non vuol dire esistere: un jolly "*.domain"
                // fa rispondere qualunque nome. Su domain-d.test era esattamente cosi' — il nome
                // rispondeva grazie al jolly, dietro Cloudflare, e la politica tornava 526.
                // createOptional guarda il record col nome ESATTO dentro la zona, corregge quelli
                // sbagliati o dietro proxy e crea quelli mancanti: e' lui che deve decidere.
                JSONObject e = auto.createOptional(d.id, "mta_sts");
                if (e.optBoolean("nonGestito", false)) {
                    // Dominio non su Cloudflare: non e' un errore, ma nemmeno una conferma.
                    boolean answers = resolves("mta-sts." + d.domain);
                    cname.put(note(d.domain, answers,
                            answers ? I18n.tr("server.sts.answersNoCf")
                                     : I18n.tr("server.sts.noAnswerNoCf")));
                    continue;
                }
                if (e.optBoolean("success", false) && !e.optBoolean("invariato", false))
                    justChanged.add(d.domain);
                cname.put(note(d.domain, e.optBoolean("success", false),
                        e.optString("nota", e.optString("error", ""))));
            }
        } catch (Exception e) {
            cname.put(note("", false, I18n.tr("server.sts.error", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        doneOnes.put(new JSONObject().put("chiave", "cname").put("titolo", "CNAME mta-sts")
                .put("dettaglio", cname));
        if (job != null) { job.advance(4, 8); job.write("[4/8] " + I18n.tr("server.sts.cnameExamined", java.util.Map.of("n", String.valueOf(cname.length())))); }

        // 4-bis. I nomi mta-sts devono puntare dritti al server.
        // Ogni dominio riporta COSA HO VISTO. Prima questo passo diceva "era gia' a posto"
        // ogni volta che non aveva FATTO nulla — compreso quando non aveva VISTO nulla:
        // account assente, zona non trovata, API muta. "Non ho potuto controllare"
        // travestito da "va tutto bene" e' il modo piu' rapido per prendere una decisione
        // sbagliata: qui, pubblicare un record MTA-STS su un nome che passa da Cloudflare.
        JSONArray proxy = new JSONArray();
        int fixed = 0, straight = 0, blind = 0;
        try {
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.notLinkedCf")));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.zoneNotFoundCf")));
                    continue;
                }
                String name = ("mta-sts." + d.domain).toLowerCase(Locale.ROOT);
                java.util.List<CloudflareManager.DnsRecordInfo> tutti =
                        cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.emptyZone")));
                    continue;
                }
                boolean visto = false;
                for (CloudflareManager.DnsRecordInfo t : tutti) {
                    if (t.name == null || !t.name.toLowerCase(Locale.ROOT).equals(name)) continue;
                    visto = true;
                    if (!t.proxied) {
                        straight++;
                        proxy.put(note(d.domain, true, I18n.tr("server.sts.pointsStraight", java.util.Map.of("tipo", String.valueOf(t.type)))));
                        continue;
                    }
                    CloudflareManager.RecordOp op = cf.setProxy(a.apiToken, zl.zoneId, t.id, false);
                    boolean done = op != null && op.success;
                    if (done) { fixed++; justChanged.add(d.domain); }
                    proxy.put(note(d.domain, done,
                            done ? I18n.tr("server.sts.proxyRemoved", java.util.Map.of("tipo", String.valueOf(t.type)))
                                  : I18n.tr("server.sts.proxyNotRemoved", java.util.Map.of("tipo", String.valueOf(t.type), "e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error)))));
                }
                if (!visto) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.noRecordNamed", java.util.Map.of("nome", String.valueOf(name)))));
                }
            }
        } catch (Exception e) {
            blind++;
            proxy.put(note("", false, I18n.tr("server.sts.checkError", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        doneOnes.put(new JSONObject().put("chiave", "proxy")
                .put("titolo", I18n.tr("server.sts.stepProxy"))
                .put("dettaglio", proxy));
        if (job != null) job.write("[5/8] " + I18n.tr("server.sts.proxySummary", java.util.Map.of("d", String.valueOf(straight), "s", String.valueOf(fixed), "c", String.valueOf(blind))));

        // 5. il certificato
        //
        // Questo passo NON rispetta il filtro per dominio, ed e' voluto: il certificato e'
        // uno solo e "--issue --force" RIDEFINISCE l'insieme dei nomi. Emetterlo con i soli
        // nomi del dominio corrente cancellerebbe dal certificato i mta-sts.* e autoconfig.*
        // di tutti gli altri — e con i record MTA-STS gia' pubblicati, quella e' posta
        // rifiutata. Si guardano sempre tutti i nomi, si emette solo se ne manca qualcuno.
        List<String> names = namesToCover();
        List<String> uncovered = new ArrayList<>();
        for (String n : names) if (!certificateCovers(n)) uncovered.add(n);
        if (!uncovered.isEmpty()) {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            String host = MtaSts.mailHost();

            // La guardia "scoperti.isEmpty()" qui sopra evita di riemettere quando i nomi
            // ci sono gia': Let's Encrypt concede 5 emissioni a settimana per lo stesso
            // insieme di nomi, e un pulsante che riemette a ogni pressione consuma quel
            // margine lasciando senza rinnovo proprio quando servirebbe.
            if (job != null) { job.advance(6, 8); job.write("[6/8] " + I18n.tr("server.sts.issuingCert", java.util.Map.of("n", String.valueOf(names.size()), "m", String.valueOf(uncovered.size())))); }
            AcmeManager.CertificateResult cr = acme.emitWithNames(host, names);
            // "Emissione fallita" da solo non serve a nessuno: la ragione vera sta nell'uscita
            // di acme.sh — un dominio che il token non copre, un limite di Let's Encrypt, una
            // zona non visibile. Senza quella riga non si diagnostica niente.
            String detail = cr.output == null ? "" : cr.output.trim();
            if (detail.length() > 4000) detail = detail.substring(detail.length() - 4000);
            JSONObject e = new JSONObject().put("success", cr.success)
                    .put("nota", cr.message).put("error", cr.message);
            JSONObject line = outcome("certificato", I18n.tr("server.sts.certTitle"), e);
            line.put("nomi", new JSONArray(names));
            // L'uscita si mostra SEMPRE, non solo quando fallisce. Buttarla via quando il
            // comando "riesce" toglie la prova proprio nel caso peggiore: quello in cui
            // riesce ma non ha fatto quello che credevamo.
            line.put("output", detail);
            doneOnes.put(line);
            if (job != null) {
                job.write("--- " + I18n.tr("server.sts.acmeOutput") + " ---");
                for (String r2 : detail.split("\n")) job.write("  " + r2);
                job.write("--- " + I18n.tr("server.sts.outputEnd") + " ---");
            }
            if (!cr.success) return stopped(r, doneOnes,
                    I18n.tr("server.sts.noCertStop"));
        } else doneOnes.put(already("certificato", I18n.tr("server.sts.certTitle")));

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
        if (!justChanged.isEmpty()) {
            if (job != null) job.write("[7/8] " + I18n.tr("server.sts.waitingDns", java.util.Map.of("n", String.valueOf(justChanged.size()), "min", String.valueOf((MAX_WAIT_MS / 60000)))));
            List<String> remain = waitForPropagation(
                    new ArrayList<>(justChanged),
                    dom -> MtaSts.publicTest(dom).optBoolean("ok", false),
                    REAL_CLOCK, MAX_WAIT_MS, WAIT_INTERVAL_MS,
                    line -> { if (job != null) job.write(line); });
            if (job != null) job.write(remain.isEmpty()
                    ? "    " + I18n.tr("server.sts.allAnswer")
                    : "    " + I18n.tr("server.sts.stillNot", java.util.Map.of("elenco", String.valueOf(String.join(", ", remain)))));
        }

        // 6-7. la prova e il record, dominio per dominio
        JSONArray finals = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                JSONObject test = MtaSts.publicTest(d.domain);
                if (!test.optBoolean("ok", false)) {
                    finals.put(note(d.domain, false, I18n.tr("server.sts.policyNotYet", java.util.Map.of("e", String.valueOf(test.optString("errore", ""))))));
                    continue;
                }
                // Non si salta piu' quando il record c'e': va controllato che l'id corrisponda
                // alla politica servita. I record creati dal vecchio pannello hanno un id fisso
                // che non cambierebbe mai.
                JSONObject e = auto.creaTxtMtaSts(d.id);
                finals.put(note(d.domain, e.optBoolean("success", false),
                        e.optString("nota", e.optString("error", ""))));
            }
        } catch (Exception e) {
            finals.put(note("", false, I18n.tr("server.sts.error", java.util.Map.of("m", String.valueOf(e.getMessage())))));
        }
        if (job != null) { job.advance(8, 8); job.write("[7-8/8] " + I18n.tr("server.sts.finalExamined", java.util.Map.of("n", String.valueOf(finals.length())))); }
        doneOnes.put(new JSONObject().put("chiave", "txt").put("titolo", I18n.tr("server.sts.finalTitle"))
                .put("dettaglio", finals));

        return r.put("success", true).put("passi", doneOnes)
                .put("nota", I18n.tr("server.sts.sequenceDone"));
    }

    /**
     * L'esito della sequenza tradotto nelle righe che la pagina DNS gia' sa disegnare
     * ({titolo, ok, messaggio}).
     *
     * La traduzione sta QUI e non nella pagina DNS perche' le forme che escono da run()
     * sono di questa classe: se le conoscesse anche chi chiama, ogni cambiamento qui dentro
     * andrebbe ricordato la' — ed e' cosi' che due pezzi di codice cominciano a divergere.
     *
     * Un passo interrotto non sparisce: se la sequenza si e' fermata, l'ultima riga dice
     * perche'. Un elenco di passi riusciti che si interrompe senza spiegazioni sarebbe la
     * cosa peggiore da mostrare, perche' somiglia a un successo.
     */
    public static JSONArray asEntries(JSONObject outcome) {
        JSONArray entries = new JSONArray();
        JSONArray steps = outcome.optJSONArray("passi");
        for (int i = 0; steps != null && i < steps.length(); i++) {
            JSONObject p = steps.optJSONObject(i);
            if (p == null) continue;
            String title = p.optString("titolo", p.optString("chiave", "passo"));
            JSONArray detail = p.optJSONArray("dettaglio");
            if (detail == null) {
                entries.put(new JSONObject().put("titolo", title)
                        .put("ok", p.optBoolean("ok", false))
                        .put("messaggio", p.optString("messaggio", "")));
                continue;
            }
            // Un passo per dominio: riuscito solo se lo sono tutte le righe, e il messaggio
            // le riporta tutte. Riassumerlo in "fatto" perderebbe l'unica riga che spiega.
            boolean all = detail.length() > 0;
            List<String> lines = new ArrayList<>();
            for (int j = 0; j < detail.length(); j++) {
                JSONObject x = detail.optJSONObject(j);
                if (x == null) continue;
                if (!x.optBoolean("ok", false)) all = false;
                String dom = x.optString("dominio", "");
                lines.add((dom.isEmpty() ? "" : dom + ": ") + x.optString("messaggio", ""));
            }
            entries.put(new JSONObject().put("titolo", title).put("ok", all)
                    .put("messaggio", String.join(" | ", lines)));
        }
        if (!outcome.optBoolean("success", false) && !outcome.optString("error", "").isEmpty())
            entries.put(new JSONObject().put("titolo", I18n.tr("server.sts.interrupted")).put("ok", false)
                    .put("messaggio", outcome.getString("error")));
        return entries;
    }

    private static JSONObject stopped(JSONObject r, JSONArray done, String why) {
        return r.put("success", false).put("passi", done).put("error", why);
    }

    private static JSONObject outcome(String key, String title, JSONObject e) {
        return new JSONObject().put("chiave", key).put("titolo", title)
                .put("ok", e.optBoolean("success", false))
                .put("messaggio", e.optString("nota", e.optString("error", "")));
    }

    private static JSONObject already(String key, String title) {
        return new JSONObject().put("chiave", key).put("titolo", title)
                .put("ok", true).put("messaggio", I18n.tr("server.sts.alreadyOk"));
    }

    private static JSONObject note(String domain, boolean ok, String message) {
        return new JSONObject().put("dominio", domain).put("ok", ok).put("messaggio", message);
    }

    /* ===================================================================
     * Misure
     * =================================================================== */

    private static List<String> domains() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }

    /** I nomi che il certificato deve coprire: l'hostname piu' mta-sts e autoconfig dei domini. */
    public static List<String> namesToCover() {
        LinkedHashSet<String> n = new LinkedHashSet<>();
        List<String> excluded = domainsOnOtherAccount();
        for (String d : domains()) {
            if (excluded.contains(d)) continue;
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
    public static List<String> domainsOnOtherAccount() {
        List<String> outside = new ArrayList<>();
        try {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            var certAcct = acme.certificateAccount(MtaSts.mailHost());
            if (certAcct == null) return outside;
            for (var d : Main.mailDatabase.getDomains()) {
                var a = acme.accountDi(d.id);
                if (a == null || a.id != certAcct.id) outside.add(d.domain);
            }
        } catch (Exception ignore) {}
        return outside;
    }

    private static boolean certificateCovers(String name) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            // Una sola implementazione della lettura dei nomi, condivisa con AcmeManager:
            // due letture separate finiscono per divergere, e una delle due sbaglia in silenzio.
            for (String n : AcmeManager.namesFromSubjectAltName(out))
                if (n.equalsIgnoreCase(name)) return true;
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
    public enum NameState { GIUSTO, DA_CORREGGERE, ASSENTE, CIECO }

    public static final class NameReview {
        public final String domain; public final NameState state;
        public final String reason; public final boolean resolves;
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
        public final boolean goesThroughProxy;
        /** Il record c'e' ma il contenuto e' sbagliato: tipo errato o destinazione errata. */
        public final boolean wrongContent;
        NameReview(String d, NameState s, String m, boolean r) { this(d, s, m, r, false, false); }
        NameReview(String d, NameState s, String m, boolean r, boolean proxy, boolean crooked) {
            domain = d; state = s; reason = m; resolves = r;
            goesThroughProxy = proxy; wrongContent = crooked;
        }
    }

    public static List<NameReview> reviewCname() {
        List<NameReview> out = new ArrayList<>();
        CloudflareManager cf;
        List<MailDatabase.Domain> domains;
        try {
            cf = new CloudflareManager(Main.mailDatabase);
            domains = Main.mailDatabase.getDomains();
        } catch (Exception e) {
            // Nessun dominio esaminato: chi chiama vede una lista vuota, non un falso "a posto".
            return out;
        }
        for (MailDatabase.Domain d : domains) {
            String full = "mta-sts." + d.domain;
            boolean resolves = resolves(full);
            try {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    out.add(new NameReview(d.domain, NameState.CIECO,
                            I18n.tr("server.sts.blindNoAccount"), resolves));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    out.add(new NameReview(d.domain, NameState.CIECO,
                            I18n.tr("server.sts.blindZone"), resolves));
                    continue;
                }
                List<CloudflareManager.DnsRecordInfo> tutti = cf.listRecords(a.apiToken, zl.zoneId);
                if (tutti.isEmpty()) {
                    out.add(new NameReview(d.domain, NameState.CIECO,
                            I18n.tr("server.sts.blindEmpty"), resolves));
                    continue;
                }
                CloudflareManager.DnsRecordInfo found = null;
                String searched = full.toLowerCase(Locale.ROOT);
                for (CloudflareManager.DnsRecordInfo t : tutti)
                    if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(searched)) {
                        found = t; break;
                    }
                if (found == null) {
                    // "Quasi certamente c'e' un jolly" era una supposizione, scritta mentre la
                    // lista completa dei record della zona era gia' in mano. Il jolly si guarda.
                    // E la differenza pesa: un jolly DIETRO PROXY non e' solo il motivo per cui
                    // il nome risponde, e' il motivo per cui risponde 526 — un fatto che il
                    // passo del proxy deve sapere, e che una supposizione non gli puo' dare.
                    CloudflareManager.DnsRecordInfo jolly = null;
                    String wildcardName = ("*." + d.domain).toLowerCase(Locale.ROOT);
                    for (CloudflareManager.DnsRecordInfo t : tutti)
                        if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(wildcardName)) {
                            jolly = t; break;
                        }
                    String why;
                    if (jolly != null)
                        // Niente parentesi qui dentro: questo motivo viene mostrato gia' dentro
                        // una parentesi, e due livelli annidati si leggono male.
                        why = ", " + (jolly.proxied
                                ? I18n.tr("server.sts.wildcardProxied", java.util.Map.of("d", String.valueOf(d.domain), "tipo", String.valueOf(jolly.type), "v", String.valueOf(jolly.content)))
                                : I18n.tr("server.sts.wildcardStraight", java.util.Map.of("d", String.valueOf(d.domain), "tipo", String.valueOf(jolly.type), "v", String.valueOf(jolly.content))));
                    else if (resolves)
                        why = ", " + I18n.tr("server.sts.answersFromOutside", java.util.Map.of("d", String.valueOf(d.domain)));
                    else why = "";
                    out.add(new NameReview(d.domain, NameState.ASSENTE,
                            I18n.tr("server.sts.noRecordInZone") + why, resolves,
                            jolly != null && jolly.proxied, false));
                    continue;
                }
                String target = Main.mailDatabase.getSetting("mail_hostname", "mail." + d.domain);
                List<String> male = new ArrayList<>();
                boolean crooked = false;
                if (!"CNAME".equalsIgnoreCase(found.type)) {
                    male.add(I18n.tr("server.sts.notCname", java.util.Map.of("tipo", String.valueOf(found.type))));
                    crooked = true;
                } else if (!DnsRules.sameName(found.content, target)) {
                    male.add(I18n.tr("server.sts.pointsElsewhere", java.util.Map.of("v", String.valueOf(found.content), "b", String.valueOf(target))));
                    crooked = true;
                }
                if (found.proxied)
                    male.add(I18n.tr("server.sts.viaCfInstead"));
                out.add(male.isEmpty()
                        ? new NameReview(d.domain, NameState.GIUSTO, I18n.tr("server.sts.pointsStraightTo", java.util.Map.of("b", String.valueOf(target))), resolves)
                        : new NameReview(d.domain, NameState.DA_CORREGGERE, String.join("; ", male),
                                        resolves, found.proxied, crooked));
            } catch (Exception e) {
                out.add(new NameReview(d.domain, NameState.CIECO,
                        I18n.tr("server.sts.checkError", java.util.Map.of("m", String.valueOf(e.getMessage()))), resolves));
            }
        }
        return out;
    }


    private static boolean resolves(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name);
            Shell.applyPath(pb);
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
     * averne nessuno (RFC 8461 §3.1, vedi DnsRules.soloMtaSts). Prima si leggeva il primo e si
     * diceva PRESENTE, e il passo poteva risultare fatto su un MTA-STS che nessuno usa.
     *
     * E' pubblica perche' la stessa lettura serve alla pagina DNS: due letture dello stesso
     * record sono due letture che un giorno rispondono in modo diverso.
     */
    public enum TxtOutcome { PRESENTE, ASSENTE, TROPPI, NON_CHIESTO }

    public static final class TxtReading {
        public final TxtOutcome outcome;
        /** Con PRESENTE, il record. Altrimenti vuoto, anche con TROPPI: li' "il" record non c'e'. */
        public final String content;
        /** Tutti i record v=STSv1 trovati: uno con PRESENTE, piu' d'uno con TROPPI. */
        public final List<String> values;
        /**
         * Con NON_CHIESTO, il perche': "il DNS risponde SERVFAIL" e "nessun DNS risponde"
         * portano a cercare il guasto in posti diversi.
         */
        public final String reason;

        private TxtReading(TxtOutcome outcome, List<String> values, String reason) {
            this.outcome = outcome;
            this.values = List.copyOf(values);
            this.content = outcome == TxtOutcome.PRESENTE ? values.get(0) : "";
            this.reason = reason;
        }
    }

    /** Dai record v=STSv1 del nome: nessuno, uno solo, o troppi. */
    private static TxtReading found(List<String> sts) {
        TxtOutcome e = sts.isEmpty() ? TxtOutcome.ASSENTE
                   : sts.size() == 1 ? TxtOutcome.PRESENTE : TxtOutcome.TROPPI;
        return new TxtReading(e, sts, "");
    }

    private static TxtReading unknown(String reason) {
        return new TxtReading(TxtOutcome.NON_CHIESTO, List.of(), reason);
    }

    public static TxtReading readTxt(String domain) {
        try {
            // Senza +short: serve lo stato della risposta. Con +short un SERVFAIL (una zona
            // rotta, un DNSSEC che non torna) esce con 0 e non stampa niente, esattamente come un
            // nome senza record: il piano leggeva "assente" e proponeva di pubblicare un record
            // che forse c'e' gia'.
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+answer",
                    "TXT", "_mta-sts." + domain);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return parseTxt(p.waitFor(), out);
        } catch (Exception e) {
            // dig che non c'e' o non parte: non ho chiesto niente a nessuno.
            return unknown(I18n.tr("server.sts.digNoStart"));
        }
    }

    // ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55131"
    private static final Pattern DIG_STATE = Pattern.compile("->>HEADER<<-.*\\bstatus:\\s*([A-Z]+)");
    // "_mta-sts.domain-d.test.  3600  IN  TXT  "v=STSv1; id=..."": nome, TTL e classe, poi il tipo
    private static final Pattern LINE_TXT = Pattern.compile("^\\S+\\s+(?:\\d+\\s+)?(?:IN\\s+)?TXT\\s+(.+)$",
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
    public static TxtReading parseTxt(int digOutput, String printed) {
        // dig torna 0 anche quando il nome non esiste: un'uscita diversa da zero vuol dire
        // che non ho CHIESTO, non che la risposta sia "niente". Sono cose opposte.
        if (digOutput == 9) return unknown(I18n.tr("server.sts.noDnsAnswers"));
        if (digOutput != 0 || printed == null) return unknown(I18n.tr("server.sts.digExit", java.util.Map.of("c", String.valueOf(digOutput))));
        Matcher state = DIG_STATE.matcher(printed);
        String s = state.find() ? state.group(1) : "";
        if (s.equals("NXDOMAIN")) return found(List.of());
        if (s.isEmpty()) return unknown(I18n.tr("server.sts.digNoStatus"));
        if (!s.equals("NOERROR")) return unknown(I18n.tr("server.sts.dnsAnswers", java.util.Map.of("s", String.valueOf(s))));
        // Tutti i TXT del nome, non il primo che va bene: il conto dei record v=STSv1 e' parte
        // della risposta.
        List<String> txt = new ArrayList<>();
        for (String line : printed.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            Matcher m = LINE_TXT.matcher(t);          // un CNAME davanti al TXT si salta
            if (m.matches()) txt.addAll(DnsRules.recordTxt(m.group(1)));
        }
        return found(DnsRules.soloMtaSts(txt));
    }

    /**
     * Il record TXT che questo pannello scriverebbe adesso.
     *
     * Non basta che il record esista: l'id deve corrispondere alla politica servita, altrimenti
     * i mittenti non si accorgeranno delle modifiche future. I record creati dal vecchio
     * pannello hanno un id fisso — un orologio scritto una volta sola — che non cambierebbe
     * mai. Un piano che li desse per "fatti" nasconderebbe proprio la cosa da sistemare.
     */
    private static String expectedTxt() {
        // Non si ricalcola qui: lo sa MtaSts, che e' anche chi serve la politica. Tre punti
        // che compongono la stessa stringa sono tre stringhe che un giorno divergono — ed e'
        // gia' successo, con l'id da orologio del riepilogo DNS.
        return MtaSts.recordTxtCorrente();
    }

    private static boolean jailActive() {
        try {
            ProcessBuilder pb = new ProcessBuilder("fail2ban-client", "status", "mailpanel-pubblico");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
