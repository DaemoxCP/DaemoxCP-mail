package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.util.Shell;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Il rapporto periodico che il pannello si manda da solo.
 *
 * Perche' esiste: le schede del pannello dicono tutto, ma solo a chi le apre. Un server che
 * funziona non si apre quasi mai, e le cose da fare — una vulnerabilita' che finalmente ha una
 * fix, un certificato in scadenza, una release che esce dal supporto — arrivano senza
 * che nessuno le stia guardando.
 *
 * Tre principi:
 *
 *  1. IN CIMA CI VA COSA C'E' DA FARE, non lo stato. Se non c'e' niente da fare, l'email lo
 *     dice in una riga: un rapporto che sembra sempre uguale smette di essere letto, e il
 *     giorno in cui contiene qualcosa nessuno se ne accorge.
 *  2. L'INVIO PASSA DA POSTFIX, con il SUO sendmail(1): non con il primo sendmail del PATH,
 *     che su FreeBSD e' mailwrapper e passa a dma (vedi sendmailDiPostfix). Il pannello
 *     gira SUL server di posta: nessuna credenziale SMTP da custodire, nessuna
 *     configurazione che possa divergere, e il messaggio esce firmato DKIM come qualunque
 *     altro.
 *  3. L'ESITO SI VERIFICA. sendmail accetta il messaggio e restituisce 0 anche quando la
 *     consegna fallira' piu' tardi, e restituiva 0 anche quando il messaggio non passava
 *     affatto da Postfix. Quindi il pannello segue il messaggio nel log della posta, per il
 *     suo Message-ID, e registra cosa ha risposto il server del destinatario: non "sendmail
 *     ha detto 0", che non vuol dire niente.
 */
public final class PeriodicReport {

    /** Data e ora nella lingua del rapporto ("alle" / "at"). */
    private static DateTimeFormatter data() {
        return DateTimeFormatter.ofPattern(I18n.tr("server.rp.dateTime"));
    }
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private final ScheduledExecutorService scheduler;

    public PeriodicReport() {
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "Rapporto-Periodico");
            t.setDaemon(true);
            return t;
        });
    }

    /** Si guarda ogni quarto d'ora se sia il momento. Il lavoro vero avviene di rado. */
    public void start() {
        scheduler.scheduleAtFixedRate(this::tick, 120, 900, TimeUnit.SECONDS);
        System.out.println("[Report] Scheduler started (checks every 15 minutes whether it is time to send)");
    }

    public void stop() {
        scheduler.shutdownNow();
        try { scheduler.awaitTermination(2, TimeUnit.SECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ===================== impostazioni =====================

    private static String imp(String chiave, String predefinito) {
        try { return Main.mailDatabase.getSetting(chiave, predefinito); }
        catch (Exception e) { return predefinito; }
    }

    private static void impSet(String chiave, String valore) {
        try { Main.mailDatabase.setSetting(chiave, valore); } catch (Exception ignored) { }
    }

    /**
     * Il dominio con cui il pannello si identifica.
     *
     * NON e' "il primo dominio dell'elenco": quello e' l'ordine di una lista, e prendendolo
     * si finisce a proporre un'identita' sul dominio di un sito che non c'entra niente — e'
     * successo, con domain-a.test. Il pannello ha un hostname suo, mail.domain-b.test: il
     * dominio e' quello che sta dopo il primo punto.
     */
    private static String dominioDelPannello() {
        String host = "";
        try { host = Main.mailDatabase.getSetting("mail_hostname", ""); } catch (Exception ignored) { }
        if (host.isEmpty())
            host = Shell.runShell(java.time.Duration.ofSeconds(20),
                    "postconf -h myhostname 2>/dev/null").outputTrim();
        int p = host.indexOf('.');
        if (p > 0 && p + 1 < host.length()) return host.substring(p + 1);
        String d = Shell.runShell(java.time.Duration.ofSeconds(20),
                "postconf -h mydomain 2>/dev/null").outputTrim();
        return d;
    }

    public static JSONObject stato() {
        String dominio = dominioDelPannello();
        String ultimo = imp("report_last", "");
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("attivo", "1".equals(imp("report_enabled", "0")))
                .put("mittente", imp("report_from", "no-reply@" + dominio))
                .put("destinatario", imp("report_to", ""))
                .put("frequenza", imp("report_freq", "settimanale"))
                .put("ora", imp("report_hour", "8"))
                .put("dominio", dominio)
                .put("ultimoInvio", ultimo)
                .put("ultimoEsito", imp("report_last_result", ""));
        r.put("prossimo", descriviProssimo(r));
        return r;
    }

    private static String descriviProssimo(JSONObject s) {
        if (!s.getBoolean("attivo")) return I18n.tr("server.rp.disabled");
        String freq = s.getString("frequenza");
        String ora = s.getString("ora");
        String u = s.getString("ultimoInvio");
        String ogni = "giornaliero".equals(freq) ? I18n.tr("server.rp.everyDay")
                    : "mensile".equals(freq) ? I18n.tr("server.rp.everyMonth") : I18n.tr("server.rp.everyWeek");
        return I18n.tr("server.rp.schedule", java.util.Map.of("ogni", String.valueOf(ogni), "ora", String.valueOf(ora)))
                + " " + (u.isEmpty() ? I18n.tr("server.rp.neverSent")
                               : I18n.tr("server.rp.lastSent", java.util.Map.of("quando", String.valueOf(u.replace('T', ' ')))));
    }

    /**
     * Salva le impostazioni, validando OGNI campo con una whitelist. Gli indirizzi finiscono
     * in un'intestazione del messaggio: un a capo dentro un indirizzo permetterebbe di
     * aggiungere intestazioni arbitrarie, che e' il modo classico di trasformare un modulo
     * di posta in un inoltro per chiunque.
     */
    public static JSONObject salvaImpostazioni(String destinatario, String mittente,
                                               String frequenza, String ora, boolean attivo) {
        JSONObject r = new JSONObject();
        destinatario = destinatario == null ? "" : destinatario.trim();
        mittente = mittente == null ? "" : mittente.trim();

        if (attivo && destinatario.isEmpty())
            return r.put("success", false).put("error", I18n.tr("server.rp.needRecipient"));
        if (!destinatario.isEmpty() && !org.mail_panel.webserver.SecurityUtils.isValidEmail(destinatario))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipient"));
        if (!mittente.isEmpty()) {
            if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(mittente))
                return r.put("success", false).put("error", I18n.tr("server.rp.badSender"));
            // Whitelist vera: non "e' un indirizzo ben formato", ma "e' UNA DELLE caselle
            // che esistono sul dominio di questo pannello". L'elenco lo conosce il pannello,
            // quindi il controllo puo' essere esatto invece che approssimato.
            JSONObject id = statoIdentita();
            JSONArray scelte = id.optJSONArray("caselleDisponibili");
            boolean ammesso = false;
            if (scelte != null)
                for (int i = 0; i < scelte.length(); i++)
                    if (scelte.getString(i).equalsIgnoreCase(mittente)) ammesso = true;
            if (!ammesso)
                return r.put("success", false).put("caselleDisponibili", scelte == null ? new JSONArray() : scelte)
                        .put("error", I18n.tr("server.rp.senderMustExist", java.util.Map.of("dominio", String.valueOf(id.optString("dominioDelPannello", "?")))) + " "
                                + (scelte == null || scelte.length() == 0
                                   ? I18n.tr("server.rp.noMailboxYet")
                                   : I18n.tr("server.rp.pickOne")));
        }
        // Nessun a capo puo' entrare in un'intestazione, in nessuna forma.
        for (String v : new String[]{destinatario, mittente})
            if (v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0 || v.indexOf('\0') >= 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.badAddress"));
        if (!java.util.List.of("giornaliero", "settimanale", "mensile").contains(frequenza))
            return r.put("success", false).put("error", I18n.tr("server.rp.badFreq"));
        int h;
        try { h = Integer.parseInt(ora.trim()); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.badHour")); }
        if (h < 0 || h > 23) return r.put("success", false).put("error", I18n.tr("server.rp.hourRange"));

        impSet("report_to", destinatario);
        if (!mittente.isEmpty()) impSet("report_from", mittente);
        impSet("report_freq", frequenza);
        impSet("report_hour", String.valueOf(h));
        impSet("report_enabled", attivo ? "1" : "0");
        // Il rapporto automatico parte da solo, fuori da ogni richiesta: esce nella lingua di chi
        // ha salvato le impostazioni
        impSet("report_lang", I18n.current());
        return stato().put("success", true).put("nota", attivo
                ? I18n.tr("server.rp.savedOn", java.util.Map.of("destinatario", String.valueOf(destinatario)))
                : I18n.tr("server.rp.savedOff"));
    }

    /** Il testo che verrebbe inviato, senza inviarlo. */
    public static JSONObject anteprima() {
        try {
            // L'anteprima non tocca la rete: la scheda promette una lettura, e deve restarlo.
            JSONObject dati = UpdateManager.reportData(false);
            JSONObject cert = avvisoCertificato();
            if (cert != null) {
                JSONArray df = dati.optJSONArray("daFare");
                if (df == null) df = new JSONArray();
                df.put(cert);
                dati.put("daFare", df);
            }
            String host = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
            String mitt = imp("report_from", "no-reply@" + dominioDelPannello());
            String dest = imp("report_to", I18n.tr("server.rp.noRecipient"));
            return new JSONObject().put("success", true)
                    .put("testo", componi(dati, host, mitt, dest))
                    .put("coseDaFare", dati.optJSONArray("daFare") == null ? 0 : dati.getJSONArray("daFare").length());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.rp.composeFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    // ===================== l'identita' del pannello =====================

    /**
     * Il pannello non ha un'identita' finche' non gliela si crea.
     *
     * Un rapporto puo' anche partire con un mittente che non esiste come casella — sendmail
     * lo accetta — ma sarebbe una scelta che si paga dopo: chi risponde riceve un rifiuto,
     * i controlli antispam dei destinatari guardano se il mittente esiste, e un'eventuale
     * notifica di mancata consegna non tornerebbe da nessuna parte.
     *
     * Quindi il pannello si crea una casella vera sul dominio che gestisce. La password e'
     * casuale e non serve a nessuno: il rapporto non fa login, esce da sendmail in locale.
     * Resta nel vault del pannello come per ogni altra casella, quindi e' recuperabile se un
     * giorno servisse davvero leggere quelle risposte.
     */
    /**
     * Cosa occupa gia' un indirizzo: una casella, un alias, o niente.
     *
     * La prima versione guardava SOLO le caselle. Su domain-a.test l'indirizzo no-reply
     * esisteva come ALIAS del sito: il pannello ha detto "non esiste", ha offerto di crearlo,
     * e creandolo ha messo una casella davanti a un alias funzionante — cambiando dove
     * finisce la posta per quell'indirizzo. Un controllo che guarda meta' delle cose non
     * dice "non lo so": dice "libero", ed e' molto peggio.
     */
    private static JSONObject occupato(org.mail_panel.database.MailDatabase.Domain dom, String indirizzo)
            throws Exception {
        for (var m : Main.mailDatabase.getMailboxes(dom.id))
            if (m.email != null && m.email.equalsIgnoreCase(indirizzo))
                return new JSONObject().put("tipo", "casella").put("nome", m.name == null ? "" : m.name)
                        .put("creato", m.createdAt == null ? "" : m.createdAt.toString());
        for (var a : Main.mailDatabase.getAliases(dom.id))
            if (a.source != null && a.source.equalsIgnoreCase(indirizzo))
                return new JSONObject().put("tipo", "alias").put("verso", a.destination == null ? "" : a.destination)
                        .put("creato", a.createdAt == null ? "" : a.createdAt.toString());
        return null;
    }

    public static JSONObject statoIdentita() {
        JSONObject r = new JSONObject().put("success", true);
        String mittente = imp("report_from", "").trim();
        try {
            java.util.List<org.mail_panel.database.MailDatabase.Domain> domini = Main.mailDatabase.getDomains();
            JSONArray nomi = new JSONArray();
            for (var d : domini) nomi.put(d.domain);
            r.put("dominiGestiti", nomi).put("mittente", mittente);

            // NON si propone piu' un indirizzo da soli. Prima si sceglieva "no-reply@" sul
            // PRIMO dominio dell'elenco: un indirizzo che il pannello non ha mai visto, su un
            // dominio scelto dall'ordine di una lista. Ora l'indirizzo lo scrive chi sa a
            // cosa serve, e il pannello si limita a dire cosa c'e' gia' li'.
            String mio = dominioDelPannello();
            org.mail_panel.database.MailDatabase.Domain domMio = null;
            for (var d : domini) if (d.domain.equalsIgnoreCase(mio)) domMio = d;
            r.put("dominioDelPannello", mio).put("dominioDelPannelloGestito", domMio != null);
            boolean mioGestito = domMio != null;

            // Le caselle che esistono sul dominio del pannello: sono le UNICHE scelte valide
            // per il mittente. Un campo di testo libero permetterebbe di scriverci dentro
            // qualunque cosa — compreso un dominio di un sito, che e' esattamente l'errore
            // gia' fatto con domain-a.test.
            JSONArray scelte = new JSONArray();
            if (domMio != null)
                for (var m : Main.mailDatabase.getMailboxes(domMio.id))
                    if (m.email != null) scelte.put(m.email);
            r.put("caselleDisponibili", scelte);
            if (mioGestito) {
                String proposto = "no-reply@" + mio;
                boolean esisteProposto = false;
                for (int q = 0; q < scelte.length(); q++)
                    if (scelte.getString(q).equalsIgnoreCase(proposto)) esisteProposto = true;
                r.put("suggerito", proposto).put("suggeritoEsiste", esisteProposto);
            }
            if (mittente.isEmpty())
                return r.put("esiste", false).put("dominioGestito", false).put("daScegliere", true)
                        .put("nota", I18n.tr("server.rp.pickSender")
                                + (mioGestito ? " " + I18n.tr("server.rp.suggestSender", java.util.Map.of("mio", String.valueOf(mio))) : ""));

            String dominio = mittente.substring(mittente.indexOf('@') + 1);
            org.mail_panel.database.MailDatabase.Domain suo = null;
            for (var d : domini) if (d.domain.equalsIgnoreCase(dominio)) suo = d;
            r.put("dominio", dominio).put("dominioGestito", suo != null);
            if (suo == null)
                return r.put("esiste", false)
                        .put("nota", I18n.tr("server.rp.domainNotManaged", java.util.Map.of("dominio", String.valueOf(dominio))));

            JSONObject gia = occupato(suo, mittente);
            r.put("occupato", gia == null ? JSONObject.NULL : gia);
            boolean suoDominio = !mio.isEmpty() && dominio.equalsIgnoreCase(mio);
            r.put("sulProprioDominio", suoDominio);
            if (gia == null)
                return r.put("esiste", false).put("creabile", suoDominio)
                        .put("nota", suoDominio
                                ? I18n.tr("server.rp.addressFree", java.util.Map.of("mittente", String.valueOf(mittente)))
                                : I18n.tr("server.rp.addressFreeOther", java.util.Map.of("mittente", String.valueOf(mittente), "dominio", String.valueOf(dominio), "mio", String.valueOf(mio))));
            if ("alias".equals(gia.optString("tipo")))
                return r.put("esiste", true).put("eAlias", true)
                        .put("nota", I18n.tr("server.rp.isAlias", java.util.Map.of("mittente", String.valueOf(mittente), "verso", String.valueOf(gia.optString("verso")))));
            return r.put("esiste", true).put("eAlias", false)
                    .put("nota", I18n.tr("server.rp.mailboxExists", java.util.Map.of("mittente", String.valueOf(mittente)))
                            + (gia.optString("nome").isEmpty() ? "" : " (\"" + gia.optString("nome") + "\")")
                            + (gia.optString("creato").isEmpty() ? "" : ", " + I18n.tr("server.rp.createdOn", java.util.Map.of("d", String.valueOf(gia.optString("creato")))))
                            + ": " + I18n.tr("server.rp.realSender"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.rp.readFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /** Crea la casella del pannello. Non tocca niente se esiste gia'. */
    public static JSONObject creaIdentita(String indirizzo) {
        JSONObject r = new JSONObject().put("indirizzo", indirizzo);
        if (indirizzo == null || !org.mail_panel.webserver.SecurityUtils.isValidEmail(indirizzo))
            return r.put("success", false).put("error", I18n.tr("server.rp.badAddressLower"));
        String dominio = indirizzo.substring(indirizzo.indexOf('@') + 1);
        try {
            org.mail_panel.database.MailDatabase.Domain suo = null;
            for (var d : Main.mailDatabase.getDomains()) if (d.domain.equalsIgnoreCase(dominio)) suo = d;
            if (suo == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.domainNotManaged2", java.util.Map.of("dominio", String.valueOf(dominio))));
            String mio = dominioDelPannello();
            if (mio.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.noPanelDomain"));
            if (!dominio.equalsIgnoreCase(mio))
                return r.put("success", false).put("dominioDelPannello", mio)
                        .put("error", I18n.tr("server.rp.onlyOwnDomain", java.util.Map.of("dominio", String.valueOf(dominio), "mio", String.valueOf(mio))));

            JSONObject gia = occupato(suo, indirizzo);
            if (gia != null) {
                boolean alias = "alias".equals(gia.optString("tipo"));
                return r.put("success", !alias).put("giaEsisteva", true).put("occupato", gia)
                        .put(alias ? "error" : "nota", alias
                                ? I18n.tr("server.rp.aliasNoCreate", java.util.Map.of("indirizzo", String.valueOf(indirizzo), "verso", String.valueOf(gia.optString("verso"))))
                                : I18n.tr("server.rp.existedAlready"));
            }

            // Password casuale robusta: nessuno deve digitarla, il rapporto non fa login.
            java.security.SecureRandom rnd = new java.security.SecureRandom();
            String alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            StringBuilder pw = new StringBuilder();
            for (int i = 0; i < 32; i++) pw.append(alfabeto.charAt(rnd.nextInt(alfabeto.length())));

            int id = Main.mailDatabase.addMailbox(suo.id, indirizzo, pw.toString(),
                    I18n.tr("server.rp.mailboxName"), 128, true);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.rp.createFailed"));
            impSet("report_from", indirizzo);
            return r.put("success", true).put("giaEsisteva", false).put("id", id)
                    .put("nota", I18n.tr("server.rp.created"));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.rp.createError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    // ===================== quando inviare =====================

    private void tick() {
        try {
            if (!"1".equals(imp("report_enabled", "0"))) return;
            String a = imp("report_to", "");
            if (a.isEmpty()) return;
            if (!eIlMomento()) return;
            // Fuori da ogni richiesta: il rapporto esce nella lingua di chi l'ha configurato
            I18n.setCurrent(imp("report_lang", "it"));
            JSONObject esito;
            try { esito = inviaAdesso(a); }
            finally { I18n.clearCurrent(); }
            System.out.println("[Report] automatic send: "
                    + (esito.optBoolean("success") ? "succeeded" : "FAILED - " + esito.optString("error")));
        } catch (Exception e) {
            System.out.println("[Report] error in the periodic check: " + e.getMessage());
        }
    }

    /**
     * Vero se e' ora di inviare. Il confronto e' sull'INTERVALLO TRASCORSO, non su un
     * calendario: cosi' un pannello spento per due giorni manda il rapporto quando torna su,
     * invece di saltarlo perche' "il giorno giusto e' passato".
     */
    static boolean eIlMomento(String frequenza, String oraTesto, String ultimoIso,
                              String ultimoTentativoIso, String ultimoEsito, LocalDateTime adesso) {
        int ora;
        try { ora = Integer.parseInt(oraTesto.trim()); } catch (Exception e) { ora = 8; }
        if (ora < 0 || ora > 23) ora = 8;
        if (adesso.getHour() < ora) return false;

        // Un invio fallito non deve essere ritentato ogni quarto d'ora per sempre.
        //
        // "report_last" viene scritto solo quando l'invio RIESCE, ed e' l'unica data che questo
        // metodo guardava: dopo un fallimento restava vecchia, la condizione "sono passati sei
        // giorni" restava vera, e lo scheduler riprovava al tick successivo. Con credenziali
        // sbagliate fanno 96 tentativi al giorno verso il server SMTP di qualcun altro, che e' il
        // modo di farsi bloccare l'indirizzo. Il difetto non si vedeva perche' ciascun tentativo,
        // preso da solo, era legittimo.
        //
        // Quindi si guarda anche l'ULTIMO TENTATIVO, riuscito o no. La data del tentativo viene
        // scritta PRIMA di provare, non dopo: se il processo muore a meta' invio, al riavvio non
        // deve ricominciare subito.
        if (ultimoEsito != null && ultimoEsito.startsWith("fallito")
                && ultimoTentativoIso != null && !ultimoTentativoIso.isBlank()) {
            try {
                long dalTentativo = java.time.temporal.ChronoUnit.HOURS.between(
                        LocalDateTime.parse(ultimoTentativoIso, ISO), adesso);
                if (dalTentativo >= 0 && dalTentativo < ORE_DOPO_FALLIMENTO) return false;
            } catch (Exception ignora) {
                // Data illeggibile: non si blocca l'invio per un dato che non si sa leggere.
            }
        }

        if (ultimoIso == null || ultimoIso.isBlank()) return true;      // mai inviato
        LocalDateTime ultimo;
        try { ultimo = LocalDateTime.parse(ultimoIso, ISO); }
        catch (Exception e) { return true; }                            // data illeggibile: si invia
        long ore = java.time.temporal.ChronoUnit.HOURS.between(ultimo, adesso);
        if (ore < 0) return false;                                      // orologio andato indietro
        switch (frequenza == null ? "" : frequenza) {
            case "giornaliero": return ore >= 20;
            case "mensile":     return ore >= 24 * 29;
            default:            return ore >= 24 * 6;                   // settimanale
        }
    }

    /** Ore da aspettare prima di riprovare dopo un invio fallito. */
    static final int ORE_DOPO_FALLIMENTO = 6;

    private boolean eIlMomento() {
        return eIlMomento(imp("report_freq", "settimanale"), imp("report_hour", "8"),
                imp("report_last", ""), imp("report_last_try", ""), imp("report_last_result", ""),
                LocalDateTime.now());
    }

    // ===================== invio =====================

    public static JSONObject inviaAdesso(String destinatario) {
        JSONObject r = new JSONObject().put("destinatario", destinatario);
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(destinatario))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipientLower"));
        String mittente = imp("report_from", "no-reply@" + dominioDelPannello());
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(mittente))
            return r.put("success", false).put("error", I18n.tr("server.rp.badSenderLower", java.util.Map.of("m", String.valueOf(mittente))));

        JSONObject dati;
        try { dati = UpdateManager.reportData(); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.collectFailed", java.util.Map.of("m", String.valueOf(e.getMessage())))); }
        // Il certificato lo conosce solo questa classe: si aggiunge qui alle cose da fare,
        // e si riordina, altrimenti "scade fra 3 giorni" finirebbe in fondo all'elenco.
        JSONArray df = dati.optJSONArray("daFare");
        if (df == null) df = new JSONArray();

        JSONObject avvisoCert = avvisoCertificato();
        if (avvisoCert != null) df.put(avvisoCert);

        // Le novita' sulle specifiche e sulle scadenze finiscono nel rapporto invece di
        // essere scoperte per caso mentre si sta facendo altro. E' il motivo per cui la
        // sorveglianza esiste: un avviso che nessuno va a cercare non e' un avviso.
        for (JSONObject x : avvisiSorveglianza()) df.put(x);

        java.util.List<JSONObject> l = new java.util.ArrayList<>();
        for (int i = 0; i < df.length(); i++) l.add(df.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgenza", 9)));
        JSONArray ord = new JSONArray();
        for (JSONObject x : l) ord.put(x);
        dati.put("daFare", ord);

        String host = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
        int quante = dati.optJSONArray("daFare") == null ? 0 : dati.getJSONArray("daFare").length();
        String oggetto = "[" + (host.isEmpty() ? I18n.tr("server.rp.mailServer") : host) + "] "
                + (quante == 0 ? I18n.tr("server.rp.allGood")
                   : quante == 1 ? I18n.tr("server.rp.todo.one")
                   : I18n.tr("server.rp.todo.other", java.util.Map.of("n", String.valueOf(quante))))
                + " - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        String corpo = componi(dati, host, mittente, destinatario);

        // Prima di provare, non dopo: se il pannello muore durante l'invio, al riavvio questa
        // data c'e' gia' e la pausa dopo un fallimento vale lo stesso.
        impSet("report_last_try", LocalDateTime.now().format(ISO));

        JSONObject esito = consegna(mittente, destinatario, oggetto, corpo);
        r.put("oggetto", oggetto).put("corpo", corpo).put("mittente", mittente)
         .put("coseDaFare", quante).put("output", esito.optString("output", ""));
        if (esito.optBoolean("success")) {
            String ora = LocalDateTime.now().format(ISO);
            impSet("report_last", ora);
            impSet("report_last_result", esito.optString("esito", "riuscito"));
            return r.put("success", true).put("quando", ora)
                    .put("avviso", esito.optBoolean("avviso", false))
                    .put("nota", esito.optString("nota", ""));
        }
        impSet("report_last_result", "fallito: " + esito.optString("error", "?"));
        return r.put("success", false).put("error", esito.optString("error", I18n.tr("server.rp.sendFailed")));
    }

    /**
     * Un messaggio del pannello a un amministratore (il codice di accesso), con lo stesso mittente
     * e lo stesso sendmail di Postfix del rapporto. Restituisce solo se e' partito: il corpo
     * contiene un codice monouso e non deve finire in nessun log, quindi l'uscita di sendmail e le
     * righe del log della posta qui non si restituiscono.
     */
    public static boolean inviaMessaggioPannello(String destinatario, String oggetto, String corpo) {
        String mittente = imp("report_from", "no-reply@" + dominioDelPannello());
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(mittente)
                || !org.mail_panel.webserver.SecurityUtils.isValidEmail(destinatario)) return false;
        return consegna(mittente, destinatario, oggetto, corpo).optBoolean("success", false);
    }

    /**
     * Consegna a Postfix con il suo sendmail(1), poi segue il messaggio nel log della posta.
     * L'oggetto viene codificato secondo RFC 2047 perche' un'intestazione non puo' contenere
     * caratteri non ASCII, e il corpo dichiara UTF-8: senza, le lettere accentate
     * arriverebbero storte. Il Message-ID lo sceglie il pannello: e' il filo che lega il
     * messaggio alle righe che Postfix scrive nel log.
     */
    private static JSONObject consegna(String da, String a, String oggetto, String corpo) {
        JSONObject r = new JSONObject();
        JSONObject scelto = sendmailDiPostfix();
        if (!scelto.optBoolean("success")) return r.put("success", false).put("error", scelto.optString("error"));
        String sendmail = scelto.getString("percorso");

        String messageId = nuovoMessageId(da);
        StringBuilder messaggio = new StringBuilder();
        messaggio.append("From: ").append(I18n.tr("server.rp.fromName")).append(" <").append(da).append(">\r\n")
                 .append("To: ").append(a).append("\r\n")
                 .append("Subject: ").append(oggetto2047(oggetto)).append("\r\n")
                 .append("Message-ID: <").append(messageId).append(">\r\n")
                 .append("MIME-Version: 1.0\r\n")
                 .append("Content-Type: text/plain; charset=UTF-8\r\n")
                 .append("Content-Transfer-Encoding: 8bit\r\n")
                 .append("Auto-Submitted: auto-generated\r\n")   // non e' posta scritta da una persona
                 .append("X-Mailer: FreeBSD Mail Panel\r\n")
                 .append("\r\n")
                 .append(corpo.replace("\n", "\r\n"));
        StringBuilder output = new StringBuilder()
                .append("* ").append(I18n.tr("server.rp.postfixSendmail", java.util.Map.of("p", String.valueOf(sendmail)))).append('\n')
                .append("* Message-ID: <").append(messageId).append(">\n");

        // Dove finisce il log adesso: le righe di questo messaggio stanno tutte dopo.
        long inizioLog = dimensioneLog();
        try {
            ProcessBuilder pb = new ProcessBuilder(sendmail, "-t", "-i", "-f", da);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (OutputStream os = p.getOutputStream()) {
                os.write(messaggio.toString().getBytes(StandardCharsets.UTF_8));
            }
            String detto = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!detto.isEmpty()) output.append(detto).append('\n');
            r.put("output", output.toString());
            boolean finito = p.waitFor(60, TimeUnit.SECONDS);
            if (!finito) { p.destroyForcibly(); return r.put("success", false).put("error", I18n.tr("server.rp.sendmailTimeout")); }
            int codice = p.exitValue();
            r.put("codice", codice);
            if (codice != 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.sendmailExit", java.util.Map.of("c", String.valueOf(codice)))
                        + (detto.isEmpty() ? "" : ": " + detto));
        } catch (Exception e) {
            return r.put("output", output.toString()).put("success", false)
                    .put("error", I18n.tr("server.rp.cannotRun", java.util.Map.of("p", String.valueOf(sendmail), "m", String.valueOf(e.getMessage()))));
        }

        // Il codice 0 dice soltanto che il messaggio e' nella coda di ingresso di Postfix.
        // Dove e' andato a finire lo dice il log.
        JSONObject log = seguiNelLog(inizioLog, messageId, a);
        JSONArray righe = log.optJSONArray("righe");
        if (righe != null && righe.length() > 0) {
            output.append("* ").append(I18n.tr("server.rp.fromMaillog", java.util.Map.of("f", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG)))).append('\n');
            for (int i = 0; i < righe.length(); i++) output.append(righe.getString(i)).append('\n');
        } else {
            output.append("* ").append(I18n.tr("server.rp.noLogLine")).append('\n');
        }
        return verdict(log).put("output", output.toString());
    }

    // ===================== quale sendmail =====================

    /** Il sendmail installato dal port di Postfix: si prova quando postconf non risponde. */
    static final String SENDMAIL_DEL_PORT = "/usr/local/sbin/sendmail";

    /** mailwrapper(8). Su FreeBSD /usr/sbin/sendmail e' lui, non Postfix. */
    static final String MAILWRAPPER = "/usr/sbin/mailwrapper";

    /**
     * Il sendmail DI POSTFIX, non "il primo sendmail che si trova nel PATH".
     *
     * Fino al 25/09/2026 lo si cercava nel PATH, dove /usr/sbin viene prima di /usr/local/sbin.
     * Si trovava /usr/sbin/sendmail, che su FreeBSD e' mailwrapper(8): passa il messaggio a chi
     * dice mailer.conf, e se nessuno l'ha cambiato — il pacchetto di Postfix non lo cambia da
     * solo — da FreeBSD 14 e' dma(8). dma accettava, restituiva 0, e consegnava da solo
     * all'MX del destinatario: senza passare dal milter, quindi senza signature DKIM, e senza
     * STARTTLS. Il pannello scriveva "riuscito"; Gmail riceveva un messaggio in chiaro e non
     * firmato, altri destinatari non lo mostravano affatto.
     *
     * Dov'e' il suo sendmail lo sa Postfix: e' sendmail_path. Se postconf non risponde si prova
     * il percorso del port. Un candidato che sia mailwrapper viene scartato, e se non resta
     * niente NON si ripiega su un altro sendmail: un errore che dice cosa manca e' meglio di
     * un invio che esce dalla porta sbagliata e si dichiara riuscito.
     *
     * Dal 24/10/2026 l'installatore scrive mailer.conf per Postfix (scripts/LocalMtaScript), e su
     * un server installato da allora anche mailwrapper arriverebbe a Postfix. Questa scelta resta
     * com'e' lo stesso: i server installati prima passano ancora a dma, e il rapporto non deve
     * dipendere da come qualcuno ha lasciato mailer.conf.
     */
    static JSONObject sendmailDiPostfix() {
        String dichiarato = Shell.runShell(java.time.Duration.ofSeconds(10),
                "postconf -h sendmail_path 2>/dev/null").outputTrim();
        return sceltaSendmail(dichiarato, SENDMAIL_DEL_PORT, MAILWRAPPER);
    }

    /** La scelta vera e propria, separata da postconf e dai percorsi reali per poterla provare. */
    static JSONObject sceltaSendmail(String dichiarato, String delPort, String mailwrapper) {
        java.util.LinkedHashSet<String> candidati = new java.util.LinkedHashSet<>();
        if (dichiarato != null && dichiarato.startsWith("/") && dichiarato.indexOf('\n') < 0)
            candidati.add(dichiarato);
        candidati.add(delPort);
        java.util.List<String> scartati = new java.util.ArrayList<>();
        for (String c : candidati) {
            String no = nonEPostfix(c, mailwrapper);
            if (no == null) return new JSONObject().put("success", true).put("percorso", c);
            scartati.add(no);
        }
        return new JSONObject().put("success", false)
                .put("error", I18n.tr("server.rp.noPostfixSendmail", java.util.Map.of("motivi", String.valueOf(String.join("; ", scartati)))));
    }

    /** null se il percorso puo' essere il sendmail di Postfix, altrimenti il motivo per cui non lo e'. */
    static String nonEPostfix(String percorso, String mailwrapper) {
        java.nio.file.Path p = java.nio.file.Path.of(percorso);
        if (!java.nio.file.Files.isRegularFile(p) || !java.nio.file.Files.isExecutable(p))
            return I18n.tr("server.rp.notExecutable", java.util.Map.of("p", String.valueOf(percorso)));
        try {
            // Stesso file, che sia un collegamento simbolico o un hard link: e' mailwrapper.
            java.nio.file.Path mw = java.nio.file.Path.of(mailwrapper);
            if (java.nio.file.Files.exists(mw) && java.nio.file.Files.isSameFile(p, mw))
                return I18n.tr("server.rp.isMailwrapper", java.util.Map.of("p", String.valueOf(percorso)));
        } catch (java.io.IOException e) {
            return I18n.tr("server.rp.cannotCheck", java.util.Map.of("p", String.valueOf(percorso), "m", String.valueOf(e.getMessage())));
        }
        return null;
    }

    /** Un Message-ID che nessun altro messaggio ha: ora UTC, 16 byte casuali, dominio del mittente. */
    static String nuovoMessageId(String mittente) {
        byte[] caso = new byte[16];
        new java.security.SecureRandom().nextBytes(caso);
        return "rapporto." + LocalDateTime.now(java.time.ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
                + "." + java.util.HexFormat.of().formatHex(caso)
                + "@" + mittente.substring(mittente.indexOf('@') + 1);
    }

    // ===================== com'e' andata =====================

    /** Per quanto si segue il messaggio nel log, prima di smettere di guardare. */
    static final int SECONDI_NEL_LOG = 30;

    /** Di log nuovo se ne leggono al massimo 4 MB: un server sotto carico ne scrive tanto. */
    private static final int LOG_MASSIMO = 4 << 20;

    private static long dimensioneLog() {
        try { return java.nio.file.Files.size(java.nio.file.Path.of(org.mail_panel.monitoring.LogManager.MAILLOG)); }
        catch (Exception e) { return -1; }
    }

    /** Le righe scritte nel log della posta da 'da' in poi. Se nel frattempo e' stato ruotato, dall'inizio. */
    private static java.util.List<String> righeDelLog(long da) {
        try (java.io.RandomAccessFile f = new java.io.RandomAccessFile(org.mail_panel.monitoring.LogManager.MAILLOG, "r")) {
            long fine = f.length();
            long inizio = da < 0 || da > fine ? 0 : da;
            inizio = Math.max(inizio, fine - LOG_MASSIMO);
            byte[] b = new byte[(int) (fine - inizio)];
            f.seek(inizio);
            f.readFully(b);
            return new String(b, StandardCharsets.UTF_8).lines().toList();
        } catch (Exception e) {
            return java.util.List.of();
        }
    }

    /**
     * Guarda il log finche' Postfix non dice com'e' andata, per al massimo SECONDI_NEL_LOG.
     * Una consegna normale si conclude in un paio di secondi; se il server del destinatario non
     * risponde, Postfix aspetta i suoi tempi e l'esito resta "in coda".
     */
    private static JSONObject seguiNelLog(long da, String messageId, String destinatario) {
        long scadenza = System.nanoTime() + TimeUnit.SECONDS.toNanos(SECONDI_NEL_LOG);
        while (true) {
            JSONObject e = esitoNelLog(righeDelLog(da), messageId, destinatario);
            String stato = e.optString("stato", "");
            if ((!stato.isEmpty() && !"in coda".equals(stato)) || System.nanoTime() >= scadenza) return e;
            try { Thread.sleep(1000); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return e; }
        }
    }

    /**
     * Cosa dice il log di Postfix del messaggio con questo Message-ID. Riceve le righe invece di
     * leggere il file, cosi' si prova con righe vere.
     *
     * cleanup scrive il Message-ID accanto al numero di coda ("4hB2Kq3Xz9: message-id=<...>"),
     * e ogni riga successiva sullo stesso messaggio porta quel numero. dma e gli altri MTA quella
     * riga non la scrivono: se manca, Postfix il messaggio non l'ha visto, e lo "stato" resta
     * vuoto invece di diventare "riuscito".
     *
     * Stati: "" (Postfix non l'ha visto), "in coda" (visto, esito non ancora scritto),
     * "consegnato", "rimandato" (Postfix riprovera' da solo), "respinto" (dal server del
     * destinatario), "rifiutato" (da Postfix stesso, prima di partire: milter o controlli).
     */
    static JSONObject esitoNelLog(java.util.List<String> righe, String messageId, String destinatario) {
        JSONObject r = new JSONObject().put("stato", "").put("righe", new JSONArray());
        java.util.regex.Pattern conId = java.util.regex.Pattern.compile(
                "(?:^|\\s)([0-9A-Za-z]+): message-id=<" + java.util.regex.Pattern.quote(messageId) + ">");
        String coda = null;
        for (String riga : righe) {
            java.util.regex.Matcher m = conId.matcher(riga);
            if (m.find()) { coda = m.group(1); break; }
        }
        if (coda == null) return r;
        r.put("coda", coda).put("stato", "in coda");

        // Le righe di QUESTO messaggio: il numero di coda come parola intera, seguito da ": ".
        java.util.regex.Pattern sue = java.util.regex.Pattern.compile(
                "(?:^|\\s)" + java.util.regex.Pattern.quote(coda) + ": (.*)$");
        java.util.regex.Pattern stato = java.util.regex.Pattern.compile(", status=([a-z]+) \\((.*)\\)\\s*$");
        java.util.List<Integer> indici = new java.util.ArrayList<>();
        int consegna = -1;              // la riga "to=<...> ... status=" che decide
        boolean perIlDestinatario = false;
        String rifiuto = null;
        for (int i = 0; i < righe.size(); i++) {
            java.util.regex.Matcher m = sue.matcher(righe.get(i));
            if (!m.find()) continue;
            indici.add(i);
            String resto = m.group(1);
            for (String tipo : new String[]{"milter-reject: ", "reject: ", "milter-discard: ", "discard: "})
                if (resto.startsWith(tipo)) rifiuto = resto.substring(tipo.length());
            if (!resto.startsWith("to=<") || !stato.matcher(resto).find()) continue;
            // Con piu' destinatari (un alias, una copia nascosta) conta la riga del destinatario
            // del rapporto; fra quelle, l'ultima, perche' un "rimandato" puo' essere seguito da
            // un "consegnato".
            boolean suo = destinatario.equalsIgnoreCase(fra(resto, "to=<", ">"))
                       || destinatario.equalsIgnoreCase(fra(resto, "orig_to=<", ">"));
            if (suo || !perIlDestinatario) { consegna = i; perIlDestinatario = suo; }
        }

        if (consegna >= 0) {
            java.util.regex.Matcher m = sue.matcher(righe.get(consegna));
            m.find();
            String resto = m.group(1);
            java.util.regex.Matcher s = stato.matcher(resto);
            s.find();
            String relay = fra(resto, "relay=", ",");
            r.put("relay", relay).put("risposta", s.group(2)).put("stato", switch (s.group(1)) {
                case "sent" -> "consegnato";
                case "deferred" -> "rimandato";
                case "bounced", "expired" -> "respinto";
                default -> "in coda";
            });
            // Se la connessione era cifrata, il processo smtp che ha consegnato lo scrive quando la
            // apre (con smtp_tls_loglevel >= 1). E' quello che Gmail chiama "crittografia standard".
            // Se la prova non c'e' non si afferma niente: la sua assenza non prova il contrario.
            int apertura = aperturaTls(righe, consegna, coda, relay);
            if (apertura >= 0) {
                String riga = righe.get(apertura);
                String tls = "TLS connection established to " + relay + ": ";
                java.util.regex.Matcher t = java.util.regex.Pattern.compile("^(\\S+) with cipher (\\S+)")
                        .matcher(riga.substring(riga.indexOf(tls) + tls.length()));
                if (t.find()) r.put("tls", t.group(1) + " (" + t.group(2) + ")");
                indici.add(apertura);
            }
        } else if (rifiuto != null) {
            // Un rifiuto temporaneo (4.x.x) non e' la fine: Postfix riprova.
            boolean temporaneo = java.util.regex.Pattern.compile("(?:^|\\s)4\\.\\d{1,3}\\.\\d{1,3}(?:\\s|$)")
                    .matcher(rifiuto).find();
            r.put("stato", temporaneo ? "rimandato" : "rifiutato").put("risposta", rifiuto);
        }

        java.util.Collections.sort(indici);
        JSONArray testo = new JSONArray();
        for (int i : indici) if (testo.length() < 30) testo.put(righe.get(i));
        return r.put("righe", testo);
    }

    /** Chi ha scritto una riga del log (programma e pid: "postfix/smtp[81242]") e che cosa. */
    record Riga(String processo, String testo) {}

    private static final java.util.regex.Pattern LINE_5424 = java.util.regex.Pattern.compile(
            "^<\\d{1,3}>1 \\S+ \\S+ (\\S+) ([0-9]+) \\S+ (?:-|(?:\\[[^\\]]*\\])+) ?(.*)$");
    private static final java.util.regex.Pattern LINE_CLASSIC = java.util.regex.Pattern.compile(
            "(?:^|\\s)([^\\s\\[\\]]+)\\[([0-9]+)\\]: (.*)$");

    /** La riga scomposta, nel formato classico di syslog o in RFC 5424; null se non e' nessuno dei due. */
    static Riga riga(String r) {
        java.util.regex.Matcher m = LINE_5424.matcher(r);
        if (!m.find()) {
            m = LINE_CLASSIC.matcher(r);
            if (!m.find()) return null;
        }
        return new Riga(m.group(1) + "[" + m.group(2) + "]", m.group(3));
    }

    /**
     * La riga in cui il processo smtp che ha consegnato ha aperto la connessione cifrata su cui
     * e' partito il messaggio, o -1 se non la si puo' indicare con certezza.
     *
     * Il relay da solo non basta: un altro processo smtp puo' aprire nello stesso momento una
     * sua connessione verso lo stesso server, cifrata mentre questa no. Contano quindi solo le
     * righe del processo che ha scritto la consegna (stesso programma, stesso pid), risalendo
     * il log. Si saltano le consegne dello stesso messaggio agli altri destinatari (stessa
     * connessione) e le righe della sessione TLS che smtp scrive dopo l'apertura con
     * smtp_tls_loglevel 2 o piu'. La prima riga diversa decide: se e' l'apertura TLS verso lo
     * stesso relay, e' questa connessione. Qualunque altra cosa (un altro messaggio, una
     * connessione caduta, il ripiego in chiaro dopo un TLS fallito) vuol dire che un'apertura
     * scritta piu' su era di un'altra connessione.
     *
     * Una connessione riusata (conn_use= nella consegna) e' stata aperta prima, per un altro
     * messaggio e magari da un altro processo: la sua apertura non si lega a questa consegna.
     */
    static int aperturaTls(java.util.List<String> righe, int consegna, String coda, String relay) {
        Riga chi = riga(righe.get(consegna));
        if (chi == null || relay.isEmpty() || "none".equals(relay) || chi.testo().contains(", conn_use=")) return -1;
        java.util.regex.Pattern apertura = java.util.regex.Pattern.compile(
                "^(?:Anonymous|Untrusted|Trusted|Verified) TLS connection established to "
                + java.util.regex.Pattern.quote(relay) + ": \\S+ with cipher ");
        java.util.regex.Pattern consegnaSua = java.util.regex.Pattern.compile(
                "^" + java.util.regex.Pattern.quote(coda) + ": to=<.*, status=[a-z]+ \\(");
        for (int i = consegna - 1; i >= 0; i--) {
            Riga r = riga(righe.get(i));
            if (r == null || !chi.processo().equals(r.processo())) continue;
            String t = r.testo();
            if (consegnaSua.matcher(t).find() || t.startsWith("SSL_connect:")
                    || t.startsWith("save session ") || t.startsWith("remove session ")) continue;
            return apertura.matcher(t).find() ? i : -1;
        }
        return -1;
    }

    /** Il testo fra 'dopo' e il primo 'fino' che lo segue; "" se 'dopo' non c'e'. */
    private static String fra(String s, String dopo, String fino) {
        int i = s.indexOf(dopo);
        if (i < 0) return "";
        i += dopo.length();
        int j = s.indexOf(fino, i);
        return (j < 0 ? s.substring(i) : s.substring(i, j)).trim();
    }

    /**
     * Dal log al verdict: cosa si registra come esito e cosa si dice a chi ha premuto il
     * pulsante.
     *
     * "success" vuol dire che il pannello non deve rimandarlo. Vale anche per un messaggio che
     * Postfix tiene in coda e riprovera' da solo: rimandarlo farebbe arrivare due rapporti. E'
     * false solo quando il messaggio di sicuro non arrivera'. "avviso" vuol dire che non e'
     * ancora arrivato, o che non si sa.
     */
    static JSONObject verdict(JSONObject log) {
        String coda = log.optString("coda", "");
        String relay = log.optString("relay", "");
        String risposta = log.optString("risposta", "");
        String tls = log.optString("tls", "");
        JSONObject v = new JSONObject();
        switch (log.optString("stato", "")) {
            case "consegnato" -> {
                String dove = relay + (tls.isEmpty() ? "" : " " + I18n.tr("server.rp.withTls", java.util.Map.of("tls", String.valueOf(tls))));
                return v.put("success", true).put("avviso", false)
                        .put("esito", corto(I18n.tr("server.rp.deliveredTo", java.util.Map.of("dove", String.valueOf(dove), "risposta", String.valueOf(risposta)))))
                        .put("nota", I18n.tr("server.rp.deliveredNote", java.util.Map.of("dove", String.valueOf(dove), "risposta", String.valueOf(risposta))));
            }
            case "rimandato" -> {
                return v.put("success", true).put("avviso", true)
                        .put("esito", corto(I18n.tr("server.rp.deferred", java.util.Map.of("risposta", String.valueOf(risposta)))))
                        .put("nota", I18n.tr("server.rp.deferredNote", java.util.Map.of("coda", String.valueOf(coda), "risposta", String.valueOf(risposta))));
            }
            case "respinto" -> {
                return v.put("success", false).put("error", corto(relay.isEmpty() || "none".equals(relay)
                        ? I18n.tr("server.rp.bounced", java.util.Map.of("risposta", String.valueOf(risposta)))
                        : I18n.tr("server.rp.bouncedBy", java.util.Map.of("relay", String.valueOf(relay), "risposta", String.valueOf(risposta)))));
            }
            case "rifiutato" -> {
                return v.put("success", false).put("error", corto(I18n.tr("server.rp.rejected", java.util.Map.of("risposta", String.valueOf(risposta)))));
            }
            case "in coda" -> {
                return v.put("success", true).put("avviso", true)
                        .put("esito", I18n.tr("server.rp.accepted", java.util.Map.of("coda", String.valueOf(coda))))
                        .put("nota", I18n.tr("server.rp.acceptedNote", java.util.Map.of("coda", String.valueOf(coda), "s", String.valueOf(SECONDI_NEL_LOG), "log", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG))));
            }
            default -> {
                return v.put("success", true).put("avviso", true)
                        .put("esito", I18n.tr("server.rp.notInLog"))
                        .put("nota", I18n.tr("server.rp.notInLogNote", java.util.Map.of("s", String.valueOf(SECONDI_NEL_LOG), "log", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG))));
            }
        }
    }

    /** L'esito finisce in una riga della scheda: una risposta lunga del server si accorcia. */
    private static String corto(String s) {
        return s.length() <= 300 ? s : s.substring(0, 297) + "...";
    }

    /** Oggetto con lettere accentate: RFC 2047, altrimenti l'intestazione non e' valida. */
    private static String oggetto2047(String s) {
        boolean soloAscii = s.chars().allMatch(c -> c >= 32 && c < 127);
        if (soloAscii) return s;
        return "=?UTF-8?B?" + Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    // ===================== il testo =====================

    private static String riga(String c, int n) { return String.valueOf(c).repeat(Math.max(0, n)); }

    /**
     * Le voci che arrivano dalla sorveglianza: specifiche sostituite o aggiornate, e versioni
     * di OpenSSL che escono dal supporto.
     *
     * Se il controllo non riesce (rete assente, fonte irraggiungibile) NON si tace: si mette
     * una voce che dice che non si e' potuto controllare. Un rapporto silenzioso perche' il
     * controllo e' fallito e' indistinguibile da un rapporto silenzioso perche' va tutto bene,
     * e sono due cose opposte.
     */
    static java.util.List<JSONObject> avvisiSorveglianza() {
        java.util.List<JSONObject> fuori = new java.util.ArrayList<>();
        try {
            JSONObject c = StandardsWatch.controlla();
            JSONArray st = c.optJSONArray("standard");
            if (st != null) for (int i = 0; i < st.length(); i++) {
                JSONObject o = st.getJSONObject(i);
                int g = o.optInt("gravita", 0);
                if (g == 2)
                    fuori.add(new JSONObject().put("urgenza", 1)
                            .put("cosa", o.optString("commento"))
                            .put("dove", I18n.tr("server.rp.whereSurveillance")));
                else if (g == 1)
                    fuori.add(new JSONObject().put("urgenza", 3)
                            .put("cosa", o.optString("commento"))
                            .put("dove", I18n.tr("server.rp.whereSurveillance")));
            }
            if (c.optInt("nonLetti", 0) > 0)
                fuori.add(new JSONObject().put("urgenza", 3)
                        .put("cosa", I18n.tr("server.rp.rfcUnread", java.util.Map.of("n", String.valueOf(c.optInt("nonLetti")))))
                        .put("dove", I18n.tr("server.rp.whereSurveillance")));
        } catch (Exception e) {
            fuori.add(new JSONObject().put("urgenza", 3)
                    .put("cosa", I18n.tr("server.rp.survFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))))
                    .put("dove", I18n.tr("server.rp.whereSurveillance")));
        }

        try {
            JSONObject o = OpensslExpiry.stato();
            JSONArray inst = o.optJSONArray("installazioni");
            if (inst != null) for (int i = 0; i < inst.length(); i++) {
                JSONObject x = inst.getJSONObject(i);
                if (!x.optBoolean("presente", false)) continue;
                int u = x.optInt("urgenza", 0);
                if (u == 1 || u == 2)
                    fuori.add(new JSONObject().put("urgenza", u == 2 ? 1 : 2)
                            .put("cosa", "OpenSSL " + x.optString("versione") + " ("
                                    + x.optString("tipo") + "): " + x.optString("commento"))
                            .put("dove", I18n.tr("server.rp.whereSurveillance")));
            }
        } catch (Exception ignore) {}

        return fuori;
    }

    static String componi(JSONObject d, String host, String mittente, String destinatario) {
        StringBuilder t = new StringBuilder();
        JSONObject so = d.optJSONObject("sistema");
        JSONArray daFare = d.optJSONArray("daFare");

        t.append(I18n.tr("server.rp.c.title")).append("\n")
         .append(riga("=", 60)).append("\n")
         .append(I18n.tr("server.rp.c.server", java.util.Map.of("v", String.valueOf(host.isEmpty() ? "-" : host)))).append("\n")
         .append(I18n.tr("server.rp.c.sent", java.util.Map.of("v", String.valueOf(LocalDateTime.now().format(data()))))).append("\n")
         .append(I18n.tr("server.rp.c.from", java.util.Map.of("v", String.valueOf(mittente)))).append("\n")
         .append(I18n.tr("server.rp.c.to", java.util.Map.of("v", String.valueOf(destinatario)))).append("\n\n");

        // --- cio' per cui il rapporto esiste ---
        t.append(I18n.tr("server.rp.c.todo")).append("\n").append(riga("-", 60)).append("\n");
        if (daFare == null || daFare.length() == 0) {
            t.append(I18n.tr("server.rp.c.nothing")).append("\n\n");
        } else {
            for (int i = 0; i < daFare.length(); i++) {
                JSONObject x = daFare.getJSONObject(i);
                int u = x.optInt("urgenza", 9);
                String etichetta = u == 0 ? I18n.tr("server.rp.c.now") : u == 1 ? I18n.tr("server.rp.c.urgent")
                        : u == 2 ? I18n.tr("server.rp.c.todoTag") : I18n.tr("server.rp.c.whenYouCan");
                t.append(etichetta).append(" ").append(x.optString("cosa")).append("\n")
                 .append("           ").append(I18n.tr("server.rp.c.where", java.util.Map.of("v", String.valueOf(x.optString("dove"))))).append("\n\n");
            }
        }

        // --- sistema ---
        t.append(I18n.tr("server.rp.c.system")).append("\n").append(riga("-", 60)).append("\n");
        if (so != null) {
            t.append(I18n.tr("server.rp.c.fbInstalled", java.util.Map.of("v", String.valueOf(so.optString("kernelInstallato", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.kernelRunning", java.util.Map.of("v", String.valueOf(so.optString("kernelInEsecuzione", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.userland", java.util.Map.of("v", String.valueOf(so.optString("userland", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.arch", java.util.Map.of("v", String.valueOf(so.optString("architettura", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.eol", java.util.Map.of("v", String.valueOf(so.optString("fineSupporto", "?")))));
            long g = d.optLong("giorniAllaFineSupporto", -1);
            if (g >= 0) t.append("  ").append(I18n.tr("server.rp.c.inDays", java.util.Map.of("n", String.valueOf(g))));
            t.append("\n");
        }
        JSONObject ramo = d.optJSONObject("branch");
        if (ramo != null) t.append(I18n.tr("server.rp.c.branch", java.util.Map.of("v", String.valueOf(ramo.optString("branch", "?"))))).append("\n");
        t.append("\n");

        // --- pacchetti ---
        t.append(I18n.tr("server.rp.c.packages")).append("\n").append(riga("-", 60)).append("\n")
         .append(I18n.tr("server.rp.c.pkgCounts", java.util.Map.of("tot", String.valueOf(d.optInt("pacchettiTotali")), "prot", String.valueOf(d.optInt("pacchettiProtetti")), "agg", String.valueOf(d.optInt("pacchettiConAggiornamento"))))).append("\n");
        JSONArray agg = d.optJSONArray("daAggiornare");
        if (agg != null && agg.length() > 0) {
            for (int i = 0; i < agg.length(); i++) t.append("  - ").append(agg.getString(i)).append("\n");
        }
        t.append("\n");

        // --- vulnerabilita' ---
        t.append(I18n.tr("server.rp.c.vulns")).append("\n").append(riga("-", 60)).append("\n");

        // Di che dati stiamo parlando. I numeri qui sotto escono dal database delle
        // vulnerabilita' e dal catalogo dei pacchetti GIA' presenti sul server: dire quanto
        // sono vecchi e' l'unica cosa che distingue una misura da un numero che sembra una
        // misura. L'anteprima non scarica niente, l'invio automatico si.
        long gv = d.optLong("vulnDbGiorni", -1), gc = d.optLong("catalogoGiorni", -1);
        t.append(I18n.tr("server.rp.c.vulnDb")).append(" ")
         .append(gv < 0 ? I18n.tr("server.rp.c.ageUnknown") : (gv == 0 ? I18n.tr("server.rp.c.updatedToday") : I18n.tr("server.rp.c.daysAgo", java.util.Map.of("n", String.valueOf(gv)))))
         .append(" ").append(d.optBoolean("vulnDbAggiornatoOra", false) ? I18n.tr("server.rp.c.downloadedNow") : I18n.tr("server.rp.c.notDownloadedNow"))
         // Del catalogo si dice quando e' stato PUBBLICATO sul server di pkg: e' la data che pkg
         // da' al file (vedi PkgCatalog), e non cambia se il server non ha niente di nuovo.
         .append(". ").append(I18n.tr("server.rp.c.catalog")).append(" ")
         .append(gc < 0 ? I18n.tr("server.rp.c.catalogUnknown")
                        : I18n.tr("server.rp.c.published", java.util.Map.of("quanto", String.valueOf(PkgCatalog.quanto(gc)), "data", String.valueOf(d.optString("catalogoData")))))
         .append(d.optBoolean("catalogoRinfrescato", false) ? ", " + I18n.tr("server.rp.c.checkedNow") : "")
         .append(".\n");
        // Piu' repository, uno senza catalogo, o nessuna data: la frase intera, che dice quale e perche'.
        JSONObject cat = d.optJSONObject("catalogo");
        if (cat != null) {
            int trovati = 0;
            JSONArray rep = cat.optJSONArray("repository");
            for (int i = 0; rep != null && i < rep.length(); i++)
                if (rep.getJSONObject(i).optBoolean("trovato")) trovati++;
            JSONArray manc = cat.optJSONArray("mancanti");
            if (gc < 0 || trovati > 1 || (manc != null && manc.length() > 0))
                t.append(cat.optString("nota")).append("\n");
        }

        // Se il conto non torna, lo si dice PRIMA dell'elenco: un elenco parziale letto come
        // completo e' peggio di nessun elenco, e chi legge deve saperlo prima di rassicurarsi.
        String nonTorna = d.optString("vulnConteggioNonTorna", "");
        if (!nonTorna.isEmpty()) t.append(I18n.tr("server.rp.c.warning", java.util.Map.of("v", String.valueOf(nonTorna)))).append("\n");
        JSONArray nc = d.optJSONArray("vulnNonCapiti");
        if (nc != null && nc.length() > 0) {
            t.append(I18n.tr("server.rp.c.unparsed")).append("\n");
            for (int i = 0; i < nc.length(); i++) t.append("  ? ").append(nc.getString(i)).append("\n");
        }

        JSONArray cr = d.optJSONArray("vulnConRimedio"), sr = d.optJSONArray("vulnSenzaRimedio");
        if ((cr == null || cr.length() == 0) && (sr == null || sr.length() == 0)) {
            t.append(I18n.tr("server.rp.c.noneAudit")).append("\n");
        } else {
            if (cr != null && cr.length() > 0) {
                t.append(I18n.tr("server.rp.c.withFix")).append("\n");
                for (int i = 0; i < cr.length(); i++) t.append("  - ").append(cr.getString(i)).append("\n");
            }
            if (sr != null && sr.length() > 0) {
                t.append(I18n.tr("server.rp.c.withoutFix")).append("\n");
                for (int i = 0; i < sr.length(); i++) t.append("  - ").append(sr.getString(i)).append("\n");
            }
        }
        t.append("\n");

        // --- certificato ---
        t.append(I18n.tr("server.rp.c.cert")).append("\n").append(riga("-", 60)).append("\n").append(certificato()).append("\n");

        // --- servizi ---
        t.append(I18n.tr("server.rp.c.services")).append("\n").append(riga("-", 60)).append("\n");
        JSONArray sv = d.optJSONArray("servizi");
        int attivi = 0;
        if (sv != null) for (int i = 0; i < sv.length(); i++) if (sv.getJSONObject(i).getBoolean("attivo")) attivi++;
        t.append(I18n.tr("server.rp.c.runningOf", java.util.Map.of("n", String.valueOf(attivi), "tot", String.valueOf(sv == null ? 0 : sv.length())))).append("\n");
        JSONArray giu = d.optJSONArray("serviziNonAttivi");
        if (giu != null && giu.length() > 0)
            for (int i = 0; i < giu.length(); i++) t.append("  ").append(I18n.tr("server.rp.c.notRunning", java.util.Map.of("v", String.valueOf(giu.getString(i))))).append("\n");
        t.append("\n");

        // --- librerie ---
        JSONArray rotti = d.optJSONArray("librerieMancanti");
        t.append(I18n.tr("server.rp.c.libs")).append("\n").append(riga("-", 60)).append("\n")
         .append(rotti == null || rotti.length() == 0
                 ? I18n.tr("server.rp.c.libsOk")
                 : I18n.tr("server.rp.c.libsMissing", java.util.Map.of("n", String.valueOf(rotti.length())))).append("\n\n");

        // --- spazio e ambienti ---
        t.append(I18n.tr("server.rp.c.space")).append("\n").append(riga("-", 60)).append("\n").append(d.optString("spazio", "-")).append("\n\n");
        JSONObject be = d.optJSONObject("ambienti");
        if (be != null && be.optBoolean("success")) {
            JSONArray el = be.optJSONArray("ambienti");
            t.append(I18n.tr("server.rp.c.waysBack")).append("\n").append(riga("-", 60)).append("\n");
            if (el != null) for (int i = 0; i < el.length(); i++) {
                JSONObject x = el.getJSONObject(i);
                t.append("  ").append(x.optString("nome")).append("   ").append(x.optString("spazio"))
                 .append("   ").append(x.optString("stato")).append("\n");
            }
            t.append("\n");
        }

        t.append(riga("=", 60)).append("\n")
         .append(I18n.tr("server.rp.c.footer")).append("\n");
        return t.toString();
    }

    /**
     * Il gestore dei certificati viene COLLEGATO da chi avvia il pannello, non cercato per
     * riflessione: cosi' il compilatore verifica i nomi. La prima versione cercava un campo
     * "Main.acmeManager" che non esiste — e' privato dentro SSLMailServer — quindi il
     * rapporto avrebbe scritto "non riesco a leggere il certificato" per sempre, senza che
     * niente lo segnalasse.
     */
    private static org.mail_panel.security.AcmeManager acme;

    public static void collega(org.mail_panel.security.AcmeManager a) { acme = a; }

    /** Lo stato del certificato, in poche righe leggibili. */
    private static String certificato() {
        if (acme == null) return I18n.tr("server.rp.c.acmeMissing") + "\n";
        try {
            org.mail_panel.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed) return I18n.tr("server.rp.c.noCert") + "\n";
            StringBuilder t = new StringBuilder();
            t.append(I18n.tr("server.rp.c.certName", java.util.Map.of("v", String.valueOf(i.commonName == null ? "-" : i.commonName)))).append("\n")
             .append(I18n.tr("server.rp.c.certIssuer", java.util.Map.of("v", String.valueOf(i.issuer == null ? "-" : i.issuer))))
             .append(i.letsEncrypt ? "  (Let's Encrypt)" : "").append("\n");
            if (i.expired) t.append(I18n.tr("server.rp.c.expired"));
            else t.append(I18n.tr("server.rp.c.expiresIn", java.util.Map.of("n", String.valueOf(i.daysUntilExpiry))));
            if (i.expiresAt != null) t.append(", ").append(I18n.tr("server.rp.c.onDate", java.util.Map.of("d", String.valueOf(i.expiresAt.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))))));
            t.append(".\n");
            return t.toString();
        } catch (Exception e) {
            return I18n.tr("server.rp.c.certReadFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))) + "\n";
        }
    }

    /** Il certificato entra anche fra le cose da fare, se sta per scadere o e' scaduto. */
    static JSONObject avvisoCertificato() {
        if (acme == null) return null;
        try {
            org.mail_panel.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed)
                return new JSONObject().put("urgenza", 2)
                        .put("cosa", I18n.tr("server.rp.c.noTlsCert"))
                        .put("dove", "SSL");
            if (i.expired)
                return new JSONObject().put("urgenza", 0)
                        .put("cosa", I18n.tr("server.rp.c.tlsExpired"))
                        .put("dove", "SSL");
            if (i.daysUntilExpiry <= 15)
                return new JSONObject().put("urgenza", i.daysUntilExpiry <= 5 ? 0 : 1)
                        .put("cosa", I18n.tr("server.rp.c.tlsExpiresIn", java.util.Map.of("n", String.valueOf(i.daysUntilExpiry))))
                        .put("dove", "SSL");
        } catch (Exception ignored) { }
        return null;
    }
}
