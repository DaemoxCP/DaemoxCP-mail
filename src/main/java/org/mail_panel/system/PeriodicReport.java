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
 *     che su FreeBSD e' mailwrapper e passa a dma (vedi postfixSendmail). Il pannello
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
            Thread t = new Thread(r, "periodic-report");
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

    /**
     * La frequenza salvata, con i nomi di adesso. Fino al 24/10/2026 si salvava "giornaliero",
     * "settimanale" o "mensile": una pianificazione gia' fatta deve continuare a valere.
     */
    static String normalizedFrequency(String f) {
        return switch (f) {
            case "giornaliero" -> "daily";
            case "settimanale" -> "weekly";
            case "mensile" -> "monthly";
            default -> f;
        };
    }

    /** L'esito di un invio fallito comincia cosi', e lo scheduler lo riconosce da qui. */
    static final String FAILED_PREFIX = "failed: ";
    /** Il prefisso che si scriveva fino al 24/10/2026: un esito gia' salvato va riconosciuto. */
    static final String OLD_FAILED_PREFIX = "fallito: ";

    static boolean isFailedOutcome(String outcome) {
        return outcome.startsWith(FAILED_PREFIX) || outcome.startsWith(OLD_FAILED_PREFIX);
    }

    /** L'esito come lo legge chi apre la pagina: il prefisso e' un codice, non un testo. */
    static String shownOutcome(String outcome) {
        for (String p : new String[]{FAILED_PREFIX, OLD_FAILED_PREFIX})
            if (outcome.startsWith(p))
                return I18n.tr("server.rp.lastFailed", java.util.Map.of("error", outcome.substring(p.length())));
        return outcome;
    }

    private static String setting(String key, String defaultValue) {
        try { return Main.mailDatabase.getSetting(key, defaultValue); }
        catch (Exception e) { return defaultValue; }
    }

    private static void storeSetting(String key, String value) {
        try { Main.mailDatabase.setSetting(key, value); } catch (Exception ignored) { }
    }

    /**
     * Il dominio con cui il pannello si identifica.
     *
     * NON e' "il primo dominio dell'elenco": quello e' l'ordine di una lista, e prendendolo
     * si finisce a proporre un'identita' sul dominio di un sito che non c'entra niente — e'
     * successo, con domain-a.test. Il pannello ha un hostname suo, mail.domain-b.test: il
     * dominio e' quello che sta dopo il primo punto.
     */
    private static String panelDomain() {
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

    public static JSONObject state() {
        String domain = panelDomain();
        String last = setting("report_last", "");
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("active", "1".equals(setting("report_enabled", "0")))
                .put("sender", setting("report_from", "no-reply@" + domain))
                .put("recipient", setting("report_to", ""))
                .put("frequency", normalizedFrequency(setting("report_freq", "weekly")))
                .put("now", setting("report_hour", "8"))
                .put("domain", domain)
                .put("lastSend", last)
                .put("lastOutcome", shownOutcome(setting("report_last_result", "")));
        r.put("next", describeNext(r));
        return r;
    }

    private static String describeNext(JSONObject s) {
        if (!s.getBoolean("active")) return I18n.tr("server.rp.disabled");
        String freq = s.getString("frequency");
        String now = s.getString("now");
        String u = s.getString("lastSend");
        String every = "daily".equals(freq) ? I18n.tr("server.rp.everyDay")
                    : "monthly".equals(freq) ? I18n.tr("server.rp.everyMonth") : I18n.tr("server.rp.everyWeek");
        return I18n.tr("server.rp.schedule", java.util.Map.of("every", String.valueOf(every), "now", String.valueOf(now)))
                + " " + (u.isEmpty() ? I18n.tr("server.rp.neverSent")
                               : I18n.tr("server.rp.lastSent", java.util.Map.of("when", String.valueOf(u.replace('T', ' ')))));
    }

    /**
     * Salva le impostazioni, validando OGNI campo con una whitelist. Gli indirizzi finiscono
     * in un'intestazione del messaggio: un a capo dentro un indirizzo permetterebbe di
     * aggiungere intestazioni arbitrarie, che e' il modo classico di trasformare un modulo
     * di posta in un inoltro per chiunque.
     */
    public static JSONObject saveSettings(String recipient, String sender,
                                               String frequency, String now, boolean active) {
        JSONObject r = new JSONObject();
        recipient = recipient == null ? "" : recipient.trim();
        sender = sender == null ? "" : sender.trim();

        if (active && recipient.isEmpty())
            return r.put("success", false).put("error", I18n.tr("server.rp.needRecipient"));
        if (!recipient.isEmpty() && !org.mail_panel.webserver.SecurityUtils.isValidEmail(recipient))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipient"));
        if (!sender.isEmpty()) {
            if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(sender))
                return r.put("success", false).put("error", I18n.tr("server.rp.badSender"));
            // Whitelist vera: non "e' un indirizzo ben formato", ma "e' UNA DELLE caselle
            // che esistono sul dominio di questo pannello". L'elenco lo conosce il pannello,
            // quindi il controllo puo' essere esatto invece che approssimato.
            JSONObject id = identityState();
            JSONArray choices = id.optJSONArray("availableMailboxes");
            boolean allowed = false;
            if (choices != null)
                for (int i = 0; i < choices.length(); i++)
                    if (choices.getString(i).equalsIgnoreCase(sender)) allowed = true;
            if (!allowed)
                return r.put("success", false).put("availableMailboxes", choices == null ? new JSONArray() : choices)
                        .put("error", I18n.tr("server.rp.senderMustExist", java.util.Map.of("domain", String.valueOf(id.optString("panelDomain", "?")))) + " "
                                + (choices == null || choices.length() == 0
                                   ? I18n.tr("server.rp.noMailboxYet")
                                   : I18n.tr("server.rp.pickOne")));
        }
        // Nessun a capo puo' entrare in un'intestazione, in nessuna forma.
        for (String v : new String[]{recipient, sender})
            if (v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0 || v.indexOf('\0') >= 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.badAddress"));
        if (!java.util.List.of("daily", "weekly", "monthly").contains(frequency))
            return r.put("success", false).put("error", I18n.tr("server.rp.badFreq"));
        int h;
        try { h = Integer.parseInt(now.trim()); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.badHour")); }
        if (h < 0 || h > 23) return r.put("success", false).put("error", I18n.tr("server.rp.hourRange"));

        storeSetting("report_to", recipient);
        if (!sender.isEmpty()) storeSetting("report_from", sender);
        storeSetting("report_freq", frequency);
        storeSetting("report_hour", String.valueOf(h));
        storeSetting("report_enabled", active ? "1" : "0");
        // Il rapporto automatico parte da solo, fuori da ogni richiesta: esce nella lingua di chi
        // ha salvato le impostazioni
        storeSetting("report_lang", I18n.current());
        return state().put("success", true).put("note", active
                ? I18n.tr("server.rp.savedOn", java.util.Map.of("recipient", String.valueOf(recipient)))
                : I18n.tr("server.rp.savedOff"));
    }

    /** Il testo che verrebbe inviato, senza inviarlo. */
    public static JSONObject preview() {
        try {
            // L'anteprima non tocca la rete: la scheda promette una lettura, e deve restarlo.
            JSONObject data = UpdateManager.reportData(false);
            JSONObject cert = certificateWarning();
            if (cert != null) {
                JSONArray df = data.optJSONArray("toDo");
                if (df == null) df = new JSONArray();
                df.put(cert);
                data.put("toDo", df);
            }
            String host = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
            String sender = setting("report_from", "no-reply@" + panelDomain());
            String dest = setting("report_to", I18n.tr("server.rp.noRecipient"));
            return new JSONObject().put("success", true)
                    .put("text", compose(data, host, sender, dest))
                    .put("thingsToDo", data.optJSONArray("toDo") == null ? 0 : data.getJSONArray("toDo").length());
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
    private static JSONObject busy(org.mail_panel.database.MailDatabase.Domain dom, String address)
            throws Exception {
        for (var m : Main.mailDatabase.getMailboxes(dom.id))
            if (m.email != null && m.email.equalsIgnoreCase(address))
                return new JSONObject().put("type", "mailbox").put("name", m.name == null ? "" : m.name)
                        .put("created", m.createdAt == null ? "" : m.createdAt.toString());
        for (var a : Main.mailDatabase.getAliases(dom.id))
            if (a.source != null && a.source.equalsIgnoreCase(address))
                return new JSONObject().put("type", "alias").put("destination", a.destination == null ? "" : a.destination)
                        .put("created", a.createdAt == null ? "" : a.createdAt.toString());
        return null;
    }

    public static JSONObject identityState() {
        JSONObject r = new JSONObject().put("success", true);
        String sender = setting("report_from", "").trim();
        try {
            java.util.List<org.mail_panel.database.MailDatabase.Domain> domains = Main.mailDatabase.getDomains();
            JSONArray names = new JSONArray();
            for (var d : domains) names.put(d.domain);
            r.put("managedDomains", names).put("sender", sender);

            // NON si propone piu' un indirizzo da soli. Prima si sceglieva "no-reply@" sul
            // PRIMO dominio dell'elenco: un indirizzo che il pannello non ha mai visto, su un
            // dominio scelto dall'ordine di una lista. Ora l'indirizzo lo scrive chi sa a
            // cosa serve, e il pannello si limita a dire cosa c'e' gia' li'.
            String mine = panelDomain();
            org.mail_panel.database.MailDatabase.Domain myDomain = null;
            for (var d : domains) if (d.domain.equalsIgnoreCase(mine)) myDomain = d;
            r.put("panelDomain", mine).put("panelDomainManaged", myDomain != null);
            boolean myManaged = myDomain != null;

            // Le caselle che esistono sul dominio del pannello: sono le UNICHE scelte valide
            // per il mittente. Un campo di testo libero permetterebbe di scriverci dentro
            // qualunque cosa — compreso un dominio di un sito, che e' esattamente l'errore
            // gia' fatto con domain-a.test.
            JSONArray choices = new JSONArray();
            if (myDomain != null)
                for (var m : Main.mailDatabase.getMailboxes(myDomain.id))
                    if (m.email != null) choices.put(m.email);
            r.put("availableMailboxes", choices);
            if (myManaged) {
                String proposed = "no-reply@" + mine;
                boolean proposedExists = false;
                for (int q = 0; q < choices.length(); q++)
                    if (choices.getString(q).equalsIgnoreCase(proposed)) proposedExists = true;
                r.put("suggested", proposed).put("suggestedExists", proposedExists);
            }
            if (sender.isEmpty())
                return r.put("exists", false).put("managedDomain", false).put("toChoose", true)
                        .put("note", I18n.tr("server.rp.pickSender")
                                + (myManaged ? " " + I18n.tr("server.rp.suggestSender", java.util.Map.of("mine", String.valueOf(mine))) : ""));

            String domain = sender.substring(sender.indexOf('@') + 1);
            org.mail_panel.database.MailDatabase.Domain its = null;
            for (var d : domains) if (d.domain.equalsIgnoreCase(domain)) its = d;
            r.put("domain", domain).put("managedDomain", its != null);
            if (its == null)
                return r.put("exists", false)
                        .put("note", I18n.tr("server.rp.domainNotManaged", java.util.Map.of("domain", String.valueOf(domain))));

            JSONObject already = busy(its, sender);
            r.put("busy", already == null ? JSONObject.NULL : already);
            boolean itsDomain = !mine.isEmpty() && domain.equalsIgnoreCase(mine);
            r.put("onOwnDomain", itsDomain);
            if (already == null)
                return r.put("exists", false).put("creatable", itsDomain)
                        .put("note", itsDomain
                                ? I18n.tr("server.rp.addressFree", java.util.Map.of("sender", String.valueOf(sender)))
                                : I18n.tr("server.rp.addressFreeOther", java.util.Map.of("sender", String.valueOf(sender), "domain", String.valueOf(domain), "mine", String.valueOf(mine))));
            if ("alias".equals(already.optString("type")))
                return r.put("exists", true).put("eAlias", true)
                        .put("note", I18n.tr("server.rp.isAlias", java.util.Map.of("sender", String.valueOf(sender), "destination", String.valueOf(already.optString("destination")))));
            return r.put("exists", true).put("eAlias", false)
                    .put("note", I18n.tr("server.rp.mailboxExists", java.util.Map.of("sender", String.valueOf(sender)))
                            + (already.optString("name").isEmpty() ? "" : " (\"" + already.optString("name") + "\")")
                            + (already.optString("created").isEmpty() ? "" : ", " + I18n.tr("server.rp.createdOn", java.util.Map.of("d", String.valueOf(already.optString("created")))))
                            + ": " + I18n.tr("server.rp.realSender"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.rp.readFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    /** Crea la casella del pannello. Non tocca niente se esiste gia'. */
    public static JSONObject createIdentity(String address) {
        JSONObject r = new JSONObject().put("address", address);
        if (address == null || !org.mail_panel.webserver.SecurityUtils.isValidEmail(address))
            return r.put("success", false).put("error", I18n.tr("server.rp.badAddressLower"));
        String domain = address.substring(address.indexOf('@') + 1);
        try {
            org.mail_panel.database.MailDatabase.Domain its = null;
            for (var d : Main.mailDatabase.getDomains()) if (d.domain.equalsIgnoreCase(domain)) its = d;
            if (its == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.domainNotManaged2", java.util.Map.of("domain", String.valueOf(domain))));
            String mine = panelDomain();
            if (mine.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.noPanelDomain"));
            if (!domain.equalsIgnoreCase(mine))
                return r.put("success", false).put("panelDomain", mine)
                        .put("error", I18n.tr("server.rp.onlyOwnDomain", java.util.Map.of("domain", String.valueOf(domain), "mine", String.valueOf(mine))));

            JSONObject already = busy(its, address);
            if (already != null) {
                boolean alias = "alias".equals(already.optString("type"));
                return r.put("success", !alias).put("alreadyExisted", true).put("busy", already)
                        .put(alias ? "error" : "note", alias
                                ? I18n.tr("server.rp.aliasNoCreate", java.util.Map.of("address", String.valueOf(address), "destination", String.valueOf(already.optString("destination"))))
                                : I18n.tr("server.rp.existedAlready"));
            }

            // Password casuale robusta: nessuno deve digitarla, il rapporto non fa login.
            java.security.SecureRandom random = new java.security.SecureRandom();
            String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            StringBuilder pw = new StringBuilder();
            for (int i = 0; i < 32; i++) pw.append(alphabet.charAt(random.nextInt(alphabet.length())));

            int id = Main.mailDatabase.addMailbox(its.id, address, pw.toString(),
                    I18n.tr("server.rp.mailboxName"), 128, true);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.rp.createFailed"));
            storeSetting("report_from", address);
            return r.put("success", true).put("alreadyExisted", false).put("id", id)
                    .put("note", I18n.tr("server.rp.created"));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.rp.createError", java.util.Map.of("m", String.valueOf(e.getMessage()))));
        }
    }

    // ===================== quando inviare =====================

    private void tick() {
        try {
            if (!"1".equals(setting("report_enabled", "0"))) return;
            String a = setting("report_to", "");
            if (a.isEmpty()) return;
            if (!isTheMoment()) return;
            // Fuori da ogni richiesta: il rapporto esce nella lingua di chi l'ha configurato
            I18n.setCurrent(setting("report_lang", "it"));
            JSONObject outcome;
            try { outcome = sendNow(a); }
            finally { I18n.clearCurrent(); }
            System.out.println("[Report] automatic send: "
                    + (outcome.optBoolean("success") ? "succeeded" : "FAILED - " + outcome.optString("error")));
        } catch (Exception e) {
            System.out.println("[Report] error in the periodic check: " + e.getMessage());
        }
    }

    /**
     * Vero se e' ora di inviare. Il confronto e' sull'INTERVALLO TRASCORSO, non su un
     * calendario: cosi' un pannello spento per due giorni manda il rapporto quando torna su,
     * invece di saltarlo perche' "il giorno giusto e' passato".
     */
    static boolean isTheMoment(String frequency, String nowText, String lastIso,
                              String lastAttemptIso, String lastOutcome, LocalDateTime now) {
        int hour;
        try { hour = Integer.parseInt(nowText.trim()); } catch (Exception e) { hour = 8; }
        if (hour < 0 || hour > 23) hour = 8;
        if (now.getHour() < hour) return false;

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
        if (lastOutcome != null && isFailedOutcome(lastOutcome)
                && lastAttemptIso != null && !lastAttemptIso.isBlank()) {
            try {
                long fromAttempt = java.time.temporal.ChronoUnit.HOURS.between(
                        LocalDateTime.parse(lastAttemptIso, ISO), now);
                if (fromAttempt >= 0 && fromAttempt < HOURS_AFTER_FAILURE) return false;
            } catch (Exception ignore) {
                // Data illeggibile: non si blocca l'invio per un dato che non si sa leggere.
            }
        }

        if (lastIso == null || lastIso.isBlank()) return true;      // mai inviato
        LocalDateTime last;
        try { last = LocalDateTime.parse(lastIso, ISO); }
        catch (Exception e) { return true; }                            // data illeggibile: si invia
        long hours = java.time.temporal.ChronoUnit.HOURS.between(last, now);
        if (hours < 0) return false;                                      // orologio andato indietro
        switch (frequency == null ? "" : frequency) {
            case "daily": return hours >= 20;
            case "monthly":     return hours >= 24 * 29;
            default:            return hours >= 24 * 6;                   // settimanale
        }
    }

    /** Ore da aspettare prima di riprovare dopo un invio fallito. */
    static final int HOURS_AFTER_FAILURE = 6;

    private boolean isTheMoment() {
        return isTheMoment(normalizedFrequency(setting("report_freq", "weekly")), setting("report_hour", "8"),
                setting("report_last", ""), setting("report_last_try", ""), setting("report_last_result", ""),
                LocalDateTime.now());
    }

    // ===================== invio =====================

    public static JSONObject sendNow(String recipient) {
        JSONObject r = new JSONObject().put("recipient", recipient);
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(recipient))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipientLower"));
        String sender = setting("report_from", "no-reply@" + panelDomain());
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(sender))
            return r.put("success", false).put("error", I18n.tr("server.rp.badSenderLower", java.util.Map.of("m", String.valueOf(sender))));

        JSONObject data;
        try { data = UpdateManager.reportData(); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.collectFailed", java.util.Map.of("m", String.valueOf(e.getMessage())))); }
        // Il certificato lo conosce solo questa classe: si aggiunge qui alle cose da fare,
        // e si riordina, altrimenti "scade fra 3 giorni" finirebbe in fondo all'elenco.
        JSONArray df = data.optJSONArray("toDo");
        if (df == null) df = new JSONArray();

        JSONObject certWarning = certificateWarning();
        if (certWarning != null) df.put(certWarning);

        // Le novita' sulle specifiche e sulle scadenze finiscono nel rapporto invece di
        // essere scoperte per caso mentre si sta facendo altro. E' il motivo per cui la
        // sorveglianza esiste: un avviso che nessuno va a cercare non e' un avviso.
        for (JSONObject x : watchWarnings()) df.put(x);

        java.util.List<JSONObject> l = new java.util.ArrayList<>();
        for (int i = 0; i < df.length(); i++) l.add(df.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgency", 9)));
        JSONArray sorted = new JSONArray();
        for (JSONObject x : l) sorted.put(x);
        data.put("toDo", sorted);

        String host = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
        int howMany = data.optJSONArray("toDo") == null ? 0 : data.getJSONArray("toDo").length();
        String subject = "[" + (host.isEmpty() ? I18n.tr("server.rp.mailServer") : host) + "] "
                + (howMany == 0 ? I18n.tr("server.rp.allGood")
                   : howMany == 1 ? I18n.tr("server.rp.todo.one")
                   : I18n.tr("server.rp.todo.other", java.util.Map.of("n", String.valueOf(howMany))))
                + " - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        String body = compose(data, host, sender, recipient);

        // Prima di provare, non dopo: se il pannello muore durante l'invio, al riavvio questa
        // data c'e' gia' e la pausa dopo un fallimento vale lo stesso.
        storeSetting("report_last_try", LocalDateTime.now().format(ISO));

        JSONObject outcome = delivery(sender, recipient, subject, body);
        r.put("subject", subject).put("body", body).put("sender", sender)
         .put("thingsToDo", howMany).put("output", outcome.optString("output", ""));
        if (outcome.optBoolean("success")) {
            String now = LocalDateTime.now().format(ISO);
            storeSetting("report_last", now);
            storeSetting("report_last_result", outcome.optString("outcome", I18n.tr("server.rp.lastSucceeded")));
            return r.put("success", true).put("when", now)
                    .put("warning", outcome.optBoolean("warning", false))
                    .put("note", outcome.optString("note", ""));
        }
        storeSetting("report_last_result", FAILED_PREFIX + outcome.optString("error", "?"));
        return r.put("success", false).put("error", outcome.optString("error", I18n.tr("server.rp.sendFailed")));
    }

    /**
     * Un messaggio del pannello a un amministratore (il codice di accesso), con lo stesso mittente
     * e lo stesso sendmail di Postfix del rapporto. Restituisce solo se e' partito: il corpo
     * contiene un codice monouso e non deve finire in nessun log, quindi l'uscita di sendmail e le
     * righe del log della posta qui non si restituiscono.
     */
    public static boolean sendPanelMessage(String recipient, String subject, String body) {
        String sender = setting("report_from", "no-reply@" + panelDomain());
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(sender)
                || !org.mail_panel.webserver.SecurityUtils.isValidEmail(recipient)) return false;
        return delivery(sender, recipient, subject, body).optBoolean("success", false);
    }

    /**
     * Consegna a Postfix con il suo sendmail(1), poi segue il messaggio nel log della posta.
     * L'oggetto viene codificato secondo RFC 2047 perche' un'intestazione non puo' contenere
     * caratteri non ASCII, e il corpo dichiara UTF-8: senza, le lettere accentate
     * arriverebbero storte. Il Message-ID lo sceglie il pannello: e' il filo che lega il
     * messaggio alle righe che Postfix scrive nel log.
     */
    private static JSONObject delivery(String from, String to, String subject, String body) {
        JSONObject r = new JSONObject();
        JSONObject chosen = postfixSendmail();
        if (!chosen.optBoolean("success")) return r.put("success", false).put("error", chosen.optString("error"));
        String sendmail = chosen.getString("path");

        String messageId = newMessageId(from);
        StringBuilder message = new StringBuilder();
        message.append("From: ").append(I18n.tr("server.rp.fromName")).append(" <").append(from).append(">\r\n")
                 .append("To: ").append(to).append("\r\n")
                 .append("Subject: ").append(subject2047(subject)).append("\r\n")
                 .append("Message-ID: <").append(messageId).append(">\r\n")
                 .append("MIME-Version: 1.0\r\n")
                 .append("Content-Type: text/plain; charset=UTF-8\r\n")
                 .append("Content-Transfer-Encoding: 8bit\r\n")
                 .append("Auto-Submitted: auto-generated\r\n")   // non e' posta scritta da una persona
                 .append("X-Mailer: FreeBSD Mail Panel\r\n")
                 .append("\r\n")
                 .append(body.replace("\n", "\r\n"));
        StringBuilder output = new StringBuilder()
                .append("* ").append(I18n.tr("server.rp.postfixSendmail", java.util.Map.of("p", String.valueOf(sendmail)))).append('\n')
                .append("* Message-ID: <").append(messageId).append(">\n");

        // Dove finisce il log adesso: le righe di questo messaggio stanno tutte dopo.
        long logStart = logSize();
        try {
            ProcessBuilder pb = new ProcessBuilder(sendmail, "-t", "-i", "-f", from);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (OutputStream os = p.getOutputStream()) {
                os.write(message.toString().getBytes(StandardCharsets.UTF_8));
            }
            String said = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!said.isEmpty()) output.append(said).append('\n');
            r.put("output", output.toString());
            boolean finished = p.waitFor(60, TimeUnit.SECONDS);
            if (!finished) { p.destroyForcibly(); return r.put("success", false).put("error", I18n.tr("server.rp.sendmailTimeout")); }
            int code = p.exitValue();
            r.put("code", code);
            if (code != 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.sendmailExit", java.util.Map.of("c", String.valueOf(code)))
                        + (said.isEmpty() ? "" : ": " + said));
        } catch (Exception e) {
            return r.put("output", output.toString()).put("success", false)
                    .put("error", I18n.tr("server.rp.cannotRun", java.util.Map.of("p", String.valueOf(sendmail), "m", String.valueOf(e.getMessage()))));
        }

        // Il codice 0 dice soltanto che il messaggio e' nella coda di ingresso di Postfix.
        // Dove e' andato a finire lo dice il log.
        JSONObject log = followInLog(logStart, messageId, to);
        JSONArray lines = log.optJSONArray("lines");
        if (lines != null && lines.length() > 0) {
            output.append("* ").append(I18n.tr("server.rp.fromMaillog", java.util.Map.of("f", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG)))).append('\n');
            for (int i = 0; i < lines.length(); i++) output.append(lines.getString(i)).append('\n');
        } else {
            output.append("* ").append(I18n.tr("server.rp.noLogLine")).append('\n');
        }
        return verdict(log).put("output", output.toString());
    }

    // ===================== quale sendmail =====================

    /** Il sendmail installato dal port di Postfix: si prova quando postconf non risponde. */
    static final String PORTS_SENDMAIL = "/usr/local/sbin/sendmail";

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
    static JSONObject postfixSendmail() {
        String declared = Shell.runShell(java.time.Duration.ofSeconds(10),
                "postconf -h sendmail_path 2>/dev/null").outputTrim();
        return sendmailChoice(declared, PORTS_SENDMAIL, MAILWRAPPER);
    }

    /** La scelta vera e propria, separata da postconf e dai percorsi reali per poterla provare. */
    static JSONObject sendmailChoice(String declared, String fromPort, String mailwrapper) {
        java.util.LinkedHashSet<String> candidates = new java.util.LinkedHashSet<>();
        if (declared != null && declared.startsWith("/") && declared.indexOf('\n') < 0)
            candidates.add(declared);
        candidates.add(fromPort);
        java.util.List<String> discarded = new java.util.ArrayList<>();
        for (String c : candidates) {
            String no = notPostfix(c, mailwrapper);
            if (no == null) return new JSONObject().put("success", true).put("path", c);
            discarded.add(no);
        }
        return new JSONObject().put("success", false)
                .put("error", I18n.tr("server.rp.noPostfixSendmail", java.util.Map.of("reasons", String.valueOf(String.join("; ", discarded)))));
    }

    /** null se il percorso puo' essere il sendmail di Postfix, altrimenti il motivo per cui non lo e'. */
    static String notPostfix(String path, String mailwrapper) {
        java.nio.file.Path p = java.nio.file.Path.of(path);
        if (!java.nio.file.Files.isRegularFile(p) || !java.nio.file.Files.isExecutable(p))
            return I18n.tr("server.rp.notExecutable", java.util.Map.of("p", String.valueOf(path)));
        try {
            // Stesso file, che sia un collegamento simbolico o un hard link: e' mailwrapper.
            java.nio.file.Path mw = java.nio.file.Path.of(mailwrapper);
            if (java.nio.file.Files.exists(mw) && java.nio.file.Files.isSameFile(p, mw))
                return I18n.tr("server.rp.isMailwrapper", java.util.Map.of("p", String.valueOf(path)));
        } catch (java.io.IOException e) {
            return I18n.tr("server.rp.cannotCheck", java.util.Map.of("p", String.valueOf(path), "m", String.valueOf(e.getMessage())));
        }
        return null;
    }

    /** Un Message-ID che nessun altro messaggio ha: ora UTC, 16 byte casuali, dominio del mittente. */
    static String newMessageId(String sender) {
        byte[] randomBytes = new byte[16];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return "report." + LocalDateTime.now(java.time.ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
                + "." + java.util.HexFormat.of().formatHex(randomBytes)
                + "@" + sender.substring(sender.indexOf('@') + 1);
    }

    // ===================== com'e' andata =====================

    /** Per quanto si segue il messaggio nel log, prima di smettere di guardare. */
    static final int SECONDS_IN_LOG = 30;

    /** Di log nuovo se ne leggono al massimo 4 MB: un server sotto carico ne scrive tanto. */
    private static final int MAX_LOG = 4 << 20;

    private static long logSize() {
        try { return java.nio.file.Files.size(java.nio.file.Path.of(org.mail_panel.monitoring.LogManager.MAILLOG)); }
        catch (Exception e) { return -1; }
    }

    /** Le righe scritte nel log della posta da 'da' in poi. Se nel frattempo e' stato ruotato, dall'inizio. */
    private static java.util.List<String> logLines(long from) {
        try (java.io.RandomAccessFile f = new java.io.RandomAccessFile(org.mail_panel.monitoring.LogManager.MAILLOG, "r")) {
            long end = f.length();
            long start = from < 0 || from > end ? 0 : from;
            start = Math.max(start, end - MAX_LOG);
            byte[] b = new byte[(int) (end - start)];
            f.seek(start);
            f.readFully(b);
            return new String(b, StandardCharsets.UTF_8).lines().toList();
        } catch (Exception e) {
            return java.util.List.of();
        }
    }

    /**
     * Guarda il log finche' Postfix non dice com'e' andata, per al massimo SECONDS_IN_LOG.
     * Una consegna normale si conclude in un paio di secondi; se il server del destinatario non
     * risponde, Postfix aspetta i suoi tempi e l'esito resta "queued".
     */
    private static JSONObject followInLog(long from, String messageId, String recipient) {
        long expiry = System.nanoTime() + TimeUnit.SECONDS.toNanos(SECONDS_IN_LOG);
        while (true) {
            JSONObject e = outcomeInLog(logLines(from), messageId, recipient);
            String state = e.optString("state", "");
            if ((!state.isEmpty() && !"queued".equals(state)) || System.nanoTime() >= expiry) return e;
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
     * Stati: "" (Postfix non l'ha visto), "queued" (visto, esito non ancora scritto),
     * "consegnato", "rimandato" (Postfix riprovera' da solo), "respinto" (dal server del
     * destinatario), "rifiutato" (da Postfix stesso, prima di partire: milter o controlli).
     */
    static JSONObject outcomeInLog(java.util.List<String> lines, String messageId, String recipient) {
        JSONObject r = new JSONObject().put("state", "").put("lines", new JSONArray());
        java.util.regex.Pattern withId = java.util.regex.Pattern.compile(
                "(?:^|\\s)([0-9A-Za-z]+): message-id=<" + java.util.regex.Pattern.quote(messageId) + ">");
        String queue = null;
        for (String line : lines) {
            java.util.regex.Matcher m = withId.matcher(line);
            if (m.find()) { queue = m.group(1); break; }
        }
        if (queue == null) return r;
        r.put("queue", queue).put("state", "queued");

        // Le righe di QUESTO messaggio: il numero di coda come parola intera, seguito da ": ".
        java.util.regex.Pattern ownPattern = java.util.regex.Pattern.compile(
                "(?:^|\\s)" + java.util.regex.Pattern.quote(queue) + ": (.*)$");
        java.util.regex.Pattern state = java.util.regex.Pattern.compile(", status=([a-z]+) \\((.*)\\)\\s*$");
        java.util.List<Integer> indexes = new java.util.ArrayList<>();
        int delivery = -1;              // la riga "to=<...> ... status=" che decide
        boolean forRecipient = false;
        String refusal = null;
        for (int i = 0; i < lines.size(); i++) {
            java.util.regex.Matcher m = ownPattern.matcher(lines.get(i));
            if (!m.find()) continue;
            indexes.add(i);
            String rest = m.group(1);
            for (String type : new String[]{"milter-reject: ", "reject: ", "milter-discard: ", "discard: "})
                if (rest.startsWith(type)) refusal = rest.substring(type.length());
            if (!rest.startsWith("to=<") || !state.matcher(rest).find()) continue;
            // Con piu' destinatari (un alias, una copia nascosta) conta la riga del destinatario
            // del rapporto; fra quelle, l'ultima, perche' un "rimandato" puo' essere seguito da
            // un "consegnato".
            boolean its = recipient.equalsIgnoreCase(between(rest, "to=<", ">"))
                       || recipient.equalsIgnoreCase(between(rest, "orig_to=<", ">"));
            if (its || !forRecipient) { delivery = i; forRecipient = its; }
        }

        if (delivery >= 0) {
            java.util.regex.Matcher m = ownPattern.matcher(lines.get(delivery));
            m.find();
            String rest = m.group(1);
            java.util.regex.Matcher s = state.matcher(rest);
            s.find();
            String relay = between(rest, "relay=", ",");
            r.put("relay", relay).put("answer", s.group(2)).put("state", switch (s.group(1)) {
                case "sent" -> "delivered";
                case "deferred" -> "deferred";
                case "bounced", "expired" -> "rejected";
                default -> "queued";
            });
            // Se la connessione era cifrata, il processo smtp che ha consegnato lo scrive quando la
            // apre (con smtp_tls_loglevel >= 1). E' quello che Gmail chiama "crittografia standard".
            // Se la prova non c'e' non si afferma niente: la sua assenza non prova il contrario.
            int opening = tlsOpening(lines, delivery, queue, relay);
            if (opening >= 0) {
                String line = lines.get(opening);
                String tls = "TLS connection established to " + relay + ": ";
                java.util.regex.Matcher t = java.util.regex.Pattern.compile("^(\\S+) with cipher (\\S+)")
                        .matcher(line.substring(line.indexOf(tls) + tls.length()));
                if (t.find()) r.put("tls", t.group(1) + " (" + t.group(2) + ")");
                indexes.add(opening);
            }
        } else if (refusal != null) {
            // Un rifiuto temporaneo (4.x.x) non e' la fine: Postfix riprova.
            boolean temporary = java.util.regex.Pattern.compile("(?:^|\\s)4\\.\\d{1,3}\\.\\d{1,3}(?:\\s|$)")
                    .matcher(refusal).find();
            r.put("state", temporary ? "deferred" : "refused").put("answer", refusal);
        }

        java.util.Collections.sort(indexes);
        JSONArray text = new JSONArray();
        for (int i : indexes) if (text.length() < 30) text.put(lines.get(i));
        return r.put("lines", text);
    }

    /** Chi ha scritto una riga del log (programma e pid: "postfix/smtp[81242]") e che cosa. */
    record Row(String process, String text) {}

    private static final java.util.regex.Pattern LINE_5424 = java.util.regex.Pattern.compile(
            "^<\\d{1,3}>1 \\S+ \\S+ (\\S+) ([0-9]+) \\S+ (?:-|(?:\\[[^\\]]*\\])+) ?(.*)$");
    private static final java.util.regex.Pattern LINE_CLASSIC = java.util.regex.Pattern.compile(
            "(?:^|\\s)([^\\s\\[\\]]+)\\[([0-9]+)\\]: (.*)$");

    /** La riga scomposta, nel formato classico di syslog o in RFC 5424; null se non e' nessuno dei due. */
    static Row line(String r) {
        java.util.regex.Matcher m = LINE_5424.matcher(r);
        if (!m.find()) {
            m = LINE_CLASSIC.matcher(r);
            if (!m.find()) return null;
        }
        return new Row(m.group(1) + "[" + m.group(2) + "]", m.group(3));
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
    static int tlsOpening(java.util.List<String> lines, int delivery, String queue, String relay) {
        Row who = line(lines.get(delivery));
        if (who == null || relay.isEmpty() || "none".equals(relay) || who.text().contains(", conn_use=")) return -1;
        java.util.regex.Pattern opening = java.util.regex.Pattern.compile(
                "^(?:Anonymous|Untrusted|Trusted|Verified) TLS connection established to "
                + java.util.regex.Pattern.quote(relay) + ": \\S+ with cipher ");
        java.util.regex.Pattern ownDelivery = java.util.regex.Pattern.compile(
                "^" + java.util.regex.Pattern.quote(queue) + ": to=<.*, status=[a-z]+ \\(");
        for (int i = delivery - 1; i >= 0; i--) {
            Row r = line(lines.get(i));
            if (r == null || !who.process().equals(r.process())) continue;
            String t = r.text();
            if (ownDelivery.matcher(t).find() || t.startsWith("SSL_connect:")
                    || t.startsWith("save session ") || t.startsWith("remove session ")) continue;
            return opening.matcher(t).find() ? i : -1;
        }
        return -1;
    }

    /** Il testo fra 'dopo' e il primo 'fino' che lo segue; "" se 'dopo' non c'e'. */
    private static String between(String s, String after, String until) {
        int i = s.indexOf(after);
        if (i < 0) return "";
        i += after.length();
        int j = s.indexOf(until, i);
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
        String queue = log.optString("queue", "");
        String relay = log.optString("relay", "");
        String answer = log.optString("answer", "");
        String tls = log.optString("tls", "");
        JSONObject v = new JSONObject();
        switch (log.optString("state", "")) {
            case "delivered" -> {
                String where = relay + (tls.isEmpty() ? "" : " " + I18n.tr("server.rp.withTls", java.util.Map.of("tls", String.valueOf(tls))));
                return v.put("success", true).put("warning", false)
                        .put("outcome", brief(I18n.tr("server.rp.deliveredTo", java.util.Map.of("where", String.valueOf(where), "answer", String.valueOf(answer)))))
                        .put("note", I18n.tr("server.rp.deliveredNote", java.util.Map.of("where", String.valueOf(where), "answer", String.valueOf(answer))));
            }
            case "deferred" -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", brief(I18n.tr("server.rp.deferred", java.util.Map.of("answer", String.valueOf(answer)))))
                        .put("note", I18n.tr("server.rp.deferredNote", java.util.Map.of("queue", String.valueOf(queue), "answer", String.valueOf(answer))));
            }
            case "rejected" -> {
                return v.put("success", false).put("error", brief(relay.isEmpty() || "none".equals(relay)
                        ? I18n.tr("server.rp.bounced", java.util.Map.of("answer", String.valueOf(answer)))
                        : I18n.tr("server.rp.bouncedBy", java.util.Map.of("relay", String.valueOf(relay), "answer", String.valueOf(answer)))));
            }
            case "refused" -> {
                return v.put("success", false).put("error", brief(I18n.tr("server.rp.rejected", java.util.Map.of("answer", String.valueOf(answer)))));
            }
            case "queued" -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", I18n.tr("server.rp.accepted", java.util.Map.of("queue", String.valueOf(queue))))
                        .put("note", I18n.tr("server.rp.acceptedNote", java.util.Map.of("queue", String.valueOf(queue), "s", String.valueOf(SECONDS_IN_LOG), "log", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG))));
            }
            default -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", I18n.tr("server.rp.notInLog"))
                        .put("note", I18n.tr("server.rp.notInLogNote", java.util.Map.of("s", String.valueOf(SECONDS_IN_LOG), "log", String.valueOf(org.mail_panel.monitoring.LogManager.MAILLOG))));
            }
        }
    }

    /** L'esito finisce in una riga della scheda: una risposta lunga del server si accorcia. */
    private static String brief(String s) {
        return s.length() <= 300 ? s : s.substring(0, 297) + "...";
    }

    /** Oggetto con lettere accentate: RFC 2047, altrimenti l'intestazione non e' valida. */
    private static String subject2047(String s) {
        boolean onlyAscii = s.chars().allMatch(c -> c >= 32 && c < 127);
        if (onlyAscii) return s;
        return "=?UTF-8?B?" + Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    // ===================== il testo =====================

    private static String line(String c, int n) { return String.valueOf(c).repeat(Math.max(0, n)); }

    /**
     * Le voci che arrivano dalla sorveglianza: specifiche sostituite o aggiornate, e versioni
     * di OpenSSL che escono dal supporto.
     *
     * Se il controllo non riesce (rete assente, fonte irraggiungibile) NON si tace: si mette
     * una voce che dice che non si e' potuto controllare. Un rapporto silenzioso perche' il
     * controllo e' fallito e' indistinguibile da un rapporto silenzioso perche' va tutto bene,
     * e sono due cose opposte.
     */
    static java.util.List<JSONObject> watchWarnings() {
        java.util.List<JSONObject> outside = new java.util.ArrayList<>();
        try {
            JSONObject c = StandardsWatch.check();
            JSONArray st = c.optJSONArray("standard");
            if (st != null) for (int i = 0; i < st.length(); i++) {
                JSONObject o = st.getJSONObject(i);
                int g = o.optInt("severity", 0);
                if (g == 2)
                    outside.add(new JSONObject().put("urgency", 1)
                            .put("what", o.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
                else if (g == 1)
                    outside.add(new JSONObject().put("urgency", 3)
                            .put("what", o.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
            }
            if (c.optInt("unread", 0) > 0)
                outside.add(new JSONObject().put("urgency", 3)
                        .put("what", I18n.tr("server.rp.rfcUnread", java.util.Map.of("n", String.valueOf(c.optInt("unread")))))
                        .put("where", I18n.tr("server.rp.whereSurveillance")));
        } catch (Exception e) {
            outside.add(new JSONObject().put("urgency", 3)
                    .put("what", I18n.tr("server.rp.survFailed", java.util.Map.of("m", String.valueOf(e.getMessage()))))
                    .put("where", I18n.tr("server.rp.whereSurveillance")));
        }

        try {
            JSONObject o = OpensslExpiry.state();
            JSONArray inst = o.optJSONArray("installs");
            if (inst != null) for (int i = 0; i < inst.length(); i++) {
                JSONObject x = inst.getJSONObject(i);
                if (!x.optBoolean("present", false)) continue;
                int u = x.optInt("urgency", 0);
                if (u == 1 || u == 2)
                    outside.add(new JSONObject().put("urgency", u == 2 ? 1 : 2)
                            .put("what", "OpenSSL " + x.optString("version") + " ("
                                    + x.optString("type") + "): " + x.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
            }
        } catch (Exception ignore) {}

        return outside;
    }

    static String compose(JSONObject d, String host, String sender, String recipient) {
        StringBuilder t = new StringBuilder();
        JSONObject os = d.optJSONObject("system");
        JSONArray toDo = d.optJSONArray("toDo");

        t.append(I18n.tr("server.rp.c.title")).append("\n")
         .append(line("=", 60)).append("\n")
         .append(I18n.tr("server.rp.c.server", java.util.Map.of("v", String.valueOf(host.isEmpty() ? "-" : host)))).append("\n")
         .append(I18n.tr("server.rp.c.sent", java.util.Map.of("v", String.valueOf(LocalDateTime.now().format(data()))))).append("\n")
         .append(I18n.tr("server.rp.c.from", java.util.Map.of("v", String.valueOf(sender)))).append("\n")
         .append(I18n.tr("server.rp.c.to", java.util.Map.of("v", String.valueOf(recipient)))).append("\n\n");

        // --- cio' per cui il rapporto esiste ---
        t.append(I18n.tr("server.rp.c.todo")).append("\n").append(line("-", 60)).append("\n");
        if (toDo == null || toDo.length() == 0) {
            t.append(I18n.tr("server.rp.c.nothing")).append("\n\n");
        } else {
            for (int i = 0; i < toDo.length(); i++) {
                JSONObject x = toDo.getJSONObject(i);
                int u = x.optInt("urgency", 9);
                String label = u == 0 ? I18n.tr("server.rp.c.now") : u == 1 ? I18n.tr("server.rp.c.urgent")
                        : u == 2 ? I18n.tr("server.rp.c.todoTag") : I18n.tr("server.rp.c.whenYouCan");
                t.append(label).append(" ").append(x.optString("what")).append("\n")
                 .append("           ").append(I18n.tr("server.rp.c.where", java.util.Map.of("v", String.valueOf(x.optString("where"))))).append("\n\n");
            }
        }

        // --- sistema ---
        t.append(I18n.tr("server.rp.c.system")).append("\n").append(line("-", 60)).append("\n");
        if (os != null) {
            t.append(I18n.tr("server.rp.c.fbInstalled", java.util.Map.of("v", String.valueOf(os.optString("installedKernel", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.kernelRunning", java.util.Map.of("v", String.valueOf(os.optString("runningKernel", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.userland", java.util.Map.of("v", String.valueOf(os.optString("userland", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.arch", java.util.Map.of("v", String.valueOf(os.optString("architecture", "?"))))).append("\n")
             .append(I18n.tr("server.rp.c.eol", java.util.Map.of("v", String.valueOf(os.optString("endOfSupport", "?")))));
            long g = d.optLong("daysToEndOfSupport", -1);
            if (g >= 0) t.append("  ").append(I18n.tr("server.rp.c.inDays", java.util.Map.of("n", String.valueOf(g))));
            t.append("\n");
        }
        JSONObject branch = d.optJSONObject("branch");
        if (branch != null) t.append(I18n.tr("server.rp.c.branch", java.util.Map.of("v", String.valueOf(branch.optString("branch", "?"))))).append("\n");
        t.append("\n");

        // --- pacchetti ---
        t.append(I18n.tr("server.rp.c.packages")).append("\n").append(line("-", 60)).append("\n")
         .append(I18n.tr("server.rp.c.pkgCounts", java.util.Map.of("tot", String.valueOf(d.optInt("totalPackages")), "locked", String.valueOf(d.optInt("lockedPackageCount")), "updatable", String.valueOf(d.optInt("packagesWithUpdate"))))).append("\n");
        JSONArray update = d.optJSONArray("toUpdate");
        if (update != null && update.length() > 0) {
            for (int i = 0; i < update.length(); i++) t.append("  - ").append(update.getString(i)).append("\n");
        }
        t.append("\n");

        // --- vulnerabilita' ---
        t.append(I18n.tr("server.rp.c.vulns")).append("\n").append(line("-", 60)).append("\n");

        // Di che dati stiamo parlando. I numeri qui sotto escono dal database delle
        // vulnerabilita' e dal catalogo dei pacchetti GIA' presenti sul server: dire quanto
        // sono vecchi e' l'unica cosa che distingue una misura da un numero che sembra una
        // misura. L'anteprima non scarica niente, l'invio automatico si.
        long gv = d.optLong("vulnDbDays", -1), gc = d.optLong("catalogDays", -1);
        t.append(I18n.tr("server.rp.c.vulnDb")).append(" ")
         .append(gv < 0 ? I18n.tr("server.rp.c.ageUnknown") : (gv == 0 ? I18n.tr("server.rp.c.updatedToday") : I18n.tr("server.rp.c.daysAgo", java.util.Map.of("n", String.valueOf(gv)))))
         .append(" ").append(d.optBoolean("vulnDbUpdatedNow", false) ? I18n.tr("server.rp.c.downloadedNow") : I18n.tr("server.rp.c.notDownloadedNow"))
         // Del catalogo si dice quando e' stato PUBBLICATO sul server di pkg: e' la data che pkg
         // da' al file (vedi PkgCatalog), e non cambia se il server non ha niente di nuovo.
         .append(". ").append(I18n.tr("server.rp.c.catalog")).append(" ")
         .append(gc < 0 ? I18n.tr("server.rp.c.catalogUnknown")
                        : I18n.tr("server.rp.c.published", java.util.Map.of("howMuch", String.valueOf(PkgCatalog.howMuch(gc)), "data", String.valueOf(d.optString("catalogDate")))))
         .append(d.optBoolean("refreshedCatalog", false) ? ", " + I18n.tr("server.rp.c.checkedNow") : "")
         .append(".\n");
        // Piu' repository, uno senza catalogo, o nessuna data: la frase intera, che dice quale e perche'.
        JSONObject cat = d.optJSONObject("catalog");
        if (cat != null) {
            int found = 0;
            JSONArray rep = cat.optJSONArray("repository");
            for (int i = 0; rep != null && i < rep.length(); i++)
                if (rep.getJSONObject(i).optBoolean("found")) found++;
            JSONArray missing = cat.optJSONArray("missing");
            if (gc < 0 || found > 1 || (missing != null && missing.length() > 0))
                t.append(cat.optString("note")).append("\n");
        }

        // Se il conto non torna, lo si dice PRIMA dell'elenco: un elenco parziale letto come
        // completo e' peggio di nessun elenco, e chi legge deve saperlo prima di rassicurarsi.
        String doesNotMatch = d.optString("vulnCountMismatch", "");
        if (!doesNotMatch.isEmpty()) t.append(I18n.tr("server.rp.c.warning", java.util.Map.of("v", String.valueOf(doesNotMatch)))).append("\n");
        JSONArray nc = d.optJSONArray("vulnNotUnderstood");
        if (nc != null && nc.length() > 0) {
            t.append(I18n.tr("server.rp.c.unparsed")).append("\n");
            for (int i = 0; i < nc.length(); i++) t.append("  ? ").append(nc.getString(i)).append("\n");
        }

        JSONArray cr = d.optJSONArray("vulnWithRemedy"), sr = d.optJSONArray("vulnWithoutRemedy");
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
        t.append(I18n.tr("server.rp.c.cert")).append("\n").append(line("-", 60)).append("\n").append(certificate()).append("\n");

        // --- servizi ---
        t.append(I18n.tr("server.rp.c.services")).append("\n").append(line("-", 60)).append("\n");
        JSONArray sv = d.optJSONArray("services");
        int active = 0;
        if (sv != null) for (int i = 0; i < sv.length(); i++) if (sv.getJSONObject(i).getBoolean("active")) active++;
        t.append(I18n.tr("server.rp.c.runningOf", java.util.Map.of("n", String.valueOf(active), "tot", String.valueOf(sv == null ? 0 : sv.length())))).append("\n");
        JSONArray down = d.optJSONArray("inactiveServices");
        if (down != null && down.length() > 0)
            for (int i = 0; i < down.length(); i++) t.append("  ").append(I18n.tr("server.rp.c.notRunning", java.util.Map.of("v", String.valueOf(down.getString(i))))).append("\n");
        t.append("\n");

        // --- librerie ---
        JSONArray broken = d.optJSONArray("missingLibraries");
        t.append(I18n.tr("server.rp.c.libs")).append("\n").append(line("-", 60)).append("\n")
         .append(broken == null || broken.length() == 0
                 ? I18n.tr("server.rp.c.libsOk")
                 : I18n.tr("server.rp.c.libsMissing", java.util.Map.of("n", String.valueOf(broken.length())))).append("\n\n");

        // --- spazio e ambienti ---
        t.append(I18n.tr("server.rp.c.space")).append("\n").append(line("-", 60)).append("\n").append(d.optString("space", "-")).append("\n\n");
        JSONObject be = d.optJSONObject("environments");
        if (be != null && be.optBoolean("success")) {
            JSONArray el = be.optJSONArray("environments");
            t.append(I18n.tr("server.rp.c.waysBack")).append("\n").append(line("-", 60)).append("\n");
            if (el != null) for (int i = 0; i < el.length(); i++) {
                JSONObject x = el.getJSONObject(i);
                t.append("  ").append(x.optString("name")).append("   ").append(x.optString("space"))
                 .append("   ").append(x.optString("state")).append("\n");
            }
            t.append("\n");
        }

        t.append(line("=", 60)).append("\n")
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

    public static void link(org.mail_panel.security.AcmeManager a) { acme = a; }

    /** Lo stato del certificato, in poche righe leggibili. */
    private static String certificate() {
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
    static JSONObject certificateWarning() {
        if (acme == null) return null;
        try {
            org.mail_panel.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed)
                return new JSONObject().put("urgency", 2)
                        .put("what", I18n.tr("server.rp.c.noTlsCert"))
                        .put("where", "SSL");
            if (i.expired)
                return new JSONObject().put("urgency", 0)
                        .put("what", I18n.tr("server.rp.c.tlsExpired"))
                        .put("where", "SSL");
            if (i.daysUntilExpiry <= 15)
                return new JSONObject().put("urgency", i.daysUntilExpiry <= 5 ? 0 : 1)
                        .put("what", I18n.tr("server.rp.c.tlsExpiresIn", java.util.Map.of("n", String.valueOf(i.daysUntilExpiry))))
                        .put("where", "SSL");
        } catch (Exception ignored) { }
        return null;
    }
}
