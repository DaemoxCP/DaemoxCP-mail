package org.mail_panel.system;

import org.json.JSONArray;
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
 * correzione, un certificato in scadenza, una release che esce dal supporto — arrivano senza
 * che nessuno le stia guardando.
 *
 * Tre principi:
 *
 *  1. IN CIMA CI VA COSA C'E' DA FARE, non lo stato. Se non c'e' niente da fare, l'email lo
 *     dice in una riga: un rapporto che sembra sempre uguale smette di essere letto, e il
 *     giorno in cui contiene qualcosa nessuno se ne accorge.
 *  2. L'INVIO PASSA DA POSTFIX, con sendmail(1). Il pannello gira SUL server di posta:
 *     nessuna credenziale SMTP da custodire, nessuna configurazione che possa divergere, e
 *     il messaggio esce firmato DKIM come qualunque altro.
 *  3. L'ESITO SI VERIFICA. sendmail accetta il messaggio e restituisce 0 anche quando la
 *     consegna fallira' piu' tardi: si registra cosa ha risposto e quando, e il pannello
 *     mostra la data dell'ultimo invio riuscito, non "dovrebbe aver funzionato".
 */
public final class RapportoPeriodico {

    private static final DateTimeFormatter DATA = DateTimeFormatter.ofPattern("dd/MM/yyyy 'alle' HH:mm");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private final ScheduledExecutorService scheduler;

    public RapportoPeriodico() {
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "Rapporto-Periodico");
            t.setDaemon(true);
            return t;
        });
    }

    /** Si guarda ogni quarto d'ora se sia il momento. Il lavoro vero avviene di rado. */
    public void start() {
        scheduler.scheduleAtFixedRate(this::tick, 120, 900, TimeUnit.SECONDS);
        System.out.println("[Rapporto] Scheduler avviato (controlla ogni 15 minuti se e' il momento di inviare)");
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
        if (!s.getBoolean("attivo")) return "Il rapporto e' disattivato: non verra' inviato.";
        String freq = s.getString("frequenza");
        String ora = s.getString("ora");
        String u = s.getString("ultimoInvio");
        String ogni = "giornaliero".equals(freq) ? "ogni giorno"
                    : "mensile".equals(freq) ? "una volta al mese" : "una volta a settimana";
        return "Invio " + ogni + ", non prima delle " + ora + ":00."
                + (u.isEmpty() ? " Non e' ancora stato inviato nessun rapporto."
                               : " Ultimo invio: " + u.replace('T', ' ') + ".");
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
            return r.put("success", false).put("error", "Serve un destinatario per attivare il rapporto.");
        if (!destinatario.isEmpty() && !org.mail_panel.webserver.SecurityUtils.isValidEmail(destinatario))
            return r.put("success", false).put("error", "Il destinatario non e' un indirizzo valido.");
        if (!mittente.isEmpty()) {
            if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(mittente))
                return r.put("success", false).put("error", "Il mittente non e' un indirizzo valido.");
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
                        .put("error", "Il mittente deve essere una casella esistente sul dominio di questo "
                                + "pannello (" + id.optString("dominioDelPannello", "?") + "). "
                                + (scelte == null || scelte.length() == 0
                                   ? "Su quel dominio non c'e' ancora nessuna casella: creane una qui sopra."
                                   : "Scegline una dall'elenco."));
        }
        // Nessun a capo puo' entrare in un'intestazione, in nessuna forma.
        for (String v : new String[]{destinatario, mittente})
            if (v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0 || v.indexOf('\0') >= 0)
                return r.put("success", false).put("error", "Indirizzo non valido.");
        if (!java.util.List.of("giornaliero", "settimanale", "mensile").contains(frequenza))
            return r.put("success", false).put("error", "Frequenza non valida.");
        int h;
        try { h = Integer.parseInt(ora.trim()); }
        catch (Exception e) { return r.put("success", false).put("error", "Ora non valida."); }
        if (h < 0 || h > 23) return r.put("success", false).put("error", "L'ora deve stare fra 0 e 23.");

        impSet("report_to", destinatario);
        if (!mittente.isEmpty()) impSet("report_from", mittente);
        impSet("report_freq", frequenza);
        impSet("report_hour", String.valueOf(h));
        impSet("report_enabled", attivo ? "1" : "0");
        return stato().put("success", true).put("nota", attivo
                ? "Salvato. Il rapporto verra' inviato a " + destinatario + "."
                : "Salvato. Il rapporto e' disattivato: non verra' inviato.");
    }

    /** Il testo che verrebbe inviato, senza inviarlo. */
    public static JSONObject anteprima() {
        try {
            // L'anteprima non tocca la rete: la scheda promette una lettura, e deve restarlo.
            JSONObject dati = UpdateManager.datiPerRapporto(false);
            JSONObject cert = avvisoCertificato();
            if (cert != null) {
                JSONArray df = dati.optJSONArray("daFare");
                if (df == null) df = new JSONArray();
                df.put(cert);
                dati.put("daFare", df);
            }
            String host = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
            String mitt = imp("report_from", "no-reply@" + dominioDelPannello());
            String dest = imp("report_to", "(nessun destinatario impostato)");
            return new JSONObject().put("success", true)
                    .put("testo", componi(dati, host, mitt, dest))
                    .put("coseDaFare", dati.optJSONArray("daFare") == null ? 0 : dati.getJSONArray("daFare").length());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", "non riesco a comporre il rapporto: " + e.getMessage());
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
                        .put("nota", "Scegli l'indirizzo da cui partiranno i rapporti. Deve stare su un "
                                + "dominio gestito da questo pannello, altrimenti i messaggi non sarebbero "
                                + "firmati DKIM da questo server. Il pannello ti dira' se quell'indirizzo "
                                + "e' gia' occupato da una casella o da un alias, PRIMA di creare qualcosa."
                                + (mioGestito ? " Il dominio con cui questo pannello si identifica e' " + mio
                                              + " (dal suo hostname), quindi un mittente sensato sarebbe "
                                              + "no-reply@" + mio + " — ma la scelta e' tua." : ""));

            String dominio = mittente.substring(mittente.indexOf('@') + 1);
            org.mail_panel.database.MailDatabase.Domain suo = null;
            for (var d : domini) if (d.domain.equalsIgnoreCase(dominio)) suo = d;
            r.put("dominio", dominio).put("dominioGestito", suo != null);
            if (suo == null)
                return r.put("esiste", false)
                        .put("nota", "Il dominio " + dominio + " non e' gestito da questo pannello: la casella "
                                + "non posso crearla io, e i messaggi partirebbero senza firma DKIM di questo server.");

            JSONObject gia = occupato(suo, mittente);
            r.put("occupato", gia == null ? JSONObject.NULL : gia);
            boolean suoDominio = !mio.isEmpty() && dominio.equalsIgnoreCase(mio);
            r.put("sulProprioDominio", suoDominio);
            if (gia == null)
                return r.put("esiste", false).put("creabile", suoDominio)
                        .put("nota", suoDominio
                                ? "L'indirizzo " + mittente + " e' libero: non esiste ne' come casella ne' come "
                                  + "alias, ed e' sul dominio di questo pannello. Si puo' creare."
                                : "L'indirizzo " + mittente + " e' libero, ma sta su " + dominio + ", che NON e' "
                                  + "il dominio di questo pannello (" + mio + "). Il pannello non crea caselle "
                                  + "sui domini di altri siti: se ti serve, creala tu dalla pagina Caselle "
                                  + "sapendo cosa c'e' gia' su quel dominio.");
            if ("alias".equals(gia.optString("tipo")))
                return r.put("esiste", true).put("eAlias", true)
                        .put("nota", "ATTENZIONE: " + mittente + " esiste gia' come ALIAS verso "
                                + gia.optString("verso") + ". I rapporti possono partire da qui senza creare "
                                + "niente, ma NON creare una casella con lo stesso indirizzo: si metterebbe "
                                + "davanti all'alias e la posta per quell'indirizzo cambierebbe destinazione.");
            return r.put("esiste", true).put("eAlias", false)
                    .put("nota", "La casella " + mittente + " esiste"
                            + (gia.optString("nome").isEmpty() ? "" : " (\"" + gia.optString("nome") + "\")")
                            + (gia.optString("creato").isEmpty() ? "" : ", creata il " + gia.optString("creato"))
                            + ": i rapporti partono da un mittente reale, firmato DKIM come qualunque altro "
                            + "messaggio di questo server.");
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", "non riesco a leggere domini, caselle e alias: " + e.getMessage());
        }
    }

    /** Crea la casella del pannello. Non tocca niente se esiste gia'. */
    public static JSONObject creaIdentita(String indirizzo) {
        JSONObject r = new JSONObject().put("indirizzo", indirizzo);
        if (indirizzo == null || !org.mail_panel.webserver.SecurityUtils.isValidEmail(indirizzo))
            return r.put("success", false).put("error", "indirizzo non valido");
        String dominio = indirizzo.substring(indirizzo.indexOf('@') + 1);
        try {
            org.mail_panel.database.MailDatabase.Domain suo = null;
            for (var d : Main.mailDatabase.getDomains()) if (d.domain.equalsIgnoreCase(dominio)) suo = d;
            if (suo == null)
                return r.put("success", false)
                        .put("error", "il dominio " + dominio + " non e' gestito da questo pannello: "
                                + "aggiungilo prima fra i domini, oppure scegli un mittente su un dominio tuo.");
            String mio = dominioDelPannello();
            if (mio.isEmpty())
                return r.put("success", false)
                        .put("error", "non riesco a stabilire il dominio di questo pannello dal suo hostname: "
                                + "senza, non creo niente da nessuna parte.");
            if (!dominio.equalsIgnoreCase(mio))
                return r.put("success", false).put("dominioDelPannello", mio)
                        .put("error", "NON creo caselle su " + dominio + ". Il pannello puo' creare la propria "
                                + "identita' SOLO sul proprio dominio, che e' " + mio + " (dal suo hostname). "
                                + "Gli altri domini gestiti appartengono a siti e servizi configurati per altro: "
                                + "creare una casella li' dentro puo' mettersi davanti a un alias esistente e "
                                + "dirottare la posta, ed e' esattamente quello che e' successo con "
                                + "no-reply@domain-a.test. Se vuoi un mittente su un altro dominio, la casella "
                                + "creala tu dalla pagina Caselle, sapendo cosa c'e' gia' li'.");

            JSONObject gia = occupato(suo, indirizzo);
            if (gia != null) {
                boolean alias = "alias".equals(gia.optString("tipo"));
                return r.put("success", !alias).put("giaEsisteva", true).put("occupato", gia)
                        .put(alias ? "error" : "nota", alias
                                ? "NON creo niente: " + indirizzo + " esiste gia' come ALIAS verso "
                                  + gia.optString("verso") + ". Creare una casella con lo stesso indirizzo la "
                                  + "metterebbe davanti all'alias e la posta cambierebbe destinazione. Se vuoi "
                                  + "usare questo indirizzo come mittente, puoi farlo senza creare niente."
                                : "La casella esisteva gia': non ho toccato niente.");
            }

            // Password casuale robusta: nessuno deve digitarla, il rapporto non fa login.
            java.security.SecureRandom rnd = new java.security.SecureRandom();
            String alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            StringBuilder pw = new StringBuilder();
            for (int i = 0; i < 32; i++) pw.append(alfabeto.charAt(rnd.nextInt(alfabeto.length())));

            int id = Main.mailDatabase.addMailbox(suo.id, indirizzo, pw.toString(),
                    "Rapporti del pannello", 128, true);
            if (id <= 0) return r.put("success", false).put("error", "creazione non riuscita");
            impSet("report_from", indirizzo);
            return r.put("success", true).put("giaEsisteva", false).put("id", id)
                    .put("nota", "Casella creata con quota 128 MB e una password casuale che nessuno deve "
                            + "digitare: il rapporto esce da sendmail in locale, non fa login. La password e' "
                            + "nel vault del pannello come per ogni altra casella, se un giorno servisse "
                            + "leggere le risposte arrivate qui.");
        } catch (Exception e) {
            return r.put("success", false).put("error", "errore nella creazione: " + e.getMessage());
        }
    }

    // ===================== quando inviare =====================

    private void tick() {
        try {
            if (!"1".equals(imp("report_enabled", "0"))) return;
            String a = imp("report_to", "");
            if (a.isEmpty()) return;
            if (!eIlMomento()) return;
            JSONObject esito = inviaAdesso(a);
            System.out.println("[Rapporto] invio automatico: "
                    + (esito.optBoolean("success") ? "riuscito" : "NON riuscito - " + esito.optString("error")));
        } catch (Exception e) {
            System.out.println("[Rapporto] errore nel controllo periodico: " + e.getMessage());
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
            return r.put("success", false).put("error", "indirizzo del destinatario non valido");
        String mittente = imp("report_from", "no-reply@" + dominioDelPannello());
        if (!org.mail_panel.webserver.SecurityUtils.isValidEmail(mittente))
            return r.put("success", false).put("error", "indirizzo del mittente non valido: " + mittente);

        JSONObject dati;
        try { dati = UpdateManager.datiPerRapporto(); }
        catch (Exception e) { return r.put("success", false).put("error", "non riesco a raccogliere i dati: " + e.getMessage()); }
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
        String oggetto = "[" + (host.isEmpty() ? "server di posta" : host) + "] "
                + (quante == 0 ? "tutto a posto" : quante + (quante == 1 ? " cosa da fare" : " cose da fare"))
                + " - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy"));
        String corpo = componi(dati, host, mittente, destinatario);

        // Prima di provare, non dopo: se il pannello muore durante l'invio, al riavvio questa
        // data c'e' gia' e la pausa dopo un fallimento vale lo stesso.
        impSet("report_last_try", LocalDateTime.now().format(ISO));

        JSONObject esito = consegna(mittente, destinatario, oggetto, corpo);
        r.put("oggetto", oggetto).put("corpo", corpo).put("mittente", mittente)
         .put("coseDaFare", quante).put("uscita", esito.optString("uscita", ""));
        if (esito.optBoolean("success")) {
            String ora = LocalDateTime.now().format(ISO);
            impSet("report_last", ora);
            impSet("report_last_result", "riuscito");
            return r.put("success", true).put("quando", ora)
                    .put("nota", "Messaggio consegnato a Postfix. Se non arriva, il motivo sara' nel "
                            + "log della posta: sendmail accetta il messaggio, la consegna avviene dopo.");
        }
        impSet("report_last_result", "fallito: " + esito.optString("error", "?"));
        return r.put("success", false).put("error", esito.optString("error", "invio non riuscito"));
    }

    /**
     * Consegna a Postfix con sendmail(1). L'oggetto viene codificato secondo RFC 2047 perche'
     * un'intestazione non puo' contenere caratteri non ASCII, e il corpo dichiara UTF-8:
     * senza, le lettere accentate arriverebbero storte.
     */
    private static JSONObject consegna(String da, String a, String oggetto, String corpo) {
        String sendmail = Shell.risolvi("sendmail");
        if (sendmail == null) sendmail = "/usr/local/sbin/sendmail";
        JSONObject r = new JSONObject();
        StringBuilder messaggio = new StringBuilder();
        messaggio.append("From: Pannello di controllo <").append(da).append(">\r\n")
                 .append("To: ").append(a).append("\r\n")
                 .append("Subject: ").append(oggetto2047(oggetto)).append("\r\n")
                 .append("MIME-Version: 1.0\r\n")
                 .append("Content-Type: text/plain; charset=UTF-8\r\n")
                 .append("Content-Transfer-Encoding: 8bit\r\n")
                 .append("Auto-Submitted: auto-generated\r\n")   // non e' posta scritta da una persona
                 .append("X-Mailer: FreeBSD Mail Panel\r\n")
                 .append("\r\n")
                 .append(corpo.replace("\n", "\r\n"));
        try {
            ProcessBuilder pb = new ProcessBuilder(sendmail, "-t", "-i", "-f", da);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (OutputStream os = p.getOutputStream()) {
                os.write(messaggio.toString().getBytes(StandardCharsets.UTF_8));
            }
            String uscita = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            boolean finito = p.waitFor(60, TimeUnit.SECONDS);
            if (!finito) { p.destroyForcibly(); return r.put("success", false).put("error", "sendmail non ha risposto entro 60 secondi"); }
            int codice = p.exitValue();
            r.put("uscita", uscita).put("codice", codice);
            return codice == 0 ? r.put("success", true)
                               : r.put("success", false).put("error", "sendmail e' uscito con codice " + codice
                                       + (uscita.isEmpty() ? "" : ": " + uscita));
        } catch (Exception e) {
            return r.put("success", false).put("error", "non riesco a eseguire " + sendmail + ": " + e.getMessage());
        }
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
            JSONObject c = Sorveglianza.controlla();
            JSONArray st = c.optJSONArray("standard");
            if (st != null) for (int i = 0; i < st.length(); i++) {
                JSONObject o = st.getJSONObject(i);
                int g = o.optInt("gravita", 0);
                if (g == 2)
                    fuori.add(new JSONObject().put("urgenza", 1)
                            .put("cosa", o.optString("commento"))
                            .put("dove", "Aggiornamenti -> Sorveglianza"));
                else if (g == 1)
                    fuori.add(new JSONObject().put("urgenza", 3)
                            .put("cosa", o.optString("commento"))
                            .put("dove", "Aggiornamenti -> Sorveglianza"));
            }
            if (c.optInt("nonLetti", 0) > 0)
                fuori.add(new JSONObject().put("urgenza", 3)
                        .put("cosa", "Non sono riuscito a controllare " + c.optInt("nonLetti")
                                + " specifiche presso il RFC Editor: non vuol dire che non sia cambiato "
                                + "niente, vuol dire che non lo so.")
                        .put("dove", "Aggiornamenti -> Sorveglianza"));
        } catch (Exception e) {
            fuori.add(new JSONObject().put("urgenza", 3)
                    .put("cosa", "La sorveglianza sulle specifiche non e' riuscita: " + e.getMessage())
                    .put("dove", "Aggiornamenti -> Sorveglianza"));
        }

        try {
            JSONObject o = ScadenzaOpenssl.stato();
            JSONArray inst = o.optJSONArray("installazioni");
            if (inst != null) for (int i = 0; i < inst.length(); i++) {
                JSONObject x = inst.getJSONObject(i);
                if (!x.optBoolean("presente", false)) continue;
                int u = x.optInt("urgenza", 0);
                if (u == 1 || u == 2)
                    fuori.add(new JSONObject().put("urgenza", u == 2 ? 1 : 2)
                            .put("cosa", "OpenSSL " + x.optString("versione") + " ("
                                    + x.optString("tipo") + "): " + x.optString("commento"))
                            .put("dove", "Aggiornamenti -> Sorveglianza"));
            }
        } catch (Exception ignore) {}

        return fuori;
    }

    static String componi(JSONObject d, String host, String mittente, String destinatario) {
        StringBuilder t = new StringBuilder();
        JSONObject so = d.optJSONObject("sistema");
        JSONArray daFare = d.optJSONArray("daFare");

        t.append("RAPPORTO DEL SERVER DI POSTA\n")
         .append(riga("=", 60)).append("\n")
         .append("Server:   ").append(host.isEmpty() ? "-" : host).append("\n")
         .append("Inviato:  ").append(LocalDateTime.now().format(DATA)).append("\n")
         .append("Da:       ").append(mittente).append("\n")
         .append("A:        ").append(destinatario).append("\n\n");

        // --- cio' per cui il rapporto esiste ---
        t.append("COSA C'E' DA FARE\n").append(riga("-", 60)).append("\n");
        if (daFare == null || daFare.length() == 0) {
            t.append("Niente. Nessun servizio fermo, nessuna correzione in attesa, nessuna\n")
             .append("scadenza vicina. Lo stato completo e' qui sotto se vuoi controllare.\n\n");
        } else {
            for (int i = 0; i < daFare.length(); i++) {
                JSONObject x = daFare.getJSONObject(i);
                int u = x.optInt("urgenza", 9);
                String etichetta = u == 0 ? "[SUBITO]  " : u == 1 ? "[URGENTE] " : u == 2 ? "[DA FARE] " : "[QUANDO PUOI] ";
                t.append(etichetta).append(x.optString("cosa")).append("\n")
                 .append("           dove: ").append(x.optString("dove")).append("\n\n");
            }
        }

        // --- sistema ---
        t.append("SISTEMA\n").append(riga("-", 60)).append("\n");
        if (so != null) {
            t.append("FreeBSD installato:    ").append(so.optString("kernelInstallato", "?")).append("\n")
             .append("Kernel in esecuzione:  ").append(so.optString("kernelInEsecuzione", "?")).append("\n")
             .append("Userland:              ").append(so.optString("userland", "?")).append("\n")
             .append("Architettura:          ").append(so.optString("architettura", "?")).append("\n")
             .append("Fine supporto:         ").append(so.optString("fineSupporto", "?"));
            long g = d.optLong("giorniAllaFineSupporto", -1);
            if (g >= 0) t.append("  (fra ").append(g).append(" giorni)");
            t.append("\n");
        }
        JSONObject ramo = d.optJSONObject("ramo");
        if (ramo != null) t.append("Ramo dei pacchetti:    ").append(ramo.optString("ramo", "?")).append("\n");
        t.append("\n");

        // --- pacchetti ---
        t.append("PACCHETTI\n").append(riga("-", 60)).append("\n")
         .append("Installati: ").append(d.optInt("pacchettiTotali")).append("   ")
         .append("protetti: ").append(d.optInt("pacchettiProtetti")).append("   ")
         .append("con aggiornamento: ").append(d.optInt("pacchettiConAggiornamento")).append("\n");
        JSONArray agg = d.optJSONArray("daAggiornare");
        if (agg != null && agg.length() > 0) {
            for (int i = 0; i < agg.length(); i++) t.append("  - ").append(agg.getString(i)).append("\n");
        }
        t.append("\n");

        // --- vulnerabilita' ---
        t.append("VULNERABILITA' NOTE\n").append(riga("-", 60)).append("\n");

        // Di che dati stiamo parlando. I numeri qui sotto escono dal database delle
        // vulnerabilita' e dal catalogo dei pacchetti GIA' presenti sul server: dire quanto
        // sono vecchi e' l'unica cosa che distingue una misura da un numero che sembra una
        // misura. L'anteprima non scarica niente, l'invio automatico si.
        long gv = d.optLong("vulnDbGiorni", -1), gc = d.optLong("catalogoGiorni", -1);
        t.append("Database delle vulnerabilita': ")
         .append(gv < 0 ? "eta' sconosciuta" : (gv == 0 ? "aggiornato oggi" : "di " + gv + " giorni fa"))
         .append(d.optBoolean("vulnDbAggiornatoOra", false) ? " (scaricato adesso)" : " (non scaricato adesso)")
         .append(". Catalogo dei pacchetti: ")
         .append(gc < 0 ? "eta' sconosciuta" : (gc == 0 ? "aggiornato oggi" : "di " + gc + " giorni fa"))
         .append(".\n");

        // Se il conto non torna, lo si dice PRIMA dell'elenco: un elenco parziale letto come
        // completo e' peggio di nessun elenco, e chi legge deve saperlo prima di rassicurarsi.
        String nonTorna = d.optString("vulnConteggioNonTorna", "");
        if (!nonTorna.isEmpty()) t.append("ATTENZIONE: ").append(nonTorna).append("\n");
        JSONArray nc = d.optJSONArray("vulnNonCapiti");
        if (nc != null && nc.length() > 0) {
            t.append("Righe che non ho saputo interpretare, e che quindi non sono in nessuno dei "
                   + "due elenchi qui sotto:\n");
            for (int i = 0; i < nc.length(); i++) t.append("  ? ").append(nc.getString(i)).append("\n");
        }

        JSONArray cr = d.optJSONArray("vulnConRimedio"), sr = d.optJSONArray("vulnSenzaRimedio");
        if ((cr == null || cr.length() == 0) && (sr == null || sr.length() == 0)) {
            t.append("Nessuna segnalata da pkg audit.\n");
        } else {
            if (cr != null && cr.length() > 0) {
                t.append("Con una correzione gia' disponibile (SI PUO' AGIRE):\n");
                for (int i = 0; i < cr.length(); i++) t.append("  - ").append(cr.getString(i)).append("\n");
            }
            if (sr != null && sr.length() > 0) {
                t.append("Senza correzione nel repository (solo da sapere, non c'e' niente da fare):\n");
                for (int i = 0; i < sr.length(); i++) t.append("  - ").append(sr.getString(i)).append("\n");
            }
        }
        t.append("\n");

        // --- certificato ---
        t.append("CERTIFICATO TLS\n").append(riga("-", 60)).append("\n").append(certificato()).append("\n");

        // --- servizi ---
        t.append("SERVIZI\n").append(riga("-", 60)).append("\n");
        JSONArray sv = d.optJSONArray("servizi");
        int attivi = 0;
        if (sv != null) for (int i = 0; i < sv.length(); i++) if (sv.getJSONObject(i).getBoolean("attivo")) attivi++;
        t.append(attivi).append(" attivi su ").append(sv == null ? 0 : sv.length()).append("\n");
        JSONArray giu = d.optJSONArray("serviziNonAttivi");
        if (giu != null && giu.length() > 0)
            for (int i = 0; i < giu.length(); i++) t.append("  NON ATTIVO: ").append(giu.getString(i)).append("\n");
        t.append("\n");

        // --- librerie ---
        JSONArray rotti = d.optJSONArray("librerieMancanti");
        t.append("LIBRERIE\n").append(riga("-", 60)).append("\n")
         .append(rotti == null || rotti.length() == 0
                 ? "Ogni pacchetto trova le librerie che richiede.\n"
                 : rotti.length() + " pacchetti non trovano una libreria che richiedono.\n").append("\n");

        // --- spazio e ambienti ---
        t.append("SPAZIO\n").append(riga("-", 60)).append("\n").append(d.optString("spazio", "-")).append("\n\n");
        JSONObject be = d.optJSONObject("ambienti");
        if (be != null && be.optBoolean("success")) {
            JSONArray el = be.optJSONArray("ambienti");
            t.append("VIE DI RITORNO (ambienti di avvio)\n").append(riga("-", 60)).append("\n");
            if (el != null) for (int i = 0; i < el.length(); i++) {
                JSONObject x = el.getJSONObject(i);
                t.append("  ").append(x.optString("nome")).append("   ").append(x.optString("spazio"))
                 .append("   ").append(x.optString("stato")).append("\n");
            }
            t.append("\n");
        }

        t.append(riga("=", 60)).append("\n")
         .append("Rapporto generato dal pannello di controllo, che gira su questo stesso\n")
         .append("server. Per cambiare destinatario, mittente o frequenza, oppure per\n")
         .append("smettere di riceverlo: pannello -> Impostazioni -> Rapporto periodico.\n");
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
        if (acme == null) return "Il gestore dei certificati non e' collegato: stato non disponibile.\n";
        try {
            org.mail_panel.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed) return "Nessun certificato installato.\n";
            StringBuilder t = new StringBuilder();
            t.append("Nome:      ").append(i.commonName == null ? "-" : i.commonName).append("\n")
             .append("Emittente: ").append(i.issuer == null ? "-" : i.issuer)
             .append(i.letsEncrypt ? "  (Let's Encrypt)" : "").append("\n");
            if (i.expired) t.append("SCADUTO");
            else t.append("Scade fra ").append(i.daysUntilExpiry).append(" giorni");
            if (i.expiresAt != null) t.append(", il ").append(i.expiresAt.format(
                    DateTimeFormatter.ofPattern("dd/MM/yyyy")));
            t.append(".\n");
            return t.toString();
        } catch (Exception e) {
            return "Non sono riuscito a leggere lo stato del certificato: " + e.getMessage() + "\n";
        }
    }

    /** Il certificato entra anche fra le cose da fare, se sta per scadere o e' scaduto. */
    static JSONObject avvisoCertificato() {
        if (acme == null) return null;
        try {
            org.mail_panel.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed)
                return new JSONObject().put("urgenza", 2)
                        .put("cosa", "Non risulta installato nessun certificato TLS.")
                        .put("dove", "SSL");
            if (i.expired)
                return new JSONObject().put("urgenza", 0)
                        .put("cosa", "Il certificato TLS e' SCADUTO: i client rifiuteranno la connessione.")
                        .put("dove", "SSL");
            if (i.daysUntilExpiry <= 15)
                return new JSONObject().put("urgenza", i.daysUntilExpiry <= 5 ? 0 : 1)
                        .put("cosa", "Il certificato TLS scade fra " + i.daysUntilExpiry + " giorni.")
                        .put("dove", "SSL");
        } catch (Exception ignored) { }
        return null;
    }
}
