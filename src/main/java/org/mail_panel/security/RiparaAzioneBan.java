package org.mail_panel.security;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Fa bannare con pf le jail che bannavano con iptables.
 *
 * Cosa era successo. Delle sette jail attive, cinque dichiaravano la propria azione
 * ("action = pf[name=...]") e due no: mailpanel-pubblico e mail-panel-auth, cioe' proprio le
 * due che proteggono il pannello. Non dichiarandola ereditavano il valore predefinito di
 * jail.conf, che e' costruito su iptables — un comando che su FreeBSD non esiste. Il risultato
 * non era un errore visibile: le jail rilevavano, contavano i tentativi e incrementavano i ban
 * regolarmente. Su mailpanel-pubblico erano 14.370 tentativi e 46 ban, nessuno dei quali ha mai
 * bloccato niente. Una jail che sbaglia comando di ban e' indistinguibile da una che funziona,
 * finche' non si guarda il firewall.
 *
 * Perche' non basta correggere il codice. Il file di mailpanel-pubblico lo riscrive il pannello
 * a ogni installazione, quindi li' la correzione arriva da sola. La sezione [mail-panel-auth] no:
 * viene aggiunta a jail.local una volta sola e poi mai piu' toccata, per non calpestare le
 * modifiche di chi la personalizza. Ottima regola, che pero' significa che su un'installazione
 * gia' fatta quella sezione resterebbe con iptables per sempre. Serve un intervento che la
 * aggiorni, e che lo faccia con la stessa cautela: cambia la riga dell'azione e nient'altro.
 *
 * Come si comporta. Prima copia, poi scrive, poi ricarica, poi RICHIEDE a fail2ban quale comando
 * esegue adesso: senza quest'ultimo passo si direbbe "riparato" avendo solo scritto un file, ed
 * e' esattamente il genere di conferma che ha lasciato passare il guasto per tutto questo tempo.
 * Se qualcosa va storto ripristina la copia e ricarica.
 */
public final class RiparaAzioneBan {

    private static final String JAIL_LOCAL = "/usr/local/etc/fail2ban/jail.local";
    private static final String JAIL_PUBBLICO = "/usr/local/etc/fail2ban/jail.d/mailpanel-pubblico.conf";
    private static final String CLIENT = "/usr/local/bin/fail2ban-client";

    private RiparaAzioneBan() { }

    /** Le jail il cui comando di ban non e' eseguibile su questo sistema. Legge e basta. */
    public static JSONObject diagnosi() {
        JSONObject r = new JSONObject();
        JSONArray rotte = new JSONArray();
        JSONArray nonGiudicate = new JSONArray();
        int esaminate = 0;
        for (String jail : jailAttive()) {
            String cmd = comandoBan(jail);
            if (cmd == null || cmd.isEmpty()) {
                // Senza l'uscita cruda questa riga e' un vicolo cieco: dice che non si sa, e non
                // lascia a chi legge nessun modo di sapere. Con l'uscita, il passo successivo lo
                // puo' fare chiunque guardi la pagina.
                nonGiudicate.put(new JSONObject().put("jail", jail)
                    .put("perche", "non sono riuscito a farmi dire quale comando esegue")
                    .put("uscita", uscitaAzioni(jail))
                    .put("log", erroriLogPer(jail))
                    .put("sezioni", sezioniCheDefiniscono(jail))
                    .put("dump", configurazioneLetta(jail)));
                continue;
            }
            String eseguibile = primoEseguibile(cmd);
            if (eseguibile == null) {
                // Salto deliberato: la riga non nomina chiaramente un programma. Va DETTO, non
                // taciuto — una jail saltata in silenzio fa diventare verde un controllo che
                // semplicemente non l'ha guardata, che e' il difetto che qui si sta cercando.
                nonGiudicate.put(new JSONObject().put("jail", jail)
                    .put("perche", "il comando non nomina un programma che io possa cercare")
                    .put("comando", cmd));
                continue;
            }
            esaminate++;
            if (esiste(eseguibile)) continue;
            rotte.put(new JSONObject()
                .put("jail", jail).put("comando", cmd).put("eseguibile", eseguibile));
        }
        return r.put("success", true).put("rotte", rotte)
                .put("esaminate", esaminate)
                .put("non_giudicate", nonGiudicate)
                .put("riparabili", rotte.length() > 0);
    }

    /** Scrive l'azione pf dove manca, ricarica, e verifica chiedendo di nuovo a fail2ban. */
    public static JSONObject ripara() {
        JSONObject r = new JSONObject();
        JSONArray passi = new JSONArray();
        List<Path> copie = new ArrayList<>();
        try {
            boolean toccato = false;
            boolean daGuardareAMano = false;

            // 1. mailpanel-pubblico: il file e' del pannello, si riscrive intero.
            Path pub = Paths.get(JAIL_PUBBLICO);
            if (Files.exists(pub)) {
                String prima = Files.readString(pub, StandardCharsets.UTF_8);
                String dopo = org.mail_panel.system.ProtezioneWeb.jail();
                // Riscrivere il file intero e' lecito solo se e' il file che scrive il pannello.
                // Se qualcuno lo ha sostituito con il proprio, sovrascriverlo cancellerebbe il
                // suo lavoro senza avvisare — e questo e' un rimedio, non un ripristino.
                if (!prima.contains("Scritto dal pannello")) {
                    passi.put(passo("mailpanel-pubblico", false,
                        JAIL_PUBBLICO + " non e' il file scritto dal pannello: non lo tocco. "
                        + "Aggiungi a mano  action = pf[name=mailpanel-pubblico, port=\"http,https\"]  "
                        + "nella sezione [mailpanel-pubblico]."));
                    daGuardareAMano = true;
                } else if (!prima.equals(dopo)) {
                    copie.add(copia(pub));
                    Files.writeString(pub, dopo, StandardCharsets.UTF_8);
                    toccato = true;
                    passi.put(passo("mailpanel-pubblico", true,
                        "Riscritto " + JAIL_PUBBLICO + ". Riga scritta: "
                        + rigaAzioneDi(dopo)));
                } else {
                    passi.put(passo("mailpanel-pubblico", true, "Gia' corretto, non toccato"));
                }
            } else {
                passi.put(passo("mailpanel-pubblico", true,
                    "La jail non e' installata su questo sistema: niente da riparare"));
            }

            // 2. mail-panel-auth: sezione dentro jail.local, si cambia solo la riga dell'azione.
            Path loc = Paths.get(JAIL_LOCAL);
            if (Files.exists(loc)) {
                String prima = Files.readString(loc, StandardCharsets.UTF_8);
                Esito e = conAzionePf(prima, "mail-panel-auth");
                switch (e.tipo) {
                    case ASSENTE -> passi.put(passo("mail-panel-auth", true,
                        "La sezione non c'e' in jail.local: niente da riparare"));
                    case GIA_A_POSTO -> passi.put(passo("mail-panel-auth", true,
                        "Gia' corretto, non toccato"));
                    case DA_GUARDARE -> {
                        passi.put(passo("mail-panel-auth", false, e.motivo));
                        daGuardareAMano = true;
                    }
                    case MODIFICATO -> {
                        copie.add(copia(loc));
                        Files.writeString(loc, e.contenuto, StandardCharsets.UTF_8);
                        toccato = true;
                        passi.put(passo("mail-panel-auth", true,
                            "Aggiornata la sola riga dell'azione in " + JAIL_LOCAL
                            + ". Riga scritta: " + rigaAzioneDi(e.contenuto)));
                    }
                }
            } else {
                passi.put(passo("mail-panel-auth", true, "jail.local non esiste: niente da riparare"));
            }

            if (!toccato && !daGuardareAMano) {
                // I file possono essere gia' corretti mentre il processo in esecuzione ha ancora
                // in memoria la configurazione di prima: sono due cose diverse, e fermarsi qui
                // direbbe "non serviva" guardando solo il disco. Se il runtime non riporta
                // l'azione di qualche jail, il lavoro non e' finito — si ricarica e si riguarda.
                java.util.List<String> mute = new ArrayList<>();
                for (String jail : new String[] { "mailpanel-pubblico", "mail-panel-auth" }) {
                    String c = comandoBan(jail);
                    if (c == null || c.isEmpty()) mute.add(jail);
                }
                if (mute.isEmpty())
                    return r.put("success", true).put("passi", passi)
                            .put("message", "Nessuna delle due jail aveva bisogno di essere corretta, "
                                          + "e a runtime entrambe riportano la propria azione.");

                passi.put(passo("configurazione", true,
                    "I file su disco sono gia' corretti, ma a runtime queste jail non riportano la "
                    + "propria azione: " + String.join(", ", mute) + ". Disco e memoria non "
                    + "coincidono, quindi ricarico e riguardo."));
                toccato = true;
            }
            if (!toccato)
                return r.put("success", false).put("passi", passi)
                        .put("message", "Non ho toccato niente: una sezione va guardata a mano, il dettaglio dice quale e perche'.");

            // 3. Ricarica.
            Shell.Result rel = Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
            if (!rel.success()) {
                ripristina(copie);
                Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
                passi.put(passo("reload", false,
                    "fail2ban ha rifiutato la configurazione, quindi ho rimesso i file com'erano e "
                    + "ricaricato. Detto da fail2ban: " + rel.output().trim()));
                return r.put("success", false).put("passi", passi)
                        .put("message", "Riparazione annullata: i file sono tornati come prima.");
            }
            passi.put(passo("reload", true,
                "fail2ban ha accettato la configurazione (fail2ban-client reload)"));

            // Il reload semplice puo' non bastare. fail2ban-client(1): "reload ... reloads the
            // configuration without restarting of the server, the option '--restart' activates
            // completely restarting of affected jails". Se dopo il reload l'azione non risulta,
            // la configurazione e' giusta ma non e' stata applicata: si ricrea la jail. Senza
            // "--unban", che il manuale indica come l'opzione che invece toglierebbe i ban.
            java.util.List<String> ancoraMute = new ArrayList<>();
            for (String jail : new String[] { "mailpanel-pubblico", "mail-panel-auth" }) {
                String c = comandoBan(jail);
                if (c == null || c.isEmpty()) ancoraMute.add(jail);
            }
            if (!ancoraMute.isEmpty()) {
                Shell.Result rs = Shell.run(Duration.ofSeconds(60), CLIENT, "reload", "--restart");
                passi.put(passo("reload --restart", rs.success(),
                    "Dopo il reload " + String.join(", ", ancoraMute) + " non riportava ancora la "
                    + "propria azione: la configurazione era letta ma non applicata, quindi ho "
                    + "ricreato le jail con \"fail2ban-client reload --restart\" (senza --unban, "
                    + "che e' l'opzione che toglierebbe i ban). Uscita: "
                    + (rs.output() == null || rs.output().isBlank() ? "(nessuna)" : rs.output().trim())));
            }

            // 4. La verifica che conta: cosa esegue ADESSO, chiesto a fail2ban.
            JSONArray verifica = new JSONArray();
            boolean tutteOk = true;
            for (String jail : new String[] { "mailpanel-pubblico", "mail-panel-auth" }) {
                String cmd = comandoBan(jail);
                boolean ok = cmd != null && cmd.contains("pfctl");
                if (cmd == null || cmd.isEmpty()) {
                    // Distinguere "non c'e'" da "c'e' e non parla": la prima non e' un guasto,
                    // la seconda si', e confonderle assolverebbe proprio il caso che stiamo
                    // inseguendo. Lo si decide chiedendo se la jail esiste, non presumendolo.
                    Shell.Result st = Shell.run(Duration.ofSeconds(10), CLIENT, "status", jail);
                    boolean esisteJail = st.success() && !st.output().contains("does not exist");
                    if (!esisteJail) {
                        verifica.put(new JSONObject().put("jail", jail).put("ok", true)
                            .put("nota", "non attiva su questo sistema"));
                        continue;
                    }
                    tutteOk = false;
                    verifica.put(new JSONObject().put("jail", jail).put("ok", false)
                        .put("nota", "la jail esiste ma non riporta nessuna azione nemmeno dopo il "
                                   + "reload. Alla richiesta delle azioni fail2ban risponde: "
                                   + uscitaAzioni(jail))
                        .put("log", erroriLogPer(jail))
                        .put("sezioni", sezioniCheDefiniscono(jail))
                        .put("dump", configurazioneLetta(jail)));
                    continue;
                }
                if (!ok) tutteOk = false;
                verifica.put(new JSONObject().put("jail", jail).put("ok", ok)
                    .put("comando", cmd));
            }
            passi.put(passo("verifica", tutteOk,
                tutteOk ? "Ogni jail riparata ora banna con pfctl, chiesto a fail2ban dopo il reload"
                        : "Dopo il reload una jail NON banna ancora con pfctl: la riparazione non ha preso"));

            return r.put("success", tutteOk).put("passi", passi).put("verifica", verifica)
                    .put("message", tutteOk
                        ? "Riparato e verificato. I ban futuri di queste jail passano da pf."
                        : "Ho scritto e ricaricato, ma la verifica non conferma: guarda il dettaglio.");
        } catch (Exception e) {
            try { ripristina(copie); Shell.run(Duration.ofSeconds(30), CLIENT, "reload"); } catch (Exception ignora) { }
            return r.put("success", false).put("passi", passi)
                    .put("message", "Errore, file ripristinati: " + e.getMessage());
        }
    }

    /**
     * Il contenuto di jail.local con l'azione pf al posto di quella che c'era.
     *
     * Si tocca UNA riga, dentro UNA sezione: il resto del file, gli spazi, i commenti e le
     * sezioni altrui restano identici byte per byte. E' un file di configurazione vivo, scritto
     * anche a mano, e un rimedio che ne riordina pezzi non richiesti fa piu' danni del guasto.
     *
     * Il caso che imporrebbe cautela e' l'azione scritta su piu' righe: in un file .conf una
     * riga indentata prosegue quella sopra, quindi sostituire solo la prima lascerebbe attaccata
     * al comando nuovo una coda che appartiene a quello vecchio. Non si prova a indovinare come
     * ricomporla: si dichiara che va guardata a mano, e non si tocca niente. Meglio non riparare
     * che riparare a meta' un file che decide chi entra.
     */
    static Esito conAzionePf(String contenuto, String jail) {
        String[] righe = contenuto.split("\n", -1);
        int inizio = -1;
        for (int i = 0; i < righe.length; i++)
            if (righe[i].trim().equals("[" + jail + "]")) { inizio = i; break; }
        if (inizio < 0) return Esito.assente();

        int fine = righe.length;
        for (int i = inizio + 1; i < righe.length; i++) {
            String t = righe[i].trim();
            if (t.startsWith("[") && t.endsWith("]")) { fine = i; break; }
        }

        // Prima si guarda, poi si scrive: si cerca la riga dell'azione e si giudica se sia
        // toccabile, senza aver ancora modificato niente.
        int rigaAzione = -1;
        for (int i = inizio + 1; i < fine; i++) {
            String t = righe[i].trim();
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) continue;
            String chiave = t.substring(0, t.indexOf('=')).trim().toLowerCase();
            if (chiave.equals("action") || chiave.equals("banaction")) { rigaAzione = i; break; }
        }

        if (rigaAzione >= 0) {
            String t = righe[rigaAzione].trim();
            String valore = t.substring(t.indexOf('=') + 1).trim();
            // "Comincia con pf" non basta per dire che va bene, e nemmeno "non contiene
            // segnaposto". Va riconosciuta la forma INTERA che si sa funzionare qui:
            // pf[name=..., port="..."]. Lo dico dopo averlo sbagliato due volte con lo stesso
            // meccanismo — prima "actiontype=<allports>", poi "actiontype=any" — ed entrambe
            // sarebbero state promosse da un controllo piu' permissivo e lasciate li' per
            // sempre, mentre fail2ban rispondeva "No actions for jail ...", cioe' quella jail
            // non bannava niente. Una porta dichiarata e' la condizione che distingue le
            // quattro jail con tabella E regola da quelle senza.
            boolean pf = valore.equals("pf") || valore.startsWith("pf[") || valore.startsWith("pf ");
            boolean formaBuona = pf && !valore.contains("<")
                              && valore.contains("port=") && valore.contains("name=");
            if (formaBuona) return Esito.giaAPosto();
            int seg = rigaAzione + 1;
            if (seg < fine && !righe[seg].trim().isEmpty()
                && (righe[seg].startsWith(" ") || righe[seg].startsWith("\t")))
                return Esito.daGuardare("l'azione di [" + jail + "] prosegue sulla riga seguente: "
                    + "sostituirne solo la prima lascerebbe attaccata al comando nuovo una coda "
                    + "del vecchio. Va sistemata a mano in " + JAIL_LOCAL + ", riga " + (rigaAzione + 1) + ".");
        }

        // allports, non la porta: l'azione pf costruisce "... to any port $port" e senza porta
        // pf rifiuta la regola, lasciando la tabella senza nessuno che la legga.
        String azione = "action   = pf[name=" + jail + ", port=\"0:65535\"]";
        java.util.List<String> out = new ArrayList<>(java.util.Arrays.asList(righe));
        if (rigaAzione >= 0) {
            out.set(rigaAzione, azione);
        } else {
            // Dopo l'ultima riga di configurazione della sezione, cosi' la si legge dove
            // ci si aspetta di trovarla e non in fondo a righe vuote.
            int dopo = inizio;
            for (int i = inizio + 1; i < fine; i++) {
                String t = righe[i].trim();
                if (!t.isEmpty() && !t.startsWith("#")) dopo = i;
            }
            out.add(dopo + 1, azione);
        }
        return Esito.modificato(String.join("\n", out));
    }

    /** Cosa e' successo alla sezione, senza doverne rileggere il testo per capirlo. */
    static final class Esito {
        enum Tipo { ASSENTE, GIA_A_POSTO, MODIFICATO, DA_GUARDARE }
        final Tipo tipo;
        final String contenuto;
        final String motivo;
        private Esito(Tipo t, String c, String m) { tipo = t; contenuto = c; motivo = m; }
        static Esito assente()            { return new Esito(Tipo.ASSENTE, null, null); }
        static Esito giaAPosto()          { return new Esito(Tipo.GIA_A_POSTO, null, null); }
        static Esito modificato(String c) { return new Esito(Tipo.MODIFICATO, c, null); }
        static Esito daGuardare(String m) { return new Esito(Tipo.DA_GUARDARE, null, m); }
    }

    /**
     * Il primo comando eseguibile nominato da un comando di ban, o null se non si puo' dire.
     *
     * Null non e' un fallimento ma una risposta: su questo si costruisce l'accusa "questa jail
     * banna con un comando che non esiste", e un'accusa sbagliata farebbe premere un pulsante
     * di riparazione a chi non ne ha bisogno. Quindi si giudica solo cio' che e' chiaramente il
     * nome di un programma: se la riga comincia con un costrutto di shell, una variabile o una
     * parola con metacaratteri, non si conclude niente.
     */
    static String primoEseguibile(String comando) {
        if (comando == null) return null;
        for (String riga : comando.split("\n")) {
            String t = riga.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String primo = t.split("\\s+")[0];
            // fail2ban lascia i segnaposto fra parentesi angolari: <iptables> nomina comunque
            // il comando, e va giudicato per quello che nomina.
            primo = primo.replace("<", "").replace(">", "");
            if (primo.isEmpty()) continue;
            if (COSTRUTTI_SHELL.contains(primo)) return null;
            if (!primo.matches("[A-Za-z0-9._/+-]+")) return null;
            return primo;
        }
        return null;
    }

    /** Parole che aprono un costrutto di shell: non sono programmi da cercare su disco. */
    private static final java.util.Set<String> COSTRUTTI_SHELL = java.util.Set.of(
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
        "case", "esac", "test", "[", "[[", "echo", "true", "false", ":", "exec",
        "eval", "export", "set", "unset", "local", "return", "exit", "printf", "cd");

    private static boolean esiste(String eseguibile) {
        if (eseguibile.startsWith("/")) return Files.isExecutable(Paths.get(eseguibile));
        for (String dir : new String[] { "/sbin", "/bin", "/usr/sbin", "/usr/bin",
                                         "/usr/local/sbin", "/usr/local/bin" })
            if (Files.isExecutable(Paths.get(dir, eseguibile))) return true;
        return false;
    }

    private static List<String> jailAttive() {
        List<String> out = new ArrayList<>();
        Shell.Result r = Shell.run(Duration.ofSeconds(10), CLIENT, "status");
        if (!r.success()) return out;
        java.util.regex.Matcher m =
            java.util.regex.Pattern.compile("Jail list:\\s*(.+)").matcher(r.output());
        if (m.find())
            for (String n : m.group(1).split(","))
                if (!n.trim().isEmpty()) out.add(n.trim());
        return out;
    }

    /** La riga dell'azione dentro un testo di configurazione: si mostra cio' che si e' scritto. */
    private static String rigaAzioneDi(String contenuto) {
        for (String r : contenuto.split("\n")) {
            String t = r.trim();
            if (t.startsWith("action") && t.contains("=")) return t;
        }
        return "(nessuna riga action trovata)";
    }

    /**
     * Le righe di /var/log/fail2ban.log che parlano di questa jail e di errori.
     *
     * Quando fail2ban dice "No actions for jail X" non spiega perche' li', ma lo ha gia' scritto
     * nel proprio log al momento del caricamento. Mostrarlo e' l'unico modo perche' chi guarda
     * la pagina — e chi legge il suo racconto — possa sapere la causa invece di ipotizzarla.
     */
    static String erroriLogPer(String jail) {
        try {
            Path log = Paths.get("/var/log/fail2ban.log");
            if (!Files.exists(log)) return "(/var/log/fail2ban.log non esiste)";
            java.util.List<String> tutte = Files.readAllLines(log, StandardCharsets.UTF_8);
            StringBuilder out = new StringBuilder();

            // 1. Le ultime righe che nominano questa jail, di qualunque livello. Il livello non
            //    si filtra: la riga piu' informativa finora e' stata una WARNING di routine
            //    ("already banned") che, venendo dal modulo delle azioni, ha dimostrato che la
            //    jail le azioni ce le ha — l'opposto di quello che sospettavo.
            java.util.List<String> sue = new ArrayList<>();
            for (int i = tutte.size() - 1; i >= 0 && sue.size() < 8; i--)
                if (tutte.get(i).contains(jail)) sue.add(0, tutte.get(i));
            out.append("— Ultime righe che nominano ").append(jail).append(":\n")
               .append(sue.isEmpty() ? "(nessuna)" : String.join("\n", sue));

            // 2. TUTTA la finestra dell'ultimo reload, senza filtri di nessun tipo.
            //
            // Le due versioni precedenti di questo riquadro hanno nascosto la risposta, ognuna a
            // modo suo: la prima filtrava per nome della jail, e un errore di caricamento il nome
            // spesso non ce l'ha; la seconda partiva dall'ultima riga contenente "reload", che e'
            // "Reload finished", mostrando solo cio' che viene DOPO — mentre la spiegazione sta
            // dentro il reload. Due filtri, due volte la stessa risposta buttata via.
            //
            // Quindi qui non si filtra: si prende la finestra e la si mostra intera. Un riquadro
            // che mostra troppo si legge; uno che mostra la cosa sbagliata fa perdere giornate.
            int fine = -1;
            for (int i = tutte.size() - 1; i >= 0; i--)
                if (tutte.get(i).contains("Reload finished")) { fine = i; break; }
            if (fine < 0)
                for (int i = tutte.size() - 1; i >= 0; i--)
                    if (tutte.get(i).contains("Reload jail")) { fine = i; break; }

            out.append("\n\n— L'ultimo reload per intero, senza filtri");
            if (fine < 0) {
                out.append(": nessun reload trovato nel log");
            } else {
                int inizio = Math.max(0, fine - 80);
                // Si risale fino all'inizio vero del reload, se lo si trova nella finestra.
                for (int i = fine; i >= inizio; i--)
                    if (tutte.get(i).contains("Reload jail") || tutte.get(i).contains("Stopping all jails")
                        || tutte.get(i).contains("Reloading")) { inizio = i; break; }
                int ultimo = Math.min(tutte.size() - 1, fine + 20);
                out.append(" (righe ").append(inizio + 1).append("-").append(ultimo + 1).append("):\n");
                for (int i = inizio; i <= ultimo; i++) out.append(tutte.get(i)).append("\n");
            }
            return out.toString();
        } catch (Exception e) {
            return "(non sono riuscito a leggere fail2ban.log: " + e.getMessage() + ")";
        }
    }

    /**
     * Ogni file di configurazione che definisce questa jail, con la sezione per intero.
     *
     * Serve a rispondere a "cosa vede fail2ban", che non e' la stessa domanda di "cosa ho
     * scritto". Fail2ban legge jail.conf, poi jail.local, poi tutto jail.d in ordine, e l'ultima
     * definizione vince: una seconda sezione con lo stesso nome, in un file che nessuno guarda,
     * spiegherebbe da sola perche' l'azione appena scritta non ha nessun effetto. Finche' non si
     * guarda, resta un'ipotesi fra le tante.
     */
    static String sezioniCheDefiniscono(String jail) {
        StringBuilder out = new StringBuilder();
        try {
            java.util.List<Path> file = new ArrayList<>();
            file.add(Paths.get("/usr/local/etc/fail2ban/jail.conf"));
            file.add(Paths.get(JAIL_LOCAL));
            Path d = Paths.get("/usr/local/etc/fail2ban/jail.d");
            if (Files.isDirectory(d))
                try (var s2 = Files.list(d)) { s2.sorted().forEach(file::add); }

            for (Path f : file) {
                if (!Files.isRegularFile(f)) continue;
                java.util.List<String> righe = Files.readAllLines(f, StandardCharsets.UTF_8);
                for (int i = 0; i < righe.size(); i++) {
                    if (!righe.get(i).trim().equals("[" + jail + "]")) continue;
                    out.append(out.length() > 0 ? "\n\n" : "")
                       .append(f).append(" (riga ").append(i + 1).append("):\n");
                    for (int j = i; j < righe.size(); j++) {
                        String t = righe.get(j).trim();
                        if (j > i && t.startsWith("[") && t.endsWith("]")) break;
                        out.append("  ").append(righe.get(j)).append("\n");
                    }
                }
            }
        } catch (Exception e) {
            return "(non sono riuscito a leggere i file di configurazione: " + e.getMessage() + ")";
        }
        return out.length() == 0
            ? "(nessun file sotto /usr/local/etc/fail2ban definisce [" + jail + "])"
            : out.toString();
    }

    /**
     * Cosa fail2ban ha INTERPRETATO dai file per questa jail.
     *
     * fail2ban-client(1): "-d  dump configuration. For debugging". E' l'unica fonte che risponde
     * a "cosa legge fail2ban", che non e' ne' "cosa ho scritto io" ne' "cosa e' caricato adesso":
     * sono tre cose diverse, e per mezza giornata ho confuso la prima con la terza. Se qui
     * compare "addaction" la configurazione e' letta bene e il problema e' nell'applicarla; se
     * non compare, il problema e' nel file.
     *
     * Legge e basta.
     */
    static String configurazioneLetta(String jail) {
        Shell.Result r = Shell.run(Duration.ofSeconds(20), CLIENT, "--dp");
        if (!r.success() || r.output() == null || r.output().isBlank())
            r = Shell.run(Duration.ofSeconds(20), CLIENT, "-d");
        if (!r.success() || r.output() == null || r.output().isBlank())
            return "(fail2ban-client non ha prodotto un dump della configurazione)";
        java.util.List<String> sue = new ArrayList<>();
        for (String riga : r.output().split("\n"))
            if (riga.contains("'" + jail + "'") || riga.contains("\"" + jail + "\"")) sue.add(riga);
        return sue.isEmpty()
            ? "(il dump non contiene nessuna riga per " + jail + ")"
            : String.join("\n", sue);
    }

    /** Cosa risponde fail2ban quando gli si chiedono le azioni di una jail, testuale. */
    private static String uscitaAzioni(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        String u = a.output() == null ? "" : a.output().trim();
        return u.isEmpty() ? "(nessuna risposta)" : u;
    }

    private static String comandoBan(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        if (!a.success()) return null;
        String coda = a.output().contains(":")
            ? a.output().substring(a.output().lastIndexOf(':') + 1) : a.output();
        for (String az : coda.split(",")) {
            String nome = az.trim();
            if (nome.isEmpty() || !nome.matches("[A-Za-z0-9._-]+")) continue;
            Shell.Result c = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "action", nome, "actionban");
            if (c.success() && !c.output().trim().isEmpty()) return c.output().trim();
        }
        return null;
    }

    private static final String CARTELLA_COPIE = "/var/db/mail-panel/copie-fail2ban";

    /**
     * La copia di sicurezza va FUORI da jail.d.
     *
     * Fail2ban carica i file di quella cartella, e una copia lasciata li' dentro e' un secondo
     * file che definisce la stessa jail a un passo dall'essere letto: basta un nome che finisca
     * per .conf. Le prime copie di oggi sono finite proprio li', e nella diagnosi comparivano
     * accanto al file vero come se fossero configurazioni attive — ambiguita' che in un file che
     * decide chi entra non ci deve essere.
     */
    private static Path copia(Path f) throws Exception {
        Path dir = Paths.get(CARTELLA_COPIE);
        Files.createDirectories(dir);
        Path c = dir.resolve(f.getFileName().toString() + ".prima-di-pf-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
        Files.copy(f, c);
        copie.put(c, f);
        return c;
    }

    /** Dove ripristinare ciascuna copia: il nome del file non basta piu' a dirlo. */
    private static final java.util.Map<Path, Path> copie = new java.util.concurrent.ConcurrentHashMap<>();

    private static void ripristina(List<Path> fatte) {
        for (Path c : fatte) {
            try {
                Path orig = RiparaAzioneBan.copie.get(c);
                if (orig != null) Files.copy(c, orig, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception ignora) { }
        }
    }

    private static JSONObject passo(String nome, boolean ok, String testo) {
        return new JSONObject().put("passo", nome).put("ok", ok).put("testo", testo);
    }
}
