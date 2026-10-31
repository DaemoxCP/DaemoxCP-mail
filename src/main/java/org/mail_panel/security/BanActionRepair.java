package org.mail_panel.security;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
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
 * ("action = pf[name=...]") e due no: la superficie pubblica (oggi mailpanel-public, allora
 * mailpanel-pubblico) e mail-panel-auth, cioe' proprio le
 * due che proteggono il pannello. Non dichiarandola ereditavano il valore predefinito di
 * jail.conf, che e' costruito su iptables — un comando che su FreeBSD non esiste. Il risultato
 * non era un errore visibile: le jail rilevavano, contavano i tentativi e incrementavano i ban
 * regolarmente. Sulla superficie pubblica erano 14.370 tentativi e 46 ban, nessuno dei quali ha mai
 * bloccato niente. Una jail che sbaglia comando di ban e' indistinguibile da una che funziona,
 * finche' non si guarda il firewall.
 *
 * Perche' non basta correggere il codice. Il file della superficie pubblica lo riscrive il pannello
 * a ogni installazione, quindi li' la fix arriva da sola. La sezione [mail-panel-auth] no:
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
public final class BanActionRepair {

    private static final String JAIL_LOCAL = "/usr/local/etc/fail2ban/jail.local";
    private static final String PUBLIC_JAIL = org.mail_panel.system.WebProtection.JAIL;
    private static final String PUBLIC_NAME = org.mail_panel.system.WebProtection.NAME;
    private static final String CLIENT = "/usr/local/bin/fail2ban-client";

    private BanActionRepair() { }

    /** Le jail il cui comando di ban non e' eseguibile su questo sistema. Legge e basta. */
    public static JSONObject diagnosis() {
        JSONObject r = new JSONObject();
        JSONArray broken = new JSONArray();
        JSONArray notJudged = new JSONArray();
        int reviewed = 0;
        for (String jail : activeJails()) {
            String cmd = banCommand(jail);
            if (cmd == null || cmd.isEmpty()) {
                // Senza l'uscita cruda questa riga e' un vicolo cieco: dice che non si sa, e non
                // lascia a chi legge nessun modo di sapere. Con l'uscita, il passo successivo lo
                // puo' fare chiunque guardi la pagina.
                notJudged.put(new JSONObject().put("jail", jail)
                    .put("why", I18n.tr("server.banfix.noCommand"))
                    .put("output", actionsOutput(jail))
                    .put("log", logErrorsFor(jail))
                    .put("sections", sectionsDefining(jail))
                    .put("dump", readConfiguration(jail)));
                continue;
            }
            String runnable = firstRunnable(cmd);
            if (runnable == null) {
                // Salto deliberato: la riga non nomina chiaramente un programma. Va DETTO, non
                // taciuto — una jail saltata in silenzio fa diventare verde un controllo che
                // semplicemente non l'ha guardata, che e' il difetto che qui si sta cercando.
                notJudged.put(new JSONObject().put("jail", jail)
                    .put("why", I18n.tr("server.banfix.noProgram"))
                    .put("command", cmd));
                continue;
            }
            reviewed++;
            if (exists(runnable)) continue;
            broken.put(new JSONObject()
                .put("jail", jail).put("command", cmd).put("runnable", runnable));
        }
        return r.put("success", true).put("broken", broken)
                .put("reviewed", reviewed)
                .put("not_judged", notJudged)
                .put("repairable", broken.length() > 0);
    }

    /** Scrive l'azione pf dove manca, ricarica, e verifica chiedendo di nuovo a fail2ban. */
    public static JSONObject repair() {
        JSONObject r = new JSONObject();
        JSONArray steps = new JSONArray();
        List<Path> copies = new ArrayList<>();
        try {
            boolean touched = false;
            boolean toReviewByHand = false;

            // 1. La superficie pubblica: il file e' del pannello, si riscrive intero.
            Path pub = Paths.get(PUBLIC_JAIL);
            if (Files.exists(pub)) {
                String before = Files.readString(pub, StandardCharsets.UTF_8);
                String after = org.mail_panel.system.WebProtection.jail();
                // Riscrivere il file intero e' lecito solo se e' il file che scrive il pannello.
                // Se qualcuno lo ha sostituito con il proprio, sovrascriverlo cancellerebbe il
                // suo lavoro senza avvisare — e questo e' un rimedio, non un ripristino.
                if (!org.mail_panel.system.PanelMarker.writtenByPanel(before)) {
                    steps.put(step(PUBLIC_NAME, false,
                        I18n.tr("server.banfix.notOurFile", java.util.Map.of("file", String.valueOf(PUBLIC_JAIL), "jail", PUBLIC_NAME))));
                    toReviewByHand = true;
                } else if (!before.equals(after)) {
                    copies.add(copy(pub));
                    Files.writeString(pub, after, StandardCharsets.UTF_8);
                    touched = true;
                    steps.put(step(PUBLIC_NAME, true,
                        I18n.tr("server.banfix.rewritten", java.util.Map.of("file", String.valueOf(PUBLIC_JAIL), "line", String.valueOf(actionLineOf(after))))));
                } else {
                    steps.put(step(PUBLIC_NAME, true, I18n.tr("server.banfix.alreadyOk")));
                }
            } else {
                steps.put(step(PUBLIC_NAME, true,
                    I18n.tr("server.banfix.notInstalled")));
            }

            // 2. mail-panel-auth: sezione dentro jail.local, si cambia solo la riga dell'azione.
            Path loc = Paths.get(JAIL_LOCAL);
            if (Files.exists(loc)) {
                String before = Files.readString(loc, StandardCharsets.UTF_8);
                Outcome e = withPfAction(before, "mail-panel-auth");
                switch (e.type) {
                    case ABSENT -> steps.put(step("mail-panel-auth", true,
                        I18n.tr("server.banfix.noSection")));
                    case ALREADY_IN_PLACE -> steps.put(step("mail-panel-auth", true,
                        I18n.tr("server.banfix.alreadyOk")));
                    case TO_REVIEW -> {
                        steps.put(step("mail-panel-auth", false, e.reason));
                        toReviewByHand = true;
                    }
                    case MODIFIED -> {
                        copies.add(copy(loc));
                        Files.writeString(loc, e.content, StandardCharsets.UTF_8);
                        touched = true;
                        steps.put(step("mail-panel-auth", true,
                            I18n.tr("server.banfix.lineUpdated", java.util.Map.of("file", String.valueOf(JAIL_LOCAL), "line", String.valueOf(actionLineOf(e.content))))));
                    }
                }
            } else {
                steps.put(step("mail-panel-auth", true, I18n.tr("server.banfix.noJailLocal")));
            }

            if (!touched && !toReviewByHand) {
                // I file possono essere gia' corretti mentre il processo in esecuzione ha ancora
                // in memoria la configurazione di prima: sono due cose diverse, e fermarsi qui
                // direbbe "non serviva" guardando solo il disco. Se il runtime non riporta
                // l'azione di qualche jail, il lavoro non e' finito — si ricarica e si riguarda.
                java.util.List<String> mute = new ArrayList<>();
                for (String jail : new String[] { PUBLIC_NAME, "mail-panel-auth" }) {
                    String c = banCommand(jail);
                    if (c == null || c.isEmpty()) mute.add(jail);
                }
                if (mute.isEmpty())
                    return r.put("success", true).put("steps", steps)
                            .put("message", I18n.tr("server.banfix.nothingNeeded"));

                steps.put(step("configuration", true,
                    I18n.tr("server.banfix.diskVsRuntime", java.util.Map.of("list", String.valueOf(String.join(", ", mute))))));
                touched = true;
            }
            if (!touched)
                return r.put("success", false).put("steps", steps)
                        .put("message", I18n.tr("server.banfix.untouched"));

            // 3. Ricarica.
            Shell.Result rel = Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
            if (!rel.success()) {
                restore(copies);
                Shell.run(Duration.ofSeconds(30), CLIENT, "reload");
                steps.put(step("reload", false,
                    I18n.tr("server.banfix.rejected", java.util.Map.of("out", String.valueOf(rel.output().trim())))));
                return r.put("success", false).put("steps", steps)
                        .put("message", I18n.tr("server.banfix.cancelled"));
            }
            steps.put(step("reload", true,
                I18n.tr("server.banfix.accepted")));

            // Il reload semplice puo' non bastare. fail2ban-client(1): "reload ... reloads the
            // configuration without restarting of the server, the option '--restart' activates
            // completely restarting of affected jails". Se dopo il reload l'azione non risulta,
            // la configurazione e' giusta ma non e' stata applicata: si ricrea la jail. Senza
            // "--unban", che il manuale indica come l'opzione che invece toglierebbe i ban.
            java.util.List<String> stillMute = new ArrayList<>();
            for (String jail : new String[] { PUBLIC_NAME, "mail-panel-auth" }) {
                String c = banCommand(jail);
                if (c == null || c.isEmpty()) stillMute.add(jail);
            }
            if (!stillMute.isEmpty()) {
                Shell.Result rs = Shell.run(Duration.ofSeconds(60), CLIENT, "reload", "--restart");
                steps.put(step("reload --restart", rs.success(),
                    I18n.tr("server.banfix.restarted", java.util.Map.of("list", String.valueOf(String.join(", ", stillMute)), "out", String.valueOf(rs.output() == null || rs.output().isBlank() ? I18n.tr("server.banfix.none") : rs.output().trim())))));
            }

            // 4. La verifica che conta: cosa esegue ADESSO, chiesto a fail2ban.
            JSONArray verification = new JSONArray();
            boolean allOk = true;
            for (String jail : new String[] { PUBLIC_NAME, "mail-panel-auth" }) {
                String cmd = banCommand(jail);
                boolean ok = cmd != null && cmd.contains("pfctl");
                if (cmd == null || cmd.isEmpty()) {
                    // Distinguere "non c'e'" da "c'e' e non parla": la prima non e' un guasto,
                    // la seconda si', e confonderle assolverebbe proprio il caso che stiamo
                    // inseguendo. Lo si decide chiedendo se la jail esiste, non presumendolo.
                    Shell.Result st = Shell.run(Duration.ofSeconds(10), CLIENT, "status", jail);
                    boolean jailExists = st.success() && !st.output().contains("does not exist");
                    if (!jailExists) {
                        verification.put(new JSONObject().put("jail", jail).put("ok", true)
                            .put("note", I18n.tr("server.banfix.notActive")));
                        continue;
                    }
                    allOk = false;
                    verification.put(new JSONObject().put("jail", jail).put("ok", false)
                        .put("note", I18n.tr("server.banfix.noActionAfter", java.util.Map.of("out", String.valueOf(actionsOutput(jail)))))
                        .put("log", logErrorsFor(jail))
                        .put("sections", sectionsDefining(jail))
                        .put("dump", readConfiguration(jail)));
                    continue;
                }
                if (!ok) allOk = false;
                verification.put(new JSONObject().put("jail", jail).put("ok", ok)
                    .put("command", cmd));
            }
            steps.put(step("review", allOk,
                allOk ? I18n.tr("server.banfix.allBan")
                        : I18n.tr("server.banfix.stillNotBan")));

            return r.put("success", allOk).put("steps", steps).put("verification", verification)
                    .put("message", allOk
                        ? I18n.tr("server.banfix.verified")
                        : I18n.tr("server.banfix.notConfirmed"));
        } catch (Exception e) {
            try { restore(copies); Shell.run(Duration.ofSeconds(30), CLIENT, "reload"); } catch (Exception ignore) { }
            return r.put("success", false).put("steps", steps)
                    .put("message", I18n.tr("server.banfix.errorRestored", java.util.Map.of("err", String.valueOf(e.getMessage()))));
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
    static Outcome withPfAction(String content, String jail) {
        String[] lines = content.split("\n", -1);
        int start = -1;
        for (int i = 0; i < lines.length; i++)
            if (lines[i].trim().equals("[" + jail + "]")) { start = i; break; }
        if (start < 0) return Outcome.absent();

        int end = lines.length;
        for (int i = start + 1; i < lines.length; i++) {
            String t = lines[i].trim();
            if (t.startsWith("[") && t.endsWith("]")) { end = i; break; }
        }

        // Prima si guarda, poi si scrive: si cerca la riga dell'azione e si giudica se sia
        // toccabile, senza aver ancora modificato niente.
        int actionLine = -1;
        for (int i = start + 1; i < end; i++) {
            String t = lines[i].trim();
            if (t.isEmpty() || t.startsWith("#") || !t.contains("=")) continue;
            String key = t.substring(0, t.indexOf('=')).trim().toLowerCase();
            if (key.equals("action") || key.equals("banaction")) { actionLine = i; break; }
        }

        if (actionLine >= 0) {
            String t = lines[actionLine].trim();
            String value = t.substring(t.indexOf('=') + 1).trim();
            // "Comincia con pf" non basta per dire che va bene, e nemmeno "non contiene
            // segnaposto". Va riconosciuta la forma INTERA che si sa funzionare qui:
            // pf[name=..., port="..."]. Lo dico dopo averlo sbagliato due volte con lo stesso
            // meccanismo — prima "actiontype=<allports>", poi "actiontype=any" — ed entrambe
            // sarebbero state promosse da un controllo piu' permissivo e lasciate li' per
            // sempre, mentre fail2ban rispondeva "No actions for jail ...", cioe' quella jail
            // non bannava niente. Una porta dichiarata e' la condizione che distingue le
            // quattro jail con tabella E regola da quelle senza.
            boolean pf = value.equals("pf") || value.startsWith("pf[") || value.startsWith("pf ");
            boolean goodForm = pf && !value.contains("<")
                              && value.contains("port=") && value.contains("name=");
            if (goodForm) return Outcome.alreadyInPlace();
            int seg = actionLine + 1;
            if (seg < end && !lines[seg].trim().isEmpty()
                && (lines[seg].startsWith(" ") || lines[seg].startsWith("\t")))
                return Outcome.toReview(I18n.tr("server.banfix.multiline", java.util.Map.of("jail", String.valueOf(jail), "file", String.valueOf(JAIL_LOCAL), "line", String.valueOf(actionLine + 1))));
        }

        // allports, non la porta: l'azione pf costruisce "... to any port $port" e senza porta
        // pf rifiuta la regola, lasciando la tabella senza nessuno che la legga.
        String action = "action   = pf[name=" + jail + ", port=\"0:65535\"]";
        java.util.List<String> out = new ArrayList<>(java.util.Arrays.asList(lines));
        if (actionLine >= 0) {
            out.set(actionLine, action);
        } else {
            // Dopo l'ultima riga di configurazione della sezione, cosi' la si legge dove
            // ci si aspetta di trovarla e non in fondo a righe vuote.
            int after = start;
            for (int i = start + 1; i < end; i++) {
                String t = lines[i].trim();
                if (!t.isEmpty() && !t.startsWith("#")) after = i;
            }
            out.add(after + 1, action);
        }
        return Outcome.modified(String.join("\n", out));
    }

    /** Cosa e' successo alla sezione, senza doverne rileggere il testo per capirlo. */
    static final class Outcome {
        enum Kind { ABSENT, ALREADY_IN_PLACE, MODIFIED, TO_REVIEW }
        final Kind type;
        final String content;
        final String reason;
        private Outcome(Kind t, String c, String m) { type = t; content = c; reason = m; }
        static Outcome absent()            { return new Outcome(Kind.ABSENT, null, null); }
        static Outcome alreadyInPlace()          { return new Outcome(Kind.ALREADY_IN_PLACE, null, null); }
        static Outcome modified(String c) { return new Outcome(Kind.MODIFIED, c, null); }
        static Outcome toReview(String m) { return new Outcome(Kind.TO_REVIEW, null, m); }
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
    static String firstRunnable(String command) {
        if (command == null) return null;
        for (String line : command.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String first = t.split("\\s+")[0];
            // fail2ban lascia i segnaposto fra parentesi angolari: <iptables> nomina comunque
            // il comando, e va giudicato per quello che nomina.
            first = first.replace("<", "").replace(">", "");
            if (first.isEmpty()) continue;
            if (SHELL_CONSTRUCTS.contains(first)) return null;
            if (!first.matches("[A-Za-z0-9._/+-]+")) return null;
            return first;
        }
        return null;
    }

    /** Parole che aprono un costrutto di shell: non sono programmi da cercare su disco. */
    private static final java.util.Set<String> SHELL_CONSTRUCTS = java.util.Set.of(
        "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
        "case", "esac", "test", "[", "[[", "echo", "true", "false", ":", "exec",
        "eval", "export", "set", "unset", "local", "return", "exit", "printf", "cd");

    private static boolean exists(String runnable) {
        if (runnable.startsWith("/")) return Files.isExecutable(Paths.get(runnable));
        for (String dir : new String[] { "/sbin", "/bin", "/usr/sbin", "/usr/bin",
                                         "/usr/local/sbin", "/usr/local/bin" })
            if (Files.isExecutable(Paths.get(dir, runnable))) return true;
        return false;
    }

    private static List<String> activeJails() {
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
    private static String actionLineOf(String content) {
        for (String r : content.split("\n")) {
            String t = r.trim();
            if (t.startsWith("action") && t.contains("=")) return t;
        }
        return I18n.tr("server.banfix.noActionLine");
    }

    /**
     * Le righe di /var/log/fail2ban.log che parlano di questa jail e di errori.
     *
     * Quando fail2ban dice "No actions for jail X" non spiega perche' li', ma lo ha gia' scritto
     * nel proprio log al momento del caricamento. Mostrarlo e' l'unico modo perche' chi guarda
     * la pagina — e chi legge il suo racconto — possa sapere la causa invece di ipotizzarla.
     */
    static String logErrorsFor(String jail) {
        try {
            Path log = Paths.get("/var/log/fail2ban.log");
            if (!Files.exists(log)) return I18n.tr("server.banfix.noLog");
            java.util.List<String> all = Files.readAllLines(log, StandardCharsets.UTF_8);
            StringBuilder out = new StringBuilder();

            // 1. Le ultime righe che nominano questa jail, di qualunque livello. Il livello non
            //    si filtra: la riga piu' informativa finora e' stata una WARNING di routine
            //    ("already banned") che, venendo dal modulo delle azioni, ha dimostrato che la
            //    jail le azioni ce le ha — l'opposto di quello che sospettavo.
            java.util.List<String> theirs = new ArrayList<>();
            for (int i = all.size() - 1; i >= 0 && theirs.size() < 8; i--)
                if (all.get(i).contains(jail)) theirs.add(0, all.get(i));
            out.append("— ").append(I18n.tr("server.banfix.lastLines", java.util.Map.of("jail", String.valueOf(jail)))).append(":\n")
               .append(theirs.isEmpty() ? I18n.tr("server.banfix.none") : String.join("\n", theirs));

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
            int end = -1;
            for (int i = all.size() - 1; i >= 0; i--)
                if (all.get(i).contains("Reload finished")) { end = i; break; }
            if (end < 0)
                for (int i = all.size() - 1; i >= 0; i--)
                    if (all.get(i).contains("Reload jail")) { end = i; break; }

            out.append("\n\n— ").append(I18n.tr("server.banfix.lastReload"));
            if (end < 0) {
                out.append(": ").append(I18n.tr("server.banfix.noReload"));
            } else {
                int start = Math.max(0, end - 80);
                // Si risale fino all'inizio vero del reload, se lo si trova nella finestra.
                for (int i = end; i >= start; i--)
                    if (all.get(i).contains("Reload jail") || all.get(i).contains("Stopping all jails")
                        || all.get(i).contains("Reloading")) { start = i; break; }
                int last = Math.min(all.size() - 1, end + 20);
                out.append(" (").append(I18n.tr("server.banfix.linesRange", java.util.Map.of("a", String.valueOf(start + 1), "b", String.valueOf(last + 1)))).append("):\n");
                for (int i = start; i <= last; i++) out.append(all.get(i)).append("\n");
            }
            return out.toString();
        } catch (Exception e) {
            return "(" + I18n.tr("server.banfix.logUnreadable", java.util.Map.of("err", String.valueOf(e.getMessage()))) + ")";
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
    static String sectionsDefining(String jail) {
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
                java.util.List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
                for (int i = 0; i < lines.size(); i++) {
                    if (!lines.get(i).trim().equals("[" + jail + "]")) continue;
                    out.append(out.length() > 0 ? "\n\n" : "")
                       .append(f).append(" (").append(I18n.tr("server.banfix.lineN", java.util.Map.of("n", String.valueOf(i + 1)))).append("):\n");
                    for (int j = i; j < lines.size(); j++) {
                        String t = lines.get(j).trim();
                        if (j > i && t.startsWith("[") && t.endsWith("]")) break;
                        out.append("  ").append(lines.get(j)).append("\n");
                    }
                }
            }
        } catch (Exception e) {
            return "(" + I18n.tr("server.banfix.confUnreadable", java.util.Map.of("err", String.valueOf(e.getMessage()))) + ")";
        }
        return out.length() == 0
            ? "(" + I18n.tr("server.banfix.noFileDefines", java.util.Map.of("jail", String.valueOf(jail))) + ")"
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
    static String readConfiguration(String jail) {
        Shell.Result r = Shell.run(Duration.ofSeconds(20), CLIENT, "--dp");
        if (!r.success() || r.output() == null || r.output().isBlank())
            r = Shell.run(Duration.ofSeconds(20), CLIENT, "-d");
        if (!r.success() || r.output() == null || r.output().isBlank())
            return I18n.tr("server.banfix.noDump");
        java.util.List<String> theirs = new ArrayList<>();
        for (String line : r.output().split("\n"))
            if (line.contains("'" + jail + "'") || line.contains("\"" + jail + "\"")) theirs.add(line);
        return theirs.isEmpty()
            ? "(" + I18n.tr("server.banfix.dumpNoLine", java.util.Map.of("jail", String.valueOf(jail))) + ")"
            : String.join("\n", theirs);
    }

    /** Cosa risponde fail2ban quando gli si chiedono le azioni di una jail, testuale. */
    private static String actionsOutput(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        String u = a.output() == null ? "" : a.output().trim();
        return u.isEmpty() ? I18n.tr("server.banfix.noAnswer") : u;
    }

    private static String banCommand(String jail) {
        Shell.Result a = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "actions");
        if (!a.success()) return null;
        String queue = a.output().contains(":")
            ? a.output().substring(a.output().lastIndexOf(':') + 1) : a.output();
        for (String az : queue.split(",")) {
            String name = az.trim();
            if (name.isEmpty() || !name.matches("[A-Za-z0-9._-]+")) continue;
            Shell.Result c = Shell.run(Duration.ofSeconds(10), CLIENT, "get", jail, "action", name, "actionban");
            if (c.success() && !c.output().trim().isEmpty()) return c.output().trim();
        }
        return null;
    }

    private static final String BACKUP_FOLDER = "/var/db/mail-panel/fail2ban-backups";

    /**
     * La copia di sicurezza va FUORI da jail.d.
     *
     * Fail2ban carica i file di quella cartella, e una copia lasciata li' dentro e' un secondo
     * file che definisce la stessa jail a un passo dall'essere letto: basta un nome che finisca
     * per .conf. Le prime copie di oggi sono finite proprio li', e nella diagnosi comparivano
     * accanto al file vero come se fossero configurazioni attive — ambiguita' che in un file che
     * decide chi entra non ci deve essere.
     */
    private static Path copy(Path f) throws Exception {
        Path dir = Paths.get(BACKUP_FOLDER);
        Files.createDirectories(dir);
        Path c = dir.resolve(f.getFileName().toString() + ".before-pf-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
        Files.copy(f, c);
        copies.put(c, f);
        return c;
    }

    /** Dove ripristinare ciascuna copia: il nome del file non basta piu' a dirlo. */
    private static final java.util.Map<Path, Path> copies = new java.util.concurrent.ConcurrentHashMap<>();

    private static void restore(List<Path> done) {
        for (Path c : done) {
            try {
                Path orig = BanActionRepair.copies.get(c);
                if (orig != null) Files.copy(c, orig, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception ignore) { }
        }
    }

    private static JSONObject step(String name, boolean ok, String text) {
        return new JSONObject().put("step", name).put("ok", ok).put("text", text);
    }
}
