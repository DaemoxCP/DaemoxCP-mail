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
        for (String jail : jailAttive()) {
            String cmd = comandoBan(jail);
            if (cmd == null || cmd.isEmpty()) continue;
            String eseguibile = primoEseguibile(cmd);
            if (eseguibile == null) continue;
            if (esiste(eseguibile)) continue;
            rotte.put(new JSONObject()
                .put("jail", jail).put("comando", cmd).put("eseguibile", eseguibile));
        }
        return r.put("success", true).put("rotte", rotte)
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
                        + "Aggiungi a mano  action = pf[name=mailpanel-pubblico, actiontype=<allports>]  "
                        + "nella sezione [mailpanel-pubblico]."));
                    daGuardareAMano = true;
                } else if (!prima.equals(dopo)) {
                    copie.add(copia(pub));
                    Files.writeString(pub, dopo, StandardCharsets.UTF_8);
                    toccato = true;
                    passi.put(passo("mailpanel-pubblico", true,
                        "Riscritto " + JAIL_PUBBLICO + " con action = pf[name=mailpanel-pubblico]"));
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
                            "Aggiornata la sola riga dell'azione in " + JAIL_LOCAL));
                    }
                }
            } else {
                passi.put(passo("mail-panel-auth", true, "jail.local non esiste: niente da riparare"));
            }

            if (!toccato)
                return r.put("success", !daGuardareAMano).put("passi", passi)
                        .put("message", daGuardareAMano
                            ? "Non ho toccato niente: una sezione va guardata a mano, il dettaglio dice quale e perche'."
                            : "Nessuna delle due jail aveva bisogno di essere corretta.");

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
            passi.put(passo("reload", true, "fail2ban ha accettato la configurazione"));

            // 4. La verifica che conta: cosa esegue ADESSO, chiesto a fail2ban.
            JSONArray verifica = new JSONArray();
            boolean tutteOk = true;
            for (String jail : new String[] { "mailpanel-pubblico", "mail-panel-auth" }) {
                String cmd = comandoBan(jail);
                boolean ok = cmd != null && cmd.contains("pfctl");
                if (cmd == null) {
                    // La jail puo' semplicemente non essere installata: non e' un fallimento.
                    verifica.put(new JSONObject().put("jail", jail).put("ok", true)
                        .put("nota", "non attiva su questo sistema"));
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
            if (valore.equals("pf") || valore.startsWith("pf[") || valore.startsWith("pf "))
                return Esito.giaAPosto();
            int seg = rigaAzione + 1;
            if (seg < fine && !righe[seg].trim().isEmpty()
                && (righe[seg].startsWith(" ") || righe[seg].startsWith("\t")))
                return Esito.daGuardare("l'azione di [" + jail + "] prosegue sulla riga seguente: "
                    + "sostituirne solo la prima lascerebbe attaccata al comando nuovo una coda "
                    + "del vecchio. Va sistemata a mano in " + JAIL_LOCAL + ", riga " + (rigaAzione + 1) + ".");
        }

        // allports, non la porta: l'azione pf costruisce "... to any port $port" e senza porta
        // pf rifiuta la regola, lasciando la tabella senza nessuno che la legga.
        String azione = "action   = pf[name=" + jail + ", actiontype=<allports>]";
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

    private static Path copia(Path f) throws Exception {
        Path c = Paths.get(f.toString() + ".prima-di-pf-"
            + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")));
        Files.copy(f, c);
        return c;
    }

    private static void ripristina(List<Path> copie) {
        for (Path c : copie) {
            try {
                String s = c.toString();
                Path orig = Paths.get(s.substring(0, s.indexOf(".prima-di-pf-")));
                Files.copy(c, orig, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception ignora) { }
        }
    }

    private static JSONObject passo(String nome, boolean ok, String testo) {
        return new JSONObject().put("passo", nome).put("ok", ok).put("testo", testo);
    }
}
