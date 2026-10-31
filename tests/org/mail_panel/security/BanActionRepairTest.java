package org.mail_panel.security;

/**
 * La modifica chirurgica di jail.local.
 *
 * Va provata perche' scrive su un file di configurazione vivo che decide chi viene bloccato, e
 * perche' i suoi errori non si vedono: una riga inserita nella sezione sbagliata, o una coda di
 * azione rimasta attaccata, producono un file che fail2ban puo' anche accettare mentre banna
 * con il comando di un'altra jail. Qui si controlla non solo che la riga giusta cambi, ma che
 * tutto il resto del file resti identico.
 */
public class BanActionRepairTest {

    private static int failed = 0;

    private static final String REAL =
        "# Auto-generato da FreeBSD-Mail-Panel\n" +
        "[mail-panel-auth]\n" +
        "enabled  = true\n" +
        "filter   = mail-panel-auth\n" +
        "logpath  = /var/log/mail-panel-auth.log\n" +
        "maxretry = 5\n" +
        "findtime = 600\n" +
        "bantime  = 3600\n" +
        "backend  = auto\n";

    public static void main(String[] args) {
        // --- Il caso vero: sezione senza azione, come sul server ---
        BanActionRepair.Outcome e = BanActionRepair.withPfAction(REAL, "mail-panel-auth");
        real("sezione senza azione: modificata", e.type == BanActionRepair.Outcome.Kind.MODIFIED);
        real("azione pf inserita", e.content.contains("action   = pf[name=mail-panel-auth, port=\"0:65535\"]"));
        // Non basta che ci sia "pf": senza una porta l'azione usa il valore predefinito
        // "any port $port", e con la porta vuota pf rifiuta la regola lasciando la tabella senza
        // nessuno che la legga — e' cio' che e' successo a recidive. La porta si dichiara.
        //
        // La prima correzione usava "actiontype", che e' la forma mostrata dalla documentazione
        // dell'azione: su questo sistema fail2ban non l'accetta come parametro di jail e carica
        // la jail SENZA nessuna azione ("No actions for jail ..."), cioe' senza bannare affatto.
        // Qui si prova la forma dichiarata con la porta, che e' quella con cui le quattro jail
        // di posta hanno tabella e regola verificate.
        real("porta dichiarata, non lasciata al valore predefinito",
            !e.content.contains("pf[name=mail-panel-auth]"));
        real("nessun actiontype: fail2ban qui lo rifiuta",
            !e.content.contains("actiontype"));
        // Va dopo l'ultima riga di configurazione, non in fondo al file dopo il ritorno a capo.
        same("inserita al posto giusto",
            "backend  = auto\naction   = pf[name=mail-panel-auth, port=\"0:65535\"]\n",
            e.content.substring(e.content.indexOf("backend  = auto")));
        // Niente altro e' cambiato.
        same("il resto del file e' intatto", REAL.replace("backend  = auto\n", ""),
            e.content.replace("backend  = auto\n", "").replace("action   = pf[name=mail-panel-auth, port=\"0:65535\"]\n", ""));

        // --- Applicarlo due volte non deve aggiungerne due ---
        BanActionRepair.Outcome again = BanActionRepair.withPfAction(e.content, "mail-panel-auth");
        real("seconda passata: gia' a posto", again.type == BanActionRepair.Outcome.Kind.ALREADY_IN_PLACE);

        // --- Un'azione iptables va sostituita, non affiancata ---
        String ipt = REAL + "action   = iptables-multiport[name=x, port=\"http\"]\n";
        BanActionRepair.Outcome s = BanActionRepair.withPfAction(ipt, "mail-panel-auth");
        real("iptables: sostituita", s.type == BanActionRepair.Outcome.Kind.MODIFIED);
        real("iptables: sparito", !s.content.contains("iptables"));
        same("una sola azione", 1, count(s.content, "action   = pf"));

        // banaction e' l'altro nome della stessa cosa e va trattato uguale.
        BanActionRepair.Outcome ba = BanActionRepair.withPfAction(
            REAL + "banaction = iptables-allports\n", "mail-panel-auth");
        real("banaction: sostituita", ba.type == BanActionRepair.Outcome.Kind.MODIFIED);
        real("banaction: iptables sparito", !ba.content.contains("iptables"));

        // --- Un segnaposto non risolto non e' "gia' a posto" ---
        // E' la forma che ha fatto smettere alle due jail del pannello di riportare la propria
        // azione: comincia con "pf[", quindi un controllo ingenuo la promuove e la lascia li'.
        BanActionRepair.Outcome ph = BanActionRepair.withPfAction(
            REAL + "action   = pf[name=mail-panel-auth, actiontype=<allports>]\n", "mail-panel-auth");
        real("segnaposto nel valore: da riscrivere",
            ph.type == BanActionRepair.Outcome.Kind.MODIFIED);
        real("segnaposto sostituito col valore letterale",
            ph.content.contains("port=\"0:65535\"") && !ph.content.contains("<allports>"));
        // Ma la forma gia' corretta non si tocca: riscriverla a ogni passaggio farebbe ricaricare
        // fail2ban senza motivo, e un rimedio che agisce sempre non si distingue da un difetto.
        real("forma corretta lasciata stare",
            BanActionRepair.withPfAction(REAL + "action   = pf[name=mail-panel-auth, port=\"0:65535\"]\n",
                "mail-panel-auth").type == BanActionRepair.Outcome.Kind.ALREADY_IN_PLACE);

        // --- La forma che fail2ban rifiuta va riscritta, non promossa ---
        // "pf[name=x, actiontype=any]" comincia con "pf[" e non contiene segnaposto: un
        // controllo che si accontenta di quello la lascia, e la jail resta senza azioni. E'
        // successo davvero, due volte di fila con due varianti. La condizione e' la porta.
        BanActionRepair.Outcome at = BanActionRepair.withPfAction(
            REAL + "action   = pf[name=mail-panel-auth, actiontype=any]\n", "mail-panel-auth");
        real("actiontype senza porta: da riscrivere",
            at.type == BanActionRepair.Outcome.Kind.MODIFIED);
        real("riscritta con la porta e senza actiontype",
            at.content.contains("port=\"0:65535\"") && !at.content.contains("actiontype"));
        // Una porta scelta da chi amministra NON si tocca: e' una configurazione, non un guasto.
        real("porta personalizzata rispettata",
            BanActionRepair.withPfAction(REAL + "action   = pf[name=mail-panel-auth, port=\"smtp,imaps\"]\n",
                "mail-panel-auth").type == BanActionRepair.Outcome.Kind.ALREADY_IN_PLACE);

        // --- Il caso che NON si deve provare a riparare ---
        String multi = REAL + "action   = iptables-multiport[name=x]\n         sendmail[dest=root]\n";
        BanActionRepair.Outcome m = BanActionRepair.withPfAction(multi, "mail-panel-auth");
        real("azione su piu' righe: si ferma", m.type == BanActionRepair.Outcome.Kind.TO_REVIEW);
        real("azione su piu' righe: niente contenuto scritto", m.content == null);
        real("azione su piu' righe: dice dove guardare", m.reason != null && m.reason.contains("riga"));

        // --- Sezione assente: non si inventa niente ---
        real("sezione assente",
            BanActionRepair.withPfAction("[altra]\nenabled = true\n", "mail-panel-auth").type
                == BanActionRepair.Outcome.Kind.ABSENT);

        // --- Il rischio peggiore: scrivere nella sezione di un'altra jail ---
        String second = REAL + "\n[sshd]\nenabled  = true\nmaxretry = 3\n";
        BanActionRepair.Outcome d = BanActionRepair.withPfAction(second, "mail-panel-auth");
        real("due sezioni: modificata", d.type == BanActionRepair.Outcome.Kind.MODIFIED);
        String sshd = d.content.substring(d.content.indexOf("[sshd]"));
        same("la sezione sshd e' intatta", "[sshd]\nenabled  = true\nmaxretry = 3\n", sshd);
        real("l'azione sta PRIMA di [sshd]",
            d.content.indexOf("action   = pf") < d.content.indexOf("[sshd]"));

        // Un commento in coda alla sezione non deve spingere l'azione dopo di lui.
        String withNote = "[mail-panel-auth]\nenabled  = true\n# nota finale\n\n[sshd]\nenabled = true\n";
        BanActionRepair.Outcome cn = BanActionRepair.withPfAction(withNote, "mail-panel-auth");
        real("l'azione segue l'ultima configurazione, non il commento",
            cn.content.indexOf("action   = pf") < cn.content.indexOf("# nota finale"));

        // --- firstRunnable: e' cio' che distingue un ban vero da uno a vuoto ---
        same("iptables riconosciuto sotto i segnaposto", "iptables",
            BanActionRepair.firstRunnable("<iptables> -I f2b-x 1 -s <ip> -j <blocktype>"));
        same("pfctl riconosciuto", "pfctl",
            BanActionRepair.firstRunnable("pfctl -a f2b/x -t f2b-x -T add <ip>"));
        same("percorso assoluto", "/sbin/pfctl",
            BanActionRepair.firstRunnable("/sbin/pfctl -t x -T add <ip>"));
        same("righe vuote in testa ignorate", "pfctl",
            BanActionRepair.firstRunnable("\n   \npfctl -t x -T add <ip>"));

        // Su questo si costruisce l'accusa "banna con un comando che non esiste". Un costrutto
        // di shell non e' un programma da cercare su disco: se si concludesse "non esiste", il
        // pannello direbbe rotta una jail sana e inviterebbe a ripararla.
        same("if non e' un programma", null,
            BanActionRepair.firstRunnable("if [ -n \"<ip>\" ]; then pfctl -T add <ip>; fi"));
        same("echo non e' un programma", null,
            BanActionRepair.firstRunnable("echo <ip> >> /var/db/lista"));
        same("una variabile non si giudica", null,
            BanActionRepair.firstRunnable("$BANCMD -s <ip>"));
        same("commenti saltati", "pfctl",
            BanActionRepair.firstRunnable("# aggiunge l'indirizzo\npfctl -t x -T add <ip>"));
        same("comando assente", null, BanActionRepair.firstRunnable(null));

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static int count(String text, String piece) {
        int n = 0, i = 0;
        while ((i = text.indexOf(piece, i)) >= 0) { n++; i += piece.length(); }
        return n;
    }

    private static void same(String name, Object expected, Object got) {
        boolean ok = expected == null ? got == null : expected.equals(got);
        System.out.println((ok ? "  ok   " : "  NO   ") + name
            + (ok ? "" : "\n         atteso [" + expected + "]\n         avuto  [" + got + "]"));
        if (!ok) failed++;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
