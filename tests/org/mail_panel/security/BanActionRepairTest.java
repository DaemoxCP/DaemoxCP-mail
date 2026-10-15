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

    private static int falliti = 0;

    private static final String REALE =
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
        BanActionRepair.Esito e = BanActionRepair.conAzionePf(REALE, "mail-panel-auth");
        vero("sezione senza azione: modificata", e.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        vero("azione pf inserita", e.contenuto.contains("action   = pf[name=mail-panel-auth, port=\"0:65535\"]"));
        // Non basta che ci sia "pf": senza una porta l'azione usa il valore predefinito
        // "any port $port", e con la porta vuota pf rifiuta la regola lasciando la tabella senza
        // nessuno che la legga — e' cio' che e' successo a recidive. La porta si dichiara.
        //
        // La prima correzione usava "actiontype", che e' la forma mostrata dalla documentazione
        // dell'azione: su questo sistema fail2ban non l'accetta come parametro di jail e carica
        // la jail SENZA nessuna azione ("No actions for jail ..."), cioe' senza bannare affatto.
        // Qui si prova la forma dichiarata con la porta, che e' quella con cui le quattro jail
        // di posta hanno tabella e regola verificate.
        vero("porta dichiarata, non lasciata al valore predefinito",
            !e.contenuto.contains("pf[name=mail-panel-auth]"));
        vero("nessun actiontype: fail2ban qui lo rifiuta",
            !e.contenuto.contains("actiontype"));
        // Va dopo l'ultima riga di configurazione, non in fondo al file dopo il ritorno a capo.
        uguale("inserita al posto giusto",
            "backend  = auto\naction   = pf[name=mail-panel-auth, port=\"0:65535\"]\n",
            e.contenuto.substring(e.contenuto.indexOf("backend  = auto")));
        // Niente altro e' cambiato.
        uguale("il resto del file e' intatto", REALE.replace("backend  = auto\n", ""),
            e.contenuto.replace("backend  = auto\n", "").replace("action   = pf[name=mail-panel-auth, port=\"0:65535\"]\n", ""));

        // --- Applicarlo due volte non deve aggiungerne due ---
        BanActionRepair.Esito bis = BanActionRepair.conAzionePf(e.contenuto, "mail-panel-auth");
        vero("seconda passata: gia' a posto", bis.tipo == BanActionRepair.Esito.Tipo.GIA_A_POSTO);

        // --- Un'azione iptables va sostituita, non affiancata ---
        String ipt = REALE + "action   = iptables-multiport[name=x, port=\"http\"]\n";
        BanActionRepair.Esito s = BanActionRepair.conAzionePf(ipt, "mail-panel-auth");
        vero("iptables: sostituita", s.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        vero("iptables: sparito", !s.contenuto.contains("iptables"));
        uguale("una sola azione", 1, conta(s.contenuto, "action   = pf"));

        // banaction e' l'altro nome della stessa cosa e va trattato uguale.
        BanActionRepair.Esito ba = BanActionRepair.conAzionePf(
            REALE + "banaction = iptables-allports\n", "mail-panel-auth");
        vero("banaction: sostituita", ba.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        vero("banaction: iptables sparito", !ba.contenuto.contains("iptables"));

        // --- Un segnaposto non risolto non e' "gia' a posto" ---
        // E' la forma che ha fatto smettere alle due jail del pannello di riportare la propria
        // azione: comincia con "pf[", quindi un controllo ingenuo la promuove e la lascia li'.
        BanActionRepair.Esito ph = BanActionRepair.conAzionePf(
            REALE + "action   = pf[name=mail-panel-auth, actiontype=<allports>]\n", "mail-panel-auth");
        vero("segnaposto nel valore: da riscrivere",
            ph.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        vero("segnaposto sostituito col valore letterale",
            ph.contenuto.contains("port=\"0:65535\"") && !ph.contenuto.contains("<allports>"));
        // Ma la forma gia' corretta non si tocca: riscriverla a ogni passaggio farebbe ricaricare
        // fail2ban senza motivo, e un rimedio che agisce sempre non si distingue da un difetto.
        vero("forma corretta lasciata stare",
            BanActionRepair.conAzionePf(REALE + "action   = pf[name=mail-panel-auth, port=\"0:65535\"]\n",
                "mail-panel-auth").tipo == BanActionRepair.Esito.Tipo.GIA_A_POSTO);

        // --- La forma che fail2ban rifiuta va riscritta, non promossa ---
        // "pf[name=x, actiontype=any]" comincia con "pf[" e non contiene segnaposto: un
        // controllo che si accontenta di quello la lascia, e la jail resta senza azioni. E'
        // successo davvero, due volte di fila con due varianti. La condizione e' la porta.
        BanActionRepair.Esito at = BanActionRepair.conAzionePf(
            REALE + "action   = pf[name=mail-panel-auth, actiontype=any]\n", "mail-panel-auth");
        vero("actiontype senza porta: da riscrivere",
            at.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        vero("riscritta con la porta e senza actiontype",
            at.contenuto.contains("port=\"0:65535\"") && !at.contenuto.contains("actiontype"));
        // Una porta scelta da chi amministra NON si tocca: e' una configurazione, non un guasto.
        vero("porta personalizzata rispettata",
            BanActionRepair.conAzionePf(REALE + "action   = pf[name=mail-panel-auth, port=\"smtp,imaps\"]\n",
                "mail-panel-auth").tipo == BanActionRepair.Esito.Tipo.GIA_A_POSTO);

        // --- Il caso che NON si deve provare a riparare ---
        String multi = REALE + "action   = iptables-multiport[name=x]\n         sendmail[dest=root]\n";
        BanActionRepair.Esito m = BanActionRepair.conAzionePf(multi, "mail-panel-auth");
        vero("azione su piu' righe: si ferma", m.tipo == BanActionRepair.Esito.Tipo.DA_GUARDARE);
        vero("azione su piu' righe: niente contenuto scritto", m.contenuto == null);
        vero("azione su piu' righe: dice dove guardare", m.motivo != null && m.motivo.contains("riga"));

        // --- Sezione assente: non si inventa niente ---
        vero("sezione assente",
            BanActionRepair.conAzionePf("[altra]\nenabled = true\n", "mail-panel-auth").tipo
                == BanActionRepair.Esito.Tipo.ASSENTE);

        // --- Il rischio peggiore: scrivere nella sezione di un'altra jail ---
        String due = REALE + "\n[sshd]\nenabled  = true\nmaxretry = 3\n";
        BanActionRepair.Esito d = BanActionRepair.conAzionePf(due, "mail-panel-auth");
        vero("due sezioni: modificata", d.tipo == BanActionRepair.Esito.Tipo.MODIFICATO);
        String sshd = d.contenuto.substring(d.contenuto.indexOf("[sshd]"));
        uguale("la sezione sshd e' intatta", "[sshd]\nenabled  = true\nmaxretry = 3\n", sshd);
        vero("l'azione sta PRIMA di [sshd]",
            d.contenuto.indexOf("action   = pf") < d.contenuto.indexOf("[sshd]"));

        // Un commento in coda alla sezione non deve spingere l'azione dopo di lui.
        String conNota = "[mail-panel-auth]\nenabled  = true\n# nota finale\n\n[sshd]\nenabled = true\n";
        BanActionRepair.Esito cn = BanActionRepair.conAzionePf(conNota, "mail-panel-auth");
        vero("l'azione segue l'ultima configurazione, non il commento",
            cn.contenuto.indexOf("action   = pf") < cn.contenuto.indexOf("# nota finale"));

        // --- primoEseguibile: e' cio' che distingue un ban vero da uno a vuoto ---
        uguale("iptables riconosciuto sotto i segnaposto", "iptables",
            BanActionRepair.primoEseguibile("<iptables> -I f2b-x 1 -s <ip> -j <blocktype>"));
        uguale("pfctl riconosciuto", "pfctl",
            BanActionRepair.primoEseguibile("pfctl -a f2b/x -t f2b-x -T add <ip>"));
        uguale("percorso assoluto", "/sbin/pfctl",
            BanActionRepair.primoEseguibile("/sbin/pfctl -t x -T add <ip>"));
        uguale("righe vuote in testa ignorate", "pfctl",
            BanActionRepair.primoEseguibile("\n   \npfctl -t x -T add <ip>"));

        // Su questo si costruisce l'accusa "banna con un comando che non esiste". Un costrutto
        // di shell non e' un programma da cercare su disco: se si concludesse "non esiste", il
        // pannello direbbe rotta una jail sana e inviterebbe a ripararla.
        uguale("if non e' un programma", null,
            BanActionRepair.primoEseguibile("if [ -n \"<ip>\" ]; then pfctl -T add <ip>; fi"));
        uguale("echo non e' un programma", null,
            BanActionRepair.primoEseguibile("echo <ip> >> /var/db/lista"));
        uguale("una variabile non si giudica", null,
            BanActionRepair.primoEseguibile("$BANCMD -s <ip>"));
        uguale("commenti saltati", "pfctl",
            BanActionRepair.primoEseguibile("# aggiunge l'indirizzo\npfctl -t x -T add <ip>"));
        uguale("comando assente", null, BanActionRepair.primoEseguibile(null));

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static int conta(String testo, String pezzo) {
        int n = 0, i = 0;
        while ((i = testo.indexOf(pezzo, i)) >= 0) { n++; i += pezzo.length(); }
        return n;
    }

    private static void uguale(String nome, Object atteso, Object avuto) {
        boolean ok = atteso == null ? avuto == null : atteso.equals(avuto);
        System.out.println((ok ? "  ok   " : "  NO   ") + nome
            + (ok ? "" : "\n         atteso [" + atteso + "]\n         avuto  [" + avuto + "]"));
        if (!ok) falliti++;
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
