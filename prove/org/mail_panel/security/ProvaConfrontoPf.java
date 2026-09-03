package org.mail_panel.security;

/**
 * Le due letture su cui si regge il confronto fra i ban di Fail2ban e le tabelle pf.
 *
 * Sono provate qui perche' sbagliano in silenzio. Un'espressione che non trova la tabella non
 * fa fallire niente: fa dire "questa jail non usa pf", il confronto sparisce dalla pagina, e
 * l'assenza si legge come "va tutto bene". Una normalizzazione mancata fa il contrario: ogni
 * indirizzo risulta in uno solo dei due insiemi e il controllo grida a ogni ban.
 */
public class ProvaConfrontoPf {

    private static int falliti = 0;

    public static void main(String[] args) {
        // --- Il comando di ban vero di fail2ban su FreeBSD (action.d/pf.conf) ---
        String reale = "pfctl -a f2b/mailpanel-pubblico -t f2b-mailpanel-pubblico -T add <ip>";
        Fail2banManager.PfBersaglio b = Fail2banManager.bersaglioDaComando(reale);
        vero("comando reale: riconosciuto", b != null);
        uguale("comando reale: tabella", "f2b-mailpanel-pubblico", b == null ? null : b.tabella);
        uguale("comando reale: ancora", "f2b/mailpanel-pubblico", b == null ? null : b.ancora);

        // Su piu' righe, come lo restituisce fail2ban-client quando l'azione ne ha piu' d'una.
        Fail2banManager.PfBersaglio m = Fail2banManager.bersaglioDaComando(
            "pfctl -a f2b/dovecot -t f2b-dovecot -T add <ip>\npfctl -a f2b/dovecot -T show");
        uguale("piu' righe: tabella", "f2b-dovecot", m == null ? null : m.tabella);

        // Senza ancora: tabella globale. Deve funzionare lo stesso, con ancora nulla.
        Fail2banManager.PfBersaglio g = Fail2banManager.bersaglioDaComando("pfctl -t permaban -T add <ip>");
        vero("senza ancora: riconosciuto", g != null);
        uguale("senza ancora: tabella", "permaban", g == null ? null : g.tabella);
        vero("senza ancora: nessuna ancora certa", g != null && g.ancora == null);

        // --- Il caso vero, ed e' quello che mi era sfuggito ---
        // fail2ban restituisce il comando con i segnaposto NON espansi, e il file dell'azione
        // definisce "pfctl = pfctl -a f2b/<name>": l'ancora e' dentro <pfctl>, invisibile qui.
        // Cercarla nel testo non la trova mai, e leggere la tabella nel ruleset principale
        // avrebbe dato "non esiste" per ogni jail sana. Va ricavata dalla tabella.
        Fail2banManager.PfBersaglio v = Fail2banManager.bersaglioDaComando("<pfctl> -t f2b-dovecot -T add <ip>");
        vero("segnaposto <pfctl>: riconosciuto come pf", v != null);
        uguale("segnaposto: tabella", "f2b-dovecot", v == null ? null : v.tabella);
        vero("segnaposto: nessuna ancora certa nel testo", v != null && v.ancora == null);
        uguale("segnaposto: ancora ricavata dalle definizioni", "f2b/dovecot",
            v == null ? null : v.ancoraProbabile);
        // Il nome puo' contenere trattini: si divide al PRIMO, che separa il prefisso f2b.
        uguale("nome con trattini", "f2b/mailpanel-pubblico",
            Fail2banManager.bersaglioDaComando("<pfctl> -t f2b-mailpanel-pubblico -T add <ip>").ancoraProbabile);
        // Una tabella senza trattino non lascia ricavare niente, e non si inventa.
        vero("niente da ricavare", Fail2banManager.bersaglioDaComando("pfctl -t permaban -T add <ip>").ancoraProbabile == null);

        // Chi non banna via pf non deve produrre un bersaglio inventato.
        vero("ipfw non e' pf", Fail2banManager.bersaglioDaComando("ipfw table 1 add <ip>") == null);
        vero("solo log non e' pf", Fail2banManager.bersaglioDaComando("echo <ip> >> /var/log/x") == null);
        vero("pfctl senza tabella", Fail2banManager.bersaglioDaComando("pfctl -a f2b/x -f /etc/x") == null);
        vero("comando assente", Fail2banManager.bersaglioDaComando(null) == null);

        // --- La normalizzazione: le due fonti scrivono lo stesso indirizzo in modi diversi ---
        // pfctl mette la maschera, fail2ban no. Il caso che conta e' che coincidano DOPO.
        uguale("pf: /32 tolto", "213.209.159.175", Fail2banManager.normalizzaIndirizzo("   213.209.159.175/32"));
        uguale("fail2ban: nudo", "213.209.159.175", Fail2banManager.normalizzaIndirizzo("213.209.159.175"));
        vero("le due fonti coincidono",
            Fail2banManager.normalizzaIndirizzo("   213.209.159.175/32")
                .equals(Fail2banManager.normalizzaIndirizzo("213.209.159.175")));
        uguale("v6: /128 tolto", "2001:db8::1", Fail2banManager.normalizzaIndirizzo("2001:db8::1/128"));
        // pfctl aggiunge i contatori dopo l'indirizzo quando gira con -v.
        uguale("contatori ignorati", "10.0.0.1", Fail2banManager.normalizzaIndirizzo("10.0.0.1   Cleared: Tue Sep  2"));
        // Una maschera vera NON va tolta: /24 non e' un indirizzo solo.
        uguale("/24 conservato", "10.0.0.0/24", Fail2banManager.normalizzaIndirizzo("10.0.0.0/24"));

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static void uguale(String nome, String atteso, String avuto) {
        boolean ok = atteso == null ? avuto == null : atteso.equals(avuto);
        System.out.println((ok ? "  ok   " : "  NO   ") + nome
            + (ok ? "" : "  atteso [" + atteso + "] avuto [" + avuto + "]"));
        if (!ok) falliti++;
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
