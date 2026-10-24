package org.mail_panel.security;

/**
 * Le due letture su cui si regge il confronto fra i ban di Fail2ban e le tabelle pf.
 *
 * Sono provate qui perche' sbagliano in silenzio. Un'espressione che non trova la tabella non
 * fa fallire niente: fa dire "questa jail non usa pf", il confronto sparisce dalla pagina, e
 * l'assenza si legge come "va tutto bene". Una normalizzazione mancata fa il contrario: ogni
 * indirizzo risulta in uno solo dei due insiemi e il controllo grida a ogni ban.
 */
public class PfComparisonTest {

    private static int failed = 0;

    public static void main(String[] args) {
        // --- Il comando di ban vero di fail2ban su FreeBSD (action.d/pf.conf) ---
        String real = "pfctl -a f2b/mailpanel-pubblico -t f2b-mailpanel-pubblico -T add <ip>";
        Fail2banManager.PfTarget b = Fail2banManager.targetFromCommand(real);
        real("comando reale: riconosciuto", b != null);
        same("comando reale: tabella", "f2b-mailpanel-pubblico", b == null ? null : b.tabella);
        same("comando reale: ancora", "f2b/mailpanel-pubblico", b == null ? null : b.ancora);

        // Su piu' righe, come lo restituisce fail2ban-client quando l'azione ne ha piu' d'una.
        Fail2banManager.PfTarget m = Fail2banManager.targetFromCommand(
            "pfctl -a f2b/dovecot -t f2b-dovecot -T add <ip>\npfctl -a f2b/dovecot -T show");
        same("piu' righe: tabella", "f2b-dovecot", m == null ? null : m.tabella);

        // Senza ancora: tabella globale. Deve funzionare lo stesso, con ancora nulla.
        Fail2banManager.PfTarget g = Fail2banManager.targetFromCommand("pfctl -t permaban -T add <ip>");
        real("senza ancora: riconosciuto", g != null);
        same("senza ancora: tabella", "permaban", g == null ? null : g.tabella);
        real("senza ancora: nessuna ancora certa", g != null && g.ancora == null);

        // --- Il caso vero, ed e' quello che mi era sfuggito ---
        // fail2ban restituisce il comando con i segnaposto NON espansi, e il file dell'azione
        // definisce "pfctl = pfctl -a f2b/<name>": l'ancora e' dentro <pfctl>, invisibile qui.
        // Cercarla nel testo non la trova mai, e leggere la tabella nel ruleset principale
        // avrebbe dato "non esiste" per ogni jail sana. Va ricavata dalla tabella.
        Fail2banManager.PfTarget v = Fail2banManager.targetFromCommand("<pfctl> -t f2b-dovecot -T add <ip>");
        real("segnaposto <pfctl>: riconosciuto come pf", v != null);
        same("segnaposto: tabella", "f2b-dovecot", v == null ? null : v.tabella);
        real("segnaposto: nessuna ancora certa nel testo", v != null && v.ancora == null);
        same("segnaposto: ancora ricavata dalle definizioni", "f2b/dovecot",
            v == null ? null : v.stillLikely);
        // Il nome puo' contenere trattini: si divide al PRIMO, che separa il prefisso f2b.
        same("nome con trattini", "f2b/mailpanel-pubblico",
            Fail2banManager.targetFromCommand("<pfctl> -t f2b-mailpanel-pubblico -T add <ip>").stillLikely);
        // Una tabella senza trattino non lascia ricavare niente, e non si inventa.
        real("niente da ricavare", Fail2banManager.targetFromCommand("pfctl -t permaban -T add <ip>").stillLikely == null);

        // Chi non banna via pf non deve produrre un bersaglio inventato.
        real("ipfw non e' pf", Fail2banManager.targetFromCommand("ipfw table 1 add <ip>") == null);
        real("solo log non e' pf", Fail2banManager.targetFromCommand("echo <ip> >> /var/log/x") == null);
        real("pfctl senza tabella", Fail2banManager.targetFromCommand("pfctl -a f2b/x -f /etc/x") == null);
        real("comando assente", Fail2banManager.targetFromCommand(null) == null);

        // --- La normalizzazione: le due fonti scrivono lo stesso indirizzo in modi diversi ---
        // pfctl mette la maschera, fail2ban no. Il caso che conta e' che coincidano DOPO.
        same("pf: /32 tolto", "213.209.159.175", Fail2banManager.normalizeAddress("   213.209.159.175/32"));
        same("fail2ban: nudo", "213.209.159.175", Fail2banManager.normalizeAddress("213.209.159.175"));
        real("le due fonti coincidono",
            Fail2banManager.normalizeAddress("   213.209.159.175/32")
                .equals(Fail2banManager.normalizeAddress("213.209.159.175")));
        same("v6: /128 tolto", "2001:db8::1", Fail2banManager.normalizeAddress("2001:db8::1/128"));
        // pfctl aggiunge i contatori dopo l'indirizzo quando gira con -v.
        same("contatori ignorati", "10.0.0.1", Fail2banManager.normalizeAddress("10.0.0.1   Cleared: Tue Sep  2"));
        // Una maschera vera NON va tolta: /24 non e' un indirizzo solo.
        same("/24 conservato", "10.0.0.0/24", Fail2banManager.normalizeAddress("10.0.0.0/24"));

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static void same(String name, String expected, String got) {
        boolean ok = expected == null ? got == null : expected.equals(got);
        System.out.println((ok ? "  ok   " : "  NO   ") + name
            + (ok ? "" : "  atteso [" + expected + "] avuto [" + got + "]"));
        if (!ok) failed++;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
