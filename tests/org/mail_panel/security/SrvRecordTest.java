package org.mail_panel.security;

/**
 * Il confronto di un record SRV con quello che il pannello vorrebbe.
 *
 * E' la funzione che ha fatto riscrivere in produzione due SRV gia' giusti, a ogni
 * esecuzione, annunciando ogni volta una differenza che non esisteva.
 */
public class SrvRecordTest {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static CloudflareManager.DnsRecordInfo srv(String content, Integer pri, Integer peso,
                                               Integer porta, String dest) {
        CloudflareManager.DnsRecordInfo t = new CloudflareManager.DnsRecordInfo();
        t.type = "SRV"; t.name = "_imaps._tcp.domain-a.test"; t.content = content;
        t.srvPriorita = pri; t.srvPeso = peso; t.srvPorta = porta; t.srvDestinazione = dest;
        return t;
    }

    public static void main(String[] a) {
        final String HOST = "mail.domain-b.test";

        System.out.println("\n== il caso vero: content a TRE campi, piu' i campi strutturati ==");
        esigi("il record risulta GIA' GIUSTO (prima veniva riscritto ogni volta)",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== e senza i campi strutturati, solo la stringa a tre campi ==");
        esigi("riconosciuto lo stesso: 'peso porta destinazione'",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        esigi("porta diversa: NON coincide",
                !AutoDns.coincide(srv("1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        esigi("destinazione diversa: NON coincide",
                !AutoDns.coincide(srv("1 993 altro.host", null, null, null, null), true, HOST, 993));

        System.out.println("\n== la forma a QUATTRO campi (uscita di dig) continua a valere ==");
        esigi("'0 1 993 host' riconosciuto",
                AutoDns.coincide(srv("0 1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        esigi("'0 1 995 host' no",
                !AutoDns.coincide(srv("0 1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== i campi strutturati hanno la precedenza sulla stringa ==");
        esigi("porta strutturata giusta, stringa sbagliata -> coincide",
                AutoDns.coincide(srv("1 995 altro.host", 0, 1, 993, HOST), true, HOST, 993));
        esigi("porta strutturata sbagliata, stringa giusta -> NON coincide",
                !AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 995, HOST), true, HOST, 993));

        System.out.println("\n== la priorita' NON fa parte della domanda ==");
        esigi("priorita' 10 invece di 0: coincide comunque",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 10, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== spazzatura: non si spaccia per giusta ==");
        esigi("stringa vuota: NON coincide",
                !AutoDns.coincide(srv("", null, null, null, null), true, HOST, 993));
        esigi("tre campi non numerici: NON coincide",
                !AutoDns.coincide(srv("a b c", null, null, null, null), true, HOST, 993));
        esigi("due soli campi: NON coincide",
                !AutoDns.coincide(srv("993 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== e il confronto NON-SRV resta quello di prima ==");
        CloudflareManager.DnsRecordInfo cn = new CloudflareManager.DnsRecordInfo();
        cn.type = "CNAME"; cn.content = "mail.domain-b.test.";
        esigi("CNAME col punto finale coincide", AutoDns.coincide(cn, false, HOST, 0));
        cn.content = "xmail.domain-b.test";
        esigi("'xmail...' non passa per 'mail...'", !AutoDns.coincide(cn, false, HOST, 0));

        System.out.println("\n== e la logica VECCHIA sullo stesso caso vero ==");
        // Com'era: solo analizzaSrv() sul content. Se passasse anche qui, il primo
        // controllo di questa prova non starebbe verificando niente.
        RegoleDns.Srv vecchia = RegoleDns.analizzaSrv("1 993 mail.domain-b.test");
        boolean vecchioEsito = vecchia != null && vecchia.porta == 993
                && RegoleDns.stessoNome(vecchia.destinazione, HOST);
        System.out.println("  analizzaSrv(\"1 993 mail.domain-b.test\") -> "
                + (vecchia == null ? "null (non riconosciuto)" : "riconosciuto"));
        esigi("la logica vecchia BOCCIA il record giusto: il difetto si riproduce", !vecchioEsito);

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
