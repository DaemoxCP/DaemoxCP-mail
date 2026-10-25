package org.mail_panel.security;

/**
 * Il confronto di un record SRV con quello che il pannello vorrebbe.
 *
 * E' la funzione che ha fatto riscrivere in produzione due SRV gia' giusti, a ogni
 * esecuzione, annunciando ogni volta una differenza che non esisteva.
 */
public class SrvRecordTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static CloudflareManager.DnsRecordInfo srv(String content, Integer priority, Integer weight,
                                               Integer port, String dest) {
        CloudflareManager.DnsRecordInfo t = new CloudflareManager.DnsRecordInfo();
        t.type = "SRV"; t.name = "_imaps._tcp.domain-a.test"; t.content = content;
        t.srvPriority = priority; t.srvWeight = weight; t.srvPort = port; t.srvDestination = dest;
        return t;
    }

    public static void main(String[] a) {
        final String HOST = "mail.domain-b.test";

        System.out.println("\n== il caso vero: content a TRE campi, piu' i campi strutturati ==");
        require("il record risulta GIA' GIUSTO (prima veniva riscritto ogni volta)",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== e senza i campi strutturati, solo la stringa a tre campi ==");
        require("riconosciuto lo stesso: 'peso porta destinazione'",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("porta diversa: NON coincide",
                !AutoDns.coincide(srv("1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("destinazione diversa: NON coincide",
                !AutoDns.coincide(srv("1 993 altro.host", null, null, null, null), true, HOST, 993));

        System.out.println("\n== la forma a QUATTRO campi (uscita di dig) continua a valere ==");
        require("'0 1 993 host' riconosciuto",
                AutoDns.coincide(srv("0 1 993 mail.domain-b.test", null, null, null, null), true, HOST, 993));
        require("'0 1 995 host' no",
                !AutoDns.coincide(srv("0 1 995 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== i campi strutturati hanno la precedenza sulla stringa ==");
        require("porta strutturata giusta, stringa sbagliata -> coincide",
                AutoDns.coincide(srv("1 995 altro.host", 0, 1, 993, HOST), true, HOST, 993));
        require("porta strutturata sbagliata, stringa giusta -> NON coincide",
                !AutoDns.coincide(srv("1 993 mail.domain-b.test", 0, 1, 995, HOST), true, HOST, 993));

        System.out.println("\n== la priorita' NON fa parte della domanda ==");
        require("priorita' 10 invece di 0: coincide comunque",
                AutoDns.coincide(srv("1 993 mail.domain-b.test", 10, 1, 993, HOST), true, HOST, 993));

        System.out.println("\n== spazzatura: non si spaccia per giusta ==");
        require("stringa vuota: NON coincide",
                !AutoDns.coincide(srv("", null, null, null, null), true, HOST, 993));
        require("tre campi non numerici: NON coincide",
                !AutoDns.coincide(srv("a b c", null, null, null, null), true, HOST, 993));
        require("due soli campi: NON coincide",
                !AutoDns.coincide(srv("993 mail.domain-b.test", null, null, null, null), true, HOST, 993));

        System.out.println("\n== e il confronto NON-SRV resta quello di prima ==");
        CloudflareManager.DnsRecordInfo cn = new CloudflareManager.DnsRecordInfo();
        cn.type = "CNAME"; cn.content = "mail.domain-b.test.";
        require("CNAME col punto finale coincide", AutoDns.coincide(cn, false, HOST, 0));
        cn.content = "xmail.domain-b.test";
        require("'xmail...' non passa per 'mail...'", !AutoDns.coincide(cn, false, HOST, 0));

        System.out.println("\n== e la logica VECCHIA sullo stesso caso vero ==");
        // Com'era: solo analyzeSrv() sul content. Se passasse anche qui, il primo
        // controllo di questa prova non starebbe verificando niente.
        DnsRules.Srv old = DnsRules.analyzeSrv("1 993 mail.domain-b.test");
        boolean oldOutcome = old != null && old.port == 993
                && DnsRules.sameName(old.destination, HOST);
        System.out.println("  analizzaSrv(\"1 993 mail.domain-b.test\") -> "
                + (old == null ? "null (non riconosciuto)" : "riconosciuto"));
        require("la logica vecchia BOCCIA il record giusto: il difetto si riproduce", !oldOutcome);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
