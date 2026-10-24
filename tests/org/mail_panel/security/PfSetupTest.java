package org.mail_panel.security;

import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * pf: che un blocco di fail2ban fermi davvero un pacchetto.
 *
 * Il difetto, misurato su una FreeBSD 15.1 appena installata col pannello mail installato e
 * acceso:
 *
 *   fail2ban dice:    203.0.113.77
 *   pf ha:            pfctl: /dev/pf: No such file or directory
 *   /etc/pf.conf:     non esiste
 *
 * Cioe' fail2ban rileva, dichiara il blocco, e il pacchetto passa. E' il caso peggiore: non
 * lascia tracce da cui accorgersi, perche' un firewall che non blocca ha lo stesso aspetto di
 * una macchina su cui non ci prova nessuno.
 *
 * Quello che va provato qui, e che leggere il codice non direbbe:
 *  - il pf.conf che l'installazione scrive **pf lo accetta**: non si guarda il testo, si
 *    lancia "pfctl -nf" per davvero;
 *  - quel pf.conf **non puo' chiudere fuori nessuno**. Non e' un'opinione sul testo: si fa
 *    stampare a pfctl le regole come le ha capite lui, e si pretende che l'unico blocco sia
 *    quello della tabella dei blocchi permanenti e che il predefinito sia "pass";
 *  - l'ordine conta: l'anchor deve venire PRIMA del pass, altrimenti il pass vince e il
 *    blocco non si applica mai;
 *  - la diagnosi dice qual e' il pezzo che manca, e nell'ordine giusto: senza il modulo nel
 *    kernel, guardare pf.conf non ha senso.
 *
 * Si lancia sulla VM, dove pfctl parla col kernel:
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.PfSetupTest
 */
public class PfSetupTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("pf-setup");
        String script = new FullMailServerScript().getScriptContent();

        OUT.println("\n== La diagnosi: quale pezzo manca, e nell'ordine che conta ==");
        check("tutto a posto: nessun motivo",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, true, true).isEmpty());
        check("senza il modulo nel kernel, lo dice (ed e' il primo: senza, pfctl non parla"
                + " nemmeno col kernel)",
                Fail2banAutoSetup.whyBansWouldNotBite(false, true, true, true).contains("kernel module"));
        check("il modulo viene incolpato prima di tutto il resto",
                Fail2banAutoSetup.whyBansWouldNotBite(false, false, false, false).contains("kernel module"));
        check("senza /etc/pf.conf, lo dice",
                Fail2banAutoSetup.whyBansWouldNotBite(true, false, true, true).contains("/etc/pf.conf does not exist"));
        check("senza l'anchor, lo dice",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, false, true).contains("f2b/*"));
        check("con pf spento, lo dice",
                Fail2banAutoSetup.whyBansWouldNotBite(true, true, true, false).contains("Status: Disabled"));
        // Nessuna combinazione incompleta deve dare "va tutto bene": e' la cosa che il
        // pannello faceva, cioe' tacere.
        int silences = 0;
        for (int c = 0; c < 16; c++) {
            boolean m = (c & 1) != 0, f = (c & 2) != 0, a = (c & 4) != 0, e = (c & 8) != 0;
            boolean everything = m && f && a && e;
            if (!everything && Fail2banAutoSetup.whyBansWouldNotBite(m, f, a, e).isEmpty()) silences++;
        }
        check("nessuna delle 15 combinazioni incomplete passa in silenzio", silences == 0);

        OUT.println("\n== L'installazione mette in piedi pf ==");
        check("lo fa dopo aver installato fail2ban",
                script.indexOf("pkg install -y security/py-fail2ban") < script.indexOf("Setting up pf"));
        check("e prima di configurare MySQL, cioe' dentro l'installazione e non dopo",
                script.indexOf("Setting up pf") < script.indexOf("[PHASE 3/10]"));
        check("dentro una jail di FreeBSD non ci prova",
                script.contains("security.jail.jailed") && script.contains("belongs to the host"));
        check("e se c'e' gia' ipfw non accende un secondo firewall a sorpresa",
                script.contains("ipfw.ko") && script.contains("already has a firewall"));
        check("un /etc/pf.conf che c'e' gia' non viene riscritto, e pf NON si accende",
                script.contains("left untouched, and pf NOT enabled"));
        check("prova la sintassi prima di accendere", script.contains("pfctl -nf /etc/pf.conf"));
        // Il restart non e' pignoleria: l'azione pf crea la propria regola in "actionstart",
        // una volta sola. Se quella volta pf non c'era, fail2ban non la riprova mai, e da li'
        // in avanti i ban creano una tabella SENZA la regola che la legge -- cioe' niente,
        // mentre fail2ban-client dice "Banned IP list". Misurato su una reinstallazione.
        check("riavvia fail2ban invece di limitarsi ad avviarlo",
                script.contains("service fail2ban restart"));
        check("e lo fa DOPO aver messo in piedi pf, non prima",
                script.indexOf("Setting up pf") < script.indexOf("service fail2ban restart"));
        check("e dopo guarda \"Status: Enabled\", non il codice d'uscita (pfctl -s info esce 0"
                + " anche a pf spento)", script.contains("grep -q \"Status: Enabled\""));
        Path generated = home.resolve("install.sh");
        Files.writeString(generated, script, StandardCharsets.UTF_8);
        check("lo script generato passa sh -n", run("/bin/sh", "-n", generated.toString()) == 0);

        OUT.println("\n== Il pf.conf che scrive: pf lo accetta, e non blocca nessun servizio ==");
        String pfConf = between(script, "cat > /etc/pf.conf << 'PFCONF'\n", "\nPFCONF\n");
        check("c'e' un pf.conf nello script", pfConf != null && !pfConf.isBlank());
        if (pfConf == null) { OUT.println("\n" + (++failed) + " CONTROLLI FALLITI"); System.exit(1); }
        check("l'anchor viene PRIMA del pass (dopo, il pass vincerebbe e il blocco non si"
                + " applicherebbe mai)", pfConf.indexOf("anchor \"f2b/*\"") < pfConf.lastIndexOf("\npass"));

        if (!Files.isExecutable(Path.of("/sbin/pfctl"))) {
            check("pfctl c'e' (questa prova va lanciata sulla VM, non sul Mac)", false);
            OUT.println("\n" + failed + " CONTROLLI FALLITI");
            System.exit(1);
        }
        // Senza il modulo pf nel kernel, pfctl non parla col kernel e qualunque cosa gli si
        // chieda fallisce con "Failed to open netlink": i controlli qui sotto direbbero
        // "pfctl ha rifiutato il file" mentre il file non e' mai stato letto. Distinguere i
        // due casi e' il punto: uno e' un pf.conf sbagliato, l'altro e' una macchina senza pf.
        if (!Fail2banAutoSetup.pfModuleLoaded()) {
            check("il modulo pf e' caricato — senza, pfctl non legge NIENTE e i controlli qui"
                    + " sotto non misurerebbero il pf.conf ma l'assenza del modulo: kldload pf", false);
            OUT.println("\n" + failed + " CONTROLLI FALLITI");
            System.exit(1);
        }
        // La lista dei blocchi permanenti deve esistere, altrimenti pfctl rifiuta la table
        // persist file: e' lo stesso ordine che tiene lo script.
        Files.createDirectories(Path.of("/var/db/mail-panel"));
        if (!Files.exists(Path.of("/var/db/mail-panel/permaban.list")))
            Files.writeString(Path.of("/var/db/mail-panel/permaban.list"), "");
        Path candidate = home.resolve("pf.conf");
        Files.writeString(candidate, pfConf + "\n", StandardCharsets.UTF_8);
        check("pfctl -nf lo accetta", run("/sbin/pfctl", "-nf", candidate.toString()) == 0);

        // Non si giudica il testo: si fa stampare a pfctl le regole come le ha capite lui.
        List<String> rules = rulesAsPfParsesThem(candidate);
        for (String r : rules) OUT.println("      " + r);
        List<String> blocks = new ArrayList<>();
        for (String r : rules) if (r.startsWith("block")) blocks.add(r);
        check("pf vede un solo blocco, e sono i blocchi permanenti del pannello: "
                + blocks.size() + " blocco/i", blocks.size() == 1 && blocks.get(0).contains("<permaban>"));
        boolean passesAll = false;
        for (String r : rules) if (r.startsWith("pass all") || r.equals("pass")) passesAll = true;
        check("e il predefinito e' passare tutto: accendere pf non chiude fuori nessuno", passesAll);
        boolean anchorBeforePass = false;
        int iAnchor = -1, iPass = -1;
        for (int i = 0; i < rules.size(); i++) {
            if (rules.get(i).startsWith("anchor") && rules.get(i).contains("f2b/")) iAnchor = i;
            if (rules.get(i).startsWith("pass")) iPass = i;
        }
        anchorBeforePass = iAnchor >= 0 && iPass >= 0 && iAnchor < iPass;
        check("anche per pf, l'anchor sta prima del pass", anchorBeforePass);
        check("e il pannello riconosce il proprio anchor in quel file",
                Fail2banAutoSetup.hasF2bAnchor(pfConf));

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Le regole come le ha capite pf: "pfctl -nvf" le ristampa normalizzate. */
    static List<String> rulesAsPfParsesThem(Path file) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/sbin/pfctl", "-nvf", file.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        List<String> rules = new ArrayList<>();
        for (String line : out.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            rules.add(t);
        }
        return rules;
    }

    static int run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) OUT.print(out);
        return code;
    }

    static String between(String text, String start, String end) {
        int a = text.indexOf(start);
        if (a < 0) return null;
        int b = text.indexOf(end, a + start.length());
        return b < 0 ? null : text.substring(a + start.length(), b);
    }
}
