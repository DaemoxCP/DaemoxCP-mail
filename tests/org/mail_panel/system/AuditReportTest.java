package org.mail_panel.system;

import org.json.JSONObject;

/**
 * Il referto delle vulnerabilita' di un pacchetto: la domanda giusta, e la prova che una
 * risposta c'e' stata.
 *
 * Il pannello chiedeva {@code pkg audit <nome>}, col solo nome. Misurato sulla VM FreeBSD
 * 15.1 il 23/10/2026:
 *
 *  - col solo nome, pkg risponde "VuXML ha voci per questo nome?", non "la versione
 *    installata e' vulnerabile?": su nginx 1.30.6,3 appena aggiornato rispondeva
 *    "nginx is vulnerable" con 25 problemi, mentre `pkg audit` senza argomenti non lo
 *    nominava affatto. E l'intestazione e' "nginx is vulnerable:", SENZA la versione,
 *    quindi il lettore dei dettagli — che cerca "nome-versione is vulnerable:" — non
 *    entrava mai nel blocco: zero CVE sempre, in entrambe le direzioni;
 *  - su php84 8.4.26, vulnerabile per davvero, la scheda del pannello diceva "[ok] Nessuna
 *    vulnerabilita' nota registrata per questo pacchetto", mentre PackagePlan.correzioni
 *    trovava la fix nella 8.4.27;
 *  - senza il database delle vulnerabilita' pkg dice "vulnxml file vuln.xml does not exist"
 *    ed esce 1, e chi cerca solo le righe "is vulnerable" conclude "nessuna vulnerabilita'":
 *    una rassicurazione al posto di un "non ho potuto controllare".
 *
 * Le uscite usate qui sono quelle vere, copiate da quella misura.
 */
public class AuditReportTest {

    private static int falliti = 0, saltati = 0;

    /** Il referto vero di `pkg audit 'php84-8.4.26'`, accorciato ai pezzi che contano. */
    private static final String REFERTO_VULNERABILE =
            "php84-8.4.26 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "  WWW: https://vuxml.FreeBSD.org/freebsd/d8e16d08-cd2f-11f1-8135-8447094a420f.html\n"
          + "\n"
          + "1 problem(s) in 1 package(s) found.\n";

    /** Il referto vero di `pkg audit 'nginx-1.30.6,3'` dopo l'aggiornamento. */
    private static final String REFERTO_PULITO = "0 problem(s) in 0 package(s) found.\n";

    /** Quello che pkg risponde senza il database delle vulnerabilita'. */
    private static final String REFERTO_SENZA_DATABASE =
            "pkg: vulnxml file vuln.xml does not exist. Try running 'pkg audit -F' first\n";

    /** Quello che rispondeva al SOLO NOME: nessuna versione nell'intestazione. */
    private static final String REFERTO_SOLO_NOME =
            "php84 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "\n"
          + "3 problem(s) in 1 package(s) found.\n";

    public static void main(String[] args) {

        // ===== 1. Un pacchetto vulnerabile: il referto dice quanti problemi, e quali =====
        JSONObject v = UpdateManager.leggiReferto(REFERTO_VULNERABILE, "php84",
                UpdateManager.refertoVuoto("php84", "8.4.26"));
        vero("il referto e' stato fatto", v.optBoolean("done"));
        vero("conta 1 problema, come la riga finale di pkg", v.optInt("problems") == 1);
        vero("legge il CVE", v.getJSONArray("cve").toString().contains("CVE-2026-11111"));
        vero("legge la descrizione", v.optString("description").contains("multiple vulnerabilities"));
        vero("legge il riferimento", v.getJSONArray("references").toString().contains("vuxml.FreeBSD.org"));

        // ===== 2. Un pacchetto pulito: zero problemi, ma il controllo c'e' stato =====
        JSONObject p = UpdateManager.leggiReferto(REFERTO_PULITO, "nginx",
                UpdateManager.refertoVuoto("nginx", "1.30.6,3"));
        vero("il referto di un pacchetto pulito e' stato fatto", p.optBoolean("done"));
        vero("e dice zero problemi", p.optInt("problems") == 0);

        // ===== 3. Senza il database: NON si dice "nessuna vulnerabilita'" =====
        JSONObject s = UpdateManager.leggiReferto(REFERTO_SENZA_DATABASE, "nginx",
                UpdateManager.refertoVuoto("nginx", "1.30.6,3"));
        vero("senza il database il referto NON risulta fatto", !s.optBoolean("done"));
        vero("e il motivo nomina pkg audit -F", s.optString("error").contains("pkg audit -F"));
        vero("e i problemi non si contano come zero rassicurante",
             s.optInt("problems") == 0 && !s.optBoolean("done"));

        // ===== 4. Uscita vuota (comando non eseguito, timeout): idem =====
        vero("un'uscita vuota non e' un referto",
             !UpdateManager.leggiReferto("", "nginx", UpdateManager.refertoVuoto("nginx", "1.0")).optBoolean("done"));
        vero("e nemmeno un'uscita nulla",
             !UpdateManager.leggiReferto(null, "nginx", UpdateManager.refertoVuoto("nginx", "1.0")).optBoolean("done"));

        // ===== 5. Il referto del SOLO NOME: perche' le due correzioni vanno insieme =====
        // Qui la riga finale c'e', quindi "done" e' vero, ma l'intestazione non porta la
        // versione e i dettagli restano vuoti: contare i CVE avrebbe dato zero mentre pkg
        // diceva "is vulnerable". Chiedere con nome e versione e' cio' che rende leggibili
        // i dettagli; pretendere la riga finale e' cio' che distingue un referto da un errore.
        JSONObject sn = UpdateManager.leggiReferto(REFERTO_SOLO_NOME, "php84",
                UpdateManager.refertoVuoto("php84", "8.4.26"));
        vero("dal referto del solo nome i dettagli non si leggono", sn.getJSONArray("cve").isEmpty());
        vero("  e il conto sarebbe 3 invece di 1", sn.optInt("problems") == 3);

        // ===== 6. Una versione che non passa il filtro non diventa una riga di comando =====
        JSONObject brutta = UpdateManager.refertoAudit("nginx", "1.0; rm -rf /");
        vero("una versione non conforme non si esegue", !brutta.optBoolean("done"));
        vero("  e lo dice", !brutta.optString("error").isEmpty());
        vero("un nome non conforme non si esegue",
             !UpdateManager.refertoAudit("ngi nx", "1.0").optBoolean("done"));

        // ===== 7. Contro pkg vero: chi e' vulnerabile per pkg lo e' anche per il referto =====
        if (!cEPkg()) {
            salta("il confronto con pkg vero: pkg non c'e' su questa macchina");
        } else {
            JSONObject corr = PackagePlan.correzioni();
            if (!corr.optBoolean("success")) {
                salta("il confronto con pkg vero: " + corr.optString("error")
                    + " (serve il database delle vulnerabilita': pkg audit -F)");
            } else {
                JSONObject per = corr.getJSONObject("pacchetti");
                java.util.Map<String, String[]> inst = PackagePlan.installati();
                int controllati = 0, concordi = 0;
                StringBuilder discordi = new StringBuilder();
                for (String nome : per.keySet()) {
                    String[] iv = inst.get(nome);
                    if (iv == null) continue;
                    JSONObject refr = UpdateManager.refertoAudit(nome, iv[0]);
                    controllati++;
                    if (refr.optBoolean("done") && refr.optInt("problems") > 0) concordi++;
                    else discordi.append(' ').append(nome).append('(')
                                 .append(refr.optBoolean("done") ? refr.optInt("problems") + " problemi" : "non fatto")
                                 .append(')');
                }
                if (controllati == 0) {
                    salta("il confronto con pkg vero: nessun pacchetto vulnerabile su questa macchina");
                } else {
                    vero("i " + controllati + " pacchetti che pkg dice vulnerabili lo sono anche nel referto"
                         + (discordi.length() > 0 ? " — discordi:" + discordi : ""),
                         concordi == controllati);
                }
                // E il caso che smaschera la domanda sbagliata: un pacchetto che pkg NON
                // considera vulnerabile ma che HA una storia in VuXML. Col solo nome pkg
                // risponde con tutte le voci di quel nome; con nome e versione risponde zero.
                // Sulla VM e' nginx, appena portato alla 1.30.6,3: 25 problemi contro 0.
                String conStoria = null;
                int soloNome = 0;
                org.json.JSONArray stack = UpdateManager.packagesStatus().optJSONArray("packages");
                for (int i = 0; stack != null && i < stack.length() && conStoria == null; i++) {
                    String nome = stack.getJSONObject(i).optString("name");
                    if (per.has(nome) || !inst.containsKey(nome)) continue;
                    int n = problemiDichiarati(org.mail_panel.util.Shell.runShell(
                            java.time.Duration.ofSeconds(120), "pkg audit " + nome + " 2>&1").output());
                    if (n > 0) { conStoria = nome; soloNome = n; }
                }
                if (conStoria == null) {
                    salta("il caso del solo nome: su questa macchina nessun pacchetto sano ha voci"
                        + " in VuXML, quindi la differenza non si puo' misurare");
                } else {
                    JSONObject refr = UpdateManager.refertoAudit(conStoria, inst.get(conStoria)[0]);
                    vero(conStoria + " " + inst.get(conStoria)[0] + ": pkg col solo nome dice "
                         + soloNome + " problemi, il referto per la versione installata ne dice "
                         + refr.optInt("problems"),
                         refr.optBoolean("done") && refr.optInt("problems") == 0);
                }
            }
        }

        System.out.println();
        if (saltati > 0) System.out.println(saltati + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(falliti == 0 ? "TUTTO OK" : falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    /** Il numero di problemi dalla riga finale di pkg audit; -1 se quella riga non c'e'. */
    private static int problemiDichiarati(String out) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(out == null ? "" : out);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static boolean cEPkg() {
        return org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }

    private static void salta(String nome) {
        System.out.println("  --   SALTATA: " + nome);
        saltati++;
    }
}
