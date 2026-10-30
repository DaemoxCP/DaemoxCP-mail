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
 *    vulnerabilita' nota registrata per questo pacchetto", mentre PackagePlan.fixes
 *    trovava la fix nella 8.4.27;
 *  - senza il database delle vulnerabilita' pkg dice "vulnxml file vuln.xml does not exist"
 *    ed esce 1, e chi cerca solo le righe "is vulnerable" conclude "nessuna vulnerabilita'":
 *    una rassicurazione al posto di un "non ho potuto controllare".
 *
 * Le uscite usate qui sono quelle vere, copiate da quella misura.
 */
public class AuditReportTest {

    private static int failures = 0, skipped = 0;

    /** Il referto vero di `pkg audit 'php84-8.4.26'`, accorciato ai pezzi che contano. */
    private static final String VULNERABLE_REPORT =
            "php84-8.4.26 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "  WWW: https://vuxml.FreeBSD.org/freebsd/d8e16d08-cd2f-11f1-8135-8447094a420f.html\n"
          + "\n"
          + "1 problem(s) in 1 package(s) found.\n";

    /** Il referto vero di `pkg audit 'nginx-1.30.6,3'` dopo l'aggiornamento. */
    private static final String CLEAN_REPORT = "0 problem(s) in 0 package(s) found.\n";

    /** Quello che pkg risponde senza il database delle vulnerabilita'. */
    private static final String REPORT_WITHOUT_DATABASE =
            "pkg: vulnxml file vuln.xml does not exist. Try running 'pkg audit -F' first\n";

    /** Quello che rispondeva al SOLO NOME: nessuna versione nell'intestazione. */
    private static final String NAME_ONLY_REPORT =
            "php84 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "\n"
          + "3 problem(s) in 1 package(s) found.\n";

    public static void main(String[] args) {

        // ===== 1. Un pacchetto vulnerabile: il referto dice quanti problemi, e quali =====
        JSONObject v = UpdateManager.readAuditReport(VULNERABLE_REPORT, "php84",
                UpdateManager.emptyAuditReport("php84", "8.4.26"));
        check("il referto e' stato fatto", v.optBoolean("done"));
        check("conta 1 problema, come la riga finale di pkg", v.optInt("problems") == 1);
        check("legge il CVE", v.getJSONArray("cve").toString().contains("CVE-2026-11111"));
        check("legge la descrizione", v.optString("description").contains("multiple vulnerabilities"));
        check("legge il riferimento", v.getJSONArray("references").toString().contains("vuxml.FreeBSD.org"));

        // ===== 2. Un pacchetto pulito: zero problemi, ma il controllo c'e' stato =====
        JSONObject p = UpdateManager.readAuditReport(CLEAN_REPORT, "nginx",
                UpdateManager.emptyAuditReport("nginx", "1.30.6,3"));
        check("il referto di un pacchetto pulito e' stato fatto", p.optBoolean("done"));
        check("e dice zero problemi", p.optInt("problems") == 0);

        // ===== 3. Senza il database: NON si dice "nessuna vulnerabilita'" =====
        JSONObject s = UpdateManager.readAuditReport(REPORT_WITHOUT_DATABASE, "nginx",
                UpdateManager.emptyAuditReport("nginx", "1.30.6,3"));
        check("senza il database il referto NON risulta fatto", !s.optBoolean("done"));
        check("e il motivo nomina pkg audit -F", s.optString("error").contains("pkg audit -F"));
        check("e i problemi non si contano come zero rassicurante",
             s.optInt("problems") == 0 && !s.optBoolean("done"));

        // ===== 4. Uscita vuota (comando non eseguito, timeout): idem =====
        check("un'uscita vuota non e' un referto",
             !UpdateManager.readAuditReport("", "nginx", UpdateManager.emptyAuditReport("nginx", "1.0")).optBoolean("done"));
        check("e nemmeno un'uscita nulla",
             !UpdateManager.readAuditReport(null, "nginx", UpdateManager.emptyAuditReport("nginx", "1.0")).optBoolean("done"));

        // ===== 5. Il referto del SOLO NOME: perche' le due correzioni vanno insieme =====
        // Qui la riga finale c'e', quindi "done" e' vero, ma l'intestazione non porta la
        // versione e i dettagli restano vuoti: contare i CVE avrebbe dato zero mentre pkg
        // diceva "is vulnerable". Chiedere con nome e versione e' cio' che rende leggibili
        // i dettagli; pretendere la riga finale e' cio' che distingue un referto da un errore.
        JSONObject nameOnlyReport = UpdateManager.readAuditReport(NAME_ONLY_REPORT, "php84",
                UpdateManager.emptyAuditReport("php84", "8.4.26"));
        check("dal referto del solo nome i dettagli non si leggono", nameOnlyReport.getJSONArray("cve").isEmpty());
        check("  e il conto sarebbe 3 invece di 1", nameOnlyReport.optInt("problems") == 3);

        // ===== 6. Una versione che non passa il filtro non diventa una riga di comando =====
        JSONObject malformed = UpdateManager.auditReport("nginx", "1.0; rm -rf /");
        check("una versione non conforme non si esegue", !malformed.optBoolean("done"));
        check("  e lo dice", !malformed.optString("error").isEmpty());
        check("un nome non conforme non si esegue",
             !UpdateManager.auditReport("ngi nx", "1.0").optBoolean("done"));

        // ===== 7. Contro pkg vero: chi e' vulnerabile per pkg lo e' anche per il referto =====
        if (!hasPkg()) {
            skip("il confronto con pkg vero: pkg non c'e' su questa macchina");
        } else {
            JSONObject fixes = PackagePlan.fixes();
            if (!fixes.optBoolean("success")) {
                skip("il confronto con pkg vero: " + fixes.optString("error")
                    + " (serve il database delle vulnerabilita': pkg audit -F)");
            } else {
                JSONObject byPackage = fixes.getJSONObject("packages");
                java.util.Map<String, String[]> inst = PackagePlan.installed();
                int checked = 0, agreeing = 0;
                StringBuilder disagreeing = new StringBuilder();
                for (String name : byPackage.keySet()) {
                    String[] iv = inst.get(name);
                    if (iv == null) continue;
                    JSONObject report = UpdateManager.auditReport(name, iv[0]);
                    checked++;
                    if (report.optBoolean("done") && report.optInt("problems") > 0) agreeing++;
                    else disagreeing.append(' ').append(name).append('(')
                                 .append(report.optBoolean("done") ? report.optInt("problems") + " problemi" : "non fatto")
                                 .append(')');
                }
                if (checked == 0) {
                    skip("il confronto con pkg vero: nessun pacchetto vulnerabile su questa macchina");
                } else {
                    check("i " + checked + " pacchetti che pkg dice vulnerabili lo sono anche nel referto"
                         + (disagreeing.length() > 0 ? " — discordi:" + disagreeing : ""),
                         agreeing == checked);
                }
                // E il caso che smaschera la domanda sbagliata: un pacchetto che pkg NON
                // considera vulnerabile ma che HA una storia in VuXML. Col solo nome pkg
                // risponde con tutte le voci di quel nome; con nome e versione risponde zero.
                // Sulla VM e' nginx, appena portato alla 1.30.6,3: 25 problemi contro 0.
                String withHistory = null;
                int nameOnly = 0;
                org.json.JSONArray stack = UpdateManager.packagesStatus().optJSONArray("packages");
                for (int i = 0; stack != null && i < stack.length() && withHistory == null; i++) {
                    String name = stack.getJSONObject(i).optString("name");
                    if (byPackage.has(name) || !inst.containsKey(name)) continue;
                    int n = declaredProblems(org.mail_panel.util.Shell.runShell(
                            java.time.Duration.ofSeconds(120), "pkg audit " + name + " 2>&1").output());
                    if (n > 0) { withHistory = name; nameOnly = n; }
                }
                if (withHistory == null) {
                    skip("il caso del solo nome: su questa macchina nessun pacchetto sano ha voci"
                        + " in VuXML, quindi la differenza non si puo' misurare");
                } else {
                    JSONObject report = UpdateManager.auditReport(withHistory, inst.get(withHistory)[0]);
                    check(withHistory + " " + inst.get(withHistory)[0] + ": pkg col solo nome dice "
                         + nameOnly + " problemi, il referto per la versione installata ne dice "
                         + report.optInt("problems"),
                         report.optBoolean("done") && report.optInt("problems") == 0);
                }
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(failures == 0 ? "TUTTO OK" : failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Il numero di problemi dalla riga finale di pkg audit; -1 se quella riga non c'e'. */
    private static int declaredProblems(String out) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(out == null ? "" : out);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static boolean hasPkg() {
        return org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    private static void skip(String name) {
        System.out.println("  --   SALTATA: " + name);
        skipped++;
    }
}
