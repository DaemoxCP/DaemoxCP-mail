package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.security.AcmeUser;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Con quale utente gira ogni servizio della posta, e due avvisi: un processo che gira da root
 * senza averne bisogno, e un utente che due servizi si dividono.
 *
 * <p>Root e' giusto solo dove serve per come il servizio e' fatto: i processi principali che aprono
 * le porte e poi cedono i privilegi (nginx, php-fpm, Postfix, Dovecot, rspamd), fail2ban che
 * comanda pf, il pannello che amministra la macchina, e i pochi processi di Postfix e Dovecot che
 * consegnano per conto di utenti diversi. Tutto il resto ha un utente suo, e un utente diviso fra
 * due servizi da' a ciascuno i file dell'altro: era il caso di Roundcube nel pool www, con
 * l'utente dei processi di nginx.
 *
 * <p>Si guarda cosa gira davvero (ps), non solo cosa dicono le configurazioni; dei pool di php-fpm
 * si guardano anche i file, perche' un pool sbagliato che oggi non ha processi li avra' domani.
 * Sola lettura: non cambia niente.
 */
public final class ServiceUsers {

    private static final Logger LOGGER = Logger.getLogger(ServiceUsers.class.getName());

    private ServiceUsers() {}

    /** Un processo: utente, pid, padre e riga di comando. */
    record Proc(String user, int pid, int ppid, String command) {}

    /**
     * Come si riconosce un processo di un servizio, e se root gli serve. Nel nome del servizio "$1"
     * diventa il primo gruppo della regex (il nome del pool di php-fpm).
     */
    record Rule(String service, Pattern command, boolean rootNeeded) {
        Rule(String service, String regex, boolean rootNeeded) { this(service, Pattern.compile(regex), rootNeeded); }
    }

    /** Nell'ordine: vince la prima che riconosce il processo. */
    static final List<Rule> RULES = List.of(
            new Rule("mail-panel", "freebsd-mail-panel[^ /]*\\.jar", true),
            new Rule("fail2ban", "fail2ban-server", true),
            new Rule("nginx", "^nginx: master process", true),
            new Rule("nginx", "^nginx: ", false),
            new Rule("php-fpm", "^php-fpm: master process", true),
            new Rule("php-fpm pool $1", "^php-fpm: pool (\\S+)", false),
            new Rule("postfix", "/libexec/postfix/master( |$)", true),
            new Rule("dovecot", "^/usr/local/sbin/dovecot( |$)", true),
            // Questi Dovecot li tiene root per come e' fatto: leggono la configurazione, scrivono il
            // log, autenticano, consegnano a utenti diversi.
            new Rule("dovecot", "^dovecot/(config|log|auth|auth-worker|ssl-params|lmtp|doveadm-server)( |$)", true),
            new Rule("dovecot", "^dovecot/", false),
            new Rule("mysql", "/libexec/mysqld( |$)|/bin/mysqld_safe( |$)", false),
            new Rule("redis", "redis-server", false),
            new Rule("clamav", "/sbin/clamd( |$)|/bin/freshclam( |$)", false),
            new Rule("rspamd", "^rspamd: main process", true),
            new Rule("rspamd", "^rspamd: ", false),
            new Rule("unbound", "local-unbound( |$)|/sbin/unbound( |$)", false));

    /** I processi di Postfix che consegnano per conto di utenti diversi: root per come e' fatto. */
    private static final Set<String> POSTFIX_PRIVILEGED = Set.of("local", "virtual", "pipe", "spawn");

    /** ps -axww -o user= -o pid= -o ppid= -o command=: su FreeBSD "-o a=,b=" fa di ",b=" l'intestazione di a. */
    static List<Proc> processes(String ps) {
        List<Proc> out = new ArrayList<>();
        if (ps == null) return out;
        Pattern line = Pattern.compile("^\\s*(\\S+)\\s+(\\d+)\\s+(\\d+)\\s+(.*)$");
        for (String l : ps.split("\n")) {
            Matcher m = line.matcher(l);
            if (m.matches()) out.add(new Proc(m.group(1), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)), m.group(4).trim()));
        }
        return out;
    }

    /** Gli utenti dei processi di ogni pool di php-fpm: pool -> utenti. */
    public static Map<String, Set<String>> poolUsers(String ps) {
        Map<String, Set<String>> out = new TreeMap<>();
        Pattern pool = Pattern.compile("^php-fpm: pool (\\S+)");
        for (Proc p : processes(ps)) {
            Matcher m = pool.matcher(p.command());
            if (m.find()) out.computeIfAbsent(m.group(1), k -> new LinkedHashSet<>()).add(p.user());
        }
        return out;
    }

    /** Un servizio: i suoi utenti, e quali processi girano da root senza bisogno. */
    static final class Service {
        final String name;
        final Set<String> users = new LinkedHashSet<>();
        final Set<String> needlessRoot = new LinkedHashSet<>();
        int processes;
        Service(String name) { this.name = name; }
    }

    /** Un avviso: il codice (per la pagina), il servizio, l'utente e il dettaglio. */
    record Problem(String code, String service, String user, String detail) {
        /** La frase per il log, in inglese come il resto del log. */
        String logText() {
            return switch (code) {
                case "root" -> service + " runs as root without needing it: " + detail;
                case "shared" -> "the user " + user + " is shared by " + detail;
                case "poolRoot" -> "the php-fpm pool " + service + " is configured to run as root (" + detail + ")";
                case "poolShared" -> "the php-fpm pool " + service + " is configured to run as " + user + ", the user of " + detail;
                case "acmeRoot" -> "acme.sh runs as root: " + detail;
                case "rotation" -> "a log rotation recreates the webmail logs as " + user + ": " + detail;
                default -> service + ": " + detail;
            };
        }
    }

    /** Il risultato: i servizi coi loro utenti e gli avvisi. */
    record Findings(Map<String, Service> services, List<Problem> problems, List<String[]> pools) {}

    /**
     * Cosa gira e con chi. {@code poolFiles}: il testo dei file di php-fpm.d; {@code rootCrontab}
     * il cron di root ("" se non c'e'); {@code acmeAsRoot} vero se acme.sh gira ancora da root;
     * {@code rotations}: il testo delle rotazioni di newsyslog.conf.d.
     */
    static Findings examine(List<Proc> procs, Map<Path, String> poolFiles, String rootCrontab,
                            boolean acmeAsRoot, Map<Path, String> rotations) {
        Map<String, Service> services = new LinkedHashMap<>();
        List<Problem> problems = new ArrayList<>();
        Map<Integer, Proc> byPid = new LinkedHashMap<>();
        for (Proc p : procs) byPid.put(p.pid(), p);

        for (Proc p : procs) {
            String name = null;
            boolean rootNeeded = false;
            for (Rule r : RULES) {
                Matcher m = r.command().matcher(p.command());
                if (!m.find()) continue;
                name = m.groupCount() > 0 && m.group(1) != null && r.service().contains("$1")
                        ? r.service().replace("$1", m.group(1)) : r.service();
                rootNeeded = r.rootNeeded();
                break;
            }
            // I figli del master di Postfix sono Postfix, qualunque nome abbiano.
            Proc parent = byPid.get(p.ppid());
            if (name == null && parent != null && parent.command().matches(".*/libexec/postfix/master( .*|$)")) {
                name = "postfix";
                rootNeeded = POSTFIX_PRIVILEGED.contains(p.command().split("\\s+")[0]);
            }
            if (name == null) continue;
            Service s = services.computeIfAbsent(name, Service::new);
            s.users.add(p.user());
            s.processes++;
            if ("root".equals(p.user()) && !rootNeeded) s.needlessRoot.add(p.command().split("\\s+")[0]);
        }
        for (Service s : services.values())
            if (!s.needlessRoot.isEmpty())
                problems.add(new Problem("root", s.name, "root", String.join(", ", s.needlessRoot)));

        // Un utente (non root) di due servizi diversi. php-fpm: ogni pool e' un servizio a se'.
        Map<String, Set<String>> byUser = new TreeMap<>();
        for (Service s : services.values())
            for (String u : s.users)
                if (!"root".equals(u)) byUser.computeIfAbsent(u, k -> new LinkedHashSet<>()).add(s.name);
        for (Map.Entry<String, Set<String>> e : byUser.entrySet())
            if (e.getValue().size() > 1)
                problems.add(new Problem("shared", String.join(", ", e.getValue()), e.getKey(), String.join(" and ", e.getValue())));

        // I pool configurati, anche quelli senza processi in questo momento.
        Set<String> webUsers = new LinkedHashSet<>(List.of(RoundcubeUser.WEB_GROUP));
        Service nginx = services.get("nginx");
        if (nginx != null) for (String u : nginx.users) if (!"root".equals(u)) webUsers.add(u);
        List<String[]> pools = new ArrayList<>();
        for (Map.Entry<Path, String> f : poolFiles.entrySet()) {
            for (RoundcubeUser.Pool pool : RoundcubeUser.pools(f.getValue())) {
                String u = pool.get("user") == null ? "" : pool.get("user");
                pools.add(new String[] { f.getKey().toString(), pool.name(), u });
                if ("root".equals(u) || u.isEmpty())
                    problems.add(new Problem("poolRoot", pool.name(), "root", f.getKey().toString()));
                else if (webUsers.contains(u))
                    problems.add(new Problem("poolShared", pool.name(), u, "nginx (" + f.getKey() + ")"));
            }
        }

        // acme.sh non e' un processo che resta: si guarda da dove lo si esegue.
        Service acme = new Service("acme.sh");
        if (acmeAsRoot) {
            acme.users.add("root");
            problems.add(new Problem("acmeRoot", "acme.sh", "root", AcmeUser.OLD_HOME));
        } else if (Files.isRegularFile(Path.of(AcmeUser.SCRIPT))) {
            acme.users.add(AcmeUser.USER);
        }
        if (rootCrontab != null)
            for (String l : rootCrontab.split("\n"))
                if (!l.trim().startsWith("#") && l.contains("acme.sh")) {
                    acme.users.add("root");
                    problems.add(new Problem("acmeRoot", "acme.sh", "root", "root's crontab: " + l.trim()));
                }
        if (!acme.users.isEmpty()) services.put(acme.name, acme);

        // Le rotazioni che ricreerebbero i log della webmail con l'utente di nginx.
        if (RoundcubeUser.migrated(RoundcubeUser.Places.real()))
            for (Map.Entry<Path, String> r : rotations.entrySet())
                for (String l : r.getValue().split("\n"))
                    if (!l.trim().startsWith("#") && (l.contains(RoundcubeUser.ROUNDCUBE_DIR) || l.contains(RoundcubeUser.PHP_ERRORS_LOG))
                            && l.matches(".*\\s" + Pattern.quote(RoundcubeUser.WEB_GROUP) + ":\\S+\\s.*"))
                        problems.add(new Problem("rotation", "newsyslog", RoundcubeUser.WEB_GROUP, r.getKey() + ": " + l.trim()));

        return new Findings(services, problems, pools);
    }

    /** Quello che c'e' su questa macchina adesso. */
    static Findings now() {
        Duration d = Duration.ofSeconds(20);
        List<Proc> procs = processes(Shell.run(d, "ps", "-axww", "-o", "user=", "-o", "pid=", "-o", "ppid=", "-o", "command=").output());
        Map<Path, String> pools = readAll(Path.of(RoundcubeUser.FPM_DIR), ".conf");
        Map<Path, String> rotations = readAll(Path.of(RoundcubeUser.NEWSYSLOG_DIR), ".conf");
        Shell.Result c = Shell.run(d, "crontab", "-l", "-u", "root");
        String crontab = c.success() ? c.output() : "";
        AcmeUser.Layout l = AcmeUser.layout();
        return examine(procs, pools, crontab, l != null && !l.asAcme(), rotations);
    }

    private static Map<Path, String> readAll(Path dir, String suffix) {
        Map<Path, String> out = new TreeMap<>();
        if (!Files.isDirectory(dir)) return out;
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : s.filter(x -> x.getFileName().toString().endsWith(suffix) && Files.isRegularFile(x)).sorted().toList())
                out.put(p, Files.readString(p, StandardCharsets.UTF_8));
        } catch (IOException e) {
            LOGGER.warning("[ServiceUsers] cannot read " + dir + ": " + e.getMessage());
        }
        return out;
    }

    /** All'avvio, dopo le migrazioni: gli avvisi nel log, uno per riga. */
    public static void logAtBoot() {
        try {
            for (Problem p : now().problems()) LOGGER.warning("[ServiceUsers] " + p.logText());
        } catch (Throwable t) {
            LOGGER.warning("[ServiceUsers] check failed: " + t);
        }
    }

    /** Per la pagina: i servizi, i loro utenti, gli avvisi. */
    public static JSONObject state() {
        Findings f = now();
        JSONArray services = new JSONArray();
        for (Service s : f.services().values()) {
            boolean warned = false;
            for (Problem p : f.problems())
                if (java.util.Arrays.asList(p.service().split(", ")).contains(s.name)) warned = true;
            services.put(new JSONObject().put("service", s.name).put("users", new JSONArray(s.users))
                    .put("processes", s.processes).put("ok", !warned));
        }
        JSONArray problems = new JSONArray();
        for (Problem p : f.problems())
            problems.put(new JSONObject().put("code", p.code()).put("text", I18n.tr("server.su." + p.code(),
                    Map.of("service", p.service(), "user", p.user(), "detail", p.detail()))));
        JSONArray pools = new JSONArray();
        for (String[] p : f.pools()) pools.put(new JSONObject().put("file", p[0]).put("pool", p[1]).put("user", p[2]));
        return new JSONObject().put("success", true).put("services", services).put("problems", problems).put("pools", pools);
    }
}
