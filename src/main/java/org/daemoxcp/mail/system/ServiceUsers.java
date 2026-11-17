package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.AcmeUser;
import org.daemoxcp.mail.util.Shell;

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
 *
 * <p>Per ogni servizio anche cosa fa ogni suo utente (reperto 228, chiesto dal committente il 15/11/2026: il pannello
 * dice sempre sotto che utente gira ogni pacchetto, e se ne usa piu' d'uno a che cosa serve ciascuno): i processi di
 * quell'utente con un nome corto (master, imap-login, qmgr, la parte web...) e una frase dai file di lingua
 * (server.su.purpose.servizio.utente) dove l'utente e' quello che il pannello installa. Anche gli utenti che girano
 * solo quando servono: acme.sh e sievec.
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

    /** Il jar del pannello nella riga di comando, col nome di adesso o con uno di prima. */
    static final String JAR = "(" + String.join("|", jarNames()) + ")[^ /]*\\.jar";

    private static List<String> jarNames() {
        List<String> n = new java.util.ArrayList<>(List.of(Product.SLUG));
        n.addAll(LegacyNames.oldNamesOf("jarNames", Product.SLUG));
        return n;
    }

    /** Nell'ordine: vince la prima che riconosce il processo. */
    static final List<Rule> RULES = List.of(
            // La parte web del pannello separato (PanelSeparation) gira col suo utente: da root e' un avviso. Il jar si
            // riconosce anche col nome di prima (sezione "jarNames"): fino al riavvio il processo lo mostra ancora.
            new Rule(Product.SLUG, JAR + ".* --web-part( |$)", false),
            new Rule(Product.SLUG, JAR, true),
            new Rule("fail2ban", "fail2ban-server", true),
            new Rule("nginx", "^nginx: master process", true),
            new Rule("nginx", "^nginx: ", false),
            new Rule("php-fpm", "^php-fpm: master process", true),
            new Rule("php-fpm pool $1", "^php-fpm: pool (\\S+)", false),
            new Rule("postfix", "/libexec/postfix/master( |$)", true),
            new Rule("dovecot", "^/usr/local/sbin/dovecot( |$)", true),
            // Questi Dovecot li tiene root per come e' fatto: leggono la configurazione, scrivono il
            // log, consegnano a utenti diversi. L'autenticazione no: auth gira gia' come dovecot, e
            // auth-worker ("dovecot/auth -w") cerca le password in MySQL, quindi root non gli serve
            // (DovecotAuthWorker lo sposta all'avvio): se lo si vede da root e' un avviso.
            new Rule("dovecot", "^dovecot/(config|log|ssl-params|lmtp|doveadm-server)( |$)", true),
            new Rule("dovecot", "^dovecot/", false),
            new Rule("mysql", "/libexec/mysqld( |$)|/bin/mysqld_safe( |$)", false),
            new Rule("redis", "redis-server", false),
            new Rule("clamav", "/sbin/clamd( |$)|/bin/freshclam( |$)", false),
            // Il processo principale di rspamd non ha bisogno di root: porte sopra la 1023 e file suoi
            // (RspamdUser lo avvia con il suo utente). Da root e' un avviso.
            new Rule("rspamd", "^rspamd: main process", false),
            new Rule("rspamd", "^rspamd: ", false),
            new Rule("unbound", "local-unbound( |$)|/sbin/unbound( |$)", false));

    /**
     * Dove root resta, il perche' detto a parole sulla pagina (server.su.rootWhy.*): solo i servizi a cui
     * root serve davvero per come sono fatti. Chi lo guarda deve poter capire che non e' una svista.
     */
    static final Map<String, String> ROOT_WHY = Map.of("postfix", "postfix", "dovecot", "dovecot", "nginx", "nginx",
            "php-fpm", "phpFpm", "fail2ban", "fail2ban", Product.SLUG, "daemoxcpMail");

    /** I processi di Postfix che consegnano per conto di utenti diversi: root per come e' fatto. */
    private static final Set<String> POSTFIX_PRIVILEGED = Set.of("local", "virtual", "pipe", "spawn");

    /** Gli interpreti: di "/bin/sh /usr/local/bin/mysqld_safe ..." conta il programma che eseguono. */
    private static final Set<String> INTERPRETERS = Set.of("sh", "bash", "perl", "python", "python3");

    /**
     * Il nome corto di un processo, per dire cosa fa: "master", "worker", "imap-login", "qmgr", "auth-worker"; del
     * pannello l'opzione con cui gira (--web la parte root, --web-part la parte web: sono due java, e il nome tecnico
     * resta tale in ogni lingua, come "master"; cosa fanno lo dicono le frasi dei file di lingua); altrimenti il
     * programma senza percorso. Puro.
     */
    static String processName(String service, String command) {
        String c = command == null ? "" : command.trim();
        if (Product.SLUG.equals(service))
            return c.matches(".*--web-part( .*|$)") ? "--web-part" : c.matches(".*--web( .*|$)") ? "--web" : "java";
        if (c.startsWith("nginx: ")) return c.replaceFirst("^nginx: (\\S+).*$", "$1");
        if (c.startsWith("php-fpm: master")) return "master";
        if (c.startsWith("php-fpm: pool ")) return "pool";
        if (c.startsWith("rspamd: ")) return c.replaceFirst("^rspamd: (\\S+).*$", "$1");
        if (c.matches(".*/libexec/postfix/master( .*|$)")) return "master";
        if (c.matches("^/usr/local/sbin/dovecot( .*|$)")) return "master";
        if (c.matches("^dovecot/auth -w( .*|$)")) return "auth-worker";
        if (c.startsWith("dovecot/")) return c.replaceFirst("^dovecot/(\\S+).*$", "$1");
        String[] t = c.split("\\s+");
        String first = base(t[0]);
        if (t.length > 1 && (INTERPRETERS.contains(first) || first.matches("python3\\.\\d+"))) first = base(t[1]);
        return first.endsWith(":") ? first.substring(0, first.length() - 1) : first;
    }

    private static String base(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /**
     * La chiave dei file di lingua per cosa fa un utente di un servizio: server.su.purpose.SERVIZIO.UTENTE, col nome del
     * servizio come lo vogliono le chiavi (daemoxcp-mail -> daemoxcpMail, php-fpm -> phpFpm, "php-fpm pool X" -> pool.X,
     * acme.sh -> acme). Pura.
     */
    static String purposeKey(String service, String user) {
        String s = switch (service) {
            case Product.SLUG -> "daemoxcpMail";
            case "php-fpm" -> "phpFpm";
            case "acme.sh" -> "acme";
            default -> service.startsWith("php-fpm pool ") ? "pool." + service.substring("php-fpm pool ".length()) : service;
        };
        return "server.su.purpose." + s + "." + user;
    }

    /**
     * Gli utenti che non tengono processi accesi ma girano quando servono: acme.sh (gia' in examine, dal suo script e
     * dal cron) e sievec, che compila le regole Sieve del pannello quando si salvano (SieveCompiler, reperto 218). Puro:
     * {@code sievecUser} dice se l'utente c'e'.
     */
    static void addOnDemand(Findings f, boolean sievecUser) {
        if (sievecUser && !f.services().containsKey(SieveCompiler.USER)) {
            Service s = new Service(SieveCompiler.USER);
            s.users.add(SieveCompiler.USER);
            s.roles.computeIfAbsent(SieveCompiler.USER, k -> new LinkedHashSet<>()).add("sievec");
            f.services().put(s.name, s);
        }
    }

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
        /** Utente -> i nomi corti dei suoi processi: cosa fa ciascun utente del servizio. */
        final Map<String, Set<String>> roles = new LinkedHashMap<>();
        final Set<String> needlessRoot = new LinkedHashSet<>();
        /** Un suo processo gira da root e gli serve: la pagina dice perche'. */
        boolean neededRoot;
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
        return examine(procs, poolFiles, rootCrontab, acmeAsRoot, rotations, false);
    }

    /**
     * Lo stesso, sapendo se c'e' Dovecot 2.4. Li' anvil gira da root per come e' fatta la 2.4 (nei valori
     * predefiniti user e' vuoto): si collega al socket di ogni processo di sessione, che gira come vmail o dovenull,
     * per contare e chiudere le connessioni. Misurato sulla VM il 09/11/2026 (reperto 213): con l'utente interno di
     * Dovecot, doveadm kick fa crollare anvil («net_connect_unix(/var/run/dovecot/srv.imap/...) failed: Permission
     * denied», poi Panic) e auth non raggiunge piu' anvil-auth-penalty. Sulla 2.3 anvil gira come dovecot: li' root
     * resta un avviso.
     */
    static Findings examine(List<Proc> procs, Map<Path, String> poolFiles, String rootCrontab,
                            boolean acmeAsRoot, Map<Path, String> rotations, boolean dovecot24) {
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
            if (dovecot24 && "dovecot".equals(name) && p.command().matches("dovecot/anvil( .*|$)")) rootNeeded = true;
            // I figli del master di Postfix sono Postfix, qualunque nome abbiano.
            Proc parent = byPid.get(p.ppid());
            if (name == null && parent != null && parent.command().matches(".*/libexec/postfix/master( .*|$)")) {
                name = "postfix";
                rootNeeded = POSTFIX_PRIVILEGED.contains(p.command().split("\\s+")[0]);
            }
            if (name == null) continue;
            Service s = services.computeIfAbsent(name, Service::new);
            s.users.add(p.user());
            s.roles.computeIfAbsent(p.user(), k -> new LinkedHashSet<>()).add(processName(name, p.command()));
            s.processes++;
            if ("root".equals(p.user()) && !rootNeeded) s.needlessRoot.add(p.command().split("\\s+")[0]);
            if ("root".equals(p.user()) && rootNeeded) s.neededRoot = true;
        }
        for (Service s : services.values())
            if (!s.needlessRoot.isEmpty())
                problems.add(new Problem("root", s.name, "root", String.join(", ", s.needlessRoot)));

        // Un utente (non root) di due servizi diversi. php-fpm: ogni pool e' un servizio a se'.
        Map<String, Set<String>> byUser = new TreeMap<>();
        for (Service s : services.values())
            for (String u : s.users)
                if (!"root".equals(u)) byUser.computeIfAbsent(u, k -> new java.util.TreeSet<>()).add(s.name);
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
            acme.roles.computeIfAbsent("root", k -> new LinkedHashSet<>()).add("acme.sh");
            problems.add(new Problem("acmeRoot", "acme.sh", "root", AcmeUser.OLD_HOME));
        } else if (Files.isRegularFile(Path.of(AcmeUser.SCRIPT))) {
            acme.users.add(AcmeUser.USER);
            acme.roles.computeIfAbsent(AcmeUser.USER, k -> new LinkedHashSet<>()).add("acme.sh");
        }
        if (rootCrontab != null)
            for (String l : rootCrontab.split("\n"))
                if (!l.trim().startsWith("#") && l.contains("acme.sh")) {
                    acme.users.add("root");
                    acme.roles.computeIfAbsent("root", k -> new LinkedHashSet<>()).add("acme.sh");
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
        boolean dovecot24 = !Shell.run(d, "pkg", "query", "-e", "%o = \"mail/dovecot24\"", "%n").outputTrim().isEmpty();
        Findings f = examine(procs, pools, crontab, l != null && !l.asAcme(), rotations, dovecot24);
        addOnDemand(f, Shell.run(d, "pw", "usershow", SieveCompiler.USER).success());
        return f;
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

    /**
     * Cosa fa ogni utente di un servizio, per la pagina: root per primo, poi gli altri come li ha visti ps; per ognuno i
     * nomi dei suoi processi e, dove i file di lingua lo sanno, a che cosa serve.
     */
    static JSONArray roles(Service s) {
        List<String> order = new ArrayList<>(s.roles.keySet());
        order.sort((a, b) -> Boolean.compare(!"root".equals(a), !"root".equals(b)));
        JSONArray out = new JSONArray();
        for (String user : order) {
            JSONObject r = new JSONObject().put("user", user).put("processes", new JSONArray(s.roles.get(user)));
            String key = purposeKey(s.name, user);
            String text = I18n.tr(key);
            if (!key.equals(text)) r.put("purpose", text);
            out.put(r);
        }
        return out;
    }

    /** Per la pagina: i servizi, i loro utenti, gli avvisi. */
    public static JSONObject state() {
        Findings f = now();
        // Il pannello non separato: la pagina lo dice, col motivo. Solo qui e non nel registro all'avvio, dove
        // l'ha gia' detto PanelSeparation.
        String notSeparated = PanelSeparation.notSeparatedReason();
        if (notSeparated != null && f.services().containsKey(Product.SLUG))
            f.problems().add(new Problem("panelLegacy", Product.SLUG, "root", notSeparated));
        JSONArray services = new JSONArray();
        for (Service s : f.services().values()) {
            boolean warned = false;
            for (Problem p : f.problems())
                if (java.util.Arrays.asList(p.service().split(", ")).contains(s.name)) warned = true;
            JSONObject o = new JSONObject().put("service", s.name).put("users", new JSONArray(s.users))
                    .put("processes", s.processes).put("ok", !warned).put("roles", roles(s));
            String why = ROOT_WHY.get(s.name);
            if (s.neededRoot && !warned && why != null) o.put("rootWhy", I18n.tr("server.su.rootWhy." + why));
            services.put(o);
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
