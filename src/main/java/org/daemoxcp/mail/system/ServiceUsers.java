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
 * Which user each mail service runs as, and two warnings: a process running as root
 * without needing it, and a user that two services share.
 *
 * <p>Root is right only where it is needed by the way the service is made: the main processes that open
 * the ports and then drop privileges (nginx, php-fpm, Postfix, Dovecot, rspamd), fail2ban which
 * drives pf, the panel which administers the machine, and the few Postfix and Dovecot processes that
 * deliver on behalf of different users. Everything else has a user of its own, and a user shared by
 * two services gives each one the other's files: that was the case of Roundcube in the www pool, with
 * the user of the nginx processes.
 *
 * <p>We look at what really runs (ps), not only at what the configurations say; for the php-fpm pools
 * the files are looked at too, because a wrong pool that has no processes today will have them tomorrow.
 * Read-only: it changes nothing.
 *
 * <p>For each service also what each of its users does (finding 228, requested by the owner on 2026-11-15: the
 * panel always says which user each package runs as, and if it uses more than one, what each one is for): the
 * processes of that user with a short name (master, imap-login, qmgr, the web part...) and a sentence from the
 * language files (server.su.purpose.service.user) where the user is the one the panel installs. Also the users
 * that run only when needed: acme.sh and sievec.
 */
public final class ServiceUsers {

    private static final Logger LOGGER = Logger.getLogger(ServiceUsers.class.getName());

    private ServiceUsers() {}

    /** A process: user, pid, parent and command line. */
    record Proc(String user, int pid, int ppid, String command) {}

    /**
     * How a process of a service is recognised, and whether it needs root. In the service name "$1"
     * becomes the first group of the regex (the name of the php-fpm pool).
     */
    record Rule(String service, Pattern command, boolean rootNeeded) {
        Rule(String service, String regex, boolean rootNeeded) { this(service, Pattern.compile(regex), rootNeeded); }
    }

    /** The panel's jar in the command line, with the current name or with an earlier one. */
    static final String JAR = "(" + String.join("|", jarNames()) + ")[^ /]*\\.jar";

    private static List<String> jarNames() {
        List<String> n = new java.util.ArrayList<>(List.of(Product.SLUG));
        n.addAll(LegacyNames.oldNamesOf("jarNames", Product.SLUG));
        return n;
    }

    /** In order: the first one that recognises the process wins. */
    static final List<Rule> RULES = List.of(
            // The panel's two daemon(8) supervisors, by their titles: the rc script's runs the root part and writes its
            // log, root like it; the web part's runs as daemoxcp_mail since 23/11/2026 (PanelSeparation): as root it
            // is a warning.
            new Rule(Product.SLUG, "^daemon: " + Pattern.quote(PanelSeparation.TITLE) + "\\[", false),
            new Rule(Product.SLUG, "^daemon: " + Pattern.quote(Product.ID) + "\\[", true),
            // The web part of the separated panel (PanelSeparation) runs as its own user: as root it is a warning.
            // The jar is also recognised by its earlier name (section "jarNames"): until the restart the process
            // still shows it.
            new Rule(Product.SLUG, JAR + ".* --web-part( |$)", false),
            new Rule(Product.SLUG, JAR, true),
            new Rule("fail2ban", "fail2ban-server", true),
            new Rule("nginx", "^nginx: master process", true),
            new Rule("nginx", "^nginx: ", false),
            new Rule("php-fpm", "^php-fpm: master process", true),
            new Rule("php-fpm pool $1", "^php-fpm: pool (\\S+)", false),
            new Rule("postfix", "/libexec/postfix/master( |$)", true),
            new Rule("dovecot", "^/usr/local/sbin/dovecot( |$)", true),
            // These Dovecot processes are kept as root by design: they read the configuration, write the
            // log, deliver to different users. Not authentication: auth already runs as dovecot, and
            // auth-worker ("dovecot/auth -w") looks up passwords in MySQL, so it does not need root
            // (DovecotAuthWorker moves it at startup): if it is seen as root it is a warning.
            new Rule("dovecot", "^dovecot/(config|log|ssl-params|lmtp|doveadm-server)( |$)", true),
            new Rule("dovecot", "^dovecot/", false),
            new Rule("mysql", "/libexec/mysqld( |$)|/bin/mysqld_safe( |$)", false),
            new Rule("redis", "redis-server", false),
            new Rule("clamav", "/sbin/clamd( |$)|/bin/freshclam( |$)", false),
            // The main rspamd process does not need root: ports above 1023 and files of its own
            // (RspamdUser starts it with its own user). As root it is a warning.
            new Rule("rspamd", "^rspamd: main process", false),
            new Rule("rspamd", "^rspamd: ", false),
            new Rule("unbound", "local-unbound( |$)|/sbin/unbound( |$)", false));

    /**
     * An official page behind what the card says about a service: its title is server.su.doc.ID in the language files.
     * Every address was opened and read before it was written here (23/11/2026), and says what the card says.
     */
    record Doc(String id, String url) {}

    /** The only hosts a documentation link may point to: the projects' own sites, FreeBSD's manual, NVD. */
    static final Set<String> DOC_HOSTS = Set.of("bugs.php.net", "dev.mysql.com", "doc.dovecot.org", "docs.rspamd.com", "github.com", "man.freebsd.org", "nginx.org", "redis.io", "www.php.net", "www.postfix.org");

    /** Service -> its official pages. "php-fpm pool" stands for every pool. */
    static final Map<String, List<Doc>> DOCS = Map.ofEntries(
            Map.entry(Product.SLUG, List.of(
                    new Doc("daemon8", "https://man.freebsd.org/cgi/man.cgi?query=daemon&sektion=8&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"),
                    new Doc("chroot8", "https://man.freebsd.org/cgi/man.cgi?query=chroot&sektion=8&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"),
                    new Doc("unixSocket", "https://man.freebsd.org/cgi/man.cgi?query=unix&sektion=4&manpath=FreeBSD+15.0-RELEASE#ADDRESSING"))),
            Map.entry("postfix", List.of(
                    new Doc("postfixPrivileged", "https://www.postfix.org/UNPRIVILEGED_README.html#security-model"),
                    new Doc("postfixMasterCf", "https://www.postfix.org/master.5.html#syntax"),
                    new Doc("postfixLocal", "https://www.postfix.org/local.8.html#security"),
                    new Doc("postfixMailOwner", "https://www.postfix.org/postconf.5.html#mail_owner"),
                    new Doc("freebsdIp", "https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"))),
            Map.entry("dovecot", List.of(
                    new Doc("dovecotMaster", "https://doc.dovecot.org/2.4.5/developers/design/processes.html#master-process"),
                    new Doc("dovecotConfigLog", "https://doc.dovecot.org/2.4.5/core/config/service.html#config"),
                    new Doc("dovecotAnvil", "https://doc.dovecot.org/2.4.5/core/config/service.html#anvil"),
                    new Doc("dovecotLogin", "https://doc.dovecot.org/2.4.5/core/config/login_processes.html#login-processes"),
                    new Doc("freebsdIp", "https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"))),
            Map.entry("nginx", List.of(
                    new Doc("nginxMaster", "https://nginx.org/en/docs/beginners_guide.html"),
                    new Doc("nginxSockets", "https://nginx.org/en/docs/control.html#reconfiguration"),
                    new Doc("nginxUser", "https://nginx.org/en/docs/ngx_core_module.html#user"),
                    new Doc("freebsdIp", "https://man.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"))),
            Map.entry("php-fpm", List.of(
                    new Doc("phpFpmUser", "https://github.com/php/php-src/blob/c93b3d151f50a30dceb41744a42d42a76ef002c8/sapi/fpm/www.conf.in#L20-L26"),
                    new Doc("phpFpmCve", "https://bugs.php.net/bug.php?id=81026"),
                    new Doc("phpFpmListen", "https://www.php.net/manual/en/install.fpm.configuration.php#listen-owner"),
                    new Doc("rcSubrUser", "https://man.freebsd.org/cgi/man.cgi?query=rc.subr&sektion=8&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"),
                    new Doc("unixSocket", "https://man.freebsd.org/cgi/man.cgi?query=unix&sektion=4&manpath=FreeBSD+15.0-RELEASE#ADDRESSING"))),
            Map.entry("php-fpm pool", List.of(
                    new Doc("phpFpmUser", "https://github.com/php/php-src/blob/c93b3d151f50a30dceb41744a42d42a76ef002c8/sapi/fpm/www.conf.in#L20-L26"),
                    new Doc("phpFpmListen", "https://www.php.net/manual/en/install.fpm.configuration.php#listen-owner"))),
            Map.entry("fail2ban", List.of(
                    new Doc("fail2banRoot", "https://github.com/fail2ban/fail2ban/blob/cae17d2f99d53d613c4e5ed9d1b2328f201a3612/doc/run-rootless.txt#L1-L5"),
                    new Doc("pfDevice", "https://man.freebsd.org/cgi/man.cgi?query=pf&sektion=4&manpath=FreeBSD+15.0-RELEASE#DESCRIPTION"),
                    new Doc("pfDeviceMode", "https://github.com/freebsd/freebsd-src/blob/2b7df8c16dc77a6774a4d309477b1238fe725d93/sys/netpfil/pf/pf_ioctl.c#L7075"))),
            Map.entry("rspamd", List.of(
                    new Doc("rspamdIsolation", "https://docs.rspamd.com/developers/architecture/#process-isolation"))),
            Map.entry("redis", List.of(
                    new Doc("redisSecurity", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/#code-security"))),
            Map.entry("clamav", List.of(
                    new Doc("clamdConf", "https://man.freebsd.org/cgi/man.cgi?query=clamd.conf&sektion=5&manpath=FreeBSD+15.0-RELEASE+and+Ports"),
                    new Doc("freshclamConf", "https://man.freebsd.org/cgi/man.cgi?query=freshclam.conf&sektion=5&manpath=FreeBSD+15.0-RELEASE+and+Ports"))),
            Map.entry("mysql", List.of(
                    new Doc("mysqlNoRoot", "https://dev.mysql.com/doc/refman/8.4/en/security-against-attack.html"),
                    new Doc("mysqlUser", "https://dev.mysql.com/doc/refman/8.4/en/changing-mysql-user.html"))),
            Map.entry("unbound", List.of(
                    new Doc("localUnbound", "https://man.freebsd.org/cgi/man.cgi?query=local-unbound.conf&sektion=5&manpath=FreeBSD+15.0-RELEASE"))),
            Map.entry("acme.sh", List.of(
                    new Doc("acmeNoRoot", "https://github.com/acmesh-official/acme.sh/blob/5567d7fe7298fd37aca53194885ba444c6678669/README.md?plain=1#L71"))),
            Map.entry("sievec", List.of(
                    new Doc("sievec", "https://doc.dovecot.org/2.4.5/core/man/sievec.1.html#description"))));

    /** The official pages of a service; every php-fpm pool has the pool's ones. */
    static List<Doc> docsOf(String service) {
        return DOCS.getOrDefault(service.startsWith("php-fpm pool ") ? "php-fpm pool" : service, List.of());
    }

    /**
     * Where root stays, the reason put into words on the page (server.su.rootWhy.*): only the services
     * that really need root by the way they are made. Whoever looks at it must be able to understand that it
     * is not an oversight.
     */
    static final Map<String, String> ROOT_WHY = Map.of("postfix", "postfix", "dovecot", "dovecot", "nginx", "nginx",
            "php-fpm", "phpFpm", "fail2ban", "fail2ban", Product.SLUG, "daemoxcpMail");

    /** The Postfix processes that deliver on behalf of different users: root by design. */
    private static final Set<String> POSTFIX_PRIVILEGED = Set.of("local", "virtual", "pipe", "spawn");

    /** The interpreters: for "/bin/sh /usr/local/bin/mysqld_safe ..." what counts is the program they run. */
    private static final Set<String> INTERPRETERS = Set.of("sh", "bash", "perl", "python", "python3");

    /**
     * The short name of a process, to say what it does: "master", "worker", "imap-login", "qmgr", "auth-worker";
     * for the panel the option it runs with (--web the root part, --web-part the web part: they are two java
     * processes, and the technical name stays the same in every language, like "master"; what they do is told by
     * the sentences in the language files); otherwise the program without its path. Pure.
     */
    static String processName(String service, String command) {
        String c = command == null ? "" : command.trim();
        if (Product.SLUG.equals(service) && c.startsWith("daemon: ")) return "daemon";
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
     * The language-file key for what a user of a service does: server.su.purpose.SERVICE.USER, with the service
     * name as the keys want it (daemoxcp-mail -> daemoxcpMail, php-fpm -> phpFpm, "php-fpm pool X" -> pool.X,
     * acme.sh -> acme). Pure.
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
     * The users that keep no processes running but run when needed: acme.sh (already in examine, from its script
     * and from cron) and sievec, which compiles the panel's Sieve rules when they are saved (SieveCompiler,
     * finding 218). Pure: {@code sievecUser} says whether the user exists.
     */
    static void addOnDemand(Findings f, boolean sievecUser) {
        if (sievecUser && !f.services().containsKey(SieveCompiler.USER)) {
            Service s = new Service(SieveCompiler.USER);
            s.users.add(SieveCompiler.USER);
            s.roles.computeIfAbsent(SieveCompiler.USER, k -> new LinkedHashSet<>()).add("sievec");
            f.services().put(s.name, s);
        }
    }

    /** ps -axww -o user= -o pid= -o ppid= -o command=: on FreeBSD "-o a=,b=" makes ",b=" the header of a. */
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

    /** The process users of each php-fpm pool: pool -> users. */
    public static Map<String, Set<String>> poolUsers(String ps) {
        Map<String, Set<String>> out = new TreeMap<>();
        Pattern pool = Pattern.compile("^php-fpm: pool (\\S+)");
        for (Proc p : processes(ps)) {
            Matcher m = pool.matcher(p.command());
            if (m.find()) out.computeIfAbsent(m.group(1), k -> new LinkedHashSet<>()).add(p.user());
        }
        return out;
    }

    /** A service: its users, and which processes run as root without needing to. */
    static final class Service {
        final String name;
        final Set<String> users = new LinkedHashSet<>();
        /** User -> the short names of its processes: what each user of the service does. */
        final Map<String, Set<String>> roles = new LinkedHashMap<>();
        final Set<String> needlessRoot = new LinkedHashSet<>();
        /** The short names of the processes that run as root: those that need it, and those that do not. */
        final Set<String> neededRootNames = new LinkedHashSet<>();
        final Set<String> needlessRootNames = new LinkedHashSet<>();
        /** One of its processes runs as root and needs it: the page says why. */
        boolean neededRoot;
        int processes;
        Service(String name) { this.name = name; }
    }

    /** A warning: the code (for the page), the service, the user and the detail. */
    record Problem(String code, String service, String user, String detail) {
        /** The sentence for the log, in English like the rest of the log. */
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

    /** The result: the services with their users and the warnings. */
    record Findings(Map<String, Service> services, List<Problem> problems, List<String[]> pools) {}

    /**
     * What runs and as whom. {@code poolFiles}: the text of the php-fpm.d files; {@code rootCrontab}
     * root's cron ("" if there is none); {@code acmeAsRoot} true if acme.sh still runs as root;
     * {@code rotations}: the text of the newsyslog.conf.d rotations.
     */
    static Findings examine(List<Proc> procs, Map<Path, String> poolFiles, String rootCrontab,
                            boolean acmeAsRoot, Map<Path, String> rotations) {
        return examine(procs, poolFiles, rootCrontab, acmeAsRoot, rotations, false);
    }

    /**
     * The same, knowing whether Dovecot 2.4 is there. There anvil runs as root by the way 2.4 is made (in the
     * default values user is empty): it connects to the socket of every session process, which runs as vmail or
     * dovenull, to count and close the connections. Measured on the VM on 2026-11-09 (finding 213): with Dovecot's
     * internal user, doveadm kick makes anvil crash ("net_connect_unix(/var/run/dovecot/srv.imap/...) failed:
     * Permission denied", then Panic) and auth no longer reaches anvil-auth-penalty. On 2.3 anvil runs as dovecot:
     * there root remains a warning.
     */
    static Findings examine(List<Proc> procs, Map<Path, String> poolFiles, String rootCrontab,
                            boolean acmeAsRoot, Map<Path, String> rotations, boolean dovecot24) {
        Map<String, Service> services = new LinkedHashMap<>();
        List<Problem> problems = new ArrayList<>();
        Map<Integer, Proc> byPid = new LinkedHashMap<>();
        for (Proc p : procs) byPid.put(p.pid(), p);

        // php-fpm's master needs root only to start pools as different users: with Roundcube's pool alone it runs as
        // roundcube (PhpFpmMaster), and as root it is a warning; with other pools (added by hand) root stays right.
        Map<String, String> poolTexts = new TreeMap<>();
        for (Map.Entry<Path, String> f : poolFiles.entrySet()) poolTexts.put(f.getKey().toString(), f.getValue());
        boolean fpmRootNeeded = !PhpFpmMaster.otherPools(poolTexts).isEmpty();

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
            if ("php-fpm".equals(name) && p.command().startsWith("php-fpm: master")) rootNeeded = fpmRootNeeded;
            // The children of the Postfix master are Postfix, whatever their name.
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
            if ("root".equals(p.user()) && !rootNeeded) {
                s.needlessRoot.add(p.command().split("\\s+")[0]);
                s.needlessRootNames.add(processName(name, p.command()));
            }
            if ("root".equals(p.user()) && rootNeeded) {
                s.neededRoot = true;
                s.neededRootNames.add(processName(name, p.command()));
            }
        }
        for (Service s : services.values())
            if (!s.needlessRoot.isEmpty())
                problems.add(new Problem("root", s.name, "root", String.join(", ", s.needlessRoot)));

        // A user (not root) of two different services. php-fpm: each pool is a service of its own.
        Map<String, Set<String>> byUser = new TreeMap<>();
        for (Service s : services.values())
            for (String u : s.users)
                if (!"root".equals(u)) byUser.computeIfAbsent(u, k -> new java.util.TreeSet<>()).add(s.name);
        for (Map.Entry<String, Set<String>> e : byUser.entrySet()) {
            Set<String> names = new java.util.TreeSet<>(e.getValue());
            // A php-fpm master that is not root runs its pools as its own user (www.conf.default: user and group "can be
            // used only if the master process running user is root"): master and pool are one program, not two services.
            if (names.contains("php-fpm") && names.stream().anyMatch(n -> n.startsWith("php-fpm pool "))) names.remove("php-fpm");
            if (names.size() > 1)
                problems.add(new Problem("shared", String.join(", ", names), e.getKey(), String.join(" and ", names)));
        }

        // The configured pools, including those without processes at the moment.
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

        // acme.sh is not a process that stays: we look at where it is run from.
        Service acme = new Service("acme.sh");
        if (acmeAsRoot) {
            acme.users.add("root");
            acme.roles.computeIfAbsent("root", k -> new LinkedHashSet<>()).add("acme.sh");
            acme.needlessRootNames.add("acme.sh");
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
                    acme.needlessRootNames.add("acme.sh");
                    problems.add(new Problem("acmeRoot", "acme.sh", "root", "root's crontab: " + l.trim()));
                }
        if (!acme.users.isEmpty()) services.put(acme.name, acme);

        // The rotations that would recreate the webmail logs with the nginx user.
        if (RoundcubeUser.migrated(RoundcubeUser.Places.real()))
            for (Map.Entry<Path, String> r : rotations.entrySet())
                for (String l : r.getValue().split("\n"))
                    if (!l.trim().startsWith("#") && (l.contains(RoundcubeUser.ROUNDCUBE_DIR) || l.contains(RoundcubeUser.PHP_ERRORS_LOG))
                            && l.matches(".*\\s" + Pattern.quote(RoundcubeUser.WEB_GROUP) + ":\\S+\\s.*"))
                        problems.add(new Problem("rotation", "newsyslog", RoundcubeUser.WEB_GROUP, r.getKey() + ": " + l.trim()));

        return new Findings(services, problems, pools);
    }

    /** What is on this machine now. */
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

    /** At startup, after the migrations: the warnings in the log, one per line. */
    public static void logAtBoot() {
        try {
            for (Problem p : now().problems()) LOGGER.warning("[ServiceUsers] " + p.logText());
        } catch (Throwable t) {
            LOGGER.warning("[ServiceUsers] check failed: " + t);
        }
    }

    /**
     * What each user of a service does, for the page: root first, then the others as ps saw them; for each one
     * the names of its processes and, where the language files know it, what it is for.
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

    /**
     * Whether a service runs something as root: "needed" (only processes that must, by the way the program is made),
     * "none", or "needless" (at least one process that does not need it: the page warns). Pure.
     */
    static String rootStatus(Service s) {
        if (!s.needlessRootNames.isEmpty() || (s.users.contains("root") && !s.neededRoot)) return "needless";
        return s.neededRoot ? "needed" : "none";
    }

    /** The short names of the processes the root status is about: those that need root, or those that should not have it. */
    static List<String> rootProcesses(Service s) {
        return switch (rootStatus(s)) {
            case "needed" -> new ArrayList<>(s.neededRootNames);
            case "needless" -> new ArrayList<>(s.needlessRootNames.isEmpty() ? s.roles.getOrDefault("root", Set.of()) : s.needlessRootNames);
            default -> List.of();
        };
    }

    /** The documentation of a service for the page: title in the reader's language and address. */
    static JSONArray docs(String service) {
        JSONArray out = new JSONArray();
        for (Doc d : docsOf(service))
            out.put(new JSONObject().put("title", I18n.tr("server.su.doc." + d.id())).put("url", d.url()));
        return out;
    }

    /** For the page: the services, their users, the warnings. */
    public static JSONObject state() {
        Findings f = now();
        // The panel not separated: the page says so, with the reason. Only here and not in the log at startup,
        // where PanelSeparation has already said it.
        String notSeparated = PanelSeparation.notSeparatedReason();
        if (notSeparated != null && f.services().containsKey(Product.SLUG))
            f.problems().add(new Problem("panelLegacy", Product.SLUG, "root", notSeparated));
        JSONArray services = new JSONArray();
        for (Service s : f.services().values()) {
            boolean warned = false;
            for (Problem p : f.problems())
                if (java.util.Arrays.asList(p.service().split(", ")).contains(s.name)) warned = true;
            JSONObject o = new JSONObject().put("service", s.name).put("users", new JSONArray(s.users))
                    .put("processes", s.processes).put("ok", !warned).put("roles", roles(s))
                    .put("root", rootStatus(s)).put("rootProcesses", new JSONArray(rootProcesses(s))).put("docs", docs(s.name));
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
