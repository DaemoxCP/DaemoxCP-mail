package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Set;
import java.util.logging.Logger;

/**
 * redis solo sul socket Unix, 0770 del gruppo redis, e rspamd in quel gruppo (reperto 235).
 *
 * <p>Prima redis ascoltava su 127.0.0.1:6379 e ::1:6379 senza password, com'e' il redis.conf del pacchetto: qualunque
 * processo della macchina (la webmail, un servizio bucato) leggeva e scriveva i dati di rspamd, cioe' Bayes, greylist,
 * limiti e storico, e poteva cancellarli tutti. Lo dice redis.conf stesso: «port 0» e redis non ascolta su TCP;
 * «unixsocket» e «unixsocketperm» il socket e i suoi permessi. Per rspamd («Redis configuration») un server redis puo'
 * essere un socket: servers = "/var/run/redis/redis.sock". Il socket nasce di redis:redis; 0770 e rspamd nel gruppo
 * redis, e ci entrano solo loro due (e root).
 *
 * <p>Sui server installati prima, all'avvio, in tre tempi, perche' rspamd non resti mai senza redis:
 * <ol>
 *   <li>redis apre anche il socket, tenendo la porta (riavviato: il socket c'e', di redis, 0770, risponde, i dati ci
 *       sono ancora), e rspamd entra nel gruppo redis;</li>
 *   <li>rspamd passa al socket (riavviato, perche' i gruppi di un processo si leggono solo quando parte: analizza un
 *       messaggio, e redis ha clienti sul socket oltre a chi glielo chiede);</li>
 *   <li>redis chiude la porta (port 0, riavviato: niente piu' 6379, e rspamd analizza e parla col socket).</li>
 * </ol>
 * Un errore nei primi due tempi rimette tutto com'era; nel terzo si torna allo stato di mezzo, che funziona, e il
 * prossimo avvio riprende da li'. Si cambia solo se redis.conf e' quello del pacchetto (una sola porta, la 6379, e
 * nessun socket) e il redis.conf di rspamd e' quello che scrive il pannello: una configurazione fatta a mano resta.
 */
public final class RedisSocket {

    private static final Logger LOGGER = Logger.getLogger(RedisSocket.class.getName());

    private RedisSocket() {}

    static final String SOCKET = "/var/run/redis/redis.sock";
    static final Path REDIS_CONF = Path.of("/usr/local/etc/redis.conf");
    static final Path RSPAMD_REDIS = Path.of("/usr/local/etc/rspamd/local.d/redis.conf");
    static final String GROUP = "redis";
    static final String RSPAMD = "rspamd";

    /** Le righe che il pannello aggiunge in fondo a redis.conf: in redis.conf vince l'ultima. */
    static final String MARK = "# mail-panel: redis solo sul socket Unix, del gruppo redis, in cui sta rspamd (reperto 235)\n";
    static final String SOCKET_LINES = "unixsocket " + SOCKET + "\nunixsocketperm 770\n";
    static final String MID = MARK + SOCKET_LINES;
    public static final String FINAL = MID + "port 0\n";

    /** Il redis.conf di rspamd come lo scrivevano gli installatori (FullMailServerScript; FullMailStackScript e RspamdScript). */
    static final Set<String> OLD_RSPAMD = Set.of("servers = \"127.0.0.1\";\n", "servers = \"127.0.0.1:6379\";\n");
    static final String NEW_RSPAMD = "servers = \"" + SOCKET + "\";\n";

    /** Quello che serve, per provarlo senza redis e rspamd. */
    interface Services {
        /** Il file, o null se non c'e'. */
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        boolean isMember(String group, String user);
        boolean setMember(String group, String user, boolean member);
        /** Riavvia redis; vero se risponde (sul socket, se redis.conf lo apre). */
        boolean restartRedis();
        /** Il socket c'e', di redis, 0770, e risponde. */
        boolean socketReady();
        /** Le chiavi del database (DBSIZE), o -1 se redis non risponde. */
        long keys();
        boolean tcpListening();
        /** Riavvia rspamd; vero se analizza un messaggio. */
        boolean restartRspamd();
        /** Dopo un messaggio analizzato, redis ha clienti sul socket oltre a chi glielo chiede. */
        boolean rspamdOnSocket();
        /** rspamd analizza un messaggio adesso. */
        boolean rspamdScans();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** redis.conf ha una sola porta attiva, la 6379, e nessun socket attivo: e' quello del pacchetto. Pura. */
    static boolean packageLike(String conf) {
        int ports = 0;
        boolean port6379 = false;
        for (String l : conf.split("\n")) {
            String t = l.trim();
            if (t.startsWith("#") || t.isEmpty()) continue;
            String[] w = t.split("\\s+");
            String k = w[0].toLowerCase();
            if (k.equals("port")) {
                ports++;
                port6379 = w.length == 2 && w[1].equals("6379");
            }
            if (k.equals("unixsocket") || k.equals("unixsocketperm") || k.equals("include")) return false;
        }
        return ports == 1 && port6379;
    }

    /** Il passaggio, puro rispetto a {@link Services}. */
    static Result run(Services sv, Path redisConf, Path rspamdRedis) {
        String conf, rs;
        try {
            conf = sv.read(redisConf);
            rs = sv.read(rspamdRedis);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "redis.conf cannot be read: " + e.getClass().getSimpleName());
        }
        if (conf == null || rs == null) return new Result(Outcome.NOTHING, "");   // redis, o rspamd con redis, non c'e'
        boolean member = sv.isMember(GROUP, RSPAMD);
        boolean isFinal = conf.contains(FINAL), isMid = !isFinal && conf.contains(MID);
        if (isFinal && NEW_RSPAMD.equals(rs) && member) return new Result(Outcome.NOTHING, "");
        boolean fromOld = !conf.contains(MARK) && packageLike(conf);
        if (!fromOld && !isMid && !isFinal)
            return new Result(Outcome.LEFT, "redis.conf is not the package's (one port, 6379, no socket): left as it is");
        if (!OLD_RSPAMD.contains(rs) && !NEW_RSPAMD.equals(rs))
            return new Result(Outcome.LEFT, "rspamd's local.d/redis.conf is not the one the panel writes: left as it is");

        long before = sv.keys();
        if (before < 0) return new Result(Outcome.LEFT, "redis does not answer now: nothing changed");
        if (!sv.rspamdScans()) return new Result(Outcome.LEFT, "rspamd does not scan a message now: nothing changed");
        try {
            // 1. redis anche sul socket; rspamd nel gruppo redis.
            if (fromOld) {
                sv.write(redisConf, conf + (conf.endsWith("\n") ? "" : "\n") + "\n" + MID);
                if (!sv.restartRedis() || !sv.socketReady())
                    return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis does not answer on " + SOCKET + " (redis, 0770)");
                if (before > 0 && sv.keys() == 0)
                    return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis restarted without its data");
            } else if (!sv.socketReady() && (!sv.restartRedis() || !sv.socketReady())) {
                // Il file aveva gia' il socket, ma redis non l'aveva aperto (un avvio interrotto a meta').
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis does not answer on " + SOCKET + " (redis, 0770)");
            }
            if (!member && !sv.setMember(GROUP, RSPAMD, true))
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "rspamd could not be added to the group " + GROUP);
            // 2. rspamd sul socket.
            if (!NEW_RSPAMD.equals(rs)) sv.write(rspamdRedis, NEW_RSPAMD);
            if (!sv.restartRspamd())
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "rspamd does not scan a message on the socket");
            if (!sv.rspamdOnSocket())
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "rspamd does not talk to redis through " + SOCKET);
        } catch (IOException e) {
            return back(sv, redisConf, conf, rspamdRedis, rs, member, "a file could not be written: " + e.getClass().getSimpleName());
        }
        if (isFinal && !sv.tcpListening())
            return new Result(Outcome.DONE, "rspamd talks to redis through " + SOCKET + " (redis, 0770; rspamd in the group redis)");
        // 3. Via la porta. Da qui lo stato di mezzo funziona: un errore ci torna, l'avvio dopo riprende.
        String withMid;
        try {
            withMid = sv.read(redisConf);
            if (!withMid.contains(FINAL)) sv.write(redisConf, withMid.replace(MID, FINAL));
        } catch (IOException e) {
            return new Result(Outcome.INCOMPLETE, "rspamd talks to redis through the socket; redis still also listens on port 6379: "
                    + e.getClass().getSimpleName());
        }
        boolean up = sv.restartRedis() && sv.socketReady();
        boolean closed = up && !sv.tcpListening();
        boolean data = up && !(before > 0 && sv.keys() == 0);
        boolean talks = up && sv.rspamdOnSocket();
        if (!up || !closed || !data || !talks) {
            try { sv.write(redisConf, withMid); } catch (IOException ignored) { }
            sv.restartRedis();
            return new Result(Outcome.INCOMPLETE, "after closing port 6379: redis " + (up ? "answers" : "DOES NOT ANSWER") + ", port 6379 "
                    + (closed ? "closed" : "still open") + ", data " + (data ? "there" : "MISSING") + ", rspamd "
                    + (talks ? "on the socket" : "NOT on the socket") + "; port 6379 open again until the next start");
        }
        return new Result(Outcome.DONE, "redis listens only on " + SOCKET + " (redis, 0770), port 6379 closed; rspamd in the group redis"
                + " talks to it there");
    }

    private static Result back(Services sv, Path redisConf, String conf, Path rspamdRedis, String rs, boolean member, String why) {
        boolean ok = true;
        try {
            sv.write(redisConf, conf);
            sv.write(rspamdRedis, rs);
        } catch (IOException e) {
            ok = false;
        }
        if (!member) ok &= sv.setMember(GROUP, RSPAMD, false);
        ok &= sv.restartRedis();
        ok &= sv.restartRspamd();
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting it back failed"));
    }

    // ===================== Il server vero =====================

    static final String REDIS_CLI = "/usr/local/bin/redis-cli";

    /**
     * I clienti di redis collegati dal socket, dall'uscita di CLIENT LIST: una riga per cliente, e il campo addr col
     * percorso del socket. Il campo si cerca col suo nome intero: ogni riga ha anche laddr, che per un cliente del
     * socket e' lo stesso percorso, e cercando solo «addr=...» la sola connessione di chi chiede contava due volte
     * (misurato sulla VM il 16/11/2026: col guasto vero, rspamd respinto con «Permission denied», la prova passava). Pura.
     */
    static int socketClients(String clientList) {
        int n = 0;
        for (String line : clientList.split("\n")) {
            for (String field : line.trim().split(" ")) {
                if (field.equals("addr=" + SOCKET + ":0")) {
                    n++;
                    break;
                }
            }
        }
        return n;
    }

    /** Il comando per chiedere qualcosa a redis: dal socket se c'e', se no dalla porta di sempre. */
    static String cli() {
        return Files.exists(Path.of(SOCKET), LinkOption.NOFOLLOW_LINKS) ? REDIS_CLI + " -s " + SOCKET : REDIS_CLI;
    }

    static Services real() {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public boolean isMember(String group, String user) {
                return RspamdUser.members(group).contains(user);
            }
            @Override public boolean setMember(String group, String user, boolean member) {
                return RspamdUser.setMember(group, user, member);
            }
            @Override public boolean restartRedis() {
                Shell.run(Duration.ofSeconds(120), "service", "redis", "restart");
                for (int i = 0; i < 60; i++) {
                    if ("PONG".equals(Shell.runShell(Duration.ofSeconds(10), cli() + " PING 2>/dev/null").outputTrim())) return true;
                    if (!sleep()) return false;
                }
                return false;
            }
            @Override public boolean socketReady() {
                try {
                    PosixFileAttributes a = Files.readAttributes(Path.of(SOCKET), PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    return a.isOther() && "redis".equals(a.owner().getName())
                            && PosixFilePermissions.toString(a.permissions()).equals("rwxrwx---")
                            && "PONG".equals(Shell.run(Duration.ofSeconds(10), REDIS_CLI, "-s", SOCKET, "PING").outputTrim());
                } catch (IOException e) {
                    return false;
                }
            }
            @Override public long keys() {
                try {
                    return Long.parseLong(Shell.runShell(Duration.ofSeconds(10), cli() + " DBSIZE 2>/dev/null").outputTrim());
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
            @Override public boolean tcpListening() {
                return !Shell.runShell(Duration.ofSeconds(20), "sockstat -46lq -p 6379 2>/dev/null").outputTrim().isEmpty();
            }
            @Override public boolean restartRspamd() {
                try {
                    return RspamdUser.restart();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            @Override public boolean rspamdOnSocket() {
                // Dopo un messaggio rspamd tiene aperte le sue connessioni; chi chiede la lista e' una di quelle sul socket.
                for (int i = 0; i < 10; i++) {
                    RspamdUser.scan();
                    String list = Shell.run(Duration.ofSeconds(10), REDIS_CLI, "-s", SOCKET, "CLIENT", "LIST").outputTrim();
                    if (socketClients(list) >= 2) return true;
                    if (!sleep()) return false;
                }
                return false;
            }
            @Override public boolean rspamdScans() {
                return RspamdUser.scan() != null;
            }
            private boolean sleep() {
                try {
                    Thread.sleep(1000);
                    return true;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        };
    }

    /** All'avvio della parte root, dopo RspamdUser. */
    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(REDIS_CLI))) return;
            Result r = run(real(), REDIS_CONF, RSPAMD_REDIS);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[RedisSocket] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[RedisSocket] left as it is: " + r.detail());
                default -> LOGGER.warning("[RedisSocket] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[RedisSocket] failed: " + t.getClass().getName());
        }
    }
}
