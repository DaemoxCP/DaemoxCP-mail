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
 * redis only on the Unix socket, 0770 for the redis group, and rspamd in that group (finding 235).
 *
 * <p>Before, redis listened on 127.0.0.1:6379 and ::1:6379 without a password, as in the package's redis.conf: any
 * process on the machine (the webmail, a compromised service) read and wrote rspamd's data, that is Bayes,
 * greylist, limits and history, and could delete all of it. redis.conf itself says so: "port 0" and redis does not
 * listen on TCP; "unixsocket" and "unixsocketperm" the socket and its permissions. For rspamd ("Redis
 * configuration") a redis server can be a socket: servers = "/var/run/redis/redis.sock". The socket is created as
 * redis:redis; 0770 and rspamd in the redis group, and only those two get in (and root).
 *
 * <p>On the servers installed earlier, at startup, in three stages, so that rspamd is never left without redis:
 * <ol>
 *   <li>redis also opens the socket, keeping the port (restarted: the socket is there, owned by redis, 0770, it
 *       answers, the data is still there), and rspamd joins the redis group;</li>
 *   <li>rspamd moves to the socket (restarted, because a process's groups are read only when it starts: it scans
 *       a message, and redis has clients on the socket besides whoever is asking);</li>
 *   <li>redis closes the port (port 0, restarted: no more 6379, and rspamd scans and talks to the socket).</li>
 * </ol>
 * An error in the first two stages puts everything back as it was; in the third it goes back to the in-between
 * state, which works, and the next startup resumes from there. It changes only if redis.conf is the package's
 * (a single port, 6379, and no socket) and rspamd's redis.conf is the one the panel writes: a configuration made
 * by hand stays.
 */
public final class RedisSocket {

    private static final Logger LOGGER = Logger.getLogger(RedisSocket.class.getName());

    private RedisSocket() {}

    static final String SOCKET = "/var/run/redis/redis.sock";
    static final Path REDIS_CONF = Path.of("/usr/local/etc/redis.conf");
    static final Path RSPAMD_REDIS = Path.of("/usr/local/etc/rspamd/local.d/redis.conf");
    static final String GROUP = "redis";
    static final String RSPAMD = "rspamd";

    /** The lines the panel adds at the end of redis.conf: in redis.conf the last one wins. */
    static final String MARK = "# daemoxcp-mail: redis only on the Unix socket, of the redis group, which rspamd is in (finding 235)\n";
    static final String SOCKET_LINES = "unixsocket " + SOCKET + "\nunixsocketperm 770\n";
    static final String MID = MARK + SOCKET_LINES;
    public static final String FINAL = MID + "port 0\n";

    /** rspamd's redis.conf as the installers wrote it (FullMailServerScript; FullMailStackScript and RspamdScript). */
    static final Set<String> OLD_RSPAMD = Set.of("servers = \"127.0.0.1\";\n", "servers = \"127.0.0.1:6379\";\n");
    static final String NEW_RSPAMD = "servers = \"" + SOCKET + "\";\n";

    /** What is needed, so that it can be tested without redis and rspamd. */
    interface Services {
        /** The file, or null if it is not there. */
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        boolean isMember(String group, String user);
        boolean setMember(String group, String user, boolean member);
        /** Restarts redis; true if it answers (on the socket, if redis.conf opens it). */
        boolean restartRedis();
        /** The socket is there, owned by redis, 0770, and it answers. */
        boolean socketReady();
        /** The keys of the database (DBSIZE), or -1 if redis does not answer. */
        long keys();
        boolean tcpListening();
        /** Restarts rspamd; true if it scans a message. */
        boolean restartRspamd();
        /** After a scanned message, redis has clients on the socket besides whoever is asking. */
        boolean rspamdOnSocket();
        /** rspamd scans a message now. */
        boolean rspamdScans();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    /** redis.conf has a single active port, 6379, and no active socket: it is the package's one. Pure. */
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

    /** The switchover, pure with respect to {@link Services}. */
    static Result run(Services sv, Path redisConf, Path rspamdRedis) {
        String conf, rs;
        try {
        // The block written in Italian by the previous versions counts as the current one (EnglishComments).
            conf = EnglishComments.english(sv.read(redisConf));
            rs = sv.read(rspamdRedis);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "redis.conf cannot be read: " + e.getClass().getSimpleName());
        }
        if (conf == null || rs == null) return new Result(Outcome.NOTHING, "");   // redis, or rspamd with redis, is not there
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
            // 1. redis on the socket too; rspamd in the redis group.
            if (fromOld) {
                sv.write(redisConf, conf + (conf.endsWith("\n") ? "" : "\n") + "\n" + MID);
                if (!sv.restartRedis() || !sv.socketReady())
                    return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis does not answer on " + SOCKET + " (redis, 0770)");
                if (before > 0 && sv.keys() == 0)
                    return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis restarted without its data");
            } else if (!sv.socketReady() && (!sv.restartRedis() || !sv.socketReady())) {
                // The file already had the socket, but redis had not opened it (a startup interrupted halfway).
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "redis does not answer on " + SOCKET + " (redis, 0770)");
            }
            if (!member && !sv.setMember(GROUP, RSPAMD, true))
                return back(sv, redisConf, conf, rspamdRedis, rs, member, "rspamd could not be added to the group " + GROUP);
            // 2. rspamd on the socket.
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
        // 3. The port goes. From here on the in-between state works: an error returns to it, the next startup resumes.
        String withMid;
        try {
            withMid = EnglishComments.english(sv.read(redisConf));
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

    // ===================== The production server =====================

    static final String REDIS_CLI = "/usr/local/bin/redis-cli";

    /**
     * The redis clients connected through the socket, from the output of CLIENT LIST: one line per client, and the
     * addr field with the socket path. The field is looked up by its whole name: every line also has laddr, which
     * for a socket client is the same path, and looking up just "addr=..." counted the single connection of the
     * one asking twice (measured on the VM on 2026-11-16: with the real fault, rspamd rejected with "Permission
     * denied", the test passed). Pure.
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

    /** The command to ask redis something: through the socket if it exists, otherwise through the usual port. */
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
                // After a message rspamd keeps its connections open; whoever asks for the list is one
                // of those on the socket.
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

    /** At root part startup, after RspamdUser. */
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
