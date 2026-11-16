package org.mail_panel.system;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * redis only on its Unix socket, 0770 of the group redis, with rspamd in that group (reperto 235). Against a fake
 * redis that listens where its redis.conf says (the last active line wins, as in redis) and a fake rspamd that
 * reaches redis only if it was started in the group redis and is pointed at the socket:
 *  1. the installer writes exactly RedisSocket.FINAL and points rspamd at the socket;
 *  2. from the package's redis.conf: DONE, port 6379 closed, the socket, rspamd in the group and on the socket, the
 *     data kept; the second run does nothing; the installer's final state does nothing either;
 *  3. what does not start: another port, a socket already there, an include, rspamd pointed elsewhere, no redis.conf,
 *     redis or rspamd not answering;
 *  4. a fault in the first two steps (redis without the socket, the group not taken, rspamd not on the socket, redis
 *     restarted empty): everything back as it was, byte for byte, port 6379 open, rspamd out of the group;
 *  5. a fault in the last step: INCOMPLETE, port 6379 open again with the socket (the middle state), and the next
 *     run finishes;
 *  6. the middle state written but redis never restarted (a start cut in half): the next run finishes.
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RedisSocketTest
 */
public class RedisSocketTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path CONF = Path.of("/fake/redis.conf");
    static final Path RS = Path.of("/fake/rspamd/local.d/redis.conf");
    /** The relevant lines of FreeBSD's redis.conf (redis 8.10.3 on the VM, 16/11/2026). */
    static final String PACKAGE = "# Redis configuration file example.\nbind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\n"
            + "# unixsocket /run/redis.sock\n# unixsocketperm 700\npidfile /var/run/redis/redis.pid\ndir /var/db/redis/\n";
    static final String OLD_RS = "servers = \"127.0.0.1\";\n";

    static final class Machine implements RedisSocket.Services {
        final Map<Path, String> files = new HashMap<>();
        final Set<String> redisGroup = new HashSet<>();
        // what redis does now (set by the last restart from redis.conf)
        boolean tcp = true, socket = false;
        // rspamd as it was started: in the group or not, pointed at the socket or not
        boolean rspamdInGroup = false, rspamdOnSocketConf = false;
        long keys = 94;
        String fault;   // "no-socket", "group-lies", "rspamd-wrong", "empty", "empty-on-close", "redis-down", "rspamd-down"
        int redisRestarts = 0, rspamdRestarts = 0;

        Machine(String conf, String rs) {
            if (conf != null) files.put(CONF, conf);
            if (rs != null) files.put(RS, rs);
        }

        @Override public String read(Path f) { return files.get(f); }
        @Override public void write(Path f, String text) { files.put(f, text); }
        @Override public boolean isMember(String g, String u) { return redisGroup.contains(u); }
        @Override public boolean setMember(String g, String u, boolean m) {
            if ("group-lies".equals(fault)) return true;
            if (m) redisGroup.add(u); else redisGroup.remove(u);
            return true;
        }
        @Override public boolean restartRedis() {
            redisRestarts++;
            if ("redis-down".equals(fault)) { tcp = false; socket = false; return false; }
            String port = "6379", unix = null;
            for (String l : files.get(CONF).split("\n")) {
                String t = l.trim();
                if (t.startsWith("#") || t.isEmpty()) continue;
                String[] w = t.split("\\s+");
                if (w[0].equals("port")) port = w[1];
                if (w[0].equals("unixsocket")) unix = w[1];
            }
            tcp = !port.equals("0");
            socket = RedisSocket.SOCKET.equals(unix) && !"no-socket".equals(fault);
            if ("empty".equals(fault) || ("empty-on-close".equals(fault) && !tcp)) keys = 0;
            return tcp || socket;
        }
        @Override public boolean socketReady() { return socket; }
        @Override public long keys() { return tcp || socket ? keys : -1; }
        @Override public boolean tcpListening() { return tcp; }
        @Override public boolean restartRspamd() {
            rspamdRestarts++;
            rspamdInGroup = redisGroup.contains("rspamd");
            rspamdOnSocketConf = RedisSocket.NEW_RSPAMD.equals(files.get(RS));
            return !"rspamd-down".equals(fault);
        }
        @Override public boolean rspamdOnSocket() {
            return !"rspamd-wrong".equals(fault) && rspamdOnSocketConf && rspamdInGroup && socket;
        }
        @Override public boolean rspamdScans() { return !"rspamd-down".equals(fault); }

        /** rspamd reaches redis at all, however it is pointed. */
        boolean rspamdReachesRedis() {
            return rspamdOnSocketConf ? socket && rspamdInGroup : tcp;
        }
    }

    static RedisSocket.Result run(Machine m) { return RedisSocket.run(m, CONF, RS); }

    public static void main(String[] args) {
        System.out.println("== 1. What the installer writes");
        String installer = new org.mail_panel.scripts.FullMailServerScript().getScriptContent();
        check("redis.conf gets RedisSocket.FINAL (socket, 0770, port 0) once, guarded", installer.contains("\n" + RedisSocket.FINAL + "REDIS_SOCKET\n")
                && installer.contains("grep -qF 'reperto 235' /usr/local/etc/redis.conf"));
        int joins = installer.indexOf("\npw groupmod redis -m rspamd\n");
        check("rspamd in the group redis before redis and rspamd start", joins > 0 && joins < installer.indexOf("service redis start")
                && joins < installer.indexOf("service rspamd start"));
        check("rspamd's redis.conf is the socket", installer.contains("<< 'RSPAMD_REDIS'\n" + RedisSocket.NEW_RSPAMD + "RSPAMD_REDIS"));
        check("no rspamd redis on 127.0.0.1 left", !installer.contains("servers = \"127.0.0.1\""));
        check("FINAL closes TCP and opens the socket 0770", RedisSocket.FINAL.contains("port 0\n")
                && RedisSocket.FINAL.contains("unixsocket /var/run/redis/redis.sock\n") && RedisSocket.FINAL.contains("unixsocketperm 770\n"));

        System.out.println("\n== 2. From the package's redis.conf");
        Machine m = new Machine(PACKAGE, OLD_RS);
        RedisSocket.Result r = run(m);
        check("DONE (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.DONE);
        check("  redis.conf: the package's text, then FINAL", m.files.get(CONF).equals(PACKAGE + "\n" + RedisSocket.FINAL));
        check("  port 6379 closed, the socket open", !m.tcp && m.socket);
        check("  rspamd in the group redis, pointed at the socket, reaching redis", m.redisGroup.contains("rspamd")
                && RedisSocket.NEW_RSPAMD.equals(m.files.get(RS)) && m.rspamdReachesRedis());
        check("  the data kept", m.keys == 94);
        int restarts = m.redisRestarts + m.rspamdRestarts;
        r = run(m);
        check("  a second run: NOTHING, nothing restarted", r.outcome() == RedisSocket.Outcome.NOTHING && m.redisRestarts + m.rspamdRestarts == restarts);

        Machine fresh = new Machine(PACKAGE + "\n" + RedisSocket.FINAL, RedisSocket.NEW_RSPAMD);
        fresh.redisGroup.add("rspamd");
        fresh.restartRedis();
        fresh.restartRspamd();
        fresh.redisRestarts = 0;
        fresh.rspamdRestarts = 0;
        r = run(fresh);
        check("the installer's final state: NOTHING", r.outcome() == RedisSocket.Outcome.NOTHING && fresh.redisRestarts == 0);

        System.out.println("\n== 3. What does not start");
        for (String[] c : new String[][]{
                {"another port", PACKAGE.replace("port 6379", "port 6380"), OLD_RS},
                {"a socket already there", PACKAGE.replace("# unixsocket /run/redis.sock", "unixsocket /tmp/redis.sock"), OLD_RS},
                {"an include", PACKAGE + "include /usr/local/etc/redis-local.conf\n", OLD_RS},
                {"two ports", PACKAGE + "port 6380\n", OLD_RS},
                {"rspamd pointed at another redis", PACKAGE, "servers = \"10.0.0.5:6379\";\n"},
                {"rspamd with more settings", PACKAGE, OLD_RS + "db = \"2\";\n"}}) {
            Machine x = new Machine(c[1], c[2]);
            r = run(x);
            check(c[0] + ": LEFT, files untouched, nothing restarted", r.outcome() == RedisSocket.Outcome.LEFT
                    && x.files.get(CONF).equals(c[1]) && x.files.get(RS).equals(c[2]) && x.redisRestarts == 0 && x.redisGroup.isEmpty());
        }
        check("no redis.conf: NOTHING", run(new Machine(null, OLD_RS)).outcome() == RedisSocket.Outcome.NOTHING);
        check("no rspamd redis.conf: NOTHING", run(new Machine(PACKAGE, null)).outcome() == RedisSocket.Outcome.NOTHING);
        Machine down = new Machine(PACKAGE, OLD_RS);
        down.tcp = false;
        r = run(down);
        check("redis not answering: LEFT, untouched", r.outcome() == RedisSocket.Outcome.LEFT && down.files.get(CONF).equals(PACKAGE));
        Machine noRspamd = new Machine(PACKAGE, OLD_RS);
        noRspamd.fault = "rspamd-down";
        r = run(noRspamd);
        check("rspamd not scanning: LEFT, untouched", r.outcome() == RedisSocket.Outcome.LEFT && noRspamd.files.get(CONF).equals(PACKAGE)
                && noRspamd.redisRestarts == 0);

        System.out.println("\n== 4. A fault in the first two steps: everything back");
        for (String fault : new String[]{"no-socket", "group-lies", "rspamd-wrong", "empty"}) {
            Machine x = new Machine(PACKAGE, OLD_RS);
            x.fault = fault;
            r = run(x);
            x.fault = null;
            check(fault + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.ROLLED_BACK);
            check("  the files byte for byte, rspamd out of the group", x.files.get(CONF).equals(PACKAGE) && x.files.get(RS).equals(OLD_RS)
                    && !x.redisGroup.contains("rspamd"));
            check("  port 6379 open and rspamd reaching redis there", x.tcp && !x.socket && x.rspamdReachesRedis() && !x.rspamdOnSocketConf);
        }
        Machine member = new Machine(PACKAGE, OLD_RS);
        member.redisGroup.add("rspamd");
        member.fault = "rspamd-wrong";
        run(member);
        check("rspamd already in the group before: a rollback leaves it there", member.redisGroup.contains("rspamd"));

        System.out.println("\n== 5. A fault in the last step: back to the middle state, then finished");
        Machine last = new Machine(PACKAGE, OLD_RS);
        last.fault = "empty-on-close";
        r = run(last);
        check("INCOMPLETE (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.INCOMPLETE);
        check("  redis.conf in the middle state, port 6379 and the socket open, rspamd on the socket",
                last.files.get(CONF).equals(PACKAGE + "\n" + RedisSocket.MID) && last.tcp && last.socket && last.rspamdReachesRedis());
        last.fault = null;
        last.keys = 90;
        r = run(last);
        check("  the next run: DONE, port closed", r.outcome() == RedisSocket.Outcome.DONE && !last.tcp
                && last.files.get(CONF).equals(PACKAGE + "\n" + RedisSocket.FINAL));

        System.out.println("\n== 6. The middle state written, redis never restarted");
        Machine cut = new Machine(PACKAGE + "\n" + RedisSocket.MID, OLD_RS);
        r = run(cut);
        check("DONE (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.DONE && !cut.tcp && cut.socket && cut.rspamdReachesRedis());

        System.out.println("\n== socketClients (real CLIENT LIST lines, redis 8.10.3 on the VM)");
        String ours = "id=314 addr=/var/run/redis/redis.sock:0 laddr=/var/run/redis/redis.sock:0 fd=163 name= age=0 idle=0 flags=U db=0"
                + " sub=0 psub=0 ssub=0 multi=-1 watch=0 qbuf=26 qbuf-free=20448 argv-mem=10 multi-mem=0 rbs=1024 rbp=0 obl=0 oll=0"
                + " omem=0 tot-mem=22426 events=r cmd=client|list user=default redir=-1 resp=2 lib-name= lib-ver=";
        String rspamd = "id=267 addr=/var/run/redis/redis.sock:0 laddr=/var/run/redis/redis.sock:0 fd=119 name= age=8 idle=8 flags=U db=0"
                + " sub=0 psub=0 ssub=0 multi=-1 watch=0 qbuf=0 qbuf-free=0 argv-mem=0 multi-mem=0 rbs=1024 rbp=0 obl=0 oll=0 omem=0"
                + " tot-mem=1928 events=r cmd=evalsha user=default redir=-1 resp=2 lib-name= lib-ver=";
        String tcp = "id=12 addr=127.0.0.1:52344 laddr=127.0.0.1:6379 fd=9 name= age=3 idle=3 flags=N db=0 cmd=get";
        check("only the one who asks: 1 (laddr does not count)", RedisSocket.socketClients(ours) == 1);
        check("rspamd and the one who asks: 2", RedisSocket.socketClients(rspamd + "\n" + ours) == 2);
        check("a TCP client does not count", RedisSocket.socketClients(tcp + "\n" + ours) == 1);
        check("nothing: 0", RedisSocket.socketClients("") == 0);

        System.out.println("\n== packageLike");
        check("the package's: yes", RedisSocket.packageLike(PACKAGE));
        check("a commented port only: no", !RedisSocket.packageLike(PACKAGE.replace("port 6379", "# port 6379")));
        check("unixsocketperm alone: no", !RedisSocket.packageLike(PACKAGE + "unixsocketperm 700\n"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
