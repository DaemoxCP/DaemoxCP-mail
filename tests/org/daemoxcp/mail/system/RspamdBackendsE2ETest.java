package org.daemoxcp.mail.system;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.integration.RspamdManager;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

/**
 * Reperti 235-237 on the VM's real redis, clamd and rspamd, as root with -De2e.vm=yes. The VM must start as an
 * installation of before: redis.conf as the package installs it, rspamd's local.d/redis.conf on 127.0.0.1, clamd.conf
 * without group or mode for the socket, no override.d/worker-controller.inc, rspamd outside the groups redis and clamav.
 *  1. before: port 6379 open and `nobody` gets PONG; clamd's socket 0666 and `nobody` gets its VERSION; the controller
 *     answers 200 with no password (the faults these fix);
 *  2. RedisSocket: DONE; port 6379 closed; the socket redis 0770; `nobody` refused both ways; rspamd scans and talks
 *     to redis through the socket; the update's data check reads a number; the second run does nothing;
 *  3. ClamdSocket: DONE; the socket clamav:clamav 0660; `nobody` gets nothing; root still asks VERSION; rspamd finds
 *     an EICAR never seen before, and clamd's log shows it scanned it; the second run does nothing;
 *  4. RspamdController: DONE; the file root:rspamd 0640; 401 without the password (127.0.0.1 and ::1) and with q1, 200
 *     with the panel's; the panel's RspamdManager reads the statistics; root-secrets.properties still 0600; the second
 *     run does nothing;
 *  5. faults on the real services, each from the state of before: rspamd not really put in the group (redis and
 *     clamd), configtest refusing, rspamd not reloaded: each ROLLED_BACK and the service as before; the admin's own
 *     secure_ip in local.d: LEFT;
 *  6. all three again: DONE (the VM stays as an upgraded server would be).
 *   java -De2e.vm=yes -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.RspamdBackendsE2ETest
 */
public class RspamdBackendsE2ETest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd).outputTrim();
    }

    static boolean nobodyRedis() {
        return sh("su -m nobody -c '/usr/local/bin/redis-cli -h 127.0.0.1 PING; /usr/local/bin/redis-cli -s " + RedisSocket.SOCKET
                + " PING' 2>&1").contains("PONG");
    }

    static boolean nobodyClamd() {
        return sh("su -m nobody -c 'printf \"zVERSION\\0\" | nc -U -w 3 " + ClamdSocket.SOCKET + "' 2>&1").contains("ClamAV");
    }

    static int controller(String host, String password) {
        String h = password == null ? "" : "-H 'Password: " + password + "' ";
        try {
            return Integer.parseInt(sh("curl -s -o /dev/null -w '%{http_code}' " + h + "http://" + host + ":11334/stat"));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static int clamdFound() {
        return Integer.parseInt(sh("grep -c FOUND /var/log/clamav/clamd.log || true"));
    }

    /** A real Services with one method replaced. */
    @SuppressWarnings("unchecked")
    static <T> T with(Class<T> type, T real, String method, java.util.function.Function<Object[], Object> replacement) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> {
            if (m.getName().equals(method)) return replacement.apply(a);
            try {
                return m.invoke(real, a);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }

    static void redisBefore(String conf, String rs) throws Exception {
        RedisSocket.Services real = RedisSocket.real();
        real.write(RedisSocket.REDIS_CONF, conf);
        real.write(RedisSocket.RSPAMD_REDIS, rs);
        RspamdUser.setMember("redis", "rspamd", false);
        real.restartRedis();
        RspamdUser.restart();
    }

    static void clamdBefore(String conf) throws Exception {
        ClamdSocket.Services real = ClamdSocket.real();
        real.write(ClamdSocket.CLAMD_CONF, conf);
        RspamdUser.setMember("clamav", "rspamd", false);
        real.restartClamd();
        RspamdUser.restart();
    }

    static void controllerBefore() throws Exception {
        Files.deleteIfExists(RspamdController.OVERRIDE);
        PanelSecrets.setText(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD, "");
        RspamdController.real().reload();
        for (int i = 0; i < 30 && controller("127.0.0.1", null) != 200; i++) Thread.sleep(1000);
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Turned on with -De2e.vm=yes, as root, on the VM: it changes redis, clamd and rspamd.");
            System.exit(0);
        }
        String redisConf = Files.readString(RedisSocket.REDIS_CONF), rspamdRedis = Files.readString(RedisSocket.RSPAMD_REDIS);
        String clamdConf = Files.readString(ClamdSocket.CLAMD_CONF);

        System.out.println("== 1. Before");
        check("redis.conf as the package's, rspamd on 127.0.0.1, clamd.conf without group or mode, no override",
                RedisSocket.packageLike(redisConf) && RedisSocket.OLD_RSPAMD.contains(rspamdRedis) && ClamdSocket.packageLike(clamdConf)
                        && !Files.exists(RspamdController.OVERRIDE));
        check("rspamd in neither group", !RspamdUser.members("redis").contains("rspamd") && !RspamdUser.members("clamav").contains("rspamd"));
        check("port 6379 listening, and `nobody` gets PONG (the fault 235 fixes)", !sh("sockstat -46lq -p 6379").isEmpty() && nobodyRedis());
        check("clamd's socket 0666, and `nobody` gets VERSION (237)", sh("stat -f %Sp " + ClamdSocket.SOCKET).equals("srw-rw-rw-") && nobodyClamd());
        check("the controller answers 200 with no password (236)", controller("127.0.0.1", null) == 200);

        System.out.println("\n== 2. RedisSocket");
        RedisSocket.Result r = RedisSocket.run(RedisSocket.real(), RedisSocket.REDIS_CONF, RedisSocket.RSPAMD_REDIS);
        check("DONE (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.DONE);
        check("  port 6379 closed", sh("sockstat -46lq -p 6379").isEmpty());
        check("  the socket: redis:redis srwxrwx---", sh("stat -f '%Su:%Sg %Sp' " + RedisSocket.SOCKET).equals("redis:redis srwxrwx---"));
        check("  `nobody` refused both ways", !nobodyRedis());
        check("  rspamd in the group redis, scanning, on the socket", RspamdUser.members("redis").contains("rspamd")
                && RspamdUser.scan() != null && RedisSocket.real().rspamdOnSocket());
        String after = sh(UpdateManager.testAfterOf("redis")[1]);
        check("  the update's data check reads a number (" + after + ")", after.matches("[1-9][0-9]*"));
        r = RedisSocket.run(RedisSocket.real(), RedisSocket.REDIS_CONF, RedisSocket.RSPAMD_REDIS);
        check("  a second run: NOTHING", r.outcome() == RedisSocket.Outcome.NOTHING);

        System.out.println("\n== 3. ClamdSocket");
        ClamdSocket.Result c = ClamdSocket.run(ClamdSocket.real(), ClamdSocket.CLAMD_CONF);
        check("DONE (" + c.detail() + ")", c.outcome() == ClamdSocket.Outcome.DONE && c.detail().contains("still finds EICAR"));
        check("  the socket: clamav:clamav srw-rw----", sh("stat -f '%Su:%Sg %Sp' " + ClamdSocket.SOCKET).equals("clamav:clamav srw-rw----"));
        check("  `nobody` gets nothing", !nobodyClamd());
        check("  root still asks VERSION (the panel's Versions page)", SoftwareVersions.askClamd(Path.of(ClamdSocket.SOCKET)) != null);
        int found = clamdFound();
        check("  rspamd finds an EICAR never seen before", ClamdSocket.real().rspamdFindsEicar());
        check("  and clamd's log shows it scanned it", clamdFound() == found + 1);
        c = ClamdSocket.run(ClamdSocket.real(), ClamdSocket.CLAMD_CONF);
        check("  a second run: NOTHING", c.outcome() == ClamdSocket.Outcome.NOTHING);

        System.out.println("\n== 4. RspamdController");
        RspamdController.Result k = RspamdController.run(RspamdController.real(), RspamdController.OVERRIDE, RspamdController.LOCAL, 30);
        check("DONE (" + k.detail() + ")", k.outcome() == RspamdController.Outcome.DONE);
        String secret = PanelSecrets.reread(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD);
        check("  the file root:rspamd 0640", sh("stat -f '%Su:%Sg %Sp' " + RspamdController.OVERRIDE).equals("root:rspamd -rw-r-----"));
        check("  401 with no password on 127.0.0.1 and ::1, and with q1", controller("127.0.0.1", null) == 401
                && controller("[::1]", null) == 401 && controller("127.0.0.1", "q1") == 401);
        check("  200 with the panel's", !secret.isEmpty() && controller("127.0.0.1", secret) == 200);
        check("  rspamc with no password: Unauthorized", sh("rspamc stat 2>&1").contains("401"));
        RspamdManager.RspamdStats stats = new RspamdManager().getStatistics();
        check("  the panel's RspamdManager reads the statistics (" + (stats == null ? "null" : stats.version) + ")",
                stats != null && !"unknown".equals(stats.version));
        check("  the panel's RspamdManager sees rspamd running", new RspamdManager().isRunning());
        check("  root-secrets.properties still root 0600", sh("stat -f '%Su %Sp' " + PanelSecrets.location(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD))
                .equals("root -rw-------"));
        k = RspamdController.run(RspamdController.real(), RspamdController.OVERRIDE, RspamdController.LOCAL, 30);
        check("  a second run: NOTHING", k.outcome() == RspamdController.Outcome.NOTHING);

        System.out.println("\n== 5. Faults, each from the state of before");
        redisBefore(redisConf, rspamdRedis);
        check("redis as before: port 6379, rspamd out of the group", !sh("sockstat -46lq -p 6379").isEmpty()
                && !RspamdUser.members("redis").contains("rspamd"));
        RedisSocket.Services lies = with(RedisSocket.Services.class, RedisSocket.real(), "setMember", a -> true);
        r = RedisSocket.run(lies, RedisSocket.REDIS_CONF, RedisSocket.RSPAMD_REDIS);
        check("rspamd not really in the group redis: ROLLED_BACK (" + r.detail() + ")", r.outcome() == RedisSocket.Outcome.ROLLED_BACK);
        check("  the files as before, port 6379 listening, rspamd scanning", Files.readString(RedisSocket.REDIS_CONF).equals(redisConf)
                && Files.readString(RedisSocket.RSPAMD_REDIS).equals(rspamdRedis) && !sh("sockstat -46lq -p 6379").isEmpty()
                && RspamdUser.scan() != null);

        clamdBefore(clamdConf);
        check("clamd as before: 0666", sh("stat -f %Sp " + ClamdSocket.SOCKET).equals("srw-rw-rw-"));
        ClamdSocket.Services clamdLies = with(ClamdSocket.Services.class, ClamdSocket.real(), "setMember", a -> true);
        c = ClamdSocket.run(clamdLies, ClamdSocket.CLAMD_CONF);
        check("rspamd not really in the group clamav: ROLLED_BACK (" + c.detail() + ")", c.outcome() == ClamdSocket.Outcome.ROLLED_BACK);
        check("  clamd.conf as before, the socket 0666, rspamd finds EICAR", Files.readString(ClamdSocket.CLAMD_CONF).equals(clamdConf)
                && sh("stat -f %Sp " + ClamdSocket.SOCKET).equals("srw-rw-rw-") && ClamdSocket.real().rspamdFindsEicar());

        controllerBefore();
        check("the controller as before: 200 with no password", controller("127.0.0.1", null) == 200);
        RspamdController.Services refuses = with(RspamdController.Services.class, RspamdController.real(), "configOk", a -> false);
        k = RspamdController.run(refuses, RspamdController.OVERRIDE, RspamdController.LOCAL, 30);
        check("configtest refusing: ROLLED_BACK (" + k.detail() + ")", k.outcome() == RspamdController.Outcome.ROLLED_BACK);
        check("  no file, no secret, 200 with no password", !Files.exists(RspamdController.OVERRIDE)
                && PanelSecrets.reread(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD).isEmpty() && controller("127.0.0.1", null) == 200);
        RspamdController.Services noReload = with(RspamdController.Services.class, RspamdController.real(), "reload", a -> null);
        k = RspamdController.run(noReload, RspamdController.OVERRIDE, RspamdController.LOCAL, 10);
        check("rspamd not reloaded (the file never taken): ROLLED_BACK (" + k.detail() + ")", k.outcome() == RspamdController.Outcome.ROLLED_BACK);
        check("  no file, no secret, 200 with no password", !Files.exists(RspamdController.OVERRIDE)
                && PanelSecrets.reread(PanelSecrets.RSPAMD_CONTROLLER_PASSWORD).isEmpty() && controller("127.0.0.1", null) == 200);
        Files.writeString(RspamdController.LOCAL, "secure_ip = \"127.0.0.1\";\n");
        k = RspamdController.run(RspamdController.real(), RspamdController.OVERRIDE, RspamdController.LOCAL, 30);
        check("the admin's secure_ip in local.d: LEFT, nothing written (" + k.detail() + ")", k.outcome() == RspamdController.Outcome.LEFT
                && !Files.exists(RspamdController.OVERRIDE));
        Files.delete(RspamdController.LOCAL);

        System.out.println("\n== 6. All three again");
        r = RedisSocket.run(RedisSocket.real(), RedisSocket.REDIS_CONF, RedisSocket.RSPAMD_REDIS);
        c = ClamdSocket.run(ClamdSocket.real(), ClamdSocket.CLAMD_CONF);
        k = RspamdController.run(RspamdController.real(), RspamdController.OVERRIDE, RspamdController.LOCAL, 30);
        check("DONE, DONE, DONE", r.outcome() == RedisSocket.Outcome.DONE && c.outcome() == ClamdSocket.Outcome.DONE
                && k.outcome() == RspamdController.Outcome.DONE);
        check("  port 6379 closed, clamd 0660, the controller 401 with no password", sh("sockstat -46lq -p 6379").isEmpty()
                && sh("stat -f %Sp " + ClamdSocket.SOCKET).equals("srw-rw----") && controller("127.0.0.1", null) == 401);
        check("  rspamd scans, finds EICAR, and its processes are all rspamd's", RspamdUser.scan() != null && ClamdSocket.real().rspamdFindsEicar()
                && RspamdUser.processes().stream().allMatch(p -> p[0].equals("rspamd")));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
