package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Le versioni del software del server di posta, lette dal server a ogni richiesta: la colonna
 * Versione di "Servizi Mail" e la tabella "Altro software" della Home.
 *
 * Ogni programma si interroga per quello che e', e il piu' vicino possibile a cio' che gira:
 *  - MySQL con SELECT VERSION() sulla connessione del pannello: risponde il server in esecuzione;
 *  - ClamAV chiedendo VERSION al demone clamd sul suo socket: il motore e le firme che usa adesso;
 *  - Java dal processo stesso del pannello, il kernel con freebsd-version -r;
 *  - gli altri dal proprio binario (postconf -h mail_version, dovecot --version, nginx -v...).
 *
 * Il pacchetto si trova con "pkg which" sul binario, non per nome: il pannello installa
 * postfix-mysql e dovecot-mysql, e "pkg query %v postfix" su quei server non trova niente (lo
 * stesso inciampo e' raccontato in DovecotConfig).
 *
 * Gira ancora la versione di prima? Per MySQL, ClamAV e Java si confronta la risposta del processo
 * con il pacchetto installato; per il kernel, freebsd-version -k con -r. Per gli altri demoni si
 * confronta l'ora di avvio del processo (dal suo pidfile) con l'ora di installazione del pacchetto
 * (pkg query %t): partito prima, sta eseguendo il codice di prima. Quando una delle due ore manca
 * non si dice niente: nessuna indicazione e' meglio di una sbagliata. Per lo stesso motivo PHP-FPM
 * non si controlla cosi': il suo reload rilancia il binario nuovo nello stesso processo, che
 * conserva l'ora di avvio, e dopo un reload l'avviso sarebbe falso.
 */
public final class SoftwareVersions {

    private SoftwareVersions() {}

    /** Il sistema da interrogare: quello vero del server, o uno finto nelle prove. */
    public interface Sistema {
        /** Uscita (stdout e stderr) del comando anche se esce con errore; null se non parte o non finisce in tempo. */
        String esegui(String... argv);
        boolean esiste(String percorso);
        /** Un file piccolo, o null se manca o e' troppo grande. */
        String leggi(String percorso);
        /** La risposta di clamd a VERSION sul suo socket, o null se non risponde. */
        String chiediClamd();
        /** SELECT VERSION() sulla connessione del pannello, o null. */
        String versioneMysql();
        /** Quando e' partito il processo, o null se non c'e' o non si sa. */
        Instant avvio(long pid);
        /** Runtime.version() della Java che esegue il pannello. */
        String versioneJava();
        /** java.home della Java che esegue il pannello. */
        String cartellaJava();
        Instant adesso();
        ZoneId zona();
    }

    /** Firme di ClamAV piu' vecchie di cosi' sono un avviso: la stessa soglia del controllo di ClamAV (Sicurezza). */
    static final int GIORNI_FIRME = 7;
    static final String PKG = "/usr/local/sbin/pkg";
    static final String SOCKET_CLAMD = "/var/run/clamav/clamd.sock";
    static final String CLAMD = "/usr/local/sbin/clamd";
    static final String MYSQLD = "/usr/local/libexec/mysqld";
    static final String ROUNDCUBE = "/usr/local/www/roundcube";
    static final String FREEBSD_VERSION = "/bin/freebsd-version";
    static final String OPENSSL_BASE = "/usr/bin/openssl";
    static final String OPENSSL_PKG = "/usr/local/bin/openssl";

    /** Una versione: solo caratteri stampabili senza spazi, come le scrivono i programmi e pkg. */
    private static final Pattern VALID_VERSION = Pattern.compile("[0-9A-Za-z.+_,:~-]{1,40}");
    private static final Pattern VALID_PATH = Pattern.compile("/[0-9A-Za-z._/+-]{1,200}");
    private static final String V = "(\\d[0-9A-Za-z.+_~-]*)";
    private static final DateTimeFormatter DATA_ORA = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    /** Con i secondi sempre: toString() li omette quando sono zero, e la pagina li taglia per posizione. */
    private static final DateTimeFormatter ISTANTE = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    /**
     * Un programma letto dal suo binario: dove sta, come gli si chiede la versione (null: solo dal
     * pacchetto), come la si riconosce nella risposta e, per i demoni, dove scrive il suo pid.
     */
    record Voce(String chiave, String nome, String ruolo, String binario, String[] comando, Pattern versione, String pidfile) {}

    private static Pattern riga(String re) { return Pattern.compile(re, Pattern.MULTILINE); }

    static final Voce POSTFIX = new Voce("postfix", "Postfix", "server.ver.role.postfix", "/usr/local/sbin/postconf",
            new String[]{"/usr/local/sbin/postconf", "-h", "mail_version"}, riga("^" + V), "/var/spool/postfix/pid/master.pid");
    static final Voce DOVECOT = new Voce("dovecot", "Dovecot", "server.ver.role.dovecot", "/usr/local/sbin/dovecot",
            new String[]{"/usr/local/sbin/dovecot", "--version"}, riga("^" + V), "/var/run/dovecot/master.pid");
    static final Voce RSPAMD = new Voce("rspamd", "Rspamd", "server.ver.role.rspamd", "/usr/local/bin/rspamd",
            new String[]{"/usr/local/bin/rspamd", "--version"}, riga("[Vv]ersion\\s+" + V), "/var/run/rspamd/rspamd.pid");
    static final Voce REDIS = new Voce("redis", "Redis", "server.ver.role.redis", "/usr/local/bin/redis-server",
            new String[]{"/usr/local/bin/redis-server", "--version"}, riga("\\bv=" + V), "/var/run/redis/redis.pid");
    static final Voce NGINX = new Voce("nginx", "nginx", "server.ver.role.nginx",
            "/usr/local/sbin/nginx", new String[]{"/usr/local/sbin/nginx", "-v"}, riga("nginx/" + V), "/var/run/nginx.pid");
    static final Voce PHP = new Voce("php", "PHP-FPM", "server.ver.role.php", "/usr/local/sbin/php-fpm",
            new String[]{"/usr/local/sbin/php-fpm", "-v"}, riga("^PHP " + V), null);
    static final Voce PIGEONHOLE = new Voce("pigeonhole", "Pigeonhole", "server.ver.role.pigeonhole",
            "/usr/local/bin/sievec", null, null, null);
    static final Voce FAIL2BAN = new Voce("fail2ban", "fail2ban", "server.ver.role.fail2ban",
            "/usr/local/bin/fail2ban-client", null, null, "/var/run/fail2ban/fail2ban.pid");
    static final Voce UNBOUND = new Voce("unbound", "Unbound", "server.ver.role.unbound",
            "/usr/local/sbin/unbound", new String[]{"/usr/local/sbin/unbound", "-V"}, riga("^Version " + V), null);
    /** Quello del sistema base c'e' su ogni FreeBSD: si mostra solo se gira (il pidfile serve a questo). */
    static final Voce LOCAL_UNBOUND = new Voce("local_unbound", "server.ver.name.localUnbound", "server.ver.role.unbound",
            "/usr/sbin/local-unbound", new String[]{"/usr/sbin/local-unbound", "-V"}, riga("^Version " + V), null);
    static final String PIDFILE_LOCAL_UNBOUND = "/var/run/local_unbound.pid";

    /** Le versioni di tutto: "servizi" per le righe di Servizi Mail, "altro" per il resto. */
    public static JSONObject leggi(Sistema s) {
        String javaBin = javaBin(s);
        List<String> binari = new ArrayList<>();
        for (String b : new String[]{POSTFIX.binario(), DOVECOT.binario(), RSPAMD.binario(), REDIS.binario(), CLAMD, MYSQLD,
                ROUNDCUBE + "/index.php", NGINX.binario(), PHP.binario(), PIGEONHOLE.binario(), FAIL2BAN.binario(),
                UNBOUND.binario(), LOCAL_UNBOUND.binario(), OPENSSL_PKG, javaBin}) {
            if (b != null && s.esiste(b)) binari.add(b);
        }
        // Chi possiede ogni binario e quando e' stato installato: due chiamate a pkg per tutti.
        Map<String, String> pacchettoDi = new HashMap<>();
        Map<String, Long> installatoIl = new HashMap<>();
        if (s.esiste(PKG) && !binari.isEmpty()) {
            List<String> argv = new ArrayList<>(List.of(PKG, "which"));
            argv.addAll(binari);
            pacchettoDi = proprietari(s.esegui(argv.toArray(String[]::new)));
            installatoIl = installazioni(s.esegui(PKG, "query", "%n %t"));
        }
        Lettura l = new Lettura(s, pacchettoDi, installatoIl);

        JSONObject servizi = new JSONObject()
                .put("postfix", l.daBinario(POSTFIX))
                .put("dovecot", l.daBinario(DOVECOT))
                .put("mysql", l.mysql())
                .put("rspamd", l.daBinario(RSPAMD))
                .put("redis", l.daBinario(REDIS))
                .put("clamav", l.clamav())
                .put("roundcube", l.roundcube());

        JSONArray altro = new JSONArray();
        altro.put(l.freebsd());
        altro.put(l.openssl(OPENSSL_BASE, "openssl", "OpenSSL", "server.ver.role.openssl"));
        if (s.esiste(OPENSSL_PKG))
            altro.put(l.openssl(OPENSSL_PKG, "openssl_pkg", "server.ver.name.opensslPkg", "server.ver.role.opensslPkg"));
        altro.put(l.daBinario(NGINX));
        altro.put(l.daBinario(PHP));
        altro.put(l.daBinario(PIGEONHOLE));
        altro.put(l.java(javaBin));
        if (s.esiste(FAIL2BAN.binario())) altro.put(l.daBinario(FAIL2BAN));
        if (s.esiste(UNBOUND.binario())) altro.put(l.daBinario(UNBOUND));
        if (s.esiste(LOCAL_UNBOUND.binario()) && l.vivo(PIDFILE_LOCAL_UNBOUND)) altro.put(l.daBinario(LOCAL_UNBOUND));

        return new JSONObject().put("success", true).put("servizi", servizi).put("altro", altro)
                .put("letteAlle", s.adesso().atZone(s.zona()).format(ISTANTE));
    }

    /** Il binario della Java che esegue il pannello, se il percorso e' di quelli che ci si aspetta. */
    private static String javaBin(Sistema s) {
        String home = s.cartellaJava();
        if (home == null || !VALID_PATH.matcher(home).matches() || home.contains("..")) return null;
        return home + "/bin/java";
    }

    /** Le letture di una richiesta: il sistema e quello che pkg ha detto dei pacchetti. */
    private record Lettura(Sistema s, Map<String, String> pacchettoDi, Map<String, Long> installatoIl) {

        String pacchetto(String binario) { return binario == null ? "" : pacchettoDi.getOrDefault(binario, ""); }

        /** Versione dal binario, o dal pacchetto se il binario non risponde; per i demoni, l'ora di avvio. */
        JSONObject daBinario(Voce v) {
            JSONObject r = voce(v.chiave(), v.nome(), v.ruolo());
            if (!s.esiste(v.binario())) return r;
            r.put("installato", true);
            String pkg = pacchetto(v.binario());
            if (!pkg.isEmpty()) r.put("pacchetto", pkg);
            String ver = v.comando() == null ? null : estrai(v.versione(), s.esegui(v.comando()));
            if (ver != null) r.put("versione", ver).put("fonte", String.join(" ", v.comando()));
            else if (!pkg.isEmpty()) r.put("versione", upstream(pkg)).put("fonte", "pkg which " + v.binario());
            if (v.pidfile() != null && !pkg.isEmpty()) avvioEInstallazione(r, v.pidfile(), nome(pkg), I18n.tr(v.nome()));
            return r;
        }

        /** Il processo e' partito prima che il suo pacchetto fosse installato: sta eseguendo la versione di prima. */
        void avvioEInstallazione(JSONObject r, String pidfile, String nomePacchetto, String chi) {
            Long pid = pid(s.leggi(pidfile));
            Instant avvio = pid == null ? null : s.avvio(pid);
            Long installato = installatoIl.get(nomePacchetto);
            if (avvio == null || installato == null) return;
            if (avvio.getEpochSecond() < installato) {
                r.put("riavvio", true).put("notaRiavvio", I18n.tr("server.ver.startedBefore", java.util.Map.of("who", String.valueOf(chi), "start", String.valueOf(data(avvio)), "inst", String.valueOf(data(Instant.ofEpochSecond(installato))))));
            }
        }

        boolean vivo(String pidfile) {
            Long pid = pid(s.leggi(pidfile));
            return pid != null && s.avvio(pid) != null;
        }

        /** Il processo risponde con una versione diversa da quella del pacchetto: va riavviato. */
        void confronta(JSONObject r, String inEsecuzione, String installata, String chi, String rimedio) {
            String a = numeri(inEsecuzione), b = numeri(installata);
            if (a.isEmpty() || b.isEmpty() || a.equals(b)) return;
            r.put("riavvio", true).put("installata", installata)
             .put("notaRiavvio", I18n.tr("server.ver.runningVsInstalled", java.util.Map.of("who", String.valueOf(chi), "run", String.valueOf(inEsecuzione), "inst", String.valueOf(installata), "fix", String.valueOf(rimedio))));
        }

        JSONObject mysql() {
            JSONObject r = voce("mysql", "MySQL", "server.ver.role.mysql");
            String pkg = pacchetto(MYSQLD);
            String vivo = valida(s.versioneMysql());
            if (vivo == null && !s.esiste(MYSQLD)) return r;
            r.put("installato", true);
            if (!pkg.isEmpty()) r.put("pacchetto", pkg);
            if (vivo != null) {
                r.put("versione", vivo).put("fonte", I18n.tr("server.ver.srcMysql")).put("inEsecuzione", true);
                if (!pkg.isEmpty()) confronta(r, vivo, upstream(pkg), "MySQL", I18n.tr("server.ver.fixMysql"));
                return r;
            }
            String ver = estrai(riga("\\bVer\\s+" + V), s.esegui(MYSQLD, "--version"));
            if (ver != null) r.put("versione", ver).put("fonte", MYSQLD + " --version");
            else if (!pkg.isEmpty()) r.put("versione", upstream(pkg)).put("fonte", "pkg which " + MYSQLD);
            return r.put("avviso", I18n.tr("server.ver.mysqlDown"));
        }

        JSONObject clamav() {
            JSONObject r = voce("clamav", "ClamAV", "server.ver.role.clamav");
            if (!s.esiste(CLAMD)) return r;
            r.put("installato", true);
            String pkg = pacchetto(CLAMD);
            if (!pkg.isEmpty()) r.put("pacchetto", pkg);
            Clamd c = clamd(s.chiediClamd(), s.zona());
            boolean daDemone = c != null;
            if (!daDemone) c = clamd(s.esegui(CLAMD, "--version"), s.zona());
            if (c == null) {
                if (!pkg.isEmpty()) r.put("versione", upstream(pkg)).put("fonte", "pkg which " + CLAMD);
                return r;
            }
            r.put("versione", c.motore()).put("fonte", daDemone ? I18n.tr("server.ver.srcClamd", java.util.Map.of("sock", String.valueOf(SOCKET_CLAMD))) : CLAMD + " --version");
            if (daDemone) r.put("inEsecuzione", true);
            if (c.firme() != null) {
                r.put("firme", c.firme());
                r.put("dettaglio", c.del() != null
                        ? I18n.tr("server.ver.sigsOf", java.util.Map.of("n", String.valueOf(c.firme()), "date", String.valueOf(data(c.del()))))
                        : I18n.tr("server.ver.sigs", java.util.Map.of("n", String.valueOf(c.firme()))));
                if (c.del() != null) {
                    long giorni = ChronoUnit.DAYS.between(c.del(), s.adesso());
                    if (giorni > GIORNI_FIRME)
                        r.put("avviso", I18n.tr("server.ver.sigsOld", java.util.Map.of("d", String.valueOf(giorni))));
                }
            }
            if (daDemone && !pkg.isEmpty())
                confronta(r, c.motore(), upstream(pkg), "clamd", I18n.tr("server.ver.fixClamav"));
            return r;
        }

        JSONObject roundcube() {
            JSONObject r = voce("roundcube", "Roundcube", "server.ver.role.roundcube");
            String indice = ROUNDCUBE + "/index.php";
            if (!s.esiste(indice)) return r;
            r.put("installato", true);
            String pkg = pacchetto(indice);
            if (!pkg.isEmpty()) r.put("pacchetto", pkg);
            String ver = estrai(Pattern.compile("RCMAIL_VERSION'\\s*,\\s*'" + V + "'"), s.leggi(ROUNDCUBE + "/program/include/iniset.php"));
            if (ver != null) r.put("versione", ver).put("fonte", "RCMAIL_VERSION in " + ROUNDCUBE + "/program/include/iniset.php");
            else if (!pkg.isEmpty()) r.put("versione", upstream(pkg)).put("fonte", "pkg which " + indice);
            return r;
        }

        JSONObject java(String javaBin) {
            JSONObject r = voce("java", "Java", "server.ver.role.java").put("installato", true);
            String ver = valida(s.versioneJava());
            if (ver == null) return r;
            r.put("versione", ver).put("fonte", I18n.tr("server.ver.srcJava")).put("inEsecuzione", true);
            String pkg = pacchetto(javaBin);
            if (!pkg.isEmpty()) {
                r.put("pacchetto", pkg);
                confronta(r, ver, upstream(pkg), I18n.tr("server.ver.panelJava"), I18n.tr("server.ver.fixPanel"));
            }
            return r;
        }

        JSONObject freebsd() {
            JSONObject r = voce("freebsd", "FreeBSD", "server.ver.role.freebsd");
            if (!s.esiste(FREEBSD_VERSION)) return r;
            String userland = valida(prima(s.esegui(FREEBSD_VERSION, "-u")));
            if (userland == null) return r;
            String inEsecuzione = valida(prima(s.esegui(FREEBSD_VERSION, "-r")));
            String installato = valida(prima(s.esegui(FREEBSD_VERSION, "-k")));
            r.put("installato", true).put("versione", userland).put("fonte", "freebsd-version -u");
            // Kernel e userland possono avere patch diverse per buone ragioni (una fix che
            // tocca solo l'una o l'altro): si dice, ma non e' un problema.
            if (inEsecuzione != null && !inEsecuzione.equals(userland)) r.put("dettaglio", I18n.tr("server.ver.kernelRunning", java.util.Map.of("v", String.valueOf(inEsecuzione))));
            // L'Handbook: kernel installato diverso da quello in esecuzione vuol dire riavvio mancante.
            if (installato != null && inEsecuzione != null && !installato.equals(inEsecuzione)) {
                r.put("riavvio", true).put("installata", installato).put("notaRiavvio", I18n.tr("server.ver.kernelReboot", java.util.Map.of("inst", String.valueOf(installato), "run", String.valueOf(inEsecuzione))));
            }
            return r;
        }

        JSONObject openssl(String binario, String chiave, String nome, String ruolo) {
            JSONObject r = voce(chiave, nome, ruolo);
            if (!s.esiste(binario)) return r;
            r.put("installato", true);
            String pkg = pacchetto(binario);
            if (!pkg.isEmpty()) r.put("pacchetto", pkg);
            String out = s.esegui(binario, "version");
            Matcher m = Pattern.compile("^(?:OpenSSL|LibreSSL)\\s+" + V + "(?:\\s+(\\d{1,2} [A-Z][a-z]{2} \\d{4}))?", Pattern.MULTILINE)
                    .matcher(out == null ? "" : out);
            if (m.find() && valida(m.group(1)) != null) {
                r.put("versione", m.group(1)).put("fonte", binario + " version");
                if (m.group(2) != null) {
                    try {
                        LocalDate d = LocalDate.parse(m.group(2), DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH));
                        r.put("dettaglio", I18n.tr("server.ver.released", java.util.Map.of("date", String.valueOf(d.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))))));
                    } catch (Exception ignorata) { /* la data e' un di piu' */ }
                }
            } else if (!pkg.isEmpty()) {
                r.put("versione", upstream(pkg)).put("fonte", "pkg which " + binario);
            }
            return r;
        }

        String data(Instant i) { return i.atZone(s.zona()).format(DATA_ORA); }
    }

    private static JSONObject voce(String chiave, String nome, String ruolo) {
        return new JSONObject().put("chiave", chiave).put("nome", I18n.tr(nome)).put("ruolo", I18n.tr(ruolo)).put("installato", false);
    }

    /** Il primo gruppo del modello nell'uscita, se e' una versione; altrimenti null. */
    static String estrai(Pattern modello, String uscita) {
        if (uscita == null) return null;
        Matcher m = modello.matcher(uscita);
        return m.find() ? valida(m.group(1)) : null;
    }

    static String valida(String v) {
        if (v == null) return null;
        String t = v.strip();
        return VALID_VERSION.matcher(t).matches() ? t : null;
    }

    private static String prima(String uscita) {
        if (uscita == null) return null;
        String t = uscita.strip();
        int a = t.indexOf('\n');
        return a < 0 ? t : t.substring(0, a).strip();
    }

    /**
     * "pkg which": "/usr/local/sbin/postconf was installed by package postfix-mysql-3.10.4,1".
     * I file che nessun pacchetto possiede ("was not found in the database") non compaiono.
     */
    static Map<String, String> proprietari(String uscita) {
        Map<String, String> m = new HashMap<>();
        if (uscita == null) return m;
        Matcher r = Pattern.compile("^(/\\S+) was installed by package (\\S+)$", Pattern.MULTILINE).matcher(uscita);
        while (r.find()) {
            String nv = r.group(2);
            int trattino = nv.lastIndexOf('-');
            if (trattino > 0 && valida(nv.substring(trattino + 1)) != null && nv.matches("[0-9A-Za-z.+_,:~-]{1,100}"))
                m.put(r.group(1), nv);
        }
        return m;
    }

    /** "pkg query '%n %t'": nome del pacchetto e ora di installazione (secondi dal 1970). */
    static Map<String, Long> installazioni(String uscita) {
        Map<String, Long> m = new HashMap<>();
        if (uscita == null) return m;
        Matcher r = Pattern.compile("^([0-9A-Za-z.+_-]{1,100}) (\\d{1,12})$", Pattern.MULTILINE).matcher(uscita);
        while (r.find()) m.put(r.group(1), Long.parseLong(r.group(2)));
        return m;
    }

    /** Il nome di un pacchetto da "nome-versione": la versione e' dopo l'ultimo trattino. */
    static String nome(String nomeVersione) {
        int t = nomeVersione.lastIndexOf('-');
        return t > 0 ? nomeVersione.substring(0, t) : nomeVersione;
    }

    /**
     * La versione del programma da quella del pacchetto, senza la revisione del port e l'epoca:
     * "postfix-mysql-3.10.4,1" -> "3.10.4", "dovecot-mysql-2.3.21.1_8" -> "2.3.21.1".
     */
    static String upstream(String nomeVersione) {
        int t = nomeVersione.lastIndexOf('-');
        String v = t >= 0 ? nomeVersione.substring(t + 1) : nomeVersione;
        return v.replaceFirst(",\\d+$", "").replaceFirst("_\\d+$", "");
    }

    /** La parte numerica iniziale, per confrontare: "8.0.43-debug" -> "8.0.43", "25.0.1+8-LTS" -> "25.0.1". */
    static String numeri(String v) {
        if (v == null) return "";
        Matcher m = Pattern.compile("^\\d+(?:\\.\\d+)*").matcher(v.strip());
        return m.find() ? m.group() : "";
    }

    /** Il pid scritto in un pidfile (Postfix lo allinea a destra con degli spazi). */
    static Long pid(String contenuto) {
        if (contenuto == null) return null;
        String t = contenuto.strip();
        if (!t.matches("\\d{1,10}")) return null;
        long p = Long.parseLong(t);
        return p > 1 ? p : null;
    }

    /** La risposta di clamd: motore, numero delle firme e loro data (null se non ci sono). */
    record Clamd(String motore, String firme, Instant del) {}

    /**
     * "ClamAV 1.4.3/27780/Thu Oct  2 08:24:28 2026": la data e' quella di ctime(), nell'ora locale
     * del server, cioe' la stessa zona della JVM che la legge qui.
     */
    static Clamd clamd(String risposta, ZoneId zona) {
        if (risposta == null) return null;
        Matcher m = Pattern.compile("ClamAV " + V + "(?:/(\\d{1,9})/([A-Za-z]{3} [A-Za-z]{3} +\\d{1,2} \\d{2}:\\d{2}:\\d{2} \\d{4}))?")
                .matcher(risposta);
        if (!m.find()) return null;
        String motore = valida(m.group(1));
        if (motore == null) return null;
        Instant del = null;
        if (m.group(3) != null) {
            try {
                del = LocalDateTime.parse(m.group(3).replaceAll(" +", " "),
                        DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH)).atZone(zona).toInstant();
            } catch (Exception ignorata) { /* senza data si mostra solo il numero */ }
        }
        return new Clamd(motore, m.group(2), del);
    }

    // ===== Il sistema vero =====

    /** Il server: comandi con Shell (argomenti separati, niente shell), file, socket di clamd. */
    public static Sistema reale(Supplier<String> versioneMysql) {
        return new Sistema() {
            public String esegui(String... argv) {
                Shell.Result r = Shell.run(Duration.ofSeconds(10), argv);
                if (r.timedOut() || r.exitCode() < 0) return null;
                String out = r.output();
                return out.length() > 65536 ? out.substring(0, 65536) : out;
            }
            public boolean esiste(String percorso) { return Files.exists(Path.of(percorso)); }
            public String leggi(String percorso) {
                try {
                    Path p = Path.of(percorso);
                    if (!Files.isRegularFile(p) || Files.size(p) > 262144) return null;
                    return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return null;
                }
            }
            public String chiediClamd() { return chiediAClamd(Path.of(SOCKET_CLAMD)); }
            public String versioneMysql() {
                try { return versioneMysql.get(); } catch (Exception e) { return null; }
            }
            public Instant avvio(long pid) {
                return ProcessHandle.of(pid).flatMap(p -> p.info().startInstant()).orElse(null);
            }
            public String versioneJava() { return Runtime.version().toString(); }
            public String cartellaJava() { return System.getProperty("java.home"); }
            public Instant adesso() { return Instant.now(); }
            public ZoneId zona() { return ZoneId.systemDefault(); }
        };
    }

    /**
     * Chiede VERSION a clamd ("z": comando e risposta terminati da un byte zero). Al massimo tre
     * secondi: una lettura bloccata su un clamd che non risponde fermerebbe la richiesta per
     * sempre, e chiudere il socket (in uscita dal try) e' cio' che la sblocca.
     */
    static String chiediAClamd(Path socket) {
        if (!Files.exists(socket)) return null;
        try (ExecutorService es = Executors.newVirtualThreadPerTaskExecutor();
             SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            Future<String> f = es.submit(() -> {
                ch.connect(UnixDomainSocketAddress.of(socket));
                ch.write(ByteBuffer.wrap("zVERSION\0".getBytes(StandardCharsets.US_ASCII)));
                ByteBuffer b = ByteBuffer.allocate(512);
                while (b.hasRemaining() && ch.read(b) > 0) {
                    if (b.position() > 0 && b.get(b.position() - 1) == 0) break;
                }
                String t = new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII);
                int zero = t.indexOf('\0');
                return (zero >= 0 ? t.substring(0, zero) : t).strip();
            });
            String r = f.get(3, TimeUnit.SECONDS);
            return r.isEmpty() ? null : r;
        } catch (Exception e) {
            return null;
        }
    }
}
