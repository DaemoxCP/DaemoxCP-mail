package org.daemoxcp.mail.monitoring;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * La coda di Postfix: elenco, contenuto di un messaggio, eliminazione, nuovo tentativo,
 * messaggi trattenuti e rilasciati, statistiche.
 *
 * Comandi di Postfix:
 *  - postqueue -j        l'elenco, un oggetto JSON per messaggio (Postfix 3.1 e successivi)
 *  - postcat -h -b -q    intestazioni e testo di un messaggio
 *  - postsuper -d / -r   elimina un messaggio / lo rimette in coda
 *  - postsuper -h / -H   trattiene / rilascia
 *  - postqueue -f        riprova subito tutto
 *
 * I comandi partono con gli argomenti separati, mai attraverso sh -c, e l'identificativo di
 * coda si controlla PRIMA di usarlo (isQueueId). Prima l'identificativo arrivava dalla richiesta
 * dritto in una riga di shell: /api/queue?action=message&id=X;comando eseguiva il comando, e
 * bastava un link aperto da un amministratore collegato.
 *
 * L'elenco si legge da postqueue -j e non dal testo di postqueue -p: il testo mette il motivo
 * del rinvio fra parentesi su una riga che il vecchio lettore scambiava per il destinatario,
 * cosi' la colonna Errore restava sempre vuota e "Elimina falliti" non trovava mai niente.
 *
 * I messaggi per chi usa il pannello passano da I18n.tr (chiavi server.queue.*), nella lingua
 * della richiesta; le eccezioni e i log restano in inglese.
 */
public class MailQueueManager {

    private static final String POSTQUEUE = "/usr/local/sbin/postqueue";
    private static final String POSTCAT = "/usr/local/sbin/postcat";
    private static final String POSTSUPER = "/usr/local/sbin/postsuper";

    /**
     * Gli identificativi di coda di Postfix sono alfanumerici: corti in esadecimale (3A1F2B4C5D)
     * o lunghi in base 52 (4Nq8Zk1yQPz9Lm2). Qualsiasi altra cosa si rifiuta senza lanciare nulla.
     */
    private static final Pattern QUEUE_ID = Pattern.compile("[0-9A-Za-z]{5,32}");

    /** Quanto testo del messaggio si mostra al massimo. */
    static final int BODY_PREVIEW = 2000;

    /** Chi lancia i comandi: Shell.run, sostituibile nelle prove. */
    public interface Runner {
        Shell.Result run(String... cmd);
    }

    private final Runner runner;

    public MailQueueManager() {
        this(Shell::run);
    }

    public MailQueueManager(Runner runner) {
        this.runner = runner;
    }

    public enum QueueState {
        ACTIVE,       // in consegna adesso
        DEFERRED,     // rinviato: errore temporaneo, Postfix riprovera'
        HOLD,         // trattenuto: non parte finche' non viene rilasciato
        INCOMING,     // appena arrivato (incoming o maildrop)
        CORRUPT,      // file di coda illeggibile
        UNKNOWN
    }

    /** true se il testo e' un identificativo di coda ammissibile. */
    public static boolean isQueueId(String id) {
        return id != null && QUEUE_ID.matcher(id).matches();
    }

    // ------------------------------------------------------------------ elenco

    /**
     * Tutti i messaggi in coda.
     *
     * @throws IllegalStateException se postqueue non risponde come dovrebbe
     */
    public List<QueuedMessage> getQueue() {
        Shell.Result r = runner.run(POSTQUEUE, "-j");
        if (!r.success()) {
            throw new IllegalStateException("postqueue -j failed (exit " + r.exitCode() + "): " + r.outputTrim());
        }
        return parseJsonQueue(r.output());
    }

    /**
     * L'uscita di postqueue -j: un oggetto JSON per riga. Le righe che non sono JSON (un avviso
     * di Postfix finito nello stesso flusso) si saltano.
     */
    public static List<QueuedMessage> parseJsonQueue(String output) {
        List<QueuedMessage> messages = new ArrayList<>();
        if (output == null) return messages;
        for (String line : output.split("\n")) {
            line = line.trim();
            if (!line.startsWith("{")) continue;
            JSONObject o;
            try {
                o = new JSONObject(line);
            } catch (JSONException e) {
                continue;
            }
            QueuedMessage m = new QueuedMessage();
            m.id = o.optString("queue_id", "");
            m.state = stateOf(o.optString("queue_name", ""));
            m.sender = o.optString("sender", "");
            m.size = o.optLong("message_size", 0);
            long arrival = o.optLong("arrival_time", 0);
            m.arrival = arrival > 0 ? Instant.ofEpochSecond(arrival) : null;
            JSONArray recipients = o.optJSONArray("recipients");
            if (recipients != null) {
                for (int i = 0; i < recipients.length(); i++) {
                    JSONObject rcpt = recipients.optJSONObject(i);
                    if (rcpt == null) continue;
                    String reason = rcpt.optString("delay_reason", "");
                    m.recipients.add(new Recipient(rcpt.optString("address", ""), reason.isBlank() ? null : reason));
                }
            }
            messages.add(m);
        }
        return messages;
    }

    private static QueueState stateOf(String queueName) {
        return switch (queueName) {
            case "active" -> QueueState.ACTIVE;
            case "deferred" -> QueueState.DEFERRED;
            case "hold" -> QueueState.HOLD;
            case "incoming", "maildrop" -> QueueState.INCOMING;
            case "corrupt" -> QueueState.CORRUPT;
            default -> QueueState.UNKNOWN;
        };
    }

    // ------------------------------------------------------------------ un messaggio

    /** Intestazioni e inizio del testo di un messaggio in coda. */
    public MessageContent getMessage(String id) {
        MessageContent content = new MessageContent();
        content.id = id;
        if (!isQueueId(id)) {
            content.error = I18n.tr("server.queue.badId");
            return content;
        }
        Shell.Result r = runner.run(POSTCAT, "-h", "-b", "-q", id);
        if (!r.success() || r.outputTrim().isEmpty()) {
            content.error = I18n.tr("server.queue.notFound", Map.of("id", id));
            return content;
        }
        parseMessage(r.output(), content);
        content.found = true;
        return content;
    }

    /** Le intestazioni fino alla prima riga vuota, poi il testo; le righe "*** ... ***" di postcat no. */
    static void parseMessage(String output, MessageContent content) {
        StringBuilder headers = new StringBuilder();
        StringBuilder body = new StringBuilder();
        boolean inBody = false;
        for (String line : output.split("\n")) {
            if (line.startsWith("*** ") && line.endsWith(" ***")) continue;
            if (!inBody) {
                if (line.isEmpty()) {
                    inBody = true;
                    continue;
                }
                headers.append(line).append("\n");
                String lower = line.toLowerCase(Locale.ROOT);
                if (lower.startsWith("from:")) content.fromHeader = line.substring(5).trim();
                else if (lower.startsWith("to:")) content.toHeader = line.substring(3).trim();
                else if (lower.startsWith("subject:")) content.subject = line.substring(8).trim();
                else if (lower.startsWith("date:")) content.dateHeader = line.substring(5).trim();
            } else {
                body.append(line).append("\n");
            }
        }
        content.headers = headers.toString();
        String text = body.toString();
        content.bodyTruncated = text.length() > BODY_PREVIEW;
        content.bodyPreview = content.bodyTruncated ? text.substring(0, BODY_PREVIEW) : text;
    }

    // ------------------------------------------------------------------ azioni

    /** Elimina un messaggio dalla coda. */
    public QueueAction removeMessage(String id) {
        if (!isQueueId(id)) return QueueAction.failed(I18n.tr("server.queue.badId"));
        Shell.Result r = runner.run(POSTSUPER, "-d", id);
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        // postsuper scrive "ID: removed" per ogni messaggio eliminato, e niente se non c'era
        if (!r.output().contains(id + ": removed")) {
            return QueueAction.failed(I18n.tr("server.queue.notFound", Map.of("id", id)));
        }
        return QueueAction.done(I18n.tr("server.queue.removed", Map.of("id", id)));
    }

    /** Rimette un messaggio in coda per un nuovo tentativo. */
    public QueueAction scheduleMessage(String id) {
        if (!isQueueId(id)) return QueueAction.failed(I18n.tr("server.queue.badId"));
        Shell.Result r = runner.run(POSTSUPER, "-r", id);
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        if (!r.output().contains(id + ": requeued")) {
            return QueueAction.failed(I18n.tr("server.queue.notFound", Map.of("id", id)));
        }
        return QueueAction.done(I18n.tr("server.queue.requeued", Map.of("id", id)));
    }

    /** Chiede a Postfix di riprovare subito tutti i messaggi. */
    public QueueAction flushQueue() {
        Shell.Result r = runner.run(POSTQUEUE, "-f");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.tr("server.queue.flushed"));
    }

    /** Trattiene tutti i messaggi in coda adesso (quelli che arrivano dopo partono normalmente). */
    public QueueAction holdAll() {
        Shell.Result r = runner.run(POSTSUPER, "-h", "ALL");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.trn("server.queue.held", countIn(r.output(), "Placed on hold"), Map.of()));
    }

    /** Rilascia tutti i messaggi trattenuti. */
    public QueueAction releaseAll() {
        Shell.Result r = runner.run(POSTSUPER, "-H", "ALL");
        if (!r.success()) return QueueAction.failed(commandFailed(r));
        return QueueAction.done(I18n.trn("server.queue.released", countIn(r.output(), "Released from hold"), Map.of()));
    }

    /** Il numero nel riepilogo di postsuper ("Placed on hold: 3 messages"); 0 se non c'e'. */
    static long countIn(String output, String label) {
        Matcher m = Pattern.compile(Pattern.quote(label) + ":\\s*(\\d{1,9})").matcher(output == null ? "" : output);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }

    private static String commandFailed(Shell.Result r) {
        String out = r.outputTrim();
        if (out.length() > 300) out = out.substring(0, 300) + "...";
        return I18n.tr("server.queue.commandFailed", Map.of("output", out));
    }

    // ------------------------------------------------------------------ statistiche

    /** Quanti messaggi per stato, il piu' vecchio, i mittenti e i domini di destinazione piu' presenti. */
    public QueueStats getStats() {
        return statsOf(getQueue());
    }

    static QueueStats statsOf(List<QueuedMessage> messages) {
        QueueStats stats = new QueueStats();
        stats.totalMessages = messages.size();
        for (QueuedMessage msg : messages) {
            stats.totalSize += msg.size;
            switch (msg.state) {
                case ACTIVE -> stats.active++;
                case DEFERRED -> stats.deferred++;
                case HOLD -> stats.hold++;
                case INCOMING -> stats.incoming++;
                default -> stats.unknown++;
            }
            if (msg.isPermanentFailure()) stats.permanent++;
            if (msg.sender != null && !msg.sender.isEmpty()) stats.topSenders.merge(msg.sender, 1, Integer::sum);
            for (Recipient r : msg.recipients) {
                int at = r.address().lastIndexOf('@');
                if (at >= 0 && at < r.address().length() - 1) {
                    stats.topDestinations.merge(r.address().substring(at + 1).toLowerCase(Locale.ROOT), 1, Integer::sum);
                }
            }
            if (msg.arrival != null && (stats.oldestMessage == null || msg.arrival.isBefore(stats.oldestMessage))) {
                stats.oldestMessage = msg.arrival;
            }
        }
        return stats;
    }

    // ------------------------------------------------------------------ errori permanenti

    /**
     * Un errore di consegna PERMANENTE.
     *
     * Il criterio non e' "e' in coda da tanto": e' il codice di risposta. SMTP distingue il
     * 4xx (riprova piu' tardi) dal 5xx (non riprovarci), e i secondi in coda non si
     * risolveranno mai da soli. Si riconoscono dal codice di stato esteso 5.x.x (RFC 3463)
     * oppure dal codice a tre cifre che comincia per 5 riportato nel messaggio d'errore.
     *
     * Il confronto NON e' su sottostringa: cercare "5." dentro il testo troverebbe anche una
     * dimensione "1.5.", un orario o un indirizzo IP, e si cancellerebbe posta buona.
     */
    public static boolean isPermanentFailure(String error) {
        if (error == null || error.isBlank()) return false;
        // 1. codice di stato esteso 5.x.y (RFC 3463), isolato: "10.5.0.1" non deve contare
        if (Pattern.compile("(?<![0-9.])5\\.[0-9]{1,3}\\.[0-9]{1,3}(?![0-9.])").matcher(error).find()) return true;
        // 2. codice di risposta a tre cifre, ma SOLO dove un codice puo' stare davvero:
        //    dopo "said:" o all'inizio della riga. Accettarlo ovunque farebbe scambiare
        //    "size=550" per un rifiuto definitivo, e si cancellerebbe un messaggio buono.
        return Pattern.compile("(?:said:\\s*|^\\s*)5[0-9]{2}(?![0-9])", Pattern.CASE_INSENSITIVE).matcher(error).find();
    }

    /** I messaggi in coda che hanno fallito in modo permanente. Legge e basta. */
    public List<QueuedMessage> permanentFailures() {
        List<QueuedMessage> out = new ArrayList<>();
        for (QueuedMessage m : getQueue()) if (m.isPermanentFailure()) out.add(m);
        return out;
    }

    /**
     * Elimina, fra i messaggi che chi usa il pannello ha visto e confermato (ids), quelli che
     * hanno ANCORA un errore permanente. Uno per uno.
     *
     * Solo quelli confermati: fra l'anteprima e la conferma la coda cambia, e un messaggio
     * arrivato nel frattempo non e' stato visto da nessuno. Solo quelli ancora permanenti: uno
     * che nel frattempo e' stato consegnato o rimesso in coda non si tocca.
     *
     * Non si usa "postsuper -d ALL deferred": cancellerebbe TUTTA la coda rinviata, compresi i
     * messaggi con errore temporaneo che sarebbero partiti al prossimo tentativo.
     */
    public QueueAction purgePermanentFailures(Collection<String> ids) {
        Set<String> confirmed = new HashSet<>();
        for (String id : ids) if (isQueueId(id)) confirmed.add(id);
        int deleted = 0, failed = 0;
        StringBuilder log = new StringBuilder();
        for (QueuedMessage m : permanentFailures()) {
            if (!confirmed.contains(m.id)) continue;
            Shell.Result r = runner.run(POSTSUPER, "-d", m.id);
            if (r.success() && r.output().contains(m.id + ": removed")) {
                deleted++;
            } else {
                failed++;
                log.append(m.id).append(": ").append(r.outputTrim()).append("\n");
            }
        }
        String message = I18n.trn("server.queue.purged", deleted, Map.of());
        if (failed > 0) message += " " + I18n.trn("server.queue.purgeFailed", failed, Map.of());
        message += " " + I18n.tr("server.queue.purgeUntouched");
        QueueAction action = failed == 0 ? QueueAction.done(message) : QueueAction.failed(message);
        action.count = deleted;
        action.output = log.toString();
        return action;
    }

    // ------------------------------------------------------------------ dati

    /** Un destinatario e, se Postfix ha gia' provato, il motivo del rinvio. */
    public record Recipient(String address, String reason) {}

    public static class QueuedMessage {
        public String id;
        public QueueState state = QueueState.UNKNOWN;
        /** Vuoto per gli avvisi di mancata consegna (mittente nullo). */
        public String sender;
        public final List<Recipient> recipients = new ArrayList<>();
        public long size;
        /** Arrivo in coda, in UTC. */
        public Instant arrival;

        /** Il primo motivo di rinvio fra i destinatari, o null. */
        public String errorReason() {
            for (Recipient r : recipients) if (r.reason() != null) return r.reason();
            return null;
        }

        /**
         * Permanente solo se lo e' per OGNI destinatario: eliminare il messaggio lo toglie a
         * tutti, e uno con un errore temporaneo (o non ancora provato) sarebbe partito.
         */
        public boolean isPermanentFailure() {
            if (recipients.isEmpty()) return false;
            for (Recipient r : recipients) if (!MailQueueManager.isPermanentFailure(r.reason())) return false;
            return true;
        }
    }

    public static class MessageContent {
        public String id;
        public boolean found;
        public String headers;
        public String bodyPreview;
        public boolean bodyTruncated;
        public String fromHeader;
        public String toHeader;
        public String subject;
        public String dateHeader;
        public String error;
    }

    public static class QueueAction {
        public boolean success;
        public String message;
        public String output;
        public int count;

        static QueueAction done(String message) {
            QueueAction a = new QueueAction();
            a.success = true;
            a.message = message;
            return a;
        }

        static QueueAction failed(String message) {
            QueueAction a = new QueueAction();
            a.message = message;
            return a;
        }
    }

    public static class QueueStats {
        public int totalMessages;
        public long totalSize;
        public int active;
        public int deferred;
        public int hold;
        public int incoming;
        public int unknown;
        /** Messaggi con un errore permanente per ogni destinatario. */
        public int permanent;
        public Instant oldestMessage;
        public final Map<String, Integer> topSenders = new HashMap<>();
        public final Map<String, Integer> topDestinations = new HashMap<>();
    }
}
