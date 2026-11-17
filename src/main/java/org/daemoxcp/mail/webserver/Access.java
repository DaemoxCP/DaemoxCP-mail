package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.security.AuthStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Objects;

/**
 * Chi puo' usare una rotta. Ogni rotta lo dichiara quando la si registra (SSLMailServer.context):
 * pubblica, o con il permesso con nome che serve (AuthStore.may). Non c'e' un context senza
 * Access: una rotta senza dichiarazione non esiste.
 *
 * Il controllo lo fa il filtro di ogni rotta, prima del gestore:
 *  - senza una sessione valida, una pagina rimanda all'accesso e una API risponde 401;
 *  - con una sessione ma senza il permesso, una pagina mostra "accesso negato" nella cornice del
 *    pannello e una API risponde 403 con forbidden: true.
 *
 * Il permesso dipende dal metodo (GET legge, il resto cambia) e, dove serve, dall'azione: quella
 * di ?action= per una GET, quella del corpo JSON per gli altri metodi. Un'azione che non e' nella
 * tabella vale come le altre richieste con lo stesso metodo.
 *
 * <p>Le operazioni pericolose chiedono anche una conferma recente:
 * una richiesta che cambia qualcosa con uno dei permessi di {@link #CONFIRMED}, o su una rotta che la chiede
 * sempre ({@link #confirmingAlways}), passa solo se chi la fa ha confermato di essere lui negli ultimi minuti. Con
 * la passkey o con un codice via email, a scelta, se ha una passkey; col codice, se non ne ha. Le azioni che
 * leggono soltanto ({@link #reading}) non la chiedono, e una GET mai.
 */
public final class Access {

    public enum Kind { PUBLIC, PAGE, API }

    private final Kind kind;
    private final String read;
    private final String write;
    private final Map<String, String> actions;
    /** Le azioni che leggono soltanto, anche se arrivano con una POST: niente conferma. */
    private final Set<String> reads;
    /** La rotta chiede la conferma a ogni richiesta che non e' una lettura, qualunque sia il permesso. */
    private final boolean confirmAlways;

    /**
     * I permessi delle operazioni pericolose: pacchetti, aggiornamenti e servizi; sicurezza e firewall; amministratori;
     * vault; impostazioni del server; chiavi SSH di root.
     */
    public static final Set<String> CONFIRMED = Set.of("system.manage", "security.manage", "admins.manage", "vault.manage",
            "settings.manage", "ssh.manage");

    private Access(Kind kind, String read, String write, Map<String, String> actions) {
        this(kind, read, write, actions, Set.of(), false);
    }

    private Access(Kind kind, String read, String write, Map<String, String> actions, Set<String> reads, boolean confirmAlways) {
        this.kind = kind;
        this.read = known(read);
        this.write = known(write);
        this.actions = actions == null ? Map.of() : Map.copyOf(actions);
        this.actions.values().forEach(Access::known);
        this.reads = Set.copyOf(reads);
        this.confirmAlways = confirmAlways;
    }

    /** La stessa rotta, con queste azioni che leggono soltanto: non chiedono la conferma. */
    public Access reading(String... actions) {
        Set<String> r = new java.util.HashSet<>(reads);
        r.addAll(Set.of(actions));
        return new Access(kind, read, write, this.actions, r, confirmAlways);
    }

    /** La stessa rotta, che chiede la conferma a ogni richiesta che cambia o rivela qualcosa («Rivela»). */
    public Access confirmingAlways() {
        return new Access(kind, read, write, actions, reads, true);
    }

    /** Un permesso scritto male si scopre all'avvio, non quando nessuno riesce a usare la pagina. */
    private static String known(String permission) {
        if (permission != null && !AuthStore.ALL_PERMISSIONS.contains(permission))
            throw new IllegalArgumentException("Unknown permission: " + permission);
        return permission;
    }

    /** Senza accesso: la pagina di accesso, i suoi file, il dizionario, l'uscita, autoconfig e MTA-STS. */
    public static final Access PUBLIC = new Access(Kind.PUBLIC, null, null, null);

    /** Una pagina: lo stesso permesso per ogni metodo. */
    public static Access page(String permission) {
        return new Access(Kind.PAGE, Objects.requireNonNull(permission), permission, null);
    }

    /** Una API: lo stesso permesso per ogni metodo. */
    public static Access api(String permission) {
        return new Access(Kind.API, Objects.requireNonNull(permission), permission, null);
    }

    /** Una API che con GET legge e con gli altri metodi cambia. */
    public static Access api(String read, String write) {
        return new Access(Kind.API, Objects.requireNonNull(read), Objects.requireNonNull(write), null);
    }

    /** Come api(read, write), con le azioni che chiedono un permesso diverso. */
    public static Access api(String read, String write, Map<String, String> actions) {
        return new Access(Kind.API, Objects.requireNonNull(read), Objects.requireNonNull(write), Objects.requireNonNull(actions));
    }

    /** Una tabella azione -> permesso: un permesso (ha un punto), poi le sue azioni, poi il permesso seguente. */
    public static Map<String, String> actions(String... permissionsAndActions) {
        Map<String, String> m = new HashMap<>();
        String permission = null;
        for (String s : permissionsAndActions) {
            if (s.contains(".")) permission = s;
            else if (m.put(s, permission) != null) throw new IllegalArgumentException("Action listed twice: " + s);
        }
        return m;
    }

    public Kind kind() { return kind; }

    public String readPermission() { return read; }

    public String writePermission() { return write; }

    /** Vero se il permesso o la conferma dipendono dall'azione: il filtro deve leggerla (dal corpo, per una POST). */
    boolean byAction() { return !actions.isEmpty() || !reads.isEmpty(); }

    /**
     * Vero se questa richiesta chiede una conferma recente: non e' una GET, non e' un'azione che legge soltanto, e il
     * suo permesso e' di un'operazione pericolosa (o la rotta la chiede sempre).
     */
    public boolean needsConfirmation(String method, String action) {
        if (kind != Kind.API || "GET".equals(method) || "HEAD".equals(method)) return false;
        if (action != null && reads.contains(action)) return false;
        return confirmAlways || CONFIRMED.contains(permissionFor(method, action));
    }

    /**
     * Vero se questa richiesta puo' cambiare qualcosa: non e' una GET, non e' un'azione che legge soltanto, e il suo
     * permesso non e' uno di quelli che vedono e basta ("x.view"). E' la regola del riavvio programmato
     * (RestartLock): fino al riavvio passano solo le richieste per cui questo e' falso.
     */
    public boolean changes(String method, String action) {
        if (kind != Kind.API || "GET".equals(method) || "HEAD".equals(method)) return false;
        if (action != null && reads.contains(action)) return false;
        String p = permissionFor(method, action);
        return p == null || !p.endsWith(".view");
    }

    /** Il permesso di una richiesta: il metodo e, se c'e', l'azione. */
    public String permissionFor(String method, String action) {
        String p = action == null ? null : actions.get(action);
        if (p != null) return p;
        return "GET".equals(method) || "HEAD".equals(method) ? read : write;
    }
}
