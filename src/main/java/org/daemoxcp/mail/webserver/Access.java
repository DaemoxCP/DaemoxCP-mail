package org.daemoxcp.mail.webserver;

import org.daemoxcp.mail.security.AuthStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.Objects;

/**
 * Who can use a route. Every route declares it when it is registered (SSLMailServer.context):
 * public, or with the named permission it needs (AuthStore.may). There is no context without
 * Access: a route without a declaration does not exist.
 *
 * The check is done by the filter of every route, before the handler:
 *  - without a valid session, a page redirects to the login and an API responds 401;
 *  - with a session but without the permission, a page shows "access denied" in the panel
 *    frame and an API responds 403 with forbidden: true.
 *
 * The permission depends on the method (GET reads, the rest changes) and, where needed, on the action: the
 * one in ?action= for a GET, the one in the JSON body for the other methods. An action that is not in the
 * table counts like the other requests with the same method.
 *
 * <p>Dangerous operations also require a recent confirmation:
 * a request that changes something with one of the permissions in {@link #CONFIRMED}, or on a route that always
 * requires it ({@link #confirmingAlways}), passes only if whoever makes it has confirmed their identity in the
 * last few minutes. With the passkey or with a code via email, as they choose, if they have a passkey; with the
 * code, if they have none. The actions that only read ({@link #reading}) do not require it, and a GET never does.
 */
public final class Access {

    public enum Kind { PUBLIC, PAGE, API }

    private final Kind kind;
    private final String read;
    private final String write;
    private final Map<String, String> actions;
    /** The actions that only read, even if they arrive with a POST: no confirmation. */
    private final Set<String> reads;
    /** The route requires confirmation on every request that is not a read, whatever the permission. */
    private final boolean confirmAlways;

    /**
     * The permissions of the dangerous operations: packages, updates and services; security and firewall;
     * administrators; vault; server settings; root SSH keys.
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

    /** The same route, with these actions that only read: they do not require confirmation. */
    public Access reading(String... actions) {
        Set<String> r = new java.util.HashSet<>(reads);
        r.addAll(Set.of(actions));
        return new Access(kind, read, write, this.actions, r, confirmAlways);
    }

    /** The same route, which requires confirmation on every request that changes or reveals something ("Reveal"). */
    public Access confirmingAlways() {
        return new Access(kind, read, write, actions, reads, true);
    }

    /** A misspelled permission is discovered at boot, not when nobody manages to use the page. */
    private static String known(String permission) {
        if (permission != null && !AuthStore.ALL_PERMISSIONS.contains(permission))
            throw new IllegalArgumentException("Unknown permission: " + permission);
        return permission;
    }

    /** Without login: the login page, its files, the dictionary, the logout, autoconfig and MTA-STS. */
    public static final Access PUBLIC = new Access(Kind.PUBLIC, null, null, null);

    /** A page: the same permission for every method. */
    public static Access page(String permission) {
        return new Access(Kind.PAGE, Objects.requireNonNull(permission), permission, null);
    }

    /** An API: the same permission for every method. */
    public static Access api(String permission) {
        return new Access(Kind.API, Objects.requireNonNull(permission), permission, null);
    }

    /** An API that reads with GET and changes with the other methods. */
    public static Access api(String read, String write) {
        return new Access(Kind.API, Objects.requireNonNull(read), Objects.requireNonNull(write), null);
    }

    /** Like api(read, write), with the actions that require a different permission. */
    public static Access api(String read, String write, Map<String, String> actions) {
        return new Access(Kind.API, Objects.requireNonNull(read), Objects.requireNonNull(write), Objects.requireNonNull(actions));
    }

    /** An action -> permission table: a permission (it has a dot), then its actions, then the next permission. */
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

    /**
     * True if the permission or the confirmation depends on the action: the filter must read it (from the body,
     * for a POST).
     */
    boolean byAction() { return !actions.isEmpty() || !reads.isEmpty(); }

    /**
     * True if this request requires a recent confirmation: it is not a GET, it is not an action that only reads, and
     * its permission is that of a dangerous operation (or the route always requires it).
     */
    public boolean needsConfirmation(String method, String action) {
        if (kind != Kind.API || "GET".equals(method) || "HEAD".equals(method)) return false;
        if (action != null && reads.contains(action)) return false;
        return confirmAlways || CONFIRMED.contains(permissionFor(method, action));
    }

    /**
     * True if this request can change something: it is not a GET, it is not an action that only reads, and its
     * permission is not one of those that only view ("x.view"). It is the rule of the scheduled restart
     * (RestartLock): until the restart only the requests for which this is false get through.
     */
    public boolean changes(String method, String action) {
        if (kind != Kind.API || "GET".equals(method) || "HEAD".equals(method)) return false;
        if (action != null && reads.contains(action)) return false;
        String p = permissionFor(method, action);
        return p == null || !p.endsWith(".view");
    }

    /** The permission of a request: the method and, if present, the action. */
    public String permissionFor(String method, String action) {
        String p = action == null ? null : actions.get(action);
        if (p != null) return p;
        return "GET".equals(method) || "HEAD".equals(method) ? read : write;
    }
}
