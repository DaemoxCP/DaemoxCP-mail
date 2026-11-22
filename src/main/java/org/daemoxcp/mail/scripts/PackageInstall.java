package org.daemoxcp.mail.scripts;

/**
 * Sorgente UNICA del modo in cui gli script installano i pacchetti: la funzione di shell
 * {@code install_packages}, da includere in uno script prima del suo primo uso.
 *
 * Perche' esiste: il codice d'uscita di {@code pkg install} non dice se i pacchetti chiesti
 * ci sono. Misurato il 24/10/2026 su FreeBSD 15.1, installazione da zero col jar di main: con
 * {@code pkg install -y dovecot-mysql dovecot-pigeonhole} il risolutore scopre, dopo aver
 * scaricato i pacchetti, che dovecot-pigeonhole vuole {@code dovecot}, il quale occupa
 * /usr/local/bin/doveadm come dovecot-mysql; scrive «Cannot solve problem using SAT solver,
 * trying another plan», toglie dal piano dovecot-mysql, installa il resto ed esce con 0.
 * L'installazione proseguiva, si dichiarava riuscita, e nessuna casella poteva entrare ne'
 * in IMAP ne' sulla 587.
 *
 * QUALE dei pacchetti chiesti cada non e' fisso: lo stesso giorno, sullo stesso catalogo,
 * chiedendo a pkg il piano su un database vuoto e coi pacchetti gia' scaricati, il risolutore
 * ha tenuto dovecot-mysql e tolto dovecot-pigeonhole. Per questo non basta correggere quella
 * riga: si controlla ogni riga, ogni volta, pacchetto per pacchetto.
 */
public final class PackageInstall {

    private PackageInstall() {}

    /** Il testo della funzione, gia' pronto da mettere in uno script. */
    public static String shellFunction() {
        return FUNCTION;
    }

    private static final String FUNCTION = """
# install_packages: "pkg install -y" on the given packages, then the proof that ALL of them are there.
#
# pkg can drop a requested package from the plan, to solve a conflict, and still exit
# with 0 (measured on 24/10/2026: dovecot-mysql silently dropped, and the Dovecot left behind
# could not read the mailboxes from MySQL). So after pkg its database is asked, one by
# one, whether each requested package is there: "pkg info -e" answers 0 only if it is installed,
# and accepts both the name (dovecot-mysql) and the origin (security/py-fail2ban).
#
# If even one is missing, or pkg exited non-zero, it stops here: going on would
# mean configuring services that are not there and declaring success at the end.
install_packages() {
    pkg install -y "$@"
    pkg_status=$?
    pkg_missing=""
    for pkg_wanted in "$@"; do
        pkg info -e "$pkg_wanted" >/dev/null 2>&1 || pkg_missing="$pkg_missing $pkg_wanted"
    done
    if [ -n "$pkg_missing" ] || [ "$pkg_status" -ne 0 ]; then
        echo ""
        echo "${RED}  ERROR: pkg did not install everything that was asked.${NC}"
        echo "  Asked:         $*"
        if [ -n "$pkg_missing" ]; then
            echo "  NOT installed:$pkg_missing"
        fi
        echo "  pkg exit code: $pkg_status"
        echo "  pkg may drop a package to solve a conflict and still exit with 0: look above"
        echo "  for 'Cannot solve problem using SAT solver' or 'conflicts with'."
        echo "  The installation stops here: going on would configure services that are not there."
        exit 1
    fi
}
""";
}
