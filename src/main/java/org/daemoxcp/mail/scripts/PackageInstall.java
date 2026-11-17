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
# install_packages: "pkg install -y" sui pacchetti dati, e poi la prova che ci sono TUTTI.
#
# pkg puo' togliere dal piano un pacchetto chiesto, per risolvere un conflitto, e uscire lo
# stesso con 0 (misurato il 24/10/2026: dovecot-mysql tolto in silenzio, e il Dovecot rimasto
# non sapeva leggere le caselle da MySQL). Quindi dopo pkg si chiede al suo database, uno per
# uno, se c'e' ognuno dei pacchetti chiesti: "pkg info -e" risponde 0 solo se e' installato,
# e accetta sia il nome (dovecot-mysql) sia l'origine (security/py-fail2ban).
#
# Se ne manca anche uno, o pkg e' uscito diverso da zero, ci si ferma qui: andare avanti
# vorrebbe dire configurare servizi che non ci sono e dichiarare riuscita alla fine.
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
