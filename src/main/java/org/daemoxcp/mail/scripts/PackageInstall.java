package org.daemoxcp.mail.scripts;

/**
 * The SINGLE source of the way the scripts install packages: the shell function
 * {@code install_packages}, to be included in a script before its first use.
 *
 * Why it exists: the exit code of {@code pkg install} does not say whether the requested packages
 * are there. Measured on 2026-10-24 on FreeBSD 15.1, clean install with the main jar: with
 * {@code pkg install -y dovecot-mysql dovecot-pigeonhole} the solver discovers, after
 * downloading the packages, that dovecot-pigeonhole wants {@code dovecot}, which takes
 * /usr/local/bin/doveadm just like dovecot-mysql; it writes "Cannot solve problem using SAT solver,
 * trying another plan", drops dovecot-mysql from the plan, installs the rest and exits with 0.
 * The installation went on, declared itself successful, and no mailbox could log in either
 * over IMAP or on 587.
 *
 * WHICH of the requested packages gets dropped is not fixed: the same day, on the same catalogue,
 * asking pkg for the plan on an empty database and with the packages already downloaded, the solver
 * kept dovecot-mysql and dropped dovecot-pigeonhole. That is why fixing that line is not enough:
 * every line is checked, every time, package by package.
 */
public final class PackageInstall {

    private PackageInstall() {}

    /** The text of the function, ready to be put into a script. */
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
