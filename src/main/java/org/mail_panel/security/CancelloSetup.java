package org.mail_panel.security;

import org.mail_panel.Main;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;

/**
 * Decide se la procedura di installazione possa ancora essere eseguita.
 *
 * Il problema che chiude. Il cancello era scritto cosi':
 *
 *     if (Main.mysqlAvailable && !Main.setupRequired) -> 403
 *
 * e "setupRequired" si ricava da MySQL (`hasAdminUser()`). Quindi bastava che MySQL non
 * rispondesse — un riavvio, un disco pieno, un processo ucciso — perche' la condizione non
 * scattasse e l'installazione tornasse accessibile A CHIUNQUE, senza autenticazione. E da
 * li' si possono eseguire script di installazione con i privilegi del pannello.
 *
 * E' un guasto che si apre invece di chiudersi: il modo sbagliato di fallire per un
 * cancello. Un lucchetto che si apre quando manca la corrente non e' un lucchetto.
 *
 * La correzione. Il segnale "l'installazione e' gia' stata fatta" viene scritto su DISCO, in
 * un file che non dipende ne' da MySQL ne' dallo schema del database locale. Il cancello
 * resta chiuso se ALMENO UNA delle due fonti dice che l'installazione c'e' gia' stata:
 *
 *   - il marcatore su disco (regge quando MySQL e' giu')
 *   - MySQL che riporta un amministratore (regge se il marcatore viene perso)
 *
 * Due fonti indipendenti, e basta una a tenere chiuso. Il caso in cui si riapre e' quello in
 * cui entrambe dicono "non ancora installato", che e' davvero un sistema nuovo.
 *
 * Il recupero. Se un giorno l'installazione va rifatta davvero con MySQL irraggiungibile,
 * serve dimostrare di avere accesso alla macchina: si crea a mano il file
 * /var/db/mailpanel/consenti-setup, e vale per QUINDICI MINUTI. Un attaccante remoto non
 * puo' crearlo; chi ha una shell da root ha gia' molto piu' di questo endpoint. La finestra
 * breve evita che un file dimenticato tenga il cancello aperto per sempre.
 */
public class CancelloSetup {

    private static final Path MARCATORE = Path.of("/var/db/mailpanel/installazione-completata");
    private static final Path SBLOCCO   = Path.of("/var/db/mailpanel/consenti-setup");
    private static final long MINUTI_VALIDITA = 15;

    private CancelloSetup() {}

    public enum Esito { APERTO_PRIMA_INSTALLAZIONE, APERTO_PER_RECUPERO, CHIUSO }

    /** Il marcatore su disco: l'installazione risulta gia' fatta. */
    public static boolean marcatorePresente() {
        try {
            return Files.exists(MARCATORE);
        } catch (Exception e) {
            // Se non si riesce nemmeno a guardare, si assume il caso PRUDENTE: gia' fatta.
            // Sbagliare qui verso "aperto" e' esattamente il difetto che stiamo correggendo.
            return true;
        }
    }

    /** MySQL risponde e riporta che un amministratore esiste. */
    public static boolean mysqlDiceInstallato() {
        return Main.mysqlAvailable && !Main.setupRequired;
    }

    /**
     * Scrive il marcatore. Da chiamare quando l'installazione finisce e ogni volta che il
     * pannello vede un amministratore: cosi' un'installazione fatta prima di questa modifica
     * viene registrata comunque, senza che nessuno debba ricordarsene.
     */
    public static void segnaCompletata() {
        try {
            if (Files.exists(MARCATORE)) return;
            Files.createDirectories(MARCATORE.getParent());
            Files.writeString(MARCATORE,
                    "Installazione completata il " + Instant.now() + ".\n"
                  + "Finche' questo file esiste, la procedura di installazione resta chiusa\n"
                  + "anche se MySQL non risponde. Non cancellarlo per \"sbloccare\" il setup:\n"
                  + "per farlo si crea " + SBLOCCO + ", che vale " + MINUTI_VALIDITA + " minuti.\n");
        } catch (Exception e) {
            System.err.println("[CancelloSetup] non riesco a scrivere il marcatore: " + e.getMessage());
        }
    }

    /** Lo sblocco manuale esiste ed e' recente. */
    public static boolean sbloccoValido() {
        try {
            if (!Files.exists(SBLOCCO)) return false;
            Instant quando = Files.getLastModifiedTime(SBLOCCO).toInstant();
            return Duration.between(quando, Instant.now()).toMinutes() < MINUTI_VALIDITA;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * La decisione, separata da dove arrivano i tre fatti. Cosi' si puo' provare per intero:
     * otto combinazioni, e nessuna lasciata al caso.
     */
    public static Esito decidi(boolean marcatore, boolean mysqlDiceInstallato, boolean sblocco) {
        boolean giaInstallato = marcatore || mysqlDiceInstallato;
        if (!giaInstallato) return Esito.APERTO_PRIMA_INSTALLAZIONE;
        return sblocco ? Esito.APERTO_PER_RECUPERO : Esito.CHIUSO;
    }

    public static Esito valuta() {
        return decidi(marcatorePresente(), mysqlDiceInstallato(), sbloccoValido());
    }

    public static boolean consentito() {
        return valuta() != Esito.CHIUSO;
    }

    /** Il motivo del rifiuto, scritto per chi lo legge in un log o in una risposta. */
    public static String motivoRifiuto() {
        return "L'installazione risulta gia' completata: questa procedura e' chiusa. "
             + "Resta chiusa anche quando MySQL non risponde, perche' un cancello che si apre "
             + "quando un componente cade non protegge niente. Se l'installazione va davvero "
             + "rifatta, crea sul server il file " + SBLOCCO + " (serve accesso alla macchina) "
             + "e riprova entro " + MINUTI_VALIDITA + " minuti.";
    }

    /** Da scrivere nel registro quando il recupero manuale viene usato. */
    public static String notaRecupero() {
        return "SETUP RIAPERTO dallo sblocco manuale " + SBLOCCO + ": qualcuno con accesso al "
             + "server lo ha creato negli ultimi " + MINUTI_VALIDITA + " minuti.";
    }
}
