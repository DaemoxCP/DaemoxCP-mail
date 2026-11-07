package org.mail_panel.gui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

import java.io.IOException;
import java.util.Arrays;

/**
 * Main Menu Chooser for FreeBSD Mail Panel
 *
 * Terminal GUI menu using Lanterna library.
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  MENU OPTIONS                                                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │  1) Set TimeZone and CloudFlare DNS                                         │
 * │  2) Edit Panel Configuration                                                │
 * │  3) Edit Roundcube Configuration (REQUIRED before install)                  │
 * │  4) Install/Reinstall Mail Server                                           │
 * │     └─ Installs: Postfix, Dovecot, Rspamd, ClamAV, Roundcube, MySQL         │
 * │  5) Emergency access code (one-time code; first administrator if none)      │
 * │  >>> Start Mail Panel WebServer <<<                                         │
 * │  Exit                                                                       │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * @see org.mail_panel.Main for the main entry point
 */
public class Chooser {
    private Window window;
    private MultiWindowTextGUI gui;
    public int option = -1;

    public Chooser() {
        this.window = new BasicWindow("FreeBSD Mail Panel - Select an option");
    }

    public void run(MultiWindowTextGUI gui) throws IOException {
        this.gui = gui;
        chooser(gui);
    }

    /**
     * Confirm action with Cancel as default (safety first)
     */
    /**
     * Cosa cancella una reinstallazione, detto prima. Prima diceva solo «la configurazione si azzera»,
     * ma lo script ricrea vuote anche le tabelle della posta e quelle delle utenze del pannello
     * (amministratori, passkey, sessioni): si cancellano, deciso dal committente il 07/11/2026.
     */
    private static String reinstallWarning() {
        org.mail_panel.i18n.I18n.setCurrent("en");
        try { return org.mail_panel.i18n.I18n.tr("server.reinstall.menuWarning"); }
        finally { org.mail_panel.i18n.I18n.clearCurrent(); }
    }

    private boolean confirmAction(String title, String message) {
        MessageDialogButton result = new MessageDialogBuilder()
            .setTitle(title)
            .setText(message)
            .addButton(MessageDialogButton.Cancel)  // Cancel first = pre-selected (SAFETY)
            .addButton(MessageDialogButton.OK)
            .build()
            .showDialog(gui);
        return result == MessageDialogButton.OK;
    }

    public void chooser(MultiWindowTextGUI gui) {
        Panel mainPanel = new Panel();
        mainPanel.setLayoutManager(new GridLayout(1).setLeftMarginSize(1).setRightMarginSize(1));

        Panel selectionPanel = new Panel();
        selectionPanel.setLayoutManager(new LinearLayout(Direction.VERTICAL));
        selectionPanel.addComponent(new Label("Select an option:"));

        ActionListBox actionListBox = new ActionListBox();

        // ============== SYSTEM CONFIGURATION ==============
        actionListBox.addItem("1) Set TimeZone and CloudFlare DNS", () -> {
            if (confirmAction("Confirm", "Configure TimeZone and CloudFlare DNS?\n\nThis will set system timezone and DNS.")) {
                setOptionAndClose(1);
            }
        });

        actionListBox.addItem("2) Edit Panel Configuration", () -> {
            if (confirmAction("Confirm", "Edit Mail Panel configuration?\n\n(Port, Host, SSL settings)")) {
                setOptionAndClose(2);
            }
        });

        actionListBox.addItem("3) Edit Roundcube Configuration", () -> {
            if (confirmAction("Confirm", "Edit Roundcube webmail configuration?\n\n(Domain, Port, SSL paths)\n\nREQUIRED before installing mail server!")) {
                setOptionAndClose(3);
            }
        });

        // ============== MAIL SERVER (UNIFIED) ==============
        actionListBox.addItem("4) Install/Reinstall Mail Server", () -> {
            if (confirmAction("Confirm Installation",
                    "Install/Reinstall the complete Mail Server?\n\n" +
                    "This will install:\n" +
                    "  • Postfix (SMTP)\n" +
                    "  • Dovecot (IMAP/POP3)\n" +
                    "  • Rspamd (Anti-Spam)\n" +
                    "  • ClamAV (Antivirus)\n" +
                    "  • Roundcube (Webmail)\n" +
                    "  • MySQL tables\n" +
                    "  • Self-signed SSL (temporary)\n\n" +
                    reinstallWarning())) {
                setOptionAndClose(4);
            }
        });

        // ============== ACCESS ==============
        // Il codice di accesso di emergenza, per quando passkey ed email non bastano: si genera
        // solo da qui (o con --access-code), cioe' da chi ha accesso al server.
        actionListBox.addItem("5) Emergency access code", () -> setOptionAndClose(5));
        actionListBox.addItem("6) Go back to the server before the last reinstallation", () -> {
            if (confirmAction("Go back",
                    "Go back to the server as it was before the last\n" +
                    "complete reinstallation (its way back)?\n\n" +
                    "The mail that arrived after it is kept.\n" +
                    "The MySQL database goes back to then.\n" +
                    "The server must restart: you choose when.")) {
                setOptionAndClose(6);
            }
        });

        // ============== START SERVER ==============
        actionListBox.addItem(">>> Start Mail Panel WebServer <<<", () -> {
            if (confirmAction("Start WebServer", "Start the Mail Panel web server?")) {
                setOptionAndClose(100);
            }
        });

        actionListBox.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.FILL,
                GridLayout.Alignment.CENTER,
                true,
                false,
                1,
                1));

        selectionPanel.addComponent(actionListBox);

        mainPanel.addComponent(selectionPanel.withBorder(Borders.singleLine("Options")));
        mainPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Button exitButton = new Button("Exit", () -> setOptionAndClose(0));
        exitButton.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.CENTER,
                GridLayout.Alignment.CENTER,
                false,
                false,
                1,
                1));
        mainPanel.addComponent(exitButton);

        this.window.setComponent(Panels.vertical(
                mainPanel.withBorder(Borders.doubleLine("FreeBSD Mail Panel v1.0")),
                new EmptySpace(new TerminalSize(0, 1))
        ));

        window.setHints(Arrays.asList(Window.Hint.CENTERED, Window.Hint.EXPANDED, Window.Hint.FULL_SCREEN));

        gui.addWindowAndWait(this.window);
    }

    private void setOptionAndClose(int option) {
        this.option = option;
        this.window.close();
    }
}
