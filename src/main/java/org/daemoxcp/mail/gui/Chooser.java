package org.daemoxcp.mail.gui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

import java.io.IOException;
import java.util.Arrays;

/**
 * Main Menu Chooser for DaemoxCP Mail
 *
 * Terminal GUI menu using Lanterna library.
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  MENU OPTIONS                                                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │  1) Time zone, clock (NTP) and DNS resolver                                 │
 * │  2) Edit Panel Configuration                                                │
 * │  3) Edit Roundcube Configuration (REQUIRED before install)                  │
 * │  4) Install/Reinstall Mail Server                                           │
 * │     └─ Installs: Postfix, Dovecot, Rspamd, ClamAV, Roundcube, MySQL         │
 * │  5) Emergency access code (one-time code; first administrator if none)      │
 * │  >>> Start Mail Panel WebServer <<<                                         │
 * │  Exit                                                                       │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * @see org.daemoxcp.mail.Main for the main entry point
 */
public class Chooser {
    private Window window;
    private MultiWindowTextGUI gui;
    private ActionListBox actionListBox;
    public int option = -1;

    /**
     * The option chosen last time. The menu is rebuilt from scratch after every option, and the selection always went
     * back to 1: after option 2 a person goes down by one and reopens 2, while after a "Cancel" it stayed where it was
     * (install from the README, 2026-11-20: this is how options 2 and 4 got opened by mistake). Now it stays on the
     * option just used.
     */
    private static int lastSelected = 0;

    public Chooser() {
        this.window = new BasicWindow(org.daemoxcp.mail.i18n.I18n.tr("brand.name") + " - " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.choose"));
    }

    public void run(MultiWindowTextGUI gui) throws IOException {
        this.gui = gui;
        chooser(gui);
    }

    /**
     * Confirm action with Cancel as default (safety first)
     */
    /**
     * What a reinstall deletes, said beforehand. Before, it only said "the configuration is reset",
     * but the script also recreates empty the mail tables and those of the panel's accounts
     * (administrators, passkeys, sessions): they are deleted, as decided by the owner on 2026-11-07.
     */
    private static String reinstallWarning() {
        return org.daemoxcp.mail.i18n.I18n.tr("server.reinstall.menuWarning");   // in the console language
    }

    /**
     * The menu title with the version of the running jar (build-info, like the dashboard). Up to 0.9.0 it was
     * hard-coded `v1.0`: a new server with the 0.9.0 beta introduced itself as 1.0. Without a recorded version (the
     * test classes, a jar built without Maven) only the name.
     */
    static String title() {
        String name = org.daemoxcp.mail.i18n.I18n.tr("brand.name");
        String version = org.daemoxcp.mail.system.PanelInfo.build().version();
        return version.isEmpty() ? name : name + " " + version;
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
        selectionPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.menu.chooseLabel")));

        actionListBox = new ActionListBox();

        // ============== SYSTEM CONFIGURATION ==============
        actionListBox.addItem("1) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.time"), () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.confirm"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.timeAsk"))) {
                setOptionAndClose(1);
            }
        });

        actionListBox.addItem("2) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.panel"), () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.confirm"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.panelAsk", java.util.Map.of("product", org.daemoxcp.mail.system.Product.NAME)))) {
                setOptionAndClose(2);
            }
        });

        actionListBox.addItem("3) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.roundcube"), () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.confirm"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.roundcubeAsk"))) {
                setOptionAndClose(3);
            }
        });

        // ============== MAIL SERVER (UNIFIED) ==============
        actionListBox.addItem("4) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.install"), () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.installTitle"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.installAsk") + "\n\n" + reinstallWarning())) {
                setOptionAndClose(4);
            }
        });

        // ============== ACCESS ==============
        // The emergency access code, for when passkeys and email are not enough: it is generated
        // only from here (or with --access-code), that is by whoever has access to the server.
        actionListBox.addItem("5) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.code"), () -> setOptionAndClose(5));
        actionListBox.addItem("6) " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.back"), () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.backTitle"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.backAsk"))) {
                setOptionAndClose(6);
            }
        });

        // ============== START SERVER ==============
        actionListBox.addItem(">>> " + org.daemoxcp.mail.i18n.I18n.tr("console.menu.start", java.util.Map.of("product", org.daemoxcp.mail.system.Product.NAME)) + " <<<", () -> {
            if (confirmAction(org.daemoxcp.mail.i18n.I18n.tr("console.menu.startTitle"), org.daemoxcp.mail.i18n.I18n.tr("console.menu.startAsk", java.util.Map.of("product", org.daemoxcp.mail.system.Product.NAME)))) {
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

        actionListBox.setSelectedIndex(Math.max(0, Math.min(lastSelected, actionListBox.getItemCount() - 1)));
        selectionPanel.addComponent(actionListBox);

        mainPanel.addComponent(selectionPanel.withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.menu.options"))));
        mainPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Button exitButton = new Button(org.daemoxcp.mail.i18n.I18n.tr("console.exit"), () -> setOptionAndClose(0));
        exitButton.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.CENTER,
                GridLayout.Alignment.CENTER,
                false,
                false,
                1,
                1));
        mainPanel.addComponent(exitButton);

        this.window.setComponent(Panels.vertical(
                mainPanel.withBorder(Borders.doubleLine(title())),
                new EmptySpace(new TerminalSize(0, 1))
        ));

        window.setHints(Arrays.asList(Window.Hint.CENTERED, Window.Hint.EXPANDED, Window.Hint.FULL_SCREEN));

        gui.addWindowAndWait(this.window);
    }

    private void setOptionAndClose(int option) {
        this.option = option;
        if (option != 0) lastSelected = actionListBox.getSelectedIndex();
        this.window.close();
    }
}
