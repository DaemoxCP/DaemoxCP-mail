package org.daemoxcp.mail.gui;

import org.daemoxcp.mail.security.PemTls;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.regex.Pattern;

public class ModifyData {
    // Panel settings only (MySQL is configured during mail server installation)
    private TextBox panelPort;
    private TextBox panelHost;
    private TextBox panelSslCert;
    private TextBox panelSslCertKey;
    private TextBox panelSslChain;
    private TextBox panelSessionPrefix;

    private Button submitButton;
    private Button exitButton;
    private dataBaseManager database_manager;
    private WindowBasedTextGUI gui;
    private Window window;

    // Validation patterns
    private static final Pattern PORT_PATTERN = Pattern.compile("^[0-9]{1,5}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+$");
    private static final Pattern PREFIX_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{1,20}$");

    // Hints
    private static final String PORT_HINT = "[0-9] (1-65535)";
    // In the console language: they are looked up when they are shown, not when the class is loaded.
    private static String hostHint() { return org.daemoxcp.mail.i18n.I18n.tr("console.cfg.hostHint"); }
    private static String pemHint() { return org.daemoxcp.mail.i18n.I18n.tr("console.cfg.pemHint"); }
    private static String prefixHint() { return org.daemoxcp.mail.i18n.I18n.tr("console.cfg.prefixHint"); }

    public ModifyData(dataBaseManager dbmanager) {
        this.database_manager = dbmanager;
        initializeComponents();
        loadDataFromDatabase();
    }

    private void initializeComponents() {
        // Panel settings only: its port and its name
        this.panelPort = new TextBox(new TerminalSize(40, 1));
        this.panelHost = new TextBox(new TerminalSize(40, 1));
        this.panelSslCert = new TextBox(new TerminalSize(40, 3));
        this.panelSslCertKey = new TextBox(new TerminalSize(40, 3));
        this.panelSslChain = new TextBox(new TerminalSize(40, 2));
        this.panelSessionPrefix = new TextBox(new TerminalSize(40, 1));

        // Validation patterns for input filtering
        panelPort.setValidationPattern(Pattern.compile("[0-9]*"));
        panelHost.setValidationPattern(Pattern.compile("[a-zA-Z0-9.-]*"));
        panelSessionPrefix.setValidationPattern(Pattern.compile("[a-zA-Z0-9_-]*"));

        this.submitButton = new Button(org.daemoxcp.mail.i18n.I18n.tr("console.save"), this::onSubmit);
        this.exitButton = new Button(org.daemoxcp.mail.i18n.I18n.tr("console.exit"), this::onExit);
    }

    private void loadDataFromDatabase() {
        try (ResultSet result = this.database_manager.get_data_config()) {
            if (result.next()) {
                // Use helper method to handle null values (setText(null) crashes Lanterna)
                setTextSafe(panelPort, result.getString("panel_port"));
                setTextSafe(panelHost, result.getString("panel_host"));
                setTextSafe(panelSslCert, result.getString("panel_ssl_cert"));
                setTextSafe(panelSslCertKey, database_manager.panelTlsKey());

                // panel_ssl_chain might not exist in older databases
                try {
                    setTextSafe(panelSslChain, result.getString("panel_ssl_chain"));
                } catch (SQLException e) {
                    // Column doesn't exist, leave empty
                    panelSslChain.setText("");
                }

                setTextSafe(panelSessionPrefix, result.getString("panel_sessions_prefix"));
            }
        } catch (SQLException e) {
            System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.loadFailed", java.util.Map.of("e", String.valueOf(e.getMessage()))));
            // Don't crash, just use default empty values
        }
    }

    /**
     * Safely set text on a TextBox, handling null values
     */
    private void setTextSafe(TextBox textBox, String value) {
        if (value == null) {
            textBox.setText("");
        } else {
            textBox.setText(value);
        }
    }

    public void show(MultiWindowTextGUI gui) {
        this.window = new BasicWindow(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.title"));

        Panel mainPanel = new Panel(new GridLayout(1).setVerticalSpacing(1));

        // Panel settings section
        mainPanel.addComponent(createPanelSettingsForm().withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.settings"))));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Hints
        mainPanel.addComponent(createHintsPanel().withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.allowedChars"))));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Buttons
        Panel buttonPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttonPanel.addComponent(submitButton);
        buttonPanel.addComponent(new EmptySpace(new TerminalSize(1, 0)));
        buttonPanel.addComponent(exitButton);
        mainPanel.addComponent(buttonPanel);

        window.setComponent(mainPanel.withBorder(Borders.doubleLine()));
        // Allow window to expand fully
        window.setHints(Arrays.asList(Window.Hint.EXPANDED));
        this.gui = gui;
        gui.addWindowAndWait(window);
    }

    private Panel createPanelSettingsForm() {
        Panel formPanel = new Panel(new GridLayout(2).setHorizontalSpacing(3).setVerticalSpacing(1));

        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.port"), panelPort);
        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.host"), panelHost);
        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.cert"), panelSslCert);
        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.key"), panelSslCertKey);
        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.chain"), panelSslChain);
        addLabelAndTextBox(formPanel, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.prefix"), panelSessionPrefix);

        return formPanel;
    }

    private Panel createHintsPanel() {
        Panel hintsPanel = new Panel(new GridLayout(2).setHorizontalSpacing(2).setVerticalSpacing(0));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.port")));
        hintsPanel.addComponent(new Label(PORT_HINT));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.host")));
        hintsPanel.addComponent(new Label(hostHint()));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.prefix")));
        hintsPanel.addComponent(new Label(prefixHint()));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.certKey")));
        hintsPanel.addComponent(new Label(pemHint()));

        return hintsPanel;
    }

    private void addLabelAndTextBox(Panel panel, String labelText, TextBox textBox) {
        panel.addComponent(new Label(labelText));
        panel.addComponent(
                Panels.horizontal(
                        textBox,
                        new EmptySpace(new TerminalSize(1, 1)),
                        new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> textBox.setText(""))
                )
        );
    }

    private String validateInputs() {
        StringBuilder errors = new StringBuilder();

        // Validate panel port
        String port = panelPort.getText().trim();
        if (port.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.portRequired")).append("\n");
        } else if (!PORT_PATTERN.matcher(port).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.portDigits")).append("\n");
        } else {
            int portNum = Integer.parseInt(port);
            if (portNum < 1 || portNum > 65535) {
                errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.portRange")).append("\n");
            }
        }

        // Validate panel host
        String host = panelHost.getText().trim();
        if (host.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.hostRequired")).append("\n");
        } else if (!HOST_PATTERN.matcher(host).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.hostBad", java.util.Map.of("hint", hostHint()))).append("\n");
        }

        // Validate session prefix
        String prefix = panelSessionPrefix.getText().trim();
        if (prefix.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.prefixRequired")).append("\n");
        } else if (!PREFIX_PATTERN.matcher(prefix).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.prefixBad", java.util.Map.of("hint", prefixHint()))).append("\n");
        }

        // SSL cert validation (optional but if one is provided, both needed)
        String sslCert = panelSslCert.getText().trim();
        String sslKey = panelSslCertKey.getText().trim();
        if (!sslCert.isEmpty() && sslKey.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.keyNeeded")).append("\n");
        }
        if (sslCert.isEmpty() && !sslKey.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.certNeeded")).append("\n");
        }

        // Certificate, key and chain: the pasted PEM, or read from the file whose path was written; then the
        // check before saving (finding 243): readable, valid now, covers the name, its own key.
        resolvedCert = resolve(sslCert, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.certName"), errors);
        resolvedKey = resolve(sslKey, org.daemoxcp.mail.i18n.I18n.tr("console.cfg.keyName"), errors);
        resolvedChain = resolve(panelSslChain.getText().trim(), org.daemoxcp.mail.i18n.I18n.tr("console.cfg.chainName"), errors);
        certCheck = null;
        if (errors.length() == 0 && !resolvedCert.isEmpty() && !resolvedKey.isEmpty()) {
            certCheck = PemTls.check(host, resolvedCert, resolvedKey, java.time.Instant.now());
            for (String e : certCheck.errors()) errors.append("- ").append(e).append("\n");
        }

        return errors.length() > 0 ? errors.toString() : null;
    }

    private String resolvedCert = "", resolvedKey = "", resolvedChain = "";
    private PemTls.Check certCheck;

    /**
     * The PEM of the field: as it is, or read from the file if the field is a path. "" if empty; an error if the
     * file does not work.
     */
    private static String resolve(String text, String what, StringBuilder errors) {
        if (text.isEmpty()) return "";
        if (!PemTls.isPath(text)) return text;
        try {
            return PemTls.readFile(java.nio.file.Path.of(text));
        } catch (java.io.IOException e) {
            errors.append("- ").append(what).append(": ").append(e.getMessage()).append("\n");
            return "";
        }
    }

    private void onSubmit() {
        String validationErrors = validateInputs();
        if (validationErrors != null) {
            MessageDialog.showMessageDialog(
                    this.gui,
                    org.daemoxcp.mail.i18n.I18n.tr("console.invalidTitle"),
                    org.daemoxcp.mail.i18n.I18n.tr("console.invalidText") + "\n\n" + validationErrors,
                    MessageDialogButton.OK
            );
            return;
        }

        StringBuilder message = new StringBuilder();
        message.append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.port")).append(" ").append(panelPort.getText()).append("\n");
        message.append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.host")).append(" ").append(panelHost.getText()).append("\n");
        message.append(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.prefix")).append(" ").append(panelSessionPrefix.getText()).append("\n");
        if (certCheck != null) {
            message.append("\n");
            for (String line : certCheck.info()) message.append(line).append("\n");
            for (String w : certCheck.warnings()) message.append(org.daemoxcp.mail.i18n.I18n.tr("console.warning")).append(" ").append(w).append("\n");
        }

        // Cancel is first = pre-selected (safety)
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                org.daemoxcp.mail.i18n.I18n.tr("console.confirmTitle"),
                org.daemoxcp.mail.i18n.I18n.tr("console.confirmSave") + "\n\n" + message.toString(),
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            if (saveDataToDatabase()) {
                MessageDialog.showMessageDialog(
                        this.gui,
                        org.daemoxcp.mail.i18n.I18n.tr("console.savedTitle"),
                        org.daemoxcp.mail.i18n.I18n.tr("console.savedText"),
                        MessageDialogButton.OK
                );
                window.close();
            } else {
                MessageDialog.showMessageDialog(
                        this.gui,
                        org.daemoxcp.mail.i18n.I18n.tr("console.errorTitle"),
                        org.daemoxcp.mail.i18n.I18n.tr("console.saveFailed"),
                        MessageDialogButton.OK
                );
            }
        }
    }

    private void onExit() {
        // Cancel is first = pre-selected (safety)
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                org.daemoxcp.mail.i18n.I18n.tr("console.exitTitle"),
                org.daemoxcp.mail.i18n.I18n.tr("console.exitText"),
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            window.close();
        }
    }

    private boolean saveDataToDatabase() {
        try {
            return database_manager.update_panel_config(
                    panelHost.getText().trim(),
                    panelPort.getText().trim(),
                    resolvedCert.trim(),
                    resolvedKey.trim(),
                    resolvedChain.trim(),
                    panelSessionPrefix.getText().trim()
            );
        } catch (Exception e) {
            MessageDialog.showMessageDialog(
                    this.gui,
                    org.daemoxcp.mail.i18n.I18n.tr("console.errorTitle"),
                    org.daemoxcp.mail.i18n.I18n.tr("console.saveFailedWhy", java.util.Map.of("e", String.valueOf(e.getMessage()))),
                    MessageDialogButton.OK
            );
            return false;
        }
    }
}
