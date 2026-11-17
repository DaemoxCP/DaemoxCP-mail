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
    private TextBox mail_panel_port;
    private TextBox mail_panel_host;
    private TextBox mail_panel_ssl_cert;
    private TextBox mail_panel_ssl_cert_key;
    private TextBox mail_panel_ssl_chain;
    private TextBox mail_panel_session_prefix;

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
    private static final String HOST_HINT = "the panel's name, e.g. panel.example.com";
    private static final String PEM_HINT = "paste the PEM, or the path of a file, e.g. /root/panel-cert.pem";
    private static final String PREFIX_HINT = "[a-z A-Z 0-9 _ -] (1-20 chars)";

    public ModifyData(dataBaseManager dbmanager) {
        this.database_manager = dbmanager;
        initializeComponents();
        loadDataFromDatabase();
    }

    private void initializeComponents() {
        // Panel settings only
        this.mail_panel_port = new TextBox(new TerminalSize(40, 1));
        this.mail_panel_host = new TextBox(new TerminalSize(40, 1));
        this.mail_panel_ssl_cert = new TextBox(new TerminalSize(40, 3));
        this.mail_panel_ssl_cert_key = new TextBox(new TerminalSize(40, 3));
        this.mail_panel_ssl_chain = new TextBox(new TerminalSize(40, 2));
        this.mail_panel_session_prefix = new TextBox(new TerminalSize(40, 1));

        // Validation patterns for input filtering
        mail_panel_port.setValidationPattern(Pattern.compile("[0-9]*"));
        mail_panel_host.setValidationPattern(Pattern.compile("[a-zA-Z0-9.-]*"));
        mail_panel_session_prefix.setValidationPattern(Pattern.compile("[a-zA-Z0-9_-]*"));

        this.submitButton = new Button("Submit", this::onSubmit);
        this.exitButton = new Button("Exit", this::onExit);
    }

    private void loadDataFromDatabase() {
        try (ResultSet result = this.database_manager.get_data_config()) {
            if (result.next()) {
                // Use helper method to handle null values (setText(null) crashes Lanterna)
                setTextSafe(mail_panel_port, result.getString("mail_panel_port"));
                setTextSafe(mail_panel_host, result.getString("mail_panel_host"));
                setTextSafe(mail_panel_ssl_cert, result.getString("mail_panel_ssl_cert"));
                setTextSafe(mail_panel_ssl_cert_key, database_manager.panelTlsKey());

                // mail_panel_ssl_chain might not exist in older databases
                try {
                    setTextSafe(mail_panel_ssl_chain, result.getString("mail_panel_ssl_chain"));
                } catch (SQLException e) {
                    // Column doesn't exist, leave empty
                    mail_panel_ssl_chain.setText("");
                }

                setTextSafe(mail_panel_session_prefix, result.getString("mail_panel_sessions_prefix"));
            }
        } catch (SQLException e) {
            System.out.println("Error loading config: " + e.getMessage());
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
        this.window = new BasicWindow("Web Panel Configuration");

        Panel mainPanel = new Panel(new GridLayout(1).setVerticalSpacing(1));

        // Panel settings section
        mainPanel.addComponent(createPanelSettingsForm().withBorder(Borders.singleLine("Panel Settings")));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Hints
        mainPanel.addComponent(createHintsPanel().withBorder(Borders.singleLine("Allowed Characters")));
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

        addLabelAndTextBox(formPanel, "PANEL PORT:", mail_panel_port);
        addLabelAndTextBox(formPanel, "PANEL HOST:", mail_panel_host);
        addLabelAndTextBox(formPanel, "SSL CERTIFICATE (PEM):", mail_panel_ssl_cert);
        addLabelAndTextBox(formPanel, "SSL PRIVATE KEY (PEM):", mail_panel_ssl_cert_key);
        addLabelAndTextBox(formPanel, "SSL CA CHAIN (optional):", mail_panel_ssl_chain);
        addLabelAndTextBox(formPanel, "SESSION PREFIX:", mail_panel_session_prefix);

        return formPanel;
    }

    private Panel createHintsPanel() {
        Panel hintsPanel = new Panel(new GridLayout(2).setHorizontalSpacing(2).setVerticalSpacing(0));

        hintsPanel.addComponent(new Label("PORT:"));
        hintsPanel.addComponent(new Label(PORT_HINT));

        hintsPanel.addComponent(new Label("HOST:"));
        hintsPanel.addComponent(new Label(HOST_HINT));

        hintsPanel.addComponent(new Label("PREFIX:"));
        hintsPanel.addComponent(new Label(PREFIX_HINT));

        hintsPanel.addComponent(new Label("CERT/KEY:"));
        hintsPanel.addComponent(new Label(PEM_HINT));

        return hintsPanel;
    }

    private void addLabelAndTextBox(Panel panel, String labelText, TextBox textBox) {
        panel.addComponent(new Label(labelText));
        panel.addComponent(
                Panels.horizontal(
                        textBox,
                        new EmptySpace(new TerminalSize(1, 1)),
                        new Button("Clear", () -> textBox.setText(""))
                )
        );
    }

    private String validateInputs() {
        StringBuilder errors = new StringBuilder();

        // Validate panel port
        String port = mail_panel_port.getText().trim();
        if (port.isEmpty()) {
            errors.append("- Panel Port is required\n");
        } else if (!PORT_PATTERN.matcher(port).matches()) {
            errors.append("- Panel Port must contain only numbers\n");
        } else {
            int portNum = Integer.parseInt(port);
            if (portNum < 1 || portNum > 65535) {
                errors.append("- Panel Port must be between 1 and 65535\n");
            }
        }

        // Validate panel host
        String host = mail_panel_host.getText().trim();
        if (host.isEmpty()) {
            errors.append("- Panel Host is required\n");
        } else if (!HOST_PATTERN.matcher(host).matches()) {
            errors.append("- Panel Host: " + HOST_HINT + "\n");
        }

        // Validate session prefix
        String prefix = mail_panel_session_prefix.getText().trim();
        if (prefix.isEmpty()) {
            errors.append("- Session prefix is required\n");
        } else if (!PREFIX_PATTERN.matcher(prefix).matches()) {
            errors.append("- Session prefix: " + PREFIX_HINT + "\n");
        }

        // SSL cert validation (optional but if one is provided, both needed)
        String sslCert = mail_panel_ssl_cert.getText().trim();
        String sslKey = mail_panel_ssl_cert_key.getText().trim();
        if (!sslCert.isEmpty() && sslKey.isEmpty()) {
            errors.append("- SSL Private Key is required when SSL Cert is provided\n");
        }
        if (sslCert.isEmpty() && !sslKey.isEmpty()) {
            errors.append("- SSL Certificate is required when SSL Key is provided\n");
        }

        // Certificato, chiave e catena: il PEM incollato, o letto dal file di cui si e' scritto il percorso; poi il
        // controllo prima di salvare (reperto 243): leggibile, valido adesso, copre il nome, chiave sua.
        resolvedCert = resolve(sslCert, "SSL Certificate", errors);
        resolvedKey = resolve(sslKey, "SSL Private Key", errors);
        resolvedChain = resolve(mail_panel_ssl_chain.getText().trim(), "SSL CA Chain", errors);
        certCheck = null;
        if (errors.length() == 0 && !resolvedCert.isEmpty() && !resolvedKey.isEmpty()) {
            certCheck = PemTls.check(host, resolvedCert, resolvedKey, java.time.Instant.now());
            for (String e : certCheck.errors()) errors.append("- ").append(e).append("\n");
        }

        return errors.length() > 0 ? errors.toString() : null;
    }

    private String resolvedCert = "", resolvedKey = "", resolvedChain = "";
    private PemTls.Check certCheck;

    /** Il PEM del campo: com'e', o letto dal file se il campo e' un percorso. "" se vuoto; un errore se il file non va. */
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
                    "Validation Error",
                    "Please fix the following errors:\n\n" + validationErrors,
                    MessageDialogButton.OK
            );
            return;
        }

        StringBuilder message = new StringBuilder();
        message.append("Panel Port: ").append(mail_panel_port.getText()).append("\n");
        message.append("Panel Host: ").append(mail_panel_host.getText()).append("\n");
        message.append("Session Prefix: ").append(mail_panel_session_prefix.getText()).append("\n");
        if (certCheck != null) {
            message.append("\n");
            for (String line : certCheck.info()) message.append(line).append("\n");
            for (String w : certCheck.warnings()) message.append("WARNING: ").append(w).append("\n");
        }

        // Cancel is first = pre-selected (safety)
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                "Confirm Changes",
                "Are you sure you want to save these changes?\n\n" + message.toString(),
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            if (saveDataToDatabase()) {
                MessageDialog.showMessageDialog(
                        this.gui,
                        "Data Saved",
                        "Your changes have been saved successfully.",
                        MessageDialogButton.OK
                );
                window.close();
            } else {
                MessageDialog.showMessageDialog(
                        this.gui,
                        "Error",
                        "There was a problem saving to the database.",
                        MessageDialogButton.OK
                );
            }
        }
    }

    private void onExit() {
        // Cancel is first = pre-selected (safety)
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                "Confirm Exit",
                "Are you sure you want to exit?\nAny unsaved changes will be lost.",
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
                    mail_panel_host.getText().trim(),
                    mail_panel_port.getText().trim(),
                    resolvedCert.trim(),
                    resolvedKey.trim(),
                    resolvedChain.trim(),
                    mail_panel_session_prefix.getText().trim()
            );
        } catch (Exception e) {
            MessageDialog.showMessageDialog(
                    this.gui,
                    "Error",
                    "Failed to save data to database: " + e.getMessage(),
                    MessageDialogButton.OK
            );
            return false;
        }
    }
}
