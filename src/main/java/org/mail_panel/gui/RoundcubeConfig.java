package org.mail_panel.gui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import org.mail_panel.sqli.dataBaseManager;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * Roundcube Webmail Configuration
 *
 * Separate screen for configuring Roundcube settings.
 * Required before installing the mail server.
 */
public class RoundcubeConfig {
    private TextBox roundcube_domain;
    private TextBox roundcube_port;
    private TextBox roundcube_ssl_cert;
    private TextBox roundcube_ssl_key;
    private TextBox roundcube_ssl_chain;

    private Button submitButton;
    private Button exitButton;
    private dataBaseManager database_manager;
    private WindowBasedTextGUI gui;
    private Window window;

    // Validation patterns
    private static final Pattern PORT_PATTERN = Pattern.compile("^[0-9]{1,5}$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+$");
    private static final Pattern PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9./_-]*$");

    public RoundcubeConfig(dataBaseManager dbmanager) {
        this.database_manager = dbmanager;
        initializeComponents();
        loadDataFromDatabase();
    }

    private void initializeComponents() {
        this.roundcube_domain = new TextBox(new TerminalSize(50, 1));
        this.roundcube_port = new TextBox(new TerminalSize(50, 1));
        this.roundcube_ssl_cert = new TextBox(new TerminalSize(50, 1));
        this.roundcube_ssl_key = new TextBox(new TerminalSize(50, 1));
        this.roundcube_ssl_chain = new TextBox(new TerminalSize(50, 1));

        // Validation patterns
        roundcube_domain.setValidationPattern(Pattern.compile("[a-zA-Z0-9.-]*"));
        roundcube_port.setValidationPattern(Pattern.compile("[0-9]*"));
        roundcube_ssl_cert.setValidationPattern(Pattern.compile("[a-zA-Z0-9./_-]*"));
        roundcube_ssl_key.setValidationPattern(Pattern.compile("[a-zA-Z0-9./_-]*"));
        roundcube_ssl_chain.setValidationPattern(Pattern.compile("[a-zA-Z0-9./_-]*"));

        this.submitButton = new Button("Save", this::onSubmit);
        this.exitButton = new Button("Cancel", this::onExit);
    }

    private void loadDataFromDatabase() {
        try (ResultSet result = this.database_manager.get_data_config()) {
            if (result.next()) {
                try {
                    setTextSafe(roundcube_domain, result.getString("roundcube_domain"));
                    String port = result.getString("roundcube_port");
                    setTextSafe(roundcube_port, (port != null && !port.isEmpty()) ? port : "8443");
                    setTextSafe(roundcube_ssl_cert, result.getString("roundcube_ssl_cert"));
                    setTextSafe(roundcube_ssl_key, result.getString("roundcube_ssl_key"));
                    setTextSafe(roundcube_ssl_chain, result.getString("roundcube_ssl_chain"));
                } catch (SQLException e) {
                    // Columns don't exist, use defaults
                    roundcube_domain.setText("");
                    roundcube_port.setText("8443");
                    roundcube_ssl_cert.setText("");
                    roundcube_ssl_key.setText("");
                    roundcube_ssl_chain.setText("");
                }
            }
        } catch (SQLException e) {
            System.out.println("Error loading config: " + e.getMessage());
        }
    }

    private void setTextSafe(TextBox textBox, String value) {
        if (value == null) {
            textBox.setText("");
        } else {
            textBox.setText(value);
        }
    }

    public void show(MultiWindowTextGUI gui) {
        this.window = new BasicWindow("Roundcube Webmail Configuration");

        Panel mainPanel = new Panel(new GridLayout(1).setVerticalSpacing(1));

        // Info message
        Panel infoPanel = new Panel();
        infoPanel.addComponent(new Label("Configure Roundcube webmail settings."));
        infoPanel.addComponent(new Label("These settings are REQUIRED before installing the mail server."));
        mainPanel.addComponent(infoPanel.withBorder(Borders.singleLine("Info")));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Roundcube settings
        mainPanel.addComponent(createRoundcubeForm().withBorder(Borders.singleLine("Roundcube Settings")));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Hints
        mainPanel.addComponent(createHintsPanel().withBorder(Borders.singleLine("Examples")));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Buttons
        Panel buttonPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttonPanel.addComponent(submitButton);
        buttonPanel.addComponent(new EmptySpace(new TerminalSize(1, 0)));
        buttonPanel.addComponent(exitButton);
        mainPanel.addComponent(buttonPanel);

        window.setComponent(mainPanel.withBorder(Borders.doubleLine()));
        window.setHints(Arrays.asList(Window.Hint.CENTERED));
        this.gui = gui;
        gui.addWindowAndWait(window);
    }

    private Panel createRoundcubeForm() {
        Panel formPanel = new Panel(new GridLayout(2).setHorizontalSpacing(3).setVerticalSpacing(1));

        formPanel.addComponent(new Label("DOMAIN:"));
        formPanel.addComponent(Panels.horizontal(
                roundcube_domain,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button("Clear", () -> roundcube_domain.setText(""))
        ));

        formPanel.addComponent(new Label("PORT:"));
        formPanel.addComponent(Panels.horizontal(
                roundcube_port,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button("Clear", () -> roundcube_port.setText(""))
        ));

        formPanel.addComponent(new Label("SSL CERT PATH (optional):"));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_cert,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button("Clear", () -> roundcube_ssl_cert.setText(""))
        ));

        formPanel.addComponent(new Label("SSL KEY PATH (optional):"));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_key,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button("Clear", () -> roundcube_ssl_key.setText(""))
        ));

        formPanel.addComponent(new Label("SSL CA CHAIN (optional):"));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_chain,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button("Clear", () -> roundcube_ssl_chain.setText(""))
        ));

        return formPanel;
    }

    private Panel createHintsPanel() {
        Panel hintsPanel = new Panel(new GridLayout(2).setHorizontalSpacing(2).setVerticalSpacing(0));

        hintsPanel.addComponent(new Label("DOMAIN:"));
        hintsPanel.addComponent(new Label("webmail.example.com, roundcube.example.com"));

        hintsPanel.addComponent(new Label("PORT:"));
        hintsPanel.addComponent(new Label("8443 (recommended), 443, 8080"));

        hintsPanel.addComponent(new Label("SSL PATHS:"));
        hintsPanel.addComponent(new Label("files that stay there (nginx reads them), e.g. /usr/local/etc/ssl/webmail/cert.pem"));

        hintsPanel.addComponent(new Label(""));
        hintsPanel.addComponent(new Label("empty: the panel's certificate if set, otherwise the mail server's"));

        return hintsPanel;
    }

    private String validateInputs() {
        StringBuilder errors = new StringBuilder();

        String domain = roundcube_domain.getText().trim();
        String port = roundcube_port.getText().trim();
        String sslCert = roundcube_ssl_cert.getText().trim();
        String sslKey = roundcube_ssl_key.getText().trim();
        String sslChain = roundcube_ssl_chain.getText().trim();

        // Domain is required
        if (domain.isEmpty()) {
            errors.append("- Domain is required\n");
        } else if (!HOST_PATTERN.matcher(domain).matches()) {
            errors.append("- Domain must contain only: a-z A-Z 0-9 . -\n");
        } else if (domain.equalsIgnoreCase(org.mail_panel.system.InstallNames.DEFAULT_WEBMAIL)) {
            // Il nome di fabbrica non e' un nome (reperto 244): l'installazione non partirebbe.
            errors.append("- Write your webmail name, for example webmail.yourdomain.com (the example name is not one)\n");
        }

        // Port is required
        if (port.isEmpty()) {
            errors.append("- Port is required\n");
        } else if (!PORT_PATTERN.matcher(port).matches()) {
            errors.append("- Port must contain only numbers\n");
        } else {
            int portNum = Integer.parseInt(port);
            if (portNum < 1 || portNum > 65535) {
                errors.append("- Port must be between 1 and 65535\n");
            }
        }

        // SSL paths validation (optional but if one is provided, both needed)
        if (!sslCert.isEmpty() && !PATH_PATTERN.matcher(sslCert).matches()) {
            errors.append("- SSL Cert path contains invalid characters\n");
        }
        if (!sslKey.isEmpty() && !PATH_PATTERN.matcher(sslKey).matches()) {
            errors.append("- SSL Key path contains invalid characters\n");
        }
        if (!sslCert.isEmpty() && sslKey.isEmpty()) {
            errors.append("- SSL Key path is required when SSL Cert path is provided\n");
        }
        if (sslCert.isEmpty() && !sslKey.isEmpty()) {
            errors.append("- SSL Cert path is required when SSL Key path is provided\n");
        }
        if (!sslChain.isEmpty() && !PATH_PATTERN.matcher(sslChain).matches()) {
            errors.append("- SSL CA Chain path contains invalid characters\n");
        }

        // Il certificato della webmail come quello del pannello (reperto 243): i file ci sono, il certificato copre il
        // nome della webmail, vale adesso e la chiave e' la sua. nginx li legge da li': devono restare dove sono.
        certCheck = null;
        if (errors.length() == 0 && !sslCert.isEmpty() && !sslKey.isEmpty()) {
            try {
                certCheck = org.mail_panel.security.PemTls.check("webmail name", domain,
                        org.mail_panel.security.PemTls.readFile(java.nio.file.Path.of(sslCert)),
                        org.mail_panel.security.PemTls.readFile(java.nio.file.Path.of(sslKey)), java.time.Instant.now());
                for (String e : certCheck.errors()) errors.append("- ").append(e).append("\n");
            } catch (java.io.IOException e) {
                errors.append("- ").append(e.getMessage()).append("\n");
            }
        }

        return errors.length() > 0 ? errors.toString() : null;
    }

    private org.mail_panel.security.PemTls.Check certCheck;

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
        message.append("Domain: ").append(roundcube_domain.getText()).append("\n");
        message.append("Port: ").append(roundcube_port.getText()).append("\n");
        if (!roundcube_ssl_cert.getText().trim().isEmpty()) {
            message.append("SSL: these files (they must stay there)\n");
            if (certCheck != null) {
                for (String line : certCheck.info()) message.append(line).append("\n");
                for (String w : certCheck.warnings()) message.append("WARNING: ").append(w).append("\n");
            }
        } else {
            message.append("SSL: the panel's certificate if one is set, otherwise the mail server's\n");
        }

        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                "Confirm Changes",
                "Save Roundcube configuration?\n\n" + message.toString(),
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            if (saveDataToDatabase()) {
                MessageDialog.showMessageDialog(
                        this.gui,
                        "Saved",
                        "Roundcube configuration saved successfully.\n\n" +
                        "Webmail URL: https://" + roundcube_domain.getText() + ":" + roundcube_port.getText(),
                        MessageDialogButton.OK
                );
                window.close();
            } else {
                MessageDialog.showMessageDialog(
                        this.gui,
                        "Error",
                        "Failed to save configuration.",
                        MessageDialogButton.OK
                );
            }
        }
    }

    private void onExit() {
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                "Confirm Exit",
                "Exit without saving?",
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            window.close();
        }
    }

    private boolean saveDataToDatabase() {
        try {
            return database_manager.updateRoundcubeConfig(
                    roundcube_domain.getText().trim(),
                    roundcube_port.getText().trim(),
                    roundcube_ssl_cert.getText().trim(),
                    roundcube_ssl_key.getText().trim(),
                    roundcube_ssl_chain.getText().trim()
            );
        } catch (Exception e) {
            return false;
        }
    }
}
