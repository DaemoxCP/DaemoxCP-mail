package org.daemoxcp.mail.gui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.gui2.dialogs.MessageDialog;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;
import org.daemoxcp.mail.sqli.dataBaseManager;

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

        this.submitButton = new Button(org.daemoxcp.mail.i18n.I18n.tr("console.save"), this::onSubmit);
        this.exitButton = new Button(org.daemoxcp.mail.i18n.I18n.tr("console.cancel"), this::onExit);
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
            System.out.println(org.daemoxcp.mail.i18n.I18n.tr("console.cfg.loadFailed", java.util.Map.of("e", String.valueOf(e.getMessage()))));
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
        this.window = new BasicWindow(org.daemoxcp.mail.i18n.I18n.tr("console.rc.title"));

        Panel mainPanel = new Panel(new GridLayout(1).setVerticalSpacing(1));

        // Info message
        Panel infoPanel = new Panel();
        infoPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.intro")));
        infoPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.required")));
        mainPanel.addComponent(infoPanel.withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.info"))));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Roundcube settings
        mainPanel.addComponent(createRoundcubeForm().withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.rc.settings"))));
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));

        // Hints
        mainPanel.addComponent(createHintsPanel().withBorder(Borders.singleLine(org.daemoxcp.mail.i18n.I18n.tr("console.examples"))));
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

        formPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domain")));
        formPanel.addComponent(Panels.horizontal(
                roundcube_domain,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> roundcube_domain.setText(""))
        ));

        formPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.port")));
        formPanel.addComponent(Panels.horizontal(
                roundcube_port,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> roundcube_port.setText(""))
        ));

        formPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.certPath")));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_cert,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> roundcube_ssl_cert.setText(""))
        ));

        formPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.keyPath")));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_key,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> roundcube_ssl_key.setText(""))
        ));

        formPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.chainPath")));
        formPanel.addComponent(Panels.horizontal(
                roundcube_ssl_chain,
                new EmptySpace(new TerminalSize(1, 1)),
                new Button(org.daemoxcp.mail.i18n.I18n.tr("console.clear"), () -> roundcube_ssl_chain.setText(""))
        ));

        return formPanel;
    }

    private Panel createHintsPanel() {
        Panel hintsPanel = new Panel(new GridLayout(2).setHorizontalSpacing(2).setVerticalSpacing(0));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domain")));
        hintsPanel.addComponent(new Label("webmail.example.com, roundcube.example.com"));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.hint.port")));
        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.portExamples")));

        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.sslPaths")));
        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.sslPathsHint")));

        hintsPanel.addComponent(new Label(""));
        hintsPanel.addComponent(new Label(org.daemoxcp.mail.i18n.I18n.tr("console.rc.sslEmptyHint")));

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
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domainRequired")).append("\n");
        } else if (!HOST_PATTERN.matcher(domain).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domainChars")).append("\n");
        } else if (domain.equalsIgnoreCase(org.daemoxcp.mail.system.InstallNames.DEFAULT_WEBMAIL)) {
            // Il nome di fabbrica non e' un nome (reperto 244): l'installazione non partirebbe.
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domainExample")).append("\n");
        }

        // Port is required
        if (port.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.portRequired")).append("\n");
        } else if (!PORT_PATTERN.matcher(port).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.portDigits")).append("\n");
        } else {
            int portNum = Integer.parseInt(port);
            if (portNum < 1 || portNum > 65535) {
                errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.portRange")).append("\n");
            }
        }

        // SSL paths validation (optional but if one is provided, both needed)
        if (!sslCert.isEmpty() && !PATH_PATTERN.matcher(sslCert).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.certChars")).append("\n");
        }
        if (!sslKey.isEmpty() && !PATH_PATTERN.matcher(sslKey).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.keyChars")).append("\n");
        }
        if (!sslCert.isEmpty() && sslKey.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.keyNeeded")).append("\n");
        }
        if (sslCert.isEmpty() && !sslKey.isEmpty()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.certNeeded")).append("\n");
        }
        if (!sslChain.isEmpty() && !PATH_PATTERN.matcher(sslChain).matches()) {
            errors.append("- ").append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.chainChars")).append("\n");
        }

        // Il certificato della webmail come quello del pannello (reperto 243): i file ci sono, il certificato copre il
        // nome della webmail, vale adesso e la chiave e' la sua. nginx li legge da li': devono restare dove sono.
        certCheck = null;
        if (errors.length() == 0 && !sslCert.isEmpty() && !sslKey.isEmpty()) {
            try {
                certCheck = org.daemoxcp.mail.security.PemTls.check("webmail", domain,
                        org.daemoxcp.mail.security.PemTls.readFile(java.nio.file.Path.of(sslCert)),
                        org.daemoxcp.mail.security.PemTls.readFile(java.nio.file.Path.of(sslKey)), java.time.Instant.now());
                for (String e : certCheck.errors()) errors.append("- ").append(e).append("\n");
            } catch (java.io.IOException e) {
                errors.append("- ").append(e.getMessage()).append("\n");
            }
        }

        return errors.length() > 0 ? errors.toString() : null;
    }

    private org.daemoxcp.mail.security.PemTls.Check certCheck;

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
        message.append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.domain")).append(" ").append(roundcube_domain.getText()).append("\n");
        message.append(org.daemoxcp.mail.i18n.I18n.tr("console.hint.port")).append(" ").append(roundcube_port.getText()).append("\n");
        if (!roundcube_ssl_cert.getText().trim().isEmpty()) {
            message.append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.sslTheseFiles")).append("\n");
            if (certCheck != null) {
                for (String line : certCheck.info()) message.append(line).append("\n");
                for (String w : certCheck.warnings()) message.append(org.daemoxcp.mail.i18n.I18n.tr("console.warning")).append(" ").append(w).append("\n");
            }
        } else {
            message.append(org.daemoxcp.mail.i18n.I18n.tr("console.rc.sslDefault")).append("\n");
        }

        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                org.daemoxcp.mail.i18n.I18n.tr("console.confirmTitle"),
                org.daemoxcp.mail.i18n.I18n.tr("console.rc.confirmSave") + "\n\n" + message.toString(),
                MessageDialogButton.Cancel,
                MessageDialogButton.OK
        );

        if (result == MessageDialogButton.OK) {
            if (saveDataToDatabase()) {
                MessageDialog.showMessageDialog(
                        this.gui,
                        org.daemoxcp.mail.i18n.I18n.tr("console.savedTitle"),
                        org.daemoxcp.mail.i18n.I18n.tr("console.rc.saved", java.util.Map.of("url", "https://" + roundcube_domain.getText() + ":" + roundcube_port.getText())),
                        MessageDialogButton.OK
                );
                window.close();
            } else {
                MessageDialog.showMessageDialog(
                        this.gui,
                        org.daemoxcp.mail.i18n.I18n.tr("console.errorTitle"),
                        org.daemoxcp.mail.i18n.I18n.tr("console.rc.saveFailed"),
                        MessageDialogButton.OK
                );
            }
        }
    }

    private void onExit() {
        MessageDialogButton result = MessageDialog.showMessageDialog(
                this.gui,
                org.daemoxcp.mail.i18n.I18n.tr("console.exitTitle"),
                org.daemoxcp.mail.i18n.I18n.tr("console.rc.exitText"),
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
