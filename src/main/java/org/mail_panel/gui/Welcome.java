package org.mail_panel.gui;

import com.googlecode.lanterna.gui2.WindowBasedTextGUI;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogBuilder;
import com.googlecode.lanterna.gui2.dialogs.MessageDialogButton;

public class Welcome {
    private String title;
    private String message;
    private MessageDialogButton[] buttons;

    public Welcome(String title, String message, MessageDialogButton... buttons) {
        this.title = title;
        this.message = message;
        this.buttons = buttons.length > 0 ? buttons : new MessageDialogButton[]{MessageDialogButton.OK};
    }

    public MessageDialogButton show(WindowBasedTextGUI textGUI) {
        MessageDialogBuilder builder = new MessageDialogBuilder()
                .setTitle(title)
                .setText(message);

        for (MessageDialogButton button : buttons) {
            builder.addButton(button);
        }

        return builder.build().showDialog(textGUI);
    }
}
