package etf.openpgp.indeksi.front;


import javafx.geometry.Pos;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.HBox;

public class PasswordDialog extends Dialog<String> {

    public PasswordDialog() {
        this("Enter password", "Enter password");
    }

    public PasswordDialog(String title, String labelText) {
        setTitle(title);
        PasswordField passwordField = new PasswordField();
        passwordField.requestFocus();
        Label label = new Label(labelText);
        HBox content = new HBox();
        content.setAlignment(Pos.CENTER_LEFT);
        content.setSpacing(10);
        content.getChildren().addAll(label, passwordField);
        getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
        getDialogPane().setContent(content);
        setResultConverter(clickedButton -> {
            if (clickedButton == ButtonType.OK) {
                return passwordField.getText();
            } else {
                return null;
            }
        });
    }



}
