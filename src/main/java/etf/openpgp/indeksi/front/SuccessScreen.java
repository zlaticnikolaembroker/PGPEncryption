package etf.openpgp.indeksi.front;

import javafx.geometry.Pos;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;

public class SuccessScreen extends Dialog<String>{

    public SuccessScreen(String title, String labelText) {
        setTitle(title);
        Label label = new Label(labelText);
        HBox content = new HBox();
        content.setAlignment(Pos.CENTER_LEFT);
        content.setSpacing(10);
        content.getChildren().addAll(label);
        getDialogPane().getButtonTypes().addAll(ButtonType.OK);
        getDialogPane().setContent(content);
        setResultConverter(clickedButton -> {
            return null;
        });
    }
}
