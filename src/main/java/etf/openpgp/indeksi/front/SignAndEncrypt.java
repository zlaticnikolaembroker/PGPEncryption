package etf.openpgp.indeksi.front;

import etf.openpgp.indeksi.crypto.KeyRings;
import etf.openpgp.indeksi.crypto.models.Key;
import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;

public class SignAndEncrypt {

    private KeyRings keyRings;

    private VBox signAndEncryptVBox;

    private boolean signingDropdownDisabled = false;

    public SignAndEncrypt(KeyRings keyRings) {
        this.keyRings = keyRings;
    }

    public VBox openSignAndEncrypt(BorderPane pane) {
        createVBox(pane);
        return signAndEncryptVBox;
    }

    private void createVBox(BorderPane pane) {
        signAndEncryptVBox = new VBox();
        signAndEncryptVBox.setPadding(new Insets(10));
        signAndEncryptVBox.setSpacing(8);

        Text title = new Text("Sign/Encrypt file");
        title.setFont(Font.font("Arial", FontWeight.BOLD, 14));
        signAndEncryptVBox.getChildren().add(title);

        HBox signingBox = new HBox();
        signingBox.setPadding(new Insets(10));
        signingBox.setSpacing(8);

        CheckBox signCheckBox = new CheckBox();
        signCheckBox.setSelected(true);
        Label signLabel = new Label("Sign as:");

        ObservableList<Key> signingKeyList = FXCollections.observableList(keyRings.getSigningKeys());
        ComboBox<Key> signingKeyComboBox = new ComboBox<>(signingKeyList);
        signingKeyComboBox.setValue(signingKeyList.get(0));
        signingKeyComboBox.disableProperty().bind(Bindings.createBooleanBinding(() -> !signCheckBox.isSelected(),
                signCheckBox.selectedProperty()));
        signingBox.getChildren().addAll(signCheckBox, signLabel, signingKeyComboBox);
        signAndEncryptVBox.getChildren().add(signingBox);

        Label recipientsLabel = new Label("Select recipients:");
        ObservableList<Key> encryptionKeyList = FXCollections.observableList(keyRings.getEncryptionKeys());
        TableView<Key> encryptionKeysTable = new TableView<>(encryptionKeyList);
        encryptionKeysTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        TableColumn<Key, String> keyNameCol = new TableColumn<>("Key name");
        keyNameCol.setCellValueFactory(new PropertyValueFactory("userId"));
        encryptionKeysTable.getColumns().add(keyNameCol);
        signAndEncryptVBox.getChildren().addAll(recipientsLabel, encryptionKeysTable);
    }

}
