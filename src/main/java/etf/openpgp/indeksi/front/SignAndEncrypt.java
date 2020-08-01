package etf.openpgp.indeksi.front;

import etf.openpgp.indeksi.crypto.Encryptor;
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
import javafx.stage.Stage;
import org.bouncycastle.openpgp.PGPException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.LinkedList;
import java.util.List;

public class SignAndEncrypt {

    private KeyRings keyRings;
    private KeyTable keyTable;
    private final Encryptor encryptor;
    private VBox signAndEncryptVBox;
    private Stage stage;

    private String filePath;

    public SignAndEncrypt(KeyRings keyRings) {
        this.keyRings = keyRings;
        this.encryptor = new Encryptor(keyRings);
    }

    public VBox openSignAndEncrypt(BorderPane pane, Stage stage, KeyTable keyTable, String filePath, KeyRings keyRings) {
        this.keyTable = keyTable;
        this.keyRings = keyRings;
        this.stage = stage;
        this.filePath = filePath;
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

        Button encryptBtn = new Button("Encrypt/Sign");
        encryptBtn.setOnAction(e -> {
            List<Key> recipientList = new LinkedList<>(encryptionKeysTable.getSelectionModel().getSelectedItems());
            boolean shouldSign = signCheckBox.isSelected();
            Key signingKey = shouldSign ? signingKeyComboBox.getValue() : null;
            try {
                if (shouldSign && !PasswordVerificator.verify(signingKey.getKeyId(), keyRings)) {
                    // ukoliko smo pokusali potpisivanje a nije verifikovana lozinka, obustavljamo
                    return;
                }
                String encryptedFilePath = filePath.concat(".asc");
                OutputStream out = new FileOutputStream(encryptedFilePath);
                encryptor.encryptFile(out, filePath, recipientList, signingKey, "test", true);
            } catch (IOException | PGPException | NoSuchProviderException | NoSuchAlgorithmException | SignatureException exception) {
                exception.printStackTrace();
            }
        });

        // encrypt dugme je disableovano ako nije selektovan nijedan primalac i nije odabrana opcija za potpis
        encryptBtn.disableProperty().bind(Bindings.createBooleanBinding(
                () -> encryptionKeysTable.getSelectionModel().getSelectedIndices().toArray().length == 0 && !signCheckBox.isSelected(),
                encryptionKeysTable.getSelectionModel().getSelectedItems(), signCheckBox.selectedProperty()));

        Button cancelBtn = new Button("Cancel");
        cancelBtn.setOnAction(e -> pane.setCenter(keyTable.openSecretKeysTable(pane, stage)));

        signAndEncryptVBox.getChildren().addAll(encryptBtn, cancelBtn);
    }

}
