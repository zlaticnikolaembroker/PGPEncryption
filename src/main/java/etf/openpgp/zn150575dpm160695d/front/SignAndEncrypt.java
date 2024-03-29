package etf.openpgp.zn150575dpm160695d.front;

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

import etf.openpgp.zn150575dpm160695d.crypto.Encryptor;
import etf.openpgp.zn150575dpm160695d.crypto.KeyRings;
import etf.openpgp.zn150575dpm160695d.crypto.Signer;
import etf.openpgp.zn150575dpm160695d.crypto.models.EncryptionAlgorithms;
import etf.openpgp.zn150575dpm160695d.crypto.models.Key;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SignAndEncrypt {

    private KeyRings keyRings;
    private KeyTable keyTable;
    private final Encryptor encryptor;
    private final Signer signer;
    private VBox signAndEncryptVBox;
    private Stage stage;

    private String filePath;

    public SignAndEncrypt(KeyRings keyRings) {
        this.keyRings = keyRings;
        this.encryptor = new Encryptor(keyRings);
        this.signer = new Signer(keyRings);
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
        if (signingKeyList.isEmpty()) {
            signCheckBox.setSelected(false);
            signCheckBox.setDisable(true);
            signingKeyComboBox.setDisable(true);
        } else {
            signingKeyComboBox.setValue(signingKeyList.get(0));
            signingKeyComboBox.disableProperty().bind(Bindings.createBooleanBinding(() -> !signCheckBox.isSelected(),
                    signCheckBox.selectedProperty()));
        }
        signingBox.getChildren().addAll(signCheckBox, signLabel, signingKeyComboBox);
        signAndEncryptVBox.getChildren().add(signingBox);

        Label recipientsLabel = new Label("Select recipients:");
        ObservableList<Key> encryptionKeyList = FXCollections.observableList(keyRings.getEncryptionKeys());
        TableView<Key> encryptionKeysTable = new TableView<>(encryptionKeyList);
        encryptionKeysTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        TableColumn<Key, String> keyNameCol = new TableColumn<>("Key name");
        keyNameCol.setCellValueFactory(new PropertyValueFactory("userId"));
        encryptionKeysTable.getColumns().add(keyNameCol);
        
        CheckBox compressChbx = new CheckBox("Compress?");
        CheckBox radix64Chbx = new CheckBox("Radix64 format?");
        signAndEncryptVBox.getChildren().addAll(compressChbx, radix64Chbx, recipientsLabel, encryptionKeysTable);

        ObservableList<String> posibleAlgorithms =
                FXCollections.observableArrayList(Arrays.stream(EncryptionAlgorithms.values())
                        .map(EncryptionAlgorithms::getLabel).collect(Collectors.toList()));
        final ComboBox<String> comboBoxAlgorithms = new ComboBox<>(posibleAlgorithms);
        comboBoxAlgorithms.setValue("3DES");

        signAndEncryptVBox.getChildren().add(comboBoxAlgorithms);

        Button encryptBtn = new Button("Encrypt/Sign");
        encryptBtn.setOnAction(e -> {
            List<Key> recipientList = new LinkedList<>(encryptionKeysTable.getSelectionModel().getSelectedItems());
            boolean shouldSign = signCheckBox.isSelected();
            Key signingKey = shouldSign ? signingKeyComboBox.getValue() : null;
            boolean shouldCompress = compressChbx.isSelected();
            boolean shouldArmor = radix64Chbx.isSelected();
            EncryptionAlgorithms encryptionAlgorithm = EncryptionAlgorithms.parse(comboBoxAlgorithms.getValue());
            String extension = "";
            try {
                String password = null;
                if (shouldSign && (password = PasswordVerificator.verify(signingKey.getKeyId(), keyRings)) == null) {
                    // ukoliko smo pokusali potpisivanje a nije verifikovana lozinka, obustavljamo
                    return;
                }
                if (recipientList.size() > 0) {
                    // ako imamo primaoce, radimo enkripciju i potpisivanje po potrebi
                    extension = shouldArmor ? ".asc" : ".gpg";
                    String encryptedFilePath = filePath.concat(extension);
                    OutputStream out = new FileOutputStream(encryptedFilePath);
                    encryptor.encryptFile(out, filePath, recipientList, signingKey, password, true, shouldCompress, shouldArmor, encryptionAlgorithm);
                } else {
                    // ako nemamo primaoce, radimo samo potpisivanje odabranim kljucem
                    extension = shouldArmor ? ".asc" : ".sig";
                    String signatureFilePath = filePath.concat(extension);
                    OutputStream out = new FileOutputStream(signatureFilePath);
                    signer.signFile(out, filePath, signingKey, password, shouldArmor);
                }
                pane.setCenter(keyTable.openSecretKeysTable(pane, stage));
            } catch (IOException | PGPException | NoSuchProviderException | NoSuchAlgorithmException | SignatureException exception) {
                InfoScreen successScreen = new InfoScreen("Something went wrong.", exception.getMessage());
                successScreen.showAndWait();
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
