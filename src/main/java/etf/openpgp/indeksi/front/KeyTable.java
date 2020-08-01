package etf.openpgp.indeksi.front;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import etf.openpgp.indeksi.crypto.KeyRings;
import javafx.geometry.Insets;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Callback;

public class KeyTable {
	
	private VBox secretKeysVBox;

	private KeyRings keyRings;
	private Stage stage;

    public KeyTable(KeyRings keyRings) {
        this.keyRings = keyRings;
    }
	
	public VBox openSecretKeysTable(BorderPane pane, Stage stage) {
		createVBox(pane, stage);
		this.stage = stage;
		return secretKeysVBox;
    }
    
    private String getNameFromUserID(String userID) {
        return userID.substring(0, userID.indexOf(" <"));
    }

    private String getEmailFromUserID(String userID) {
        return userID.substring(userID.indexOf(" <") + 2, userID.indexOf(">"));
    }
	
	private List<KeyColumn> getKeyColumns() {
		Map<String, Integer> shownKeys = new HashMap<>();
		
		List<KeyColumn> result = new ArrayList<KeyColumn>();
		
        Iterator<PGPSecretKeyRing> secKrIter = keyRings.getSecretKeyRings().getKeyRings();
        
        while (secKrIter.hasNext()) {
        	PGPSecretKeyRing skr = secKrIter.next();
            Iterator<PGPSecretKey> secKeysIter = skr.getSecretKeys();
            boolean found = false; 
            while (secKeysIter.hasNext()) {
                PGPSecretKey key = secKeysIter.next();
                Iterator<String> userIDs = key.getUserIDs();
                
                long keyID =  key.getKeyID();
                if (!found) {
                    String email = "", name = "";
                    if (userIDs.hasNext()) {
                        String userId = userIDs.next();
                        name = getNameFromUserID(userId);
                        email = getEmailFromUserID(userId);
                    }
                    
                    result.add(new KeyColumn(email, name, "", keyID, false, null, key));
                    shownKeys.put(Long.toString(keyID), 1);
                    found = true;
                } else {
                	shownKeys.put(Long.toString(keyID), 1);
                }
            }
        }
        
        Iterator<PGPPublicKeyRing> publicKeyIterator = keyRings.getPublicKeyRings().getKeyRings();
        while (publicKeyIterator.hasNext()) {
        	PGPPublicKeyRing skr = publicKeyIterator.next();
        	Iterator<PGPPublicKey> pubKeysIter = skr.getPublicKeys();
            while (pubKeysIter.hasNext()) {
                PGPPublicKey key = pubKeysIter.next();
                Iterator<String> userIDs = key.getUserIDs();
                long keyID = key.getKeyID();
                if (shownKeys.get(Long.toString(keyID)) == null) {
                    String email = "", name = "";
                    if (userIDs.hasNext()) {
                        String userId = userIDs.next();
                        name = getNameFromUserID(userId);
                        email = getEmailFromUserID(userId);
                    }
                
                    result.add(new KeyColumn(email, name, "", keyID, true, key, null));
                    shownKeys.put(Long.toString(keyID), 1);
                    break;
                }
                
            }
        }
        
        return result;
	}
	
	private void createVBox(BorderPane pane, Stage stage) {
		secretKeysVBox = new VBox();
		secretKeysVBox.setPadding(new Insets(10));
		secretKeysVBox.setSpacing(8);

	    Text title = new Text("Keys table:");
	    title.setFont(Font.font("Arial", FontWeight.BOLD, 14));
	    secretKeysVBox.getChildren().add(title);
	     
	    TableView tableView = new TableView();
	    

		TableColumn<String, KeyColumn> column1 = new TableColumn<>("Email");
		column1.setCellValueFactory(new PropertyValueFactory<>("email"));


		TableColumn<String, KeyColumn> column2 = new TableColumn<>("Name");
		column2.setCellValueFactory(new PropertyValueFactory<>("name"));
		
		TableColumn<String, KeyColumn> column3 = new TableColumn<>("KeyID");
		column3.setCellValueFactory(new PropertyValueFactory<>("keyId"));
		
		TableColumn<String, KeyColumn> column4 = new TableColumn<>("Is Public");
		column4.setCellValueFactory(new PropertyValueFactory<>("isPublic"));
		
		TableColumn<KeyColumn, Void> deleteBtn = new TableColumn<>("Delete");
		
		TableColumn<KeyColumn, Void> exportBtn = new TableColumn<>("Export");
		
		TableColumn<KeyColumn, Void> exportSecretBtn = new TableColumn<>("Export secret");

        Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>> deleteCellFactory = new Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>>() {
            @Override
            public TableCell<KeyColumn, Void> call(final TableColumn<KeyColumn, Void> param) {
                final TableCell<KeyColumn, Void> cell = new TableCell<KeyColumn, Void>() {

                    private final Button btn = new Button("Delete");

                    @Override
                    public void updateItem(Void item, boolean empty) {
                        super.updateItem(item, empty);
                        if (empty) {
                            setGraphic(null);
                        } else {
                            btn.setOnAction(event -> {
                                KeyColumn keyColumn = getTableView().getItems().get(getIndex());
                                Dialog<Boolean> confirmDialog = showConfirmDialog(keyColumn.getName(), keyColumn.getEmail(), "delete");
                                Optional<Boolean> confirmationOptional = confirmDialog.showAndWait();
                                Boolean deletionConfirmed = confirmationOptional.get();
                                if (deletionConfirmed) {
                                    Long keyId = keyColumn.getOriginalKeyId();
                                    boolean isPublic = keyColumn.getIsPublic();
                                    if (deleteKey(keyId, isPublic)) refreshTableRows(tableView);
                                }
                            });
                            setGraphic(btn);
                        }
                        setText(null);
                    }
                };
                return cell;
            }
        };
        
        Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>> exportCellFactory = new Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>>() {
            @Override
            public TableCell<KeyColumn, Void> call(final TableColumn<KeyColumn, Void> param) {
                final TableCell<KeyColumn, Void> cell = new TableCell<KeyColumn, Void>() {

                    private final Button btn = new Button("Export");

                    @Override
                    public void updateItem(Void item, boolean empty) {
                        super.updateItem(item, empty);
                        if (empty) {
                            setGraphic(null);
                        } else {
                            btn.setOnAction(event -> {
                                KeyColumn keyColumn = getTableView().getItems().get(getIndex());
                                Dialog<Boolean> confirmDialog = showConfirmDialog(keyColumn.getName(), keyColumn.getEmail(), "export");
                                Optional<Boolean> confirmationOptional = confirmDialog.showAndWait();
                                Boolean exportConfirmed = confirmationOptional.get();
                                if (exportConfirmed) {
                                    String fileName = chooseFileName(stage); 
                                    
                                    if (fileName != null){
                                        if (fileName.substring(fileName.length() - 4) != ".asc") {
                                            fileName += ".asc";
                                        }
                                    	keyRings.exportPublicKeyRing(fileName, keyColumn.getUserId());   
                                    }
                                }
                            });
                            setGraphic(btn);
                        }
                        setText(null);
                    }
                };
                return cell;
            }
        };
        
        Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>> exportSecretCellFactory = new Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>>() {
            @Override
            public TableCell<KeyColumn, Void> call(final TableColumn<KeyColumn, Void> param) {
                final TableCell<KeyColumn, Void> cell = new TableCell<KeyColumn, Void>() {

                    private final Button btn = new Button("Export Secret");

                    @Override
                    public void updateItem(Void item, boolean empty) {
                        super.updateItem(item, empty);
                        if (empty) {
                            setGraphic(null);
                        } else {
                            KeyColumn keyColumn = getTableView().getItems().get(getIndex());
                                if (!keyColumn.getIsPublic()) {
                                    btn.setOnAction(event -> {
                                        Dialog<Boolean> confirmDialog = showConfirmDialog(keyColumn.getName(), keyColumn.getEmail(), "export secret");
                                        Optional<Boolean> confirmationOptional = confirmDialog.showAndWait();
                                        Boolean exportSecreatConfirmed = confirmationOptional.get();
                                        if (exportSecreatConfirmed) {
                                            String fileName = chooseFileName(stage);
                                           
                                            
                                            if (fileName != null){
                                                if (fileName.substring(fileName.length() - 4) != ".asc") {
                                                    fileName += ".asc";
                                                }
                                                if (PasswordVerificator.verify(keyColumn.getOriginalKeyId(), keyRings)) {
                                                    // verifikacija lozinke je uspesna, exportujemo kljuc
                                                    keyRings.exportSecretKeyRing(fileName, keyColumn.getUserId());
                                                }
                                            }
                                        }
                                    });
                                    setGraphic(btn);
                                }
                            
                        }
                        setText(null);
                    }
                };
                return cell;
            }
        };

        deleteBtn.setCellFactory(deleteCellFactory);
        exportBtn.setCellFactory(exportCellFactory);
        exportSecretBtn.setCellFactory(exportSecretCellFactory);

		tableView.getColumns().add(column1);
		tableView.getColumns().add(column2);
		tableView.getColumns().add(column3);
		tableView.getColumns().add(column4);
		tableView.getColumns().add(deleteBtn);
		tableView.getColumns().add(exportBtn);
		tableView.getColumns().add(exportSecretBtn);
		
		refreshTableRows(tableView);

	}

    private boolean deleteKey(Long keyId, boolean isPublic) {
	    boolean keyDeleted = false;
        if (isPublic) {
            try {
                keyRings.deletePublicKey(keyId);
                keyDeleted = true;
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        } else {
            if (PasswordVerificator.verify(keyId, keyRings)) {
                // verifikacija lozinke je uspesna, brisemo kljuc
                keyRings.deleteSecretKey(keyId);
                keyDeleted = true;
            }
        }
        return keyDeleted;
    }

    private Dialog showConfirmDialog(String name, String email, String message) {
        Dialog<Boolean> confirmDialog = new Dialog();
        confirmDialog.setTitle("Are you sure?");
        Label label = new Label("Are you sure you want to " + message + " key " + name + "<" + email + ">");
        HBox content = new HBox();
        content.getChildren().add(label);
        confirmDialog.getDialogPane().getButtonTypes().addAll(ButtonType.YES, ButtonType.NO);
        confirmDialog.setResultConverter(buttonClicked -> {
            if (buttonClicked == ButtonType.YES) return Boolean.TRUE;
            else return Boolean.FALSE;
        });
        confirmDialog.getDialogPane().setContent(content);

        return confirmDialog;
    }
	
	private String chooseFileName(Stage stage) {
		FileChooser fileChooser = new FileChooser();
 
        //Set extension filter for text files
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("ASC files (*.asc)", "*.asc");
        fileChooser.getExtensionFilters().add(extFilter);
 
        //Show save file dialog
        File file = fileChooser.showSaveDialog(stage);
 
        if (file != null) {
            return file.getPath();
        }
        return null;
	}
	
	private void refreshTableRows(TableView tableView) {
		secretKeysVBox.getChildren().clear();
		tableView.getItems().clear();
		List<KeyColumn> keysList = getKeyColumns();
		
		for(int i = 0; i < keysList.size(); i++) {
			tableView.getItems().add(keysList.get(i));
		}
		
		secretKeysVBox.getChildren().add(tableView);
	}
}
