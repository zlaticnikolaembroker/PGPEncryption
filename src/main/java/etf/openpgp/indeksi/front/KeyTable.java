package etf.openpgp.indeksi.front;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import etf.openpgp.indeksi.crypto.KeyRings;
import javafx.event.ActionEvent;
import javafx.geometry.Insets;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.scene.control.Button;
import javafx.scene.control.TableCell;
import javafx.stage.Stage;
import javafx.util.Callback;

public class KeyTable {
	
	private static VBox secretKeysVBox;
	
	public static VBox openSecretKeysTable(BorderPane pane) {
		createVBox(pane);
		return secretKeysVBox;
    }
    
    private static String getNameFromUserID(String userID) {
        return userID.substring(0, userID.indexOf(" <"));
    }

    private static String getEmailFromUserID(String userID) {
        return userID.substring(userID.indexOf(" <") + 2, userID.indexOf(">"));
    }

    private static Map<String, Integer> shownKeys = new HashMap<>();
	
	private static List<KeyColumn> getKeyColumns() {
		
		List<KeyColumn> result = new ArrayList<KeyColumn>();
		
        Iterator<PGPSecretKeyRing> secKrIter = KeyRings.getSecretKeyRings().getKeyRings();
        
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
        
        Iterator<PGPPublicKeyRing> publicKeyIterator = KeyRings.getPublicKeyRings().getKeyRings();
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
	
	private static void createVBox(BorderPane pane) {
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
		
		TableColumn<KeyColumn, Void> colBtn = new TableColumn("Delete");

        Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>> cellFactory = new Callback<TableColumn<KeyColumn, Void>, TableCell<KeyColumn, Void>>() {
            @Override
            public TableCell<KeyColumn, Void> call(final TableColumn<KeyColumn, Void> param) {
                final TableCell<KeyColumn, Void> cell = new TableCell<KeyColumn, Void>() {

                    private final Button btn = new Button("Delete");

                    {
                        
                    }

                    @Override
                    public void updateItem(Void item, boolean empty) {
                        super.updateItem(item, empty);
                        if (empty) {
                            setGraphic(null);
                        } else {
                            setGraphic(btn);
                        }
                    }
                };
                return cell;
            }
        };

        colBtn.setCellFactory(cellFactory);

		tableView.getColumns().add(column1);
		tableView.getColumns().add(column2);
		tableView.getColumns().add(column3);
		tableView.getColumns().add(column4);
		tableView.getColumns().add(colBtn);
		
		List<KeyColumn> keysList = getKeyColumns();
		
		for(int i = 0; i < keysList.size(); i++) {
			tableView.getItems().add(keysList.get(i));
		}
		
		secretKeysVBox.getChildren().add(tableView);

	}
}
