package etf.openpgp.indeksi;

import java.util.Optional;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;

public class GenerateKey {
	
	private static VBox generateKeyVBox;
	
	private static String name, email, algorithm, password;
	private static int keySize;
	
	public static VBox openAddKeyMenu(BorderPane pane) {
		createVBox(pane);
		return generateKeyVBox;
	}
	
	private static TextInputDialog openPasswordField(BorderPane pane) {
		TextInputDialog dialog = new TextInputDialog("Choose password");
		dialog.setTitle("Enter password");
		
		return dialog;
	}
	
	private static void createVBox(BorderPane pane) {
		generateKeyVBox = new VBox();
		generateKeyVBox.setPadding(new Insets(10));
		generateKeyVBox.setSpacing(8);

	    Text title = new Text("Generate new key");
	    title.setFont(Font.font("Arial", FontWeight.BOLD, 14));
	    generateKeyVBox.getChildren().add(title);
	     
	    Label nameLabel = new Label("Enter name:");
	    generateKeyVBox.getChildren().add(nameLabel);
	    
	    TextField nameField = new TextField();
	    generateKeyVBox.getChildren().add(nameField);
	     
	    Label mail = new Label("Enter mail:");
	    generateKeyVBox.getChildren().add(mail);
	    
	    TextField mailField = new TextField();
	    generateKeyVBox.getChildren().add(mailField);
	    
	    Label keySizeLabel = new Label("Choose key size:");
	    generateKeyVBox.getChildren().add(keySizeLabel);
	    
	    ObservableList<String> options = 
	    	    FXCollections.observableArrayList(
	    	        "1024",
	    	        "2048",
	    	        "4096"
	    	    );
	    final ComboBox<String> comboBox = new ComboBox<String>(options);
	    comboBox.setValue("1024");
	    generateKeyVBox.getChildren().add(comboBox);
	    
	    Label keyEncryptAlgorithmLabel = new Label("Choose key encypt algorithm:");
	    generateKeyVBox.getChildren().add(keyEncryptAlgorithmLabel);
	    
	    ObservableList<String> posibleAlgorithms = 
	    	    FXCollections.observableArrayList(
	    	        "3DES",
	    	        "IDEA"
	    	    );
	    final ComboBox<String> comboBoxAlgorithms = new ComboBox<String>(posibleAlgorithms);
	    comboBoxAlgorithms.setValue("3DES");
	    generateKeyVBox.getChildren().add(comboBoxAlgorithms);
	     
	    Button generateKey = new Button("GENERATE");
	    generateKeyVBox.getChildren().add(generateKey);
	    
	    generateKey.setOnAction(new EventHandler<ActionEvent>() {
	        public void handle(ActionEvent e) {
	            email = mailField.getText();
	            name = nameField.getText();
	            keySize = Integer.parseInt(comboBox.getValue());
	            algorithm = comboBoxAlgorithms.getValue();
	            
	            boolean everythingOK = true;
	           
	            if(name.length() == 0) {
	            	everythingOK = false;
	            }
	            
	            if(email.length() == 0) {
	            	everythingOK = false;
	            }
	            
	            if(everythingOK) {
	            	boolean passwordEntered = false;
	            	TextInputDialog dialog = openPasswordField(pane);
	            	while(!passwordEntered) {
	            		Optional<String> result = dialog.showAndWait();
	            		if (result.isPresent()){
	            			password = result.get();
	            			System.out.print(password);
	            			passwordEntered = true;
	            		} else {
	            			dialog.setHeaderText("You have to enter password");
	            		}
	            	}
	            }
	        }
	    });
	    
	    Button cancel = new Button("CANCEL");
	    cancel.setOnAction(new EventHandler<ActionEvent>() {
	        public void handle(ActionEvent e) {
	            pane.setCenter(null);
	        }
	    });
	    generateKeyVBox.getChildren().add(cancel);

	}

}
