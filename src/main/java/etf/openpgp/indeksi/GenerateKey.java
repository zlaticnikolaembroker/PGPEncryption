package etf.openpgp.indeksi;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;

public class GenerateKey {
	
	private static VBox generateKeyVBox;
	
	private static String name, email;
	private static int keySize;
	
	public static VBox openAddKeyMenu(BorderPane pane) {
		createVBox(pane);
		return generateKeyVBox;
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
	     
	    Button generateKey = new Button("GENERATE");
	    generateKeyVBox.getChildren().add(generateKey);
	    
	    generateKey.setOnAction(new EventHandler<ActionEvent>() {
	        public void handle(ActionEvent e) {
	            email = mailField.getText();
	            name = nameField.getText();
	            keySize = Integer.parseInt(comboBox.getValue());
	            
	            boolean everythingOK = true;
	           
	            if(name.length() == 0) {
	            	everythingOK = false;
	            }
	            
	            if(email.length() == 0) {
	            	everythingOK = false;
	            }
	            
	            if(everythingOK) {
	            	System.out.print(keySize);
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
