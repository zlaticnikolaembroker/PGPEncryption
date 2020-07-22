package etf.openpgp.indeksi;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;

public class GenerateKey {
	
	private static VBox generateKeyVBox;
	
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
	     
	    Label name = new Label("Enter name:");
	    generateKeyVBox.getChildren().add(name);
	     
	    Label mail = new Label("Enter mail:");
	    generateKeyVBox.getChildren().add(mail);
	     
	    Button generateKey = new Button("GENERATE");
	    generateKeyVBox.getChildren().add(generateKey);
	    
	    Button cancel = new Button("CANCEL");
	    cancel.setOnAction(new EventHandler<ActionEvent>() {
	        public void handle(ActionEvent e) {
	            pane.setCenter(null);
	        }
	    });
	    generateKeyVBox.getChildren().add(cancel);

	}

}
