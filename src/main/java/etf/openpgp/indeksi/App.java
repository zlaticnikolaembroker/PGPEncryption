package etf.openpgp.indeksi;

import java.io.File;
import java.util.Arrays;

import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;  
import javafx.event.ActionEvent;
import javafx.event.EventHandler;


/**
 * Hello world!
 *
 */
public class App extends Application
{
	
	private void ChooseFileToEncryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to encrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		File selectedFile = fileChooser.showOpenDialog(stage);
		if (selectedFile != null) {
		   System.out.println(selectedFile.getName());
		}
	}
	
	private void ChooseFileToDecryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to decrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		File selectedFile = fileChooser.showOpenDialog(stage);
		if (selectedFile != null) {
		   System.out.println(selectedFile.getName());
		}
	}
	
    @Override
    public void start(final Stage stage) {
        BorderPane root = new BorderPane();  
        Scene scene = new Scene(root,800,500);  
        MenuBar menubar = new MenuBar();  
        
        Menu KeysMenu = new Menu("Keys");  
        MenuItem keysMenu1=new MenuItem("Genereate key pair");  
        MenuItem keysMenu2=new MenuItem("Import key pair");  
        MenuItem keysMenu3=new MenuItem("Export key pair");  
        
        Menu EncryptMenu=new Menu("Encrypt");
        MenuItem encryptMenuItem1 = new MenuItem("Choose file");
        encryptMenuItem1.setOnAction(new EventHandler<ActionEvent>() {

			@Override
			public void handle(ActionEvent event) {
				ChooseFileToEncryptClicked(stage);
				
			}
		});
        
        Menu DecryptMenu=new Menu("Decrypt");  
        MenuItem decryptMenuItem1 = new MenuItem("Choose file");
        decryptMenuItem1.setOnAction(new EventHandler<ActionEvent>() {

			@Override
			public void handle(ActionEvent event) {
				ChooseFileToDecryptClicked(stage);
				
			}
		});
        
        KeysMenu.getItems().addAll(keysMenu1,keysMenu2,keysMenu3);  
        EncryptMenu.getItems().addAll(encryptMenuItem1);
        DecryptMenu.getItems().addAll(decryptMenuItem1);
        
        menubar.getMenus().addAll(KeysMenu,EncryptMenu, DecryptMenu);  
        
        root.setTop(menubar);  
        
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
