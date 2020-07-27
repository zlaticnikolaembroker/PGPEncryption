package etf.openpgp.indeksi;

import java.io.*;

import etf.openpgp.indeksi.crypto.KeyRings;
import etf.openpgp.indeksi.crypto.generators.RSAKeyPairGenerator;
import etf.openpgp.indeksi.front.GenerateKey;
import etf.openpgp.indeksi.front.SecretKeysTable;
import javafx.application.Application;
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;  
import javafx.event.ActionEvent;
import javafx.event.EventHandler;


public class App extends Application
{

	private KeyRings keyRings = new KeyRings(new RSAKeyPairGenerator());
	
	private void ChooseFileToEncryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to encrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		try {
			readFile(stage, fileChooser);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private void ChooseFileToDecryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to decrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		try {
			readFile(stage, fileChooser);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	private void ChooseFileForKeyPairImporting(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to import key pair");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.asc"));
		try {
			InputStream fileIs = readFile(stage, fileChooser);
			keyRings.importKeyPair(fileIs);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

	private InputStream readFile(Stage stage, FileChooser fileChooser) throws FileNotFoundException {
		File selectedFile = fileChooser.showOpenDialog(stage);
		return new FileInputStream(selectedFile);
	}

	private void saveTextToFile(String content, File file) {
        try {
            PrintWriter writer;
            writer = new PrintWriter(file);
            writer.println(content);
            writer.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
	
	private void ExportKeyPair(String sampleText, Stage stage) {
		FileChooser fileChooser = new FileChooser();
 
        //Set extension filter for text files
        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("ASC files (*.asc)", "*.asc");
        fileChooser.getExtensionFilters().add(extFilter);
 
        //Show save file dialog
        File file = fileChooser.showSaveDialog(stage);
 
        if (file != null) {
            saveTextToFile(sampleText, file);
        }
	}
	
	private void GenerateNewKeyPair(BorderPane pane) {
		pane.setCenter(GenerateKey.openAddKeyMenu(pane));
	}
	
    @Override
    public void start(final Stage stage) {
        BorderPane root = new BorderPane();  
        Scene scene = new Scene(root,800,500);  
        MenuBar menubar = new MenuBar();  
        
        Menu KeysMenu = new Menu("Keys");  
        MenuItem keysMenu1=new MenuItem("Genereate key pair");  
        keysMenu1.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				GenerateNewKeyPair(root);
			}
		});
        
        MenuItem keysMenu2=new MenuItem("Import key pair");
        keysMenu2.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				ChooseFileForKeyPairImporting(stage);
			}
        });
        
        final String sampleText = "Test";
        MenuItem keysMenu3=new MenuItem("Export key pair");  
        keysMenu3.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				ExportKeyPair(sampleText, stage);
			}
		});
        
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
        root.setCenter(SecretKeysTable.openSecretKeysTable(root));
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
