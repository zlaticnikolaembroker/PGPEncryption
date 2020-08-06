package etf.openpgp.indeksi;

import java.io.*;

import etf.openpgp.indeksi.crypto.Decryptor;
import etf.openpgp.indeksi.crypto.KeyRings;
import etf.openpgp.indeksi.crypto.generators.RSAKeyPairGenerator;
import etf.openpgp.indeksi.front.GenerateKey;
import etf.openpgp.indeksi.front.InfoScreen;
import etf.openpgp.indeksi.front.KeyTable;
import etf.openpgp.indeksi.front.SignAndEncrypt;
import javafx.application.Application;
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;  
import javafx.event.ActionEvent;
import javafx.event.EventHandler;


public class App extends Application
{

	private KeyRings keyRings;

	private GenerateKey generateKey;
	private SignAndEncrypt signAndEncrypt;
	private KeyTable keyTable;

	public App() {
		this.keyRings = new KeyRings(new RSAKeyPairGenerator());

		this.keyTable = new KeyTable(keyRings);
		this.generateKey = new GenerateKey(keyRings, keyTable);
		this.signAndEncrypt = new SignAndEncrypt(keyRings);
	}

	private void ChooseFileToEncryptClicked(Stage stage, BorderPane root) {
		String filePath = chooseFile(stage);
		if (filePath != null) {
			root.setCenter(signAndEncrypt.openSignAndEncrypt(root, stage, keyTable, filePath, keyRings));
		}
	}
	
	private File ChooseFileToDecryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to decrypt");
		
		try {
			return readFile(stage, fileChooser);
		} catch (FileNotFoundException e) {
			InfoScreen successScreen = new InfoScreen("Something went wrong.", e.getMessage());
            successScreen.showAndWait();
			e.printStackTrace();
		}
		return null;
	}
	
	private void ChooseFileForKeyPairImporting(Stage stage, BorderPane pane) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to import key pair");
		
		try {
			File file = readFile(stage, fileChooser);
			if (file != null) {
				InputStream fileIs = new FileInputStream(file);
				if (fileIs != null) {
					keyRings.importKeyPair(fileIs);
					pane.setCenter(keyTable.openSecretKeysTable(pane, stage));
				}
			}
		} catch (FileNotFoundException e) {
			InfoScreen successScreen = new InfoScreen("Something went wrong.", e.getMessage());
            successScreen.showAndWait();
			e.printStackTrace();
		}
	}

	private File readFile(Stage stage, FileChooser fileChooser) throws FileNotFoundException {
		return fileChooser.showOpenDialog(stage);
	}

	
	
	private void GenerateNewKeyPair(BorderPane pane, Stage stage) {
		pane.setCenter(generateKey.openAddKeyMenu(pane, stage));
	}

	private String chooseFile(Stage stage) {
		FileChooser fileChooser = new FileChooser();

		//Set extension filter for text files
		FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("All files (*)", "*.*");
		fileChooser.getExtensionFilters().add(extFilter);

		//Show save file dialog
		File file = fileChooser.showOpenDialog(stage);

		if (file != null) {
			return file.getPath();
		}
		return null;
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
				GenerateNewKeyPair(root, stage);
			}
		});
        
        MenuItem keysMenu2=new MenuItem("Import key pair");
        keysMenu2.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				ChooseFileForKeyPairImporting(stage, root);
			}
        });
        
        Menu EncryptMenu=new Menu("Encrypt/Sign");
        MenuItem encryptMenuItem1 = new MenuItem("Choose file");
        encryptMenuItem1.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				ChooseFileToEncryptClicked(stage, root);
				
			}
		});
        
        Menu DecryptMenu=new Menu("Decrypt/Verify");  
        MenuItem decryptMenuItem1 = new MenuItem("Choose file");
        decryptMenuItem1.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				File fileToDecrypt = ChooseFileToDecryptClicked(stage);
				if (fileToDecrypt != null) {
					try {
						InputStream in = new FileInputStream(fileToDecrypt);
						Decryptor decryptor = new Decryptor(keyRings);
						try {
							decryptor.decryptOrVerifyFile(in, fileToDecrypt.getPath(), stage);
							root.setCenter(keyTable.openSecretKeysTable(root, stage));
						} catch (Exception e) {
							InfoScreen successScreen = new InfoScreen("Something went wrong.", e.getMessage());
            				successScreen.showAndWait();
							e.printStackTrace();
						}
					} catch (FileNotFoundException e) {
						InfoScreen successScreen = new InfoScreen("Something went wrong.", e.getMessage());
            			successScreen.showAndWait();
						e.printStackTrace();
					}
				}
			}
		});
        
        KeysMenu.getItems().addAll(keysMenu1,keysMenu2);  
        EncryptMenu.getItems().addAll(encryptMenuItem1);
        DecryptMenu.getItems().addAll(decryptMenuItem1);
        
        menubar.getMenus().addAll(KeysMenu,EncryptMenu, DecryptMenu);  
        
        root.setTop(menubar);
        root.setCenter(keyTable.openSecretKeysTable(root, stage));
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
