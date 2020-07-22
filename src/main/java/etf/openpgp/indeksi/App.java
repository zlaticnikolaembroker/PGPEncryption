package etf.openpgp.indeksi;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;

import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;  
import javafx.event.ActionEvent;
import javafx.event.EventHandler;


public class App extends Application
{
	
	private void ChooseFileToEncryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to encrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		File selectedFile = fileChooser.showOpenDialog(stage);
		if (selectedFile != null) {
			BufferedReader br = null;
			try {
				br = new BufferedReader(new FileReader(selectedFile));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} 
			  
			String st; 
			try {
				while ((st = br.readLine()) != null) 
					System.out.println(st);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void ChooseFileToDecryptClicked(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to decrypt");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.txt"));
		File selectedFile = fileChooser.showOpenDialog(stage);
		if (selectedFile != null) {
			BufferedReader br = null;
			try {
				br = new BufferedReader(new FileReader(selectedFile));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} 
			  
			String st; 
			try {
				while ((st = br.readLine()) != null) 
					System.out.println(st);
			} catch (IOException e) {
				e.printStackTrace();
			} 
			  
		}
	}
	
	private void ChooseFileForKeyPairImporting(Stage stage) {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Open file to import key pair");
		
		fileChooser.getExtensionFilters().addAll(
		         new ExtensionFilter("Text Files", "*.asc"));
		File selectedFile = fileChooser.showOpenDialog(stage);
		if (selectedFile != null) {
			BufferedReader br = null;
			try {
				br = new BufferedReader(new FileReader(selectedFile));
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} 
			  
			String st; 
			try {
				while ((st = br.readLine()) != null) 
					System.out.println(st);
			} catch (IOException e) {
				e.printStackTrace();
			} 
			  
		}
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
	
	private void GenerateNewKeyPair() {
		
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
				GenerateNewKeyPair();
			}
		});
        
        MenuItem keysMenu2=new MenuItem("Import key pair");
        keysMenu2.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				ChooseFileForKeyPairImporting(stage);
			}
        });
        
        final String sampleText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut \n"
                + "labore et dolore magna aliqua.\n"
                + "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.\n"
                + "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.\n"
                + "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
        
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
        
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
