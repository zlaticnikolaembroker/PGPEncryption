package etf.openpgp.indeksi;

import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;  
import javafx.stage.Stage;  
import javafx.event.ActionEvent;
import javafx.event.EventHandler;


/**
 * Hello world!
 *
 */
public class App extends Application
{
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
        Menu DecryptMenu=new Menu("Decrypt");  
        
        root.setTop(menubar);  
        KeysMenu.getItems().addAll(keysMenu1,keysMenu2,keysMenu3);  
        menubar.getMenus().addAll(KeysMenu,EncryptMenu, DecryptMenu);  
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
