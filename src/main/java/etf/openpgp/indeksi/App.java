package etf.openpgp.indeksi;

import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.BorderPane;  
import javafx.stage.Stage;  


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
        Menu FileMenu = new Menu("File");  
        MenuItem filemenu1=new MenuItem("new");  
        MenuItem filemenu2=new MenuItem("Save");  
        MenuItem filemenu3=new MenuItem("Exit");  
        Menu EditMenu=new Menu("Edit");  
        MenuItem EditMenu1=new MenuItem("Cut");  
        MenuItem EditMenu2=new MenuItem("Copy");  
        MenuItem EditMenu3=new MenuItem("Paste");  
        EditMenu.getItems().addAll(EditMenu1,EditMenu2,EditMenu3);  
        root.setTop(menubar);  
        FileMenu.getItems().addAll(filemenu1,filemenu2,filemenu3);  
        menubar.getMenus().addAll(FileMenu,EditMenu);  
        stage.setScene(scene);  
        stage.show();  
    }

    public static void app() {
        launch();
    }
}
