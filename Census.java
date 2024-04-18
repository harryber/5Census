import java.util.HashMap;
import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;


public class Census {
    private HashMap<String, Board> boards;
    private HashMap<String, User> users;
    private User currentUser;
    private Board currentBoard;

    public Census(String boardFile, String userFile) throws IOException, ClassNotFoundException {
        loadBoards(boardFile);
        loadUsers(userFile);
    }

    public void setCurrentUser(String userName){
        User newUser = users.get(userName);
        if(newUser != null){
            currentUser = newUser;
        }
    }

    public void switchBoard(String boardName){
        Board newSelected = boards.get(boardName);
        if(newSelected!= null){
            if(newSelected.getCollege().equals(currentUser.getSchoolAffiliation())){
                currentBoard = newSelected;
            }
            else{
                //Not authroized for this board
            }
        }
        else{
            //this board does not exist 
        }
    }



    private void loadBoards(String boardFile) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(boardFile);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        HashMap<String, Board> blist = (HashMap<String, Board>) objectInputStream.readObject();
        this.boards = blist;
        objectInputStream.close();
    }

    private void loadUsers(String userFile) throws IOException, ClassNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(userFile);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        HashMap<String, User> ulist = (HashMap<String, User>) objectInputStream.readObject();
        this.users = ulist;
        objectInputStream.close();
    }

    public void saveBoards(String filename) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(this.boards);
        objectOutputStream.flush();
        objectOutputStream.close();
    }

    public void saveUsers(String filename) throws IOException, ClassNotFoundException  {
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(this.users);
        objectOutputStream.flush();
        objectOutputStream.close();
    }


    public static void main(String[] args) {
        System.out.println("I exist to compile.");
    }
}
