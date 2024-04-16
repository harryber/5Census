import java.util.HashMap;

public class Census {
    private HashMap<String, Board> boards;
    private HashMap<String, User> users;
    private User currentUser;
    private Board currentBoard;

    public Census(String boardFile, Path userFile) {
        loadBoards();

    }

    public setCurrentUser(String userName){
        User newUser = users.get(userName);
        if(newUser != null){
            currentUser = newUser;
        }
    }

    public switchBoard(String boardName){
        Board newSelected = board.get(boardName);
        if(newSelected!= null){
            if(newSelected.college.equals(currentUser.college)){
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

    private loadBoards(String boardFile){
        FileInputStream fileInputStream = new FileInputStream(filename);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        @SuppressWarnings("unchecked")
        HashMap<String, Board> blist = (HashMap<String, Board>) objectInputStream.readObject();
        this.boards = blist;
        objectInputStream.close();
    }

    private void saveBoards(String filename) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(filename);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
        objectOutputStream.writeObject(this.boards);
        objectOutputStream.flush();
        objectOutputStream.close();
    }

}
