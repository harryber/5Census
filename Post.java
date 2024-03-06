
public class Post {
    private String uid;
    private String u_name;
    private String boardName;
    private boolean user_location;
    private boolean reader_location;
    private String content;

    public Post(String boardName, String content) {
        this.boardName = boardName;
        this.content = content;
        this.user_location = true;
        this.reader_location = true;
    }

    public Post(String id, String user_name, String board_name, boolean u_local, boolean local_vis, String message) {
        uid = id;
        u_name = user_name;
        this.boardName = board_name;
        user_location = u_local;
        reader_location = local_vis;
        content = message;
    }

    public String getPostContent() {
        return content;
    }

    public boolean isPosterLocal() {
        return user_location;

    }

    public boolean isReaderPublic() {
        return reader_location;
    }

    public String toString() {
        String str = "";
        if (user_location) {
            str += "Posted by: " + u_name + " at " + boardName + "\n";
        } else {
            str += "Posted by: " + u_name + " remotely \n";
        }

        str += content;

        return str;
    }
}