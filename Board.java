import java.io.Serializable;
import java.util.ArrayList;

public class Board implements Serializable {
    private String name;
    private ArrayList<String> college;
    private ArrayList<Post> public_posts;
    private ArrayList<Post> local_posts;

    public Board(String board_name, ArrayList<String> board_college) {
        name = board_name;
        college = board_college;
        public_posts = new ArrayList<Post>();
        local_posts = new ArrayList<Post>();
    }

    public void addPost(Post newPost) {
        if (newPost.isReaderPublic()) {
            public_posts.add(newPost);
        } else {
            local_posts.add(newPost);
        }
    }

    public String viewPublicPosts() {
        String str = name + " board posts:" + "\n";
        // for (int i = public_posts.size() - 1; i >= 0; i--) {
        // str += public_posts.get(i);
        // str += "\n";
        // }

        for (int i = 0; i < public_posts.size(); i++) {
            str += public_posts.get(i).getPostContent() + "\n";
        }

        return str;
    }
public boolean hasAccess(User user){
        for (int i =0; i< college.size(); i++){
            if(college.get(i).equals(user.getSchoolAffiliation())){
                return true;
            }
        }
        return false;
}
    public String viewLocalPosts() {
        String str = "Posts on " + name + "\n";
        for (int i = local_posts.size() - 1; i >= 0; i--) {
            str += local_posts.get(i);
            str += "\n";
        }

        return str;
    }
    public ArrayList<Post> getLocalPosts() {
        return local_posts;
    }
    public ArrayList<Post> getPublicPosts() {
        return public_posts;
    }

    public void setLocalPosts(ArrayList<Post> localPosts) {
        this.local_posts = local_posts;
    }
    public void setPublicPosts(ArrayList<Post> publicPosts) {
        this.public_posts = public_posts;
    }
    public String getName() {
        return name;
    }

    public ArrayList<String> getCollege() {
        return college;
    }

    public static void main(String[] args) {
        System.out.println("I exist to compile");
    }

}
