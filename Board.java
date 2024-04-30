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
        StringBuilder str = new StringBuilder(name + " board posts:" + "\n");
        // for (int i = public_posts.size() - 1; i >= 0; i--) {
        // str += public_posts.get(i);
        // str += "\n";
        // }

        for (Post publicPost : public_posts) {
            String postStr = publicPost.getUserName() + ": " + publicPost.getPostContent() + "\n";
            str.append(postStr);
        }

        return str.toString();
    }
    public boolean hasAccess(User user){
        for (String c : college) {
            if (c.equals(user.getSchoolAffiliation())) {
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

    public void setLocalPosts(ArrayList<Post> localP) {
        local_posts = localP;
    }
    public void setPublicPosts(ArrayList<Post> publicP) {
        public_posts = publicP;
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
