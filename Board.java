import java.util.ArrayList;

public class Board {
    private String name;
    private ArrayList<Post> public_posts;
    private ArrayList<Post> local_posts;

    public Board(String board_name) {
        name = board_name;
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
        String str = "Posts on " + name + "\n";
        for (int i = public_posts.size() - 1; i >= 0; i--) {
            str += public_posts.get(i);
            str += "\n";
        }

        return str;
    }

    public String viewLocalPosts() {
        String str = "Posts on " + name + "\n";
        for (int i = local_posts.size() - 1; i >= 0; i--) {
            str += local_posts.get(i);
            str += "\n";
        }

        return str;
    }

}
