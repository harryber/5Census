import java.io.Serializable;

public class User implements Serializable {
    private String user_name;
    private String college;
    private String email;
    private boolean verifed;
    private ArrayList<Post> posts;

    public User(String name, String collegeMember, String user_mail) {
        user_name = name;
        college = collegeMember;
        email = user_mail;
        posts = new ArrayList<Post>();
        verifed = false;
    }

    public addPost(Post newPost){
        posts.add(newPost);
    }

    public resetPassword(){
//RESET PASSWORD USING EMAIL
    }

    public verifyMail(){
        // ADD EMAIL VERIFICATION
    }

    public getCollege(){
        return college;
    }

    public getName(){
        return name;
    }

    public isVerifed(){
        return verifed;
    }
}
