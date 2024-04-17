import java.io.Serializable;
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
public class User implements Serializable {
    private String userName;
    private String college;
    private String email;
    private boolean verifed;
    private ArrayList<Post> posts;

    public User(String name, String collegeMember, String user_mail) {
        userName = name;
        college = collegeMember;
        email = user_mail;
        posts = new ArrayList<Post>();
        verifed = false;
    }

    public void addPost(Post newPost){
        posts.add(newPost);
    }

    public void resetPassword(){
//RESET PASSWORD USING EMAIL
    }

    public void verifyMail(){
        // ADD EMAIL VERIFICATION
    }

    public String getCollege(){
        return college;
    }

    public String getName(){
        return userName;
    }

    public boolean isVerifed(){
        return verifed;
    }

    public static void main(String[] args) {
        System.out.println("I exist to compile");
    }
}
