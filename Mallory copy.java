package main;

import java.io.*;
import java.net.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Mallory needs to have 2 ports, one to recieve messages from alice (like bob's code)
 * and one to send messages to Bob (like Alice's code)
 *
 */
public class Mallory {
    private boolean mac;
    private boolean enc;
    private boolean mkey;
    private PublicKey alice_key;
    private PublicKey bob_key;
    private PublicKey alice_mackey;
    private PublicKey bob_mackey;
    private SecretKey secretKey;

    public Mallory(String alicePort, String bobPort, String config)
            throws Exception {

        // Apply configuration
        if (config.compareTo("noCrypto") == 0) {
            mac = false;
            enc = false;
        } else if (config.compareTo("enc") == 0) {
            mac = false;
            enc = true;
        } else if (config.compareTo("mac") == 0) {
            mac = true;
            enc = false;
        } else if (config.compareTo("EncThenMac") == 0) {
            mac = true;
            enc = true;
        }
        alice_key = Gen.readPKCS8PublicKey(new File("a_public.pem"));
        bob_key = Gen.readPKCS8PublicKey(new File("b_public.pem"));
        alice_mackey = Gen.readPKCS8PublicKey(new File("a_macpublic.pem"));
        bob_mackey = Gen.readPKCS8PublicKey(new File("b_macpublic.pem"));

        Scanner console = new Scanner(System.in);
        // obtain Bob's port number and connect to it
        int serverPort = Integer.parseInt(bobPort);
        String serverAddress = "localhost";
        int portNumber = Integer.parseInt(alicePort);

        try {
            System.out.println("Connecting to port " + portNumber + "...");
            ServerSocket mServer = new ServerSocket(portNumber);
            System.out.println("Mallory Server started at port " + portNumber);

            // accept the client(a.k.a. Alice)
            Socket clientSocket = mServer.accept();
            System.out.println("Client connected");
            DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));

            // Receiving stuff from User to send to Bob
            System.out.println("Connecting to Server at (" + bobPort + ", " + serverAddress + ")...");
            Socket serverSocket = new Socket(serverAddress, serverPort);
            System.out.println("Connected to Server");

            DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());

            boolean finished = false;
            // read input from Alice
            String incomingMsg = "";
            String userLine = "";
            boolean first = true;
            while (!finished) {
                try {

                    incomingMsg = streamIn.readUTF();
                    if (first) {
                        if (enc && !mac) {
                            System.out.println(
                                    "Would you like to replace the keyagreement with your own key for bob? (y/n): ");
                            mkey = console.nextLine().equals("y");
                            if (mkey) {
                                streamOut.writeUTF(keyAgreement());
                                streamOut.flush();
                            } else {
                                // automatically forwards key aggreement
                                streamOut.writeUTF(incomingMsg);
                                streamOut.flush();
                            }

                        } else {
                            // automatically forwards key aggreement
                            streamOut.writeUTF(incomingMsg);
                            streamOut.flush();
                        }

                    } else {
                        if (mac) {
                            if (enc) {
                                System.out.println("Encrypted Signed Message (cipher, GCM IV, tag): " + incomingMsg);
                            }
                            System.out.println("Signed msg (message, signature):" + incomingMsg);
                        } else if (enc) {
                            System.out.println("Encrypted  Message (cipher, GCM IV): " + incomingMsg);
                        } else {
                            System.out.println("Recieved msg: " + incomingMsg);
                        }
                    }

                    // Alice says done
                    if (incomingMsg.split(",")[0].equals("done")) {
                        System.out.println("Alice has typed done and will stop sending messages");
                        finished = true;
                    }

                    // USER INPUT
                    if (!first) {
                        String packagedMsg;
                        System.out.print(
                                "Choose Actions: 1 to forward message unchanged to Bob \n 2 to enter new message \n3 to delete message \n done to exit program\n");
                        userLine = console.nextLine();
                        if (userLine.equals("1")) {
                            packagedMsg = incomingMsg;
                            streamOut.writeUTF(packagedMsg);
                            streamOut.flush();
                            System.out.println("Message sent");

                        } else if (userLine.equals("2")) {
                            System.out.println("Enter new message: ");
                            userLine = console.nextLine();
                            packagedMsg = packageMessage(userLine);
                            streamOut.writeUTF(packagedMsg);
                            streamOut.flush();
                            System.out.println("Message sent");

                        } else if (userLine.equals("3")) {
                            System.out.println("Message deleted- Not Sent to Bob");
                        } else if (userLine.equals("done")) {
                            finished = true;
                        } else {
                            System.out.println("Invalid Option " + userLine + " entered; Message deleted");
                        }

                        // Mallory says done
                        finished = userLine.equals("done") || finished;
                    } else {
                        first = false;
                    }

                } catch (IOException ioe) {
                    // disconnect if there is an error reading the input
                    finished = true;
                }
            }

            // close all the sockets and console
            console.close();
            streamOut.close();
            serverSocket.close();
            mServer.close();
            streamIn.close();
            System.out.println("Mallory closed");
        } catch (IOException e) {
            // print error
            System.out.println("Connection failed due to following reason");
            System.out.println(e);
        }

    }

    private String keyAgreement() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, SignatureException {
        StringBuilder acc = new StringBuilder();

        acc.append("Bob,");

        acc.append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        acc.append(",");

        KeyGenerator factory = KeyGenerator.getInstance("AES");
        secretKey = factory.generateKey();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, bob_key);

        String cipherTxt = "Alice,";

        cipherTxt += Gen.encodeHexString(secretKey.getEncoded());

        String encr_cipher = Gen.encodeHexString(cipher.doFinal(cipherTxt.getBytes()));

        acc.append(encr_cipher);

        return acc.toString();

    }

    /**
     * args[0] ; port that Alice will connect to (Mallory's port)
     * args[1] ; port that bob will listen to
     * args[2] ; program configuration
     */
    public static void main(String[] args) {

        // check for correct # of parameters
        if (args.length != 3) {
            System.out.println("Incorrect number of parameters");
        } else {
            // Security.addProvider(new
            // org.bouncycastle.jce.provider.BouncyCastleProvider());

            // create Alice to start communication
            try {
                Mallory mallory = new Mallory(args[0], args[1], args[2]);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    private String packageMessage(String message) throws Exception {
        StringBuilder acc = new StringBuilder();
        if (mkey) {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            GCMParameterSpec spec = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);

            acc.append(Gen.encodeHexString(cipher.doFinal(message.getBytes())));
            acc.append(",");
            acc.append(Gen.encodeHexString(spec.getIV()));

        } else {
            acc.append(message);
        }

        return acc.toString();
    }

}
