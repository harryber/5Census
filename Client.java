
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

	// instance variables
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private PublicKey publicMacKey;
	private PrivateKey privateMacKey;
	private PublicKey bobKey;
	private PublicKey bobMacKey;
	private SecretKey secretKey;
	private Scanner console;

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public enum UserAction {
		LOGOUT, VIEW, SUBMIT, DELETE, EDIT
	}

	public Client(String serverPortStr)
			throws Exception {

		publicKey = Gen.readPKCS8PublicKey(new File("a_public.pem"));
		privateKey = Gen.readPKCS8PrivateKey(new File("a_private.pem"));
		bobKey = Gen.readPKCS8PublicKey(new File("b_public.pem"));
		publicMacKey = Gen.readPKCS8PublicKey(new File("a_macpublic.pem"));
		privateMacKey = Gen.readPKCS8PrivateKey(new File("a_macprivate.pem"));
		bobMacKey = Gen.readPKCS8PublicKey(new File("b_macpublic.pem"));

		console = new Scanner(System.in);
		System.out.println("This is Alice");

		// obtain server's port number and connect to it
		int serverPort = Integer.parseInt(serverPortStr);
		String serverAddress = "localhost";

		try {
			System.out.println("Connecting to Server at (" + serverPort + ", " + serverAddress + ")...");
			Socket serverSocket = new Socket(serverAddress, serverPort);
			System.out.println("Connected to Server");

			DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());
			DataInputStream streamIn = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
			streamOut.writeUTF(keyAgreement());
			streamOut.flush();

			// obtain the message from the user and send it to Server
			// the communication ends when the user inputs "done"
			String line = "";
			String messageToSend = "";
			String packagedMsg = "";
			boolean keepLooping = true;
			while (keepLooping) {
				try {
					System.out.print("\nWhat would you like to do? \n logout \n exit \n view board \n post message\n\n");
					line = console.nextLine();

					switch (line) {
						case "logout":
							System.out.println("HAH you thought you could escape?");
							break;
						case "exit":
							keepLooping = false;
							break;
						case "view board":
							// select a board to look at
							boardSelectClient(streamIn, streamOut);

							// ask server to display a board
							packagedMsg = packageMessage("<display board>");
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();
	
							// print the server's response
							String incomingMsg = decryptMessage(streamIn.readUTF());
							System.out.println(incomingMsg);
							break;
						case "post message":
							boardSelectClient(streamIn, streamOut);						
							
							messageToSend = "<post to board>";
							streamOut.writeUTF(packageMessage(messageToSend));
							System.out.println("What message would you like to post?\n");
							messageToSend = console.nextLine();
							packagedMsg = packageMessage(messageToSend);
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();
							// System.out.println("Message sent");
							break;
						default:
							System.out.println("Invalid action");
							break;
					}

					

				} catch (IOException ioe) {
					System.out.println("Sending error: " + ioe.getMessage());
				}
			}

			// close all the sockets and console
			console.close();
			streamOut.close();
			serverSocket.close();

		} catch (IOException e) {
			// print error
			System.out.println("Connection failed due to following reason");
			System.out.println(e);
		}
	}

	private Integer boardSelectClient(DataInputStream streamIn, DataOutputStream streamOut) throws Exception {
		try {
			// send a request to see the board options
			streamOut.writeUTF(packageMessage("<boards request>"));
			String incomingMsg = decryptMessage(streamIn.readUTF());
			System.out.println("Select a board:\n" + incomingMsg + "\n");
			
			// pick a board
			int selection = Integer.parseInt(console.nextLine());
			streamOut.writeUTF(packageMessage(String.valueOf(selection)));
			return selection;
		}
		catch (IOException ioe) {
			System.out.println("Could not get boards to select: " + ioe.getMessage());
			return -1;
		}

	}

	private String packageMessage(String message) throws Exception {
		StringBuilder acc = new StringBuilder();

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		GCMParameterSpec spec = cipher.getParameters().getParameterSpec(GCMParameterSpec.class);

		acc.append(Gen.encodeHexString(cipher.doFinal(message.getBytes())));
		acc.append(",");
		acc.append(Gen.encodeHexString(spec.getIV()));

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateMacKey); // signs with alice's private key
		sign.update(acc.toString().getBytes());
		acc.append(",");
		acc.append(Gen.encodeHexString(sign.sign()));

		return acc.toString();
	}

	public String decryptMessage(String message)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		String[] tokens = message.split(",");
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec params = new GCMParameterSpec(128, Gen.decodeHexString(tokens[1]));

		cipher.init(Cipher.DECRYPT_MODE, secretKey, params);

		return new String(cipher.doFinal(Gen.decodeHexString(tokens[0])));
	}

	private String keyAgreement() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {
		StringBuilder acc = new StringBuilder();

		acc.append("Bob,");

		acc.append(LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
		acc.append(",");

		KeyGenerator factory = KeyGenerator.getInstance("AES");
		factory.init(256);
		secretKey = factory.generateKey();

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, bobKey);

		String cipherTxt = "Alice,";

		cipherTxt += Gen.encodeHexString(secretKey.getEncoded());

		String encr_cipher = Gen.encodeHexString(cipher.doFinal(cipherTxt.getBytes()));

		acc.append(encr_cipher);

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateMacKey); // signs with alice's private key

		sign.update(acc.toString().getBytes());
		// acc.append(",");
		byte[] signed = sign.sign();

		acc.append(",");
		acc.append(Gen.encodeHexString(signed));

		return acc.toString();

	}

	/**
	 * args[0] ; port that Alice will connect to (Mallory's port)
	 * args[1] ; program configuration
	 */
	public static void main(String[] args) {

		// check for correct # of parameters
		if (args.length != 1) {
			System.out.println("Incorrect number of parameters");
		} else {
			// Security.addProvider(new
			// org.bouncycastle.jce.provider.BouncyCastleProvider());

			// create Alice to start communication
			try {
				Client alice = new Client(args[0]);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}
}
