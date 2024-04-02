
import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {

	// instance variables
	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;
	private RSAPublicKey publicMacKey;
	private RSAPrivateKey privateMacKey;
	private RSAPublicKey aliceKey;
	private RSAPublicKey aliceMacKey;
	private SecretKey secretKey;
	private ArrayList<Board> boards;

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public Server(String bobPort, ArrayList<Board> boardArr) throws Exception {

		publicKey = Gen.readPKCS8PublicKey(new File("b_public.pem"));
		privateKey = Gen.readPKCS8PrivateKey(new File("b_private.pem"));
		aliceKey = Gen.readPKCS8PublicKey(new File("a_public.pem"));

		publicMacKey = Gen.readPKCS8PublicKey(new File("b_macpublic.pem"));
		privateMacKey = Gen.readPKCS8PrivateKey(new File("b_macprivate.pem"));
		aliceMacKey = Gen.readPKCS8PublicKey(new File("a_macpublic.pem"));

		readBoardFile("boards.txt");

		HashMap<String, String> loginMap = new HashMap<String, String>();
		loginMap.put("Steve", "12345");
		loginMap.put("Alice", "321");
		loginMap.put("Irwin", "password!");

		// notify the identity of the server to the user
		System.out.println("This is Bob");

		// attempt to create a server with the given port number
		int portNumber = Integer.parseInt(bobPort);
		try {
			System.out.println("Connecting to port " + portNumber + "...");
			ServerSocket bobServer = new ServerSocket(portNumber);
			bobServer.setReuseAddress(true);
			System.out.println("Bob Server started at port " + portNumber);

			// accept the client (a.k.a. Alice)
			Socket clientSocket = bobServer.accept();
			System.out.println("Client connected");
			DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
			DataOutputStream streamOut = new DataOutputStream(clientSocket.getOutputStream());
			boolean finished = false;
			boolean first = true;
			boolean user_authenticated = false;
			// read input from Alice
			String messageToSend = "";
			String packagedMsg = "";
			Board selectedBoard = new Board("<NULL BOARD>");
			// Scanner console = new Scanner(System.in);
			while (!finished) {
				try {
					String incomingMsg = streamIn.readUTF();
					if (first) {
						finished = !keyAgreement(incomingMsg);
						first = false;

						while (!user_authenticated) {
							messageToSend = "Enter username and password (separated by space)";
							System.out.println(messageToSend);
							streamOut.writeUTF(packageMessage(messageToSend));
							streamOut.flush();

							String credentials = streamIn.readUTF();
							String[] parts = credentials.split(" ");
							String username = parts[0];
							String password = parts[1];

							if (loginMap.containsKey(username) && loginMap.get(username).equals(password)) {
								user_authenticated = true;
								streamOut.writeUTF("success");
								streamOut.flush();
							} else {
								streamOut.writeUTF("failure");
								streamOut.flush();
							}
						}

					} else {
						if (verifyMessage(incomingMsg)) {

							switch (decryptMessage(incomingMsg)) {
								case "<post to board>":

									if (checkForErrorBoardSelection(selectedBoard, streamOut,
											"Error posting to board, selected board invalid.")) {
										// streamOut.writeUTF("<board select failed>");
										// streamOut.flush();
										break;

										// } else {
										// streamOut.writeUTF("<board select success>");
										// streamOut.flush();
									}

									incomingMsg = streamIn.readUTF();
									if (verifyMessage(incomingMsg)) {
										String postContents = decryptMessage(incomingMsg);

										Post newPost = new Post(selectedBoard.getName(), postContents);
										selectedBoard.addPost(newPost);
										System.out.println(
												selectedBoard.getName() + ": " + selectedBoard.viewPublicPosts());
									} else {
										System.out.println("Signature Verifcation Failed");
										finished = true;
									}

									break;
								case "<boards request>":
									selectedBoard = boardSelectServer(boards, streamIn, streamOut);
									break;
								case "<display board>":
									if (checkForErrorBoardSelection(selectedBoard, streamOut,
											"Error displaying board, selected board invalid."))
										break;
									String boardContents = selectedBoard.viewPublicPosts();
									streamOut.writeUTF(packageMessage(boardContents));
									break;
								default:
									break;
							}

							if (decryptMessage(incomingMsg).equals("SEND ME THE BOARD PLEEEEEASE")) {
								System.out.println("Sending board to client...");
								// messageToSend = console.nextLine();

								packagedMsg = packageMessage(messageToSend);
								streamOut.writeUTF(packagedMsg);
								streamOut.flush();
							}

							System.out.println("Recieved msg: " + decryptMessage(incomingMsg));
						} else {
							System.out.println("Signature Verifcation Failed");
							finished = true;
						}
					}
					finished = incomingMsg.split(",")[0].equals("done") || finished; // possibly need to update
				} catch (IOException ioe) {
					// disconnect if there is an error reading the input
					finished = true;
				}
			}

			// clean up the connections before closing
			saveBoards("boards.txt");
			bobServer.close();
			streamIn.close();
			// console.close();
			System.out.println("Bob closed");
		} catch (IOException e) {
			// print error if the server fails to create itself
			System.out.println("Error in creating the server");
			System.out.println(e);
		}

	}

	private boolean checkForErrorBoardSelection(Board selectedBoard, DataOutputStream streamOut, String message)
			throws IOException, Exception {
		// Do not write to a board if a board is not selected properly
		if (selectedBoard.getName().equals("<NULL BOARD>")) {
			streamOut.writeUTF(packageMessage(message));
			streamOut.flush();
			return true;
		}
		return false;
	}

	/**
	 * Bridge method between server and client in order
	 * to determine which board the client is trying to
	 * interact with
	 * 
	 * @param boardArr  Array of all boards
	 * @param streamIn
	 * @param streamOut
	 * @return
	 * @throws Exception
	 */
	private Board boardSelectServer(ArrayList<Board> boardArr, DataInputStream streamIn, DataOutputStream streamOut)
			throws Exception {
		// Construct the string of boards to send
		String messageToSend = "Select a board:\n";
		for (int i = 0; i < boardArr.size(); i++) {
			messageToSend += i + ": " + boardArr.get(i).getName() + "\n";
		}

		// Send the boards to the client
		String packagedMsg = packageMessage(messageToSend);
		streamOut.writeUTF(packagedMsg);
		streamOut.flush();

		Board postBoard = new Board("<NULL BOARD>");

		// User inputs a board to select
		String selection = decryptMessage(streamIn.readUTF());

		// Confirm that the selected board actually exists

		for (Board b : boardArr) {
			if (b.getName().equals(selection)) {
				postBoard = b;
			}
		}

		return postBoard;
	}

	public boolean verifyMessage(String message)
			throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
		String[] tokens = message.split(",");
		Signature check = Signature.getInstance("SHA256withRSA");
		check.initVerify(aliceMacKey); // will check for Alice's signature

		check.update(message.substring(0, message.lastIndexOf(",")).getBytes());
		return check.verify(Gen.decodeHexString(tokens[tokens.length - 1]));
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

	public boolean keyAgreement(String message)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		String[] tokens = message.split(",");

		if (!tokens[0].equals("Bob")) {
			System.out.println("Message not sent to Bob");
			return false;
		}

		LocalDateTime time = LocalDateTime.parse(tokens[1], DateTimeFormatter.ISO_LOCAL_DATE_TIME);

		if (LocalDateTime.now().isAfter(time.plusMinutes(2))) {
			System.out.println("Old Message");
			return false;
		}

		Signature check = Signature.getInstance("SHA256withRSA");
		check.initVerify(aliceMacKey); // will check for Alice's signature

		check.update(message.substring(0, message.lastIndexOf(",")).getBytes());
		if (!check.verify(Gen.decodeHexString(tokens[3]))) {
			System.out.println("Signature Failed");
			return false;
		}

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		String[] decrypted = new String(cipher.doFinal(Gen.decodeHexString(tokens[2]))).split(",");

		if (!decrypted[0].equals("Alice")) {
			System.out.println("Message not sent from Alice");
			return false;
		}

		secretKey = new SecretKeySpec(Gen.decodeHexString(decrypted[1]), "AES");

		return true;
	}

	/**
	 * args[0] ; port that Alice will connect to
	 * args[1] ; program configuration
	 */
	public static void main(String[] args) {
		// check for correct # of parameters
		if (args.length != 1) {
			System.out.println("Incorrect number of parameters");
			return;
		}

		// Board edmundsBoard = new Board("edmunds");
		// Board fraryBoard = new Board("frary");
		ArrayList<Board> boardArr = new ArrayList<>();
		// boardArr.add(edmundsBoard);
		// boardArr.add(fraryBoard);

		// Security.addProvider(new
		// org.bouncycastle.jce.provider.BouncyCastleProvider());

		// create Bob
		try {
			Server bob = new Server(args[0], boardArr);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void readBoardFile(String filename) throws IOException, ClassNotFoundException {

		FileInputStream fileInputStream = new FileInputStream(filename);
		ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
		@SuppressWarnings("unchecked")
		ArrayList<Board> blist = (ArrayList<Board>) objectInputStream.readObject();
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

}
