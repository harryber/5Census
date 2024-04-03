
import org.springframework.security.crypto.bcrypt.BCrypt;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;

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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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

	private ServerSocket serverSocket;

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public ArrayList<Board> boardArr;
	public Board selectedBoard;

	private static final String DB_NAME = "database";
	private static final String COLLECTION_NAME = "users";

    private MongoCollection<Document> collection;

	public Server(String bobPort, MongoCollection<Document> collection, ArrayList<Board> boardArr) throws Exception {

		publicKey = Gen.readPKCS8PublicKey(new File("b_public.pem"));
		privateKey = Gen.readPKCS8PrivateKey(new File("b_private.pem"));
		aliceKey = Gen.readPKCS8PublicKey(new File("a_public.pem"));

		publicMacKey = Gen.readPKCS8PublicKey(new File("b_macpublic.pem"));
		privateMacKey = Gen.readPKCS8PrivateKey(new File("b_macprivate.pem"));
		aliceMacKey = Gen.readPKCS8PublicKey(new File("a_macpublic.pem"));
		readBoardFile("boards.txt");
		this.collection = collection;
		// notify the identity of the server to the user
		System.out.println("This is Bob");

		// attempt to create a server with the given port number
		int portNumber = Integer.parseInt(bobPort);
		try {
			System.out.println("Connecting to port " + portNumber + "...");
			serverSocket = new ServerSocket(portNumber);
			serverSocket.setReuseAddress(true);
			System.out.println("Bob Server started at port " + portNumber);

		} catch (IOException e) {
			// print error if the server fails to create itself
			System.out.println("Error in creating the server");
			System.out.println(e);
		}

		// clean up the connections before closing
		// serverSocket.close();
		// System.out.println("Bob closed");

	}

	public void start() {
		while (true) {
			try {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Client connected");

				ClientHandler clientHandler = new ClientHandler(clientSocket);
				new Thread(clientHandler).start();

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private class ClientHandler implements Runnable {
		private Socket clientSocket;
		private DataInputStream streamIn;
		private DataOutputStream streamOut;

		public ClientHandler(Socket socket) {
			this.clientSocket = socket;
			try {
				streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
				streamOut = new DataOutputStream(clientSocket.getOutputStream());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		@Override
		public void run() {
			boolean finished = false;
			boolean first = true;

			try {
				while (!finished) {
					if (streamIn.available() > 0) {
						String incomingMsg = streamIn.readUTF();
						if (first) {
							finished = !keyAgreement(incomingMsg);
							first = false;
							authenticateUser(streamIn, streamOut);
						} else {
							if (verifyMessage(incomingMsg)) {
								String decryptedMsg = decryptMessage(incomingMsg);
								processMessage(decryptedMsg, streamIn, streamOut);
							} else {
								System.out.println("Signature Verification Failed");
								finished = true;
							}
						}
						finished = incomingMsg.split(",")[0].equals("done") || finished;
					}
				}
			} catch (SocketException e) {
				System.out.println("Client connection closed unexpectedly");
			} catch (IOException | NoSuchAlgorithmException | InvalidKeyException | SignatureException
					| NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
				System.out.println("IO Exception occurred: " + e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw new RuntimeException(e);
			} catch (Exception e) {
				throw new RuntimeException(e);
			} finally {
				// clean up client if connection closed
				try {
					clientSocket.close();
					streamIn.close();
					streamOut.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		private void authenticateUser(DataInputStream streamIn, DataOutputStream streamOut) throws Exception {
			while (true) {
				String messageToSend = "Enter username and password (separated by space), or enter 1 to create an account";
				streamOut.writeUTF(packageMessage(messageToSend));
				streamOut.flush();
				String signInOrRegister = streamIn.readUTF();
				System.out.println(signInOrRegister);
				// Attempt to authenticate user

				if (!signInOrRegister.equals("1")) {
					String credentials = signInOrRegister;
					String[] parts = credentials.split(" ");
					String username = parts[0];
					String password = parts[1];
					Document query = new Document("username", username);
					Document user = collection.find(query).first();
					if (user != null) {
						String hashedPassword = user.getString("password");
						// Check if the entered password matches the stored hashed password
						if (BCrypt.checkpw(password, hashedPassword)) {
							System.out.println("User logged in successfully");
							streamOut.writeUTF("success");
							streamOut.flush();
							break;
						}
					}
					System.out.println("User not found or invalid credentials."); // Better handling needed
					streamOut.writeUTF("failure");
					streamOut.flush();
				} else {
					String newUserCredentials = streamIn.readUTF();
					String[] parts = newUserCredentials.split(" ");
					String username = parts[0];
					String password = parts[1];

					String salt = BCrypt.gensalt();
					String hashedPassword = BCrypt.hashpw(password, salt);

					Document user = new Document("username", username).append("password", hashedPassword).append("salt", salt);
					collection.insertOne(user);
					streamOut.writeUTF("success");
					streamOut.flush();
					break;
				}
			}
		}

		private void processMessage(String decryptedMsg, DataInputStream streamIn, DataOutputStream streamOut)
				throws Exception {

			switch (decryptedMsg) {
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

					String incomingMsg = streamIn.readUTF();
					if (verifyMessage(incomingMsg)) {
						String postContents = decryptMessage(incomingMsg);

						Post newPost = new Post(selectedBoard.getName(), postContents);
						selectedBoard.addPost(newPost);
						System.out.println(selectedBoard.getName() + ": " + selectedBoard.viewPublicPosts());
					} else {
						System.out.println("Signature Verification Failed");
						// finished = true;
					}

					break;
				case "<boards request>":
					// System.out.println(streamIn.readUTF());
					selectedBoard = boardSelectServer(boardArr, streamIn, streamOut);
					break;
				case "<display board>":
					// System.out.println(streamIn.readUTF());
					if (checkForErrorBoardSelection(selectedBoard, streamOut,
							"Error displaying board, selected board invalid."))
						break;
					String boardContents = selectedBoard.viewPublicPosts();
					streamOut.writeUTF(packageMessage(boardContents));
					break;
				default:
					break;
			}
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

		String connectionString = "mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
		MongoClient mongoClient = MongoClients.create(connectionString);
        MongoDatabase database = mongoClient.getDatabase(DB_NAME);
		MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);

		ArrayList<Board> boardArr = new ArrayList<>();


		// create Bob
		try {
			Server bob = new Server(args[0],collection, boardArr);
			bob.start();
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
		this.boardArr = blist;
		objectInputStream.close();
	}

	private void saveBoards(String filename) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(filename);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream);
		objectOutputStream.writeObject(this.boardArr);
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
