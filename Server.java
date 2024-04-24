
import com.mongodb.client.model.Filters;
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
import java.util.List;

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

	public ArrayList<Board> boardArr = loadBoards();
	public Board selectedBoard;
	public HashMap<String, User> users;
	public User currentUser;

	private static final String DB_NAME = "database";
	private static final String COLLECTION_NAME = "users";
	private static final String BOARDS_NAME = "users";

	private MongoCollection<Document> collection;

	public Server(String bobPort, MongoCollection<Document> collection, ArrayList<Board> boardArr) throws Exception {

		publicKey = Gen.readPKCS8PublicKey(new File("b_public.pem"));
		privateKey = Gen.readPKCS8PrivateKey(new File("b_private.pem"));
		aliceKey = Gen.readPKCS8PublicKey(new File("a_public.pem"));

		publicMacKey = Gen.readPKCS8PublicKey(new File("b_macpublic.pem"));
		privateMacKey = Gen.readPKCS8PrivateKey(new File("b_macprivate.pem"));
		aliceMacKey = Gen.readPKCS8PublicKey(new File("a_macpublic.pem"));

		this.collection = collection;


		// notify the identity of the server to the user
//		System.out.println("This is Bob");

		// attempt to create a server with the given port number
		int portNumber = Integer.parseInt(bobPort);
		try {
			System.out.println("Connecting to port: " + portNumber + "...");
			serverSocket = new ServerSocket(portNumber);
			serverSocket.setReuseAddress(true);
//			System.out.println("Bob Server started at port " + portNumber);
			System.out.println("Connected to port: " + portNumber);

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
//				System.out.println("Client connected");

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
				String signInOrRegister = decryptMessage(streamIn.readUTF());

				// Attempt to authenticate user
				if (!signInOrRegister.equals("1")) {
					String credentials = signInOrRegister;

					String[] parts = credentials.split("\\s+");
					if (parts.length != 2) {
						streamOut.writeUTF("failure");
						streamOut.flush();
						continue;
					}
					String username = parts[0];
					String password = parts[1];
					Document query = new Document("username", username);
					Document user = collection.find(query).first();
					if (user != null) {
						String hashedPassword = user.getString("password");


						// Check if the entered password matches the stored hashed password
						if (BCrypt.checkpw(password, hashedPassword)) {
							System.out.println("User logged in successfully");
							streamOut.writeUTF(packageMessage("success"));
							streamOut.flush();

							// Send the user their school affiliation
							String schoolAffiliation = user.getString("schoolAffiliation");
							streamOut.writeUTF(packageMessage(schoolAffiliation));
							streamOut.flush();
							System.out.println("affiliation sent");

							break;
						}
					}
					System.out.println("User not found or invalid credentials.");
					// TODO: better handling if user exists, "forgot password" option
					streamOut.writeUTF(packageMessage("failure"));
					streamOut.flush();
				} else { // add new user to db
					String newUserCredentials = decryptMessage(streamIn.readUTF());
					String[] parts = newUserCredentials.split("\\s+");
					String username = parts[0];
					String password = parts[1];

					// check if username is taken
					Document existingUser = collection.find(new Document("username", username)).first();
					if (existingUser != null) {
						streamOut.writeUTF(packageMessage("failure"));
						streamOut.flush();

					} else {
						String schoolAffiliation = decryptMessage(streamIn.readUTF());
						String salt = BCrypt.gensalt();
						String hashedPassword = BCrypt.hashpw(password, salt);

							Document user = new Document("username", username).append("password", hashedPassword)
								.append("salt", salt).append("schoolAffiliation", schoolAffiliation);
						collection.insertOne(user);
						System.out.println("New account created");
						streamOut.writeUTF(packageMessage("success"));
						streamOut.flush();
						break;
					}
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
						postToBoard(selectedBoard.getName(), newPost);
//						saveBoard(selectedBoard);
//						saveBoards("boards.txt");
					} else {
						System.out.println("Signature Verification Failed");
						// finished = true;
					}

					break;
				case "<boards request>":
					// how to get the current user?

					String username = streamIn.readUTF();
					System.out.println("The username is " + username);
					User user = createUserObjectFromName(username);
					selectedBoard = boardSelectServer(boardArr, user, streamIn, streamOut);
					break;
				case "<display board>":
					if (checkForErrorBoardSelection(selectedBoard, streamOut,
							"Error displaying board, selected board invalid."))
						break;
					String boardContents = selectedBoard.viewPublicPosts();
					ArrayList<Post> posts = getPublicPosts(selectedBoard.getName());
//					streamOut.writeUTF(packageMessage(boardContents));

					streamOut.writeUTF(packageMessage(posts.toString()));
					streamOut.flush();
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

	private boolean checkForBoardAuthorization(Board selectedBoard, DataOutputStream streamOut, String message)
			throws IOException, Exception {
		// Do not allow access if user not apart of the board's college
		if (selectedBoard.getCollege().equals("<NULL BOARD>")) {
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
	private Board boardSelectServer(ArrayList<Board> boardArr, User user, DataInputStream streamIn, DataOutputStream streamOut)
			throws Exception {
		System.out.println("Board select server...");
		// Construct the string of boards to send
		StringBuilder messageToSend = new StringBuilder("Select a board:\n");
		for (Board board : boardArr) {
			// indicate to the user whether they have access to the board or not
			System.out.println(board.getName());
			if (board.hasAccess(user)) {
				messageToSend.append(board.getName()).append("\n");
			}
			else {
				messageToSend.append(board.getName()).append(" (locked)\n");
			}

		}

		// Send the boards to the client
		String packagedMsg = packageMessage(messageToSend.toString());
		streamOut.writeUTF(packagedMsg);
		streamOut.flush();


		ArrayList<String> tempCollege = new ArrayList<String>();
		tempCollege.add("<NULL COLLEGE>");
		Board postBoard = new Board("<NULL BOARD>",tempCollege );
//		Board postBoard = new Board("<NULL BOARD>");

		// User inputs a board to select
		String selection = decryptMessage(streamIn.readUTF());
		System.out.println("received a board selection...");
		// Confirm that the selected board actually exists
		for (Board b : boardArr) {
			if (b.getName().equals(selection)) {
				postBoard = b;
			}
		}

		// if the user has access, return true and let the user know
		if (postBoard.hasAccess(user)) {
			streamOut.writeUTF(packageMessage("<good board>"));
			streamOut.flush();
			return postBoard;
		}

		// if the user does not have access, tell the user which school the board belongs to
		String boardAffiliation = packageMessage(postBoard.getCollege().toString());
		streamOut.writeUTF(boardAffiliation);
		streamOut.flush();
		return null;
//		else {
//			messageToSend.append(board.getName()).append(" (locked)\n");
//		}
//
//		// Send that board's school affiliation to check if this is legal to view
//		String boardAffiliation = packageMessage(postBoard.getCollege().toString());
//		streamOut.writeUTF(boardAffiliation);
//		streamOut.flush();


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

	public static Board createBoard(String boardName, ArrayList<String> boardCollege) {
		return new Board(boardName, boardCollege);
	}

	public static void saveBoard(Board board) {
		try (var mongoClient = MongoClients.create("mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")) {
			MongoDatabase database = mongoClient.getDatabase("database");
			MongoCollection<Document> collection = database.getCollection("boards");

			Document existingBoard = collection.find(Filters.eq("name", board.getName())).first();
			if (existingBoard != null) {
				// Board already exists, update it
				Document updateQuery = new Document("$set", new Document()
						.append("college", board.getCollege())
						.append("publicPosts", postsToDocuments(board.getPublicPosts()))
						.append("localPosts", postsToDocuments(board.getLocalPosts())));
				collection.updateOne(Filters.eq("name", board.getName()), updateQuery);
				System.out.println("Board updated: " + board.getName());
			} else {
				// Board doesn't exist, insert it
				Document boardDoc = new Document()
						.append("name", board.getName())
						.append("college", board.getCollege())
						.append("publicPosts", postsToDocuments(board.getPublicPosts()))
						.append("localPosts", postsToDocuments(board.getLocalPosts()));
				collection.insertOne(boardDoc);
				System.out.println("Board saved: " + board.getName());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void postToBoard(String boardName, Post post) {
		try (var mongoClient = MongoClients.create("mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")) {
			MongoDatabase database = mongoClient.getDatabase("database");
			MongoCollection<Document> collection = database.getCollection("boards");

			// Query the board from the database
			Document query = new Document("name", boardName);
			Document boardDoc = collection.find(query).first();

			if (boardDoc != null) {
				// Retrieve existing public posts from the board document
				List<Document> publicPostsDocs = (List<Document>) boardDoc.get("publicPosts");
				ArrayList<Post> publicPosts = new ArrayList<>();
				if (publicPostsDocs != null) {
					// Convert existing public posts documents to Post objects
					for (Document publicPostDoc : publicPostsDocs) {
						String title = publicPostDoc.getString("title");
						String content = publicPostDoc.getString("content");
						publicPosts.add(new Post(title, content));
					}
				}

				// Add the new post to the list of public posts
				publicPosts.add(post);

				// Update the board document with the updated list of public posts
				Document updateQuery = new Document("$set", new Document("publicPosts", postsToDocuments(publicPosts)));
				collection.updateOne(query, updateQuery);
			} else {
				System.out.println("Board not found: " + boardName);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static ArrayList<Post> getPublicPosts(String boardName) {
		ArrayList<Post> publicPosts = new ArrayList<>();
		try (var mongoClient = MongoClients.create("mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")) {
			MongoDatabase database = mongoClient.getDatabase("database");
			MongoCollection<Document> collection = database.getCollection("boards");

			Document query = new Document("name", boardName);
			Document boardDoc = collection.find(query).first();

			if (boardDoc != null) {
				List<Document> publicPostsDocs = (List<Document>) boardDoc.get("publicPosts");
				if (publicPostsDocs != null) {
					for (Document postDoc : publicPostsDocs) {
						String title = postDoc.getString("title");
						String content = postDoc.getString("content");
						publicPosts.add(new Post(title, content));
					}
				} else {
					System.out.println("No public posts found for board: " + boardName);
				}
			} else {
				System.out.println("Board not found: " + boardName);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return publicPosts;
	}

	private static List<Document> postsToDocuments(ArrayList<Post> posts) {
		List<Document> documents = new ArrayList<>();
		for (Post post : posts) {
			Document postDoc = new Document()
					.append("title", "todo")
					.append("content", post.getPostContent());
			documents.add(postDoc);
		}
		return documents;
	}

	private List<Post> documentsToPosts(ArrayList<Document> documents) {
		List<Post> posts = new ArrayList<>();
		for (Document doc : documents) {
			String title = doc.getString("title");
			String content = doc.getString("content");
			Post post = new Post(title, content);
			posts.add(post);
		}
		return posts;
	}

	public static ArrayList<Board> loadBoards() {
		ArrayList<Board> boards = new ArrayList<>();
		try (var mongoClient = MongoClients.create("mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")) {
			MongoDatabase database = mongoClient.getDatabase("database");
			MongoCollection<Document> collection = database.getCollection("boards");

			for (Document doc : collection.find()) {
				String name = doc.getString("name");
				ArrayList<String> schoolAffiliations = new ArrayList<>();
				ArrayList<Post> publicPosts = new ArrayList<>();
				ArrayList<Post> localPosts = new ArrayList<>();

				List<String> collegeDocs = (List<String>)doc.get("college");
				if (collegeDocs != null) {
					for (String school : collegeDocs) {
						schoolAffiliations.add(school.toString());
					}
				}

				List<Document> publicPostsDocs = (List<Document>) doc.get("publicPosts");
				if (publicPostsDocs != null) {
					for (Document postDoc : publicPostsDocs) {
						String title = postDoc.getString("title");
						String content = postDoc.getString("content");
						publicPosts.add(new Post(title, content));
					}
				}

				List<Document> localPostsDocs = (List<Document>) doc.get("localPosts");
				if (localPostsDocs != null) {
					for (Document postDoc : localPostsDocs) {
						String title = postDoc.getString("title");
						String content = postDoc.getString("content");
						localPosts.add(new Post(title, content));
					}
				}


				Board board = new Board(name, schoolAffiliations);
//				System.out.println("BOARD: " + board.getName() + ", schools: " + schoolAffiliations.getFirst());
				board.setPublicPosts(publicPosts);
				board.setLocalPosts(localPosts);
				boards.add(board);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return boards;
	}

    private User createUserObjectFromName(String username) {
		User user = null;

		Document query = new Document("username", username);
		Document userInfo = collection.find(query).first();

		if (userInfo != null) {
			String schoolAffiliation = userInfo.getString("schoolAffiliation");
			// any other info that users need in future will go here...


			user = new User(username, schoolAffiliation);
		}

		return user;
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

//		ArrayList<String> honSchools = new ArrayList<>();
//		honSchools.add("po");
//		honSchools.add("cmc");
//		honSchools.add("pz");
//		honSchools.add("hmc");
//		honSchools.add("sc");
//
//		ArrayList<String> moundSchools = new ArrayList<>();
//		moundSchools.add("pz");
//		Board honnoldBoard = createBoard("honnold library", honSchools);
//		Board moundsBoard = createBoard("mounds", moundSchools);
//		saveBoard(honnoldBoard);
//		saveBoard(moundsBoard);

		ArrayList<Board> boardArr = loadBoards();

//		for (Board board : boardArr) {
//			System.out.println(board.getName());
//		}

		// create Bob
		try {
			Server bob = new Server(args[0], collection, boardArr);
			bob.start();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
}
