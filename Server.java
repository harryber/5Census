
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
import com.mongodb.client.result.UpdateResult;
import org.bson.conversions.Bson;
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
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.security.KeyStore;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;


public class Server {

	// instance variables

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public ArrayList<Board> boardArr = loadBoards();
	public Board selectedBoard;
	public HashMap<String, User> users;
	public String currentUserName;

	private static final String DB_NAME = "database";
	private static final String COLLECTION_NAME = "users";
	private static final String BOARDS_NAME = "users";

	private MongoCollection<Document> collection;

	private static final String[] protocols = new String[]{"TLSv1.3"};

	private static final String[] cipher_suites = new String[]{"TLS_AES_256_GCM_SHA384"};
	private static final String KEYSTORE_PATH = "server-keystore.jks";
	private static final String KEYSTORE_PASS = "Keystore1!";



	public SSLServerSocket serverSocket;

	public Server(String bobPort, MongoCollection<Document> collection, ArrayList<Board> boardArr) throws Exception {

		this.collection = collection;


		// notify the identity of the server to the user
		System.out.println("This is Bob");

		// attempt to create a server with the given port number
		int portNumber = Integer.parseInt(bobPort);
		try {
			System.out.println("Connecting to port " + portNumber + "...");

			KeyStore keyStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(KEYSTORE_PATH);
			keyStore.load(fis, KEYSTORE_PASS.toCharArray());
			KeyStore trustStore = KeyStore.getInstance("JKS");
			trustStore.load(new FileInputStream("server-truststore.jks"), "Keystore1!".toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(trustStore);


			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(keyStore, KEYSTORE_PASS.toCharArray());


			SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
			serverSocket = (SSLServerSocket) factory.createServerSocket(1010);

			serverSocket.setEnabledProtocols(protocols);
			serverSocket.setEnabledCipherSuites(cipher_suites);
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
				System.out.println("Attempting to establish new client connection");
//				serverSocket.setSoTimeout(5000); 5 second timeout
				SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
				System.out.println("Client connected");

				BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				String line;
				while ((line = reader.readLine()) != null) {
					System.out.println("Received from client: " + line);
					break;
				}

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
				System.out.println("streamIn created");
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
					if (first) {
						System.out.println("Attempting to verify user");
						authenticateUser(streamIn, streamOut);
						first = false;
					}
//					System.out.println(streamIn.available());
					String incomingMsg = streamIn.readUTF();
					processMessage(incomingMsg, streamIn, streamOut);
					finished = incomingMsg.split(",")[0].equals("done") || finished;
//					if (streamIn.available() > 0) {
//						String incomingMsg = streamIn.readUTF();
//						processMessage(incomingMsg, streamIn, streamOut);
//						finished = incomingMsg.split(",")[0].equals("done") || finished;
//					}
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
				String messageToSend =
						"┌────────────────────────────────────────────────────┐\n" +
						"│ Please choose an option:                           │\n" +
						"│                                                    │\n" +
						"│ • Enter username and password (separated by space) │\n" +
						"│ • Enter 1 to create an account                     │\n" +
						"│ • Enter 2 to recover password                      │\n" +
						"└────────────────────────────────────────────────────┘";

				streamOut.writeUTF(messageToSend);
				streamOut.flush();
				String signInOrRegister = streamIn.readUTF();

				// create a new user in db
				if (signInOrRegister.equals("1")) {
					String newUserCredentials = streamIn.readUTF();
					String[] parts = newUserCredentials.split("\\s+");
					String username = parts[0];
					String password = parts[1];

					// check if username is taken
					Document existingUser = collection.find(new Document("username", username)).first();
					if (existingUser != null) {
						streamOut.writeUTF("failure");
						streamOut.flush();

					} else {

						// programming password recovery
						streamOut.writeUTF("Enter a recovery question for your account:");
						streamOut.flush();
						String question = streamIn.readUTF();
						System.out.println("question: " + question);
						String answer = streamIn.readUTF();
						System.out.println("answer: " + answer);
						System.out.println("Question: " + question + ", answer: " + answer);
						String schoolAffiliation = streamIn.readUTF();
						String salt = BCrypt.gensalt();
						String hashedPassword = BCrypt.hashpw(password, salt);

						Document user = new Document("username", username)
								.append("password", hashedPassword)
								.append("salt", salt)
								.append("schoolAffiliation", schoolAffiliation)
								.append("question", question)
								.append("answer", answer);

						collection.insertOne(user);
						System.out.println("New account created");
						streamOut.writeUTF("<success>");
						streamOut.flush();
						break;

					}
				}
				else if (signInOrRegister.equals("2")) {
					String username = streamIn.readUTF();
					Document query = new Document("username", username);
					Document user = collection.find(query).first();

					if (user != null) {
						String question = user.getString("question");
						streamOut.writeUTF(question);
						streamOut.flush();

						String providedAnswer = streamIn.readUTF();

						System.out.println("Provided answer: " + providedAnswer + ", answer: " + user.getString("answer"));
						if (providedAnswer.equals(user.getString("answer"))) {
							streamOut.writeUTF("<success>");
							streamOut.flush();
							System.out.println("About to reset password.");

							String newPassword = streamIn.readUTF();

							String salt = BCrypt.gensalt();
							String hashedPassword = BCrypt.hashpw(newPassword, salt);

							Bson update = Updates.set("password", hashedPassword);
							UpdateResult result = collection.updateOne(user, update);
							streamOut.writeUTF("<success>");
							streamOut.flush();

							String schoolAffiliation = user.getString("schoolAffiliation");
							streamOut.writeUTF(schoolAffiliation);
							streamOut.flush();
							break;
						}
					}
					System.out.println("Recovery failed.");
					// TODO: better handling if user exists, "forgot password" option
					streamOut.writeUTF("<failure>");
					streamOut.flush();

				} else { // verify login
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
							streamOut.writeUTF("<success>");
							streamOut.flush();

							// Send the user their school affiliation
							String schoolAffiliation = user.getString("schoolAffiliation");
							streamOut.writeUTF(schoolAffiliation);
							streamOut.flush();
							System.out.println("affiliation sent");

							break;
						}
					}
					System.out.println("User not found or invalid credentials.");
					// TODO: better handling if user exists, "forgot password" option
					streamOut.writeUTF("failure");
					streamOut.flush();

				}
			}
		}

		private void processMessage(String decryptedMsg, DataInputStream streamIn, DataOutputStream streamOut)
				throws Exception {
			System.out.println("Processing client message");
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

					String postContents = streamIn.readUTF();

//					Post newPost = new Post(selectedBoard.getName(), postContents);
//					selectedBoard.addPost(newPost);
//					System.out.println(selectedBoard.getName() + ": " + selectedBoard.viewPublicPosts());
//					postToBoard(selectedBoard.getName(), newPost);


					Post newPost = new Post(currentUserName, selectedBoard.getName(), postContents);
					selectedBoard.addPost(newPost);
					System.out.println(selectedBoard.getName() + ": " + selectedBoard.viewPublicPosts());
					postToBoard(selectedBoard.getName(), newPost);
//					saveBoard(selectedBoard);
//					saveBoards("boards.txt");
				

					break;
				case "<boards request>":
					currentUserName = streamIn.readUTF();
					System.out.println("The username is " + currentUserName);
					User user = createUserObjectFromName(currentUserName);
					selectedBoard = boardSelectServer(user, streamIn, streamOut);
					break;
				case "<display board>":
					// System.out.println(streamIn.readUTF());
					if (checkForErrorBoardSelection(selectedBoard, streamOut,
							"Error displaying board, selected board invalid."))
						break;
					String boardContents = selectedBoard.viewPublicPosts();
					ArrayList<Post> posts = getPublicPosts(selectedBoard.getName());
					System.out.println(posts.toString());
					selectedBoard.setPublicPosts(posts);
					System.out.println(selectedBoard.getPublicPosts().toString());
//					streamOut.writeUTF(packageMessage(boardContents));

//					selectedBoard.setPublicPosts(getPublicPosts(selectedBoard.getName()));
					streamOut.writeUTF(selectedBoard.viewPublicPosts());
					streamOut.flush();
					break;
				case "<create board>":
					String boardName = streamIn.readUTF();
					System.out.println("The board name is " + boardName);
					// make sure a board of this name doesn't already exist
					if (checkForBoardExistence(boardName)) {
						streamOut.writeUTF("<halt>");
						streamOut.flush();
					}
					else {
						streamOut.writeUTF("<continue>");
						streamOut.flush();
					}

					String schoolAffiliationString = streamIn.readUTF();
					System.out.println("School affiliations: " + schoolAffiliationString);
					// school string parser
					ArrayList<String> schoolAffiliations = createSchoolArrFromStr(schoolAffiliationString);
					if (schoolAffiliations == null) break;

					Board newBoard = createBoard(boardName, schoolAffiliations);
					saveBoard(newBoard);

				default:
					break;
			}
		}
	}

	private ArrayList<String> createSchoolArrFromStr(String schoolAffiliationString) {
		String[] schoolsStrArr = schoolAffiliationString.split("\\s+");
		ArrayList<String> schoolsArr = new ArrayList<>();
		for (String school : schoolsStrArr) {
			school = school.toLowerCase();
			if (school.equals("po") || school.equals("hmc") || school.equals("cmc") ||
					school.equals("pz") || school.equals("sc")) {
				schoolsArr.add(school);
			}
			else {
				return null;
			}
		}
		return schoolsArr;
	}

	private boolean checkForBoardExistence(String boardName) {
		try (var mongoClient = MongoClients.create("mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")) {
			MongoDatabase database = mongoClient.getDatabase("database");
			MongoCollection<Document> collection = database.getCollection("boards");

			Document query = new Document("name", boardName);
			Document boardDoc = collection.find(query).first();
			System.out.println(boardDoc != null);
			return boardDoc != null;
		}
	 	catch (Exception e) {
			e.printStackTrace();
			return true;
		}

	}

	private boolean checkForErrorBoardSelection(Board selectedBoard, DataOutputStream streamOut, String message)
			throws IOException, Exception {
		// Do not write to a board if a board is not selected properly
		if (selectedBoard.getName().equals("<NULL BOARD>")) {
			streamOut.writeUTF(message);
			streamOut.flush();
			return true;
		}
		return false;
	}

	private boolean checkForBoardAuthorization(Board selectedBoard, DataOutputStream streamOut, String message)
			throws IOException, Exception {
		// Do not allow access if user not apart of the board's college
		if (selectedBoard.getCollege().equals("<NULL BOARD>")) {
			streamOut.writeUTF(message);
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
	 * @param streamIn
	 * @param streamOut
	 * @return
	 * @throws Exception
	 */
	private Board boardSelectServer(User user, DataInputStream streamIn, DataOutputStream streamOut)
			throws Exception {
		System.out.println("Board select server...");
		boardArr = loadBoards();
		// Construct the string of boards to send
		StringBuilder messageToSend = new StringBuilder("Select a board:\n");
		for (Board board : boardArr) {
			// indicate to the user whether they have access to the board or not
			System.out.println(board.getName());
			if (board.hasAccess(user)) {
				messageToSend.append(" -").append(board.getName()).append("\n");
			}
			else {
				messageToSend.append(" -").append(board.getName()).append(" (locked)\n");
			}

		}

		// Send the boards to the client
		streamOut.writeUTF(String.valueOf(messageToSend));
		streamOut.flush();


		ArrayList<String> tempCollege = new ArrayList<String>();
		tempCollege.add("<NULL COLLEGE>");
		Board postBoard = new Board("<NULL BOARD>",tempCollege );
//		Board postBoard = new Board("<NULL BOARD>");

		// User inputs a board to select
		String selection = streamIn.readUTF();
		System.out.println("received a board selection...");
		// Confirm that the selected board actually exists
		for (Board b : boardArr) {
			if (b.getName().equals(selection)) {
				postBoard = b;
			}
		}

        if (postBoard.hasAccess(user)) {
            streamOut.writeUTF("<good board>");
            streamOut.flush();
            return postBoard;
        }

        // if the user does not have access, tell the user which school the board belongs to
        String boardAffiliation = postBoard.getCollege().toString();
        streamOut.writeUTF(boardAffiliation);
        streamOut.flush();
        return null;
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
						String postUser = publicPostDoc.getString("postUser");
						String content = publicPostDoc.getString("content");
						publicPosts.add(new Post(postUser, boardName, content));
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
						String postUser = postDoc.getString("postUser");
						String content = postDoc.getString("content");
						publicPosts.add(new Post(postUser, boardName, content));
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
					.append("postUser", post.getUserName())
					.append("content", post.getPostContent());
			documents.add(postDoc);
		}
		return documents;
	}

	private List<Post> documentsToPosts(ArrayList<Document> documents) {
		List<Post> posts = new ArrayList<>();
		for (Document doc : documents) {
			String postUser = doc.getString("postUser");
			String content = doc.getString("content");
			// board name?
			Post post = new Post(postUser, content);
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
				String boardName = doc.getString("name");
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
						String postUser = postDoc.getString("postUser");
						String content = postDoc.getString("content");
						publicPosts.add(new Post(postUser, boardName, content));
					}
				}

				List<Document> localPostsDocs = (List<Document>) doc.get("localPosts");
				if (localPostsDocs != null) {
					for (Document postDoc : localPostsDocs) {
						String title = postDoc.getString("title");
						String content = postDoc.getString("content");
						localPosts.add(new Post(title, boardName, content));
					}
				}


				Board board = new Board(boardName, schoolAffiliations);
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
		if (args.length < 1) {
			System.out.println("Incorrect number of parameters");
			return;
		}

		String connectionString = "mongodb+srv://cdv1:TrSLjmjeLmgkYPBm@cluster0.gqjf9pj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
		MongoClient mongoClient = MongoClients.create(connectionString);
		MongoDatabase database = mongoClient.getDatabase(DB_NAME);
		MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);

//		Board boardPO = createBoard("frary", "PO");
//		Board boardHMC = createBoard("hoch", "HMC");
//		saveBoard(boardPO);
//		saveBoard(boardHMC);

		ArrayList<Board> boardArr = loadBoards();
		// create Bob
		try {
			Server bob = new Server(args[0], collection, boardArr);
			bob.start();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
