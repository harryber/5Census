
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.*;

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
import javax.net.ssl.*;
import java.io.*;

public class Client {

	// instance variables
	private Scanner console;
	private User localUser;

	private static final String[] protocols = new String[]{"TLSv1.3"};

	private static final String[] cipher_suites = new String[]{"TLS_AES_256_GCM_SHA384"};
	private static final String TRUSTSTORE_PATH = "client-truststore.jks";
	private static final String TRUSTSTORE_PASS = "keystore1!";

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public enum UserAction {
		LOGOUT, VIEW, SUBMIT, DELETE, EDIT
	}

	public Client(String serverPortStr)
			throws Exception {

		console = new Scanner(System.in);
		System.out.println("This is Alice");

		// obtain server's port number and connect to it
		int serverPort = Integer.parseInt(serverPortStr);
		String serverAddress = "localhost";

		SSLSocket socket = null;


		try {

			KeyStore trustStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH);
			trustStore.load(fis, TRUSTSTORE_PASS.toCharArray());

			System.out.println("Connecting to Server at (" + serverPort + ", " + serverAddress + ")...");



			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(trustStore);


			SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
			sslContext.init(null, tmf.getTrustManagers(), null);

			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			socket = (SSLSocket) factory.createSocket("localhost", 1010);

			socket.setEnabledProtocols(protocols);
			socket.setEnabledCipherSuites(cipher_suites);
			socket.startHandshake();
			System.out.println("Handshake complete");

			OutputStreamWriter writer = new OutputStreamWriter(socket.getOutputStream());
			writer.write("Hello, Server!\n");
			writer.flush();

			DataOutputStream streamOut = new DataOutputStream(socket.getOutputStream());
			DataInputStream streamIn = new DataInputStream(new BufferedInputStream(socket.getInputStream()));


			// obtain the message from the user and send it to Server
			// the communication ends when the user inputs "done"
			String line = "";
			String messageToSend = "";
			String packagedMsg = "";
			boolean keepLooping = true;
			boolean logged_in = false;
			while (keepLooping) {
				while (!logged_in) {
					String serverResponse = streamIn.readUTF();
					System.out.println(serverResponse);
					String credentials = console.nextLine();

					streamOut.writeUTF(credentials);
					streamOut.flush();


					// Username requirements: Alphanumeric, length between 4 and 16
					Pattern usernamePattern = Pattern.compile("^[a-zA-Z0-9]{4,16}$");
					// Password requirements: length between 8 and 32, include a symbol or number, one capital
					Pattern passwordPattern = Pattern.compile("^(?=.*[0-9!@#$%^&*()])(?=.*[A-Z]).{8,32}$");

					String username = "";
					String password = "";

					if (credentials.equals("1")) {
						boolean validCredentials = false;
						while (!validCredentials) {
							System.out.println("Enter new username and password separated by space");
							System.out.println("Username requirements: Alphanumeric, length between 4 and 16");
							System.out.println("Password requirements: length between 8 and 32, include a symbol or number, one capital");
							credentials = console.nextLine();

							String[] parts = credentials.split("\\s+");
							if (parts.length != 2) {
								System.out.println("Invalid input format. Please enter username and password separated by space.");
								continue;
							}

							username = parts[0];
							password = parts[1];

							Matcher usernameMatcher = usernamePattern.matcher(username);
							Matcher passwordMatcher = passwordPattern.matcher(password);

							if (!usernameMatcher.matches() || !passwordMatcher.matches()) {
								System.out.println("Failed to meet username or password requirements."); // this is bad. tells you if you didnt enter a properly formatted password
							} else {
								validCredentials = true;
							}
						}

						streamOut.writeUTF(credentials);
						streamOut.flush();

						// Select a college
						boolean validCollege = false;
						String schoolAffiliation = "";
						while (!validCollege) {
							System.out.println("Which college do you belong to? [PO, HMC, CMC, PZ, SC]");
							schoolAffiliation = console.nextLine();
							schoolAffiliation = schoolAffiliation.toLowerCase();
							if (schoolAffiliation.equals("po") || schoolAffiliation.equals("hmc") || schoolAffiliation.equals("cmc") ||
									schoolAffiliation.equals("pz") || schoolAffiliation.equals("sc")) {

								validCollege = true;
							}
							else {
								System.out.println("Invalid school selection");
							}
						}

						streamOut.writeUTF(schoolAffiliation);
						streamOut.flush();

						localUser = new User(username, schoolAffiliation);
					}
					//TODO: Local user is only set if creating an account.

					String authStatus = streamIn.readUTF();
					if (authStatus.equals("success")) {
						logged_in = true;
						System.out.println("Logged in");
					} else {
						System.out.println("Failed to create account or log in (username may be taken). Please try again.");
                    }



				}

				try {
					System.out.print("\nWhat would you like to do? \n post message \n view board \n logout \n exit \n\n");
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
							boolean canView = boardSelectClient(streamIn, streamOut);
							if (!canView) break;

							// ask server to display a board
							packagedMsg = "<display board>";
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();


							// print the server's response
							String incomingMsg = streamIn.readUTF();
							System.out.println(incomingMsg);



							break;
						case "post message":
							boolean canPost = boardSelectClient(streamIn, streamOut);

							if (!canPost) break;

							messageToSend = "<post to board>";
							streamOut.writeUTF(messageToSend);
							streamOut.flush();

							// if (decryptMessage(streamIn.readUTF()).equals("<board select failed>"))

							System.out.println("What message would you like to post?\n");
							messageToSend = console.nextLine();
							packagedMsg = messageToSend;
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
			socket.close();

		} catch (IOException e) {
			// print error
			System.out.println("Connection failed due to following reason");
			System.out.println(e);
		}
	}

	private boolean boardSelectClient(DataInputStream streamIn, DataOutputStream streamOut) throws Exception {
		try {
			// send a request to see the board options
			streamOut.writeUTF("<boards request>");
			String boardMsgPrompt = streamIn.readUTF();
			// System.out.println("Select a board:\n" + incomingMsg + "\n");
			System.out.println(boardMsgPrompt);
			// pick a board
			String selection = console.nextLine();
			streamOut.writeUTF(selection);
			streamOut.flush();

			String boardAffiliation = streamIn.readUTF();
			boardAffiliation = boardAffiliation.toLowerCase();

			if (boardAffiliation.equals(localUser.getSchoolAffiliation())) {
				return true;
			}

			System.out.println("This board belongs to: " + boardAffiliation + ", and you belong to: " + localUser.getSchoolAffiliation());
			return false;
		}
		catch (IOException ioe) {
			System.out.println("Could not get boards to select: " + ioe.getMessage());
			return false;
		}

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
			// create Alice to start communication
			try {
				Client alice = new Client(args[0]);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}
}

