
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.*;
import javax.net.ssl.*;
public class Client {

	// instance variables
	private Scanner console;
	private User localUser;

	private static final String[] protocols = new String[]{"TLSv1.3"};

	private static final String[] cipher_suites = new String[]{"TLS_AES_256_GCM_SHA384"};
	private static final String TRUSTSTORE_PATH = "client-truststore.jks";
	private static final String TRUSTSTORE_PASS = "Keystore1!";

	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	private Audit audit;

	public enum UserAction {
		LOGOUT, VIEW, SUBMIT, DELETE, EDIT
	}

	public Client(String serverPortStr, String auditFile)
			throws Exception {

		audit = new Audit(auditFile);

		console = new Scanner(System.in);
//		System.out.println("This is Alice");

		// obtain server's port number and connect to it
		int serverPort = Integer.parseInt(serverPortStr);
		String serverAddress = "localhost";

		SSLSocket socket = null;


		try {

			KeyStore trustStore = KeyStore.getInstance("JKS");
			FileInputStream fis = new FileInputStream(TRUSTSTORE_PATH);
			trustStore.load(fis, TRUSTSTORE_PASS.toCharArray());

			String introMessage = "┌───────────────────────────────────────────────────────────────────────┐\n" +
					"│ Startup                                                               │\n" +
					"├───────────────────────────────────────────────────────────────────────┤\n" +
					"│ Connecting to server at " + serverAddress + ":" + serverPort + "...                             │\n";



//			String connectingMessage = "╔════════════════════════════════════════════════╗\n" +
//					"║ Connecting to server at " + serverAddress + ":" + serverPort + " ...     ║\n";

			System.out.print(introMessage);

//			System.out.println("Connecting to server at port " + serverPort + " & address " + serverAddress + "...");

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(trustStore);


			SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
			sslContext.init(null, tmf.getTrustManagers(), null);

			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			socket = (SSLSocket) factory.createSocket("localhost", 1010);

			socket.setEnabledProtocols(protocols);
			socket.setEnabledCipherSuites(cipher_suites);
			socket.startHandshake();

			String introMessage2 =
					"│ Handshake completed, connected!                                       │\n" +
					"└───────────────────────────────────────────────────────────────────────┘";


			System.out.println(introMessage2);

//			System.out.println("Handshake completed, connected!");
//			for (int i = 0; i < 60; i++)
//				System.out.print("*");
//			System.out.println();
//			System.out.println();

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

					String optionsScreen =
							"┌───────────────────────────────────────────────────────────────────────┐\n" +
							"│ Login                               					                │\n" +
							"├───────────────────────────────────────────────────────────────────────┤\n" +
							"│ • Enter username and password (separated by space)	      		    │\n" +
							"│ • Enter 1 to create an account     				                    │\n" +
							"│ • Enter 2 to recover password                                   		│\n" +
							"└───────────────────────────────────────────────────────────────────────┘";

					streamOut.writeUTF(messageToSend);
					streamOut.flush();
					System.out.println(optionsScreen);

//					System.out.println(serverResponse);
					String credentials = console.nextLine();

					streamOut.writeUTF(credentials);
					streamOut.flush();


					// Username requirements: Alphanumeric, length between 4 and 16
					Pattern usernamePattern = Pattern.compile("^[a-zA-Z0-9]{4,16}$");
					// Password requirements: length between 8 and 32, include a symbol or number, one capital
					Pattern passwordPattern = Pattern.compile("^(?=.*[0-9!@#$%^&*()])(?=.*[A-Z]).{8,32}$");

					String username = "";
					String password = "";
					String localSchoolAffiliation = "<NULL>";


					if (credentials.equals("1")) {
						boolean validCredentials = false;
						while (!validCredentials) {

							String createAccountMessage = "┌───────────────────────────────────────────────────────────────────────┐\n" +
									"│ Signup                                                                │\n" +
									"├───────────────────────────────────────────────────────────────────────┤\n" +
									"│ Enter a new username and password (space separated)                   │\n" +
									"│                                                                       │\n" +
									"│ Username requirements:                                                │\n" +
									"│ - Alphanumeric characters only                                        │\n" +
									"│ - Length between 4 and 16 characters                                  │\n" +
									"│                                                                       │\n" +
									"│ Password requirements:                                                │\n" +
									"│ - Length between 8 and 32 characters                                  │\n" +
									"│ - Include at least one symbol or number                               │\n" +
									"│ - Include at least one uppercase letter                               │\n" +
									"└───────────────────────────────────────────────────────────────────────┘";

							System.out.println(createAccountMessage);
//
//							System.out.println("Enter a new username and password (space separated)");
//							System.out.println("Username requirements: Alphanumeric, length between 4 and 16");
//							System.out.println("Password requirements: length between 8 and 32, include a symbol or number, one capital");
							credentials = console.nextLine();

							String[] parts = credentials.split("\\s+");
							if (parts.length != 2) {
								audit.logPrint("Invalid input format. Please enter username and password separated by space.");
								audit.logPrint(credentials);
								continue;
							}

							username = parts[0];
							password = parts[1];

							Matcher usernameMatcher = usernamePattern.matcher(username);
							Matcher passwordMatcher = passwordPattern.matcher(password);

							if (!usernameMatcher.matches() || !passwordMatcher.matches()) {
//								System.out.println("Failed to meet username or password requirements."); // this is bad. tells you if you didnt enter a properly formatted password
								audit.logPrint("Failed to meet username or password requirements."); // this is bad. tells you if you didnt enter a properly formatted password
								audit.logPrint("Username: " + username);
							} else {

								validCredentials = true;
							}
						}
						String[] parts = credentials.split("\\s+");
						username = parts[0];
						password = parts[1];
						streamOut.writeUTF(credentials);
						streamOut.flush();

						// programming password recovery
//						streamOut.writeUTF("In order to recover passwords in case of loss, please enter a security question:");
//						System.out.println(streamIn.readUTF());

						String screen =
								"┌───────────────────────────────────────────────────────────────────────┐\n" +
								"│ Signup                                                                │\n" +
								"├───────────────────────────────────────────────────────────────────────┤\n" +
								"│ Enter a security question for password recovery.                      │\n" +
								"└───────────────────────────────────────────────────────────────────────┘";
						System.out.println(screen);

						String question = console.nextLine();

						String answer = "a";
						String tmp = "b";
						while (!answer.equals(tmp)) {

							String answerScreen =
									"┌───────────────────────────────────────────────────────────────────────┐\n" +
											"│ Signup                                                                │\n" +
											"├───────────────────────────────────────────────────────────────────────┤\n" +
											"│ Enter a secure answer for your recovery question.                     │\n" +
											"└───────────────────────────────────────────────────────────────────────┘";
							System.out.println(answerScreen);

//							System.out.println("Please enter an answer to your security question:");
							answer = console.nextLine();

							String answerConfScreen =
									"┌───────────────────────────────────────────────────────────────────────┐\n" +
											"│ Signup                                                                │\n" +
											"├───────────────────────────────────────────────────────────────────────┤\n" +
											"│ Re-enter a secure answer for your recovery question.                  │\n" +
											"└───────────────────────────────────────────────────────────────────────┘";
							System.out.println(answerConfScreen);

//							System.out.println("Please confirm your answer:");
							tmp = console.nextLine();

							if (!answer.equals(tmp)) {

								String answerMisMatchScreen =
										"┌───────────────────────────────────────────────────────────────────────┐\n" +
												"│ Signup                                                                │\n" +
												"├───────────────────────────────────────────────────────────────────────┤\n" +
												"│ Answers do not match. Please try again.                               │\n" +
												"└───────────────────────────────────────────────────────────────────────┘";
								System.out.println(answerMisMatchScreen);

//								System.out.println("Security answers do not match, please try again");
							}

						}

						streamOut.writeUTF(question);
						streamOut.flush();
						streamOut.writeUTF(answer);
						streamOut.flush();

						// Select a college
						boolean validCollege = false;
						String schoolAffiliation = "";
						while (!validCollege) {

							String collegeScreen =
									"┌───────────────────────────────────────────────────────────────────────┐\n" +
									"│ Signup                                                                │\n" +
									"├───────────────────────────────────────────────────────────────────────┤\n" +
									"│ Enter a college affiliation [PO, HMC, CMC, PZ, SC]                    │\n" +
									"└───────────────────────────────────────────────────────────────────────┘";

							System.out.println(collegeScreen);

//							audit.logPrint("User is selecting a college");
//							System.out.println("Which college do you belong to? [PO, HMC, CMC, PZ, SC]");
//							audit.logPrint("Which college do you belong to? [PO, HMC, CMC, PZ, SC]");
							schoolAffiliation = console.nextLine();
							schoolAffiliation = schoolAffiliation.toLowerCase();
							if (schoolAffiliation.equals("po") || schoolAffiliation.equals("hmc") || schoolAffiliation.equals("cmc") ||
									schoolAffiliation.equals("pz") || schoolAffiliation.equals("sc")) {

								validCollege = true;
//								audit.logPrint("User has selected a valid college:" + schoolAffiliation);
							}
							else {

								String invalidSchool =
										"┌───────────────────────────────────────────────────────────────────────┐\n" +
										"│ Signup                                                                │\n" +
										"├───────────────────────────────────────────────────────────────────────┤\n" +
										"│ Invalid school selection. Please choose one of [PO, HMC, CMC, PZ, SC] │\n" +
										"└───────────────────────────────────────────────────────────────────────┘";


								System.out.println(invalidSchool);
//								audit.logPrint("Invalid school selection");
							}
						}

						streamOut.writeUTF(schoolAffiliation);
						streamOut.flush();

						localUser = new User(username, schoolAffiliation, question, answer);
					}
					else if (credentials.equals("2")) {
						String newPassword = "";

						String signInMessage =
								"┌───────────────────────────────────────────────────────────────────────┐\n" +
										"│ Account Recovery                                                      │\n" +
										"├───────────────────────────────────────────────────────────────────────┤\n" +
										"│ Enter username             											│\n" +
										"└───────────────────────────────────────────────────────────────────────┘";



						System.out.println(signInMessage);
						username = console.nextLine();
						streamOut.writeUTF(username);
						streamOut.flush();

						String question = streamIn.readUTF();

						String recoveryMessage =
								"┌───────────────────────────────────────────────────────────────────────┐\n" +
								"│ Signin                                                                 │\n" +
								"├───────────────────────────────────────────────────────────────────────┤\n" +
								"│" + question +                                                        "│\n" +
								"└───────────────────────────────────────────────────────────────────────┘";



						System.out.println(recoveryMessage);

						System.out.println("Answer: ");
						String answer = console.nextLine();
						streamOut.writeUTF(answer);
						streamOut.flush();

						String responseOp = streamIn.readUTF();
						if (responseOp.equals("<success>")) {
							///

							boolean validCredentials = false;
							while (!validCredentials) {
								System.out.println("What is your new password?");
								System.out.println("Password requirements: length between 8 and 32, include a symbol or number, one capital");
								newPassword = console.nextLine();
								Matcher passwordMatcher = passwordPattern.matcher(newPassword);

								if (!passwordMatcher.matches()) {
//								System.out.println("Failed to meet username or password requirements."); // this is bad. tells you if you didnt enter a properly formatted password
									audit.logPrint("Failed to meet (recovery) password requirements."); // this is bad. tells you if you didnt enter a properly formatted password
								} else {
									validCredentials = true;
								}
							}

							streamOut.writeUTF(newPassword);
							streamOut.flush();

						}
						else {
							System.out.println("Security question failed.");
						}


					}
					else {
						String[] parts = credentials.split("\\s+");
						username = parts[0];
					}

					String authStatus = streamIn.readUTF();
					if (authStatus.equals("<success>")) {
						logged_in = true;
						if (localUser == null) {
							localSchoolAffiliation = streamIn.readUTF();
							localUser = new User(username, localSchoolAffiliation);
						}
						audit.logPrint("User has logged in");
					} else {
						continue;
//						audit.logPrint("Failed to create account or log in (username may be taken). Please try again.");
                    }



				}

				try {
					audit.logPrint("\nWhat would you like to do? \n -post message \n -view board \n -create board \n -exit \n\n");
					line = console.nextLine();

					switch (line) {
//						case "logout":
////							System.out.println("HAH you thought you could escape?");
//							audit.logPrint("User has logged out");
//							break;
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
                            audit.logPrint(incomingMsg);



							break;
						case "post message":
							boolean canPost = boardSelectClient(streamIn, streamOut);

							if (!canPost) break;

							messageToSend = "<post to board>";
							streamOut.writeUTF(messageToSend);
							streamOut.flush();

							audit.logPrint("What message would you like to post?\n");
							messageToSend = console.nextLine();
							packagedMsg = messageToSend;
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();
							// System.out.println("Message sent");
							break;
						case "create board":
							messageToSend = "<create board>";
							streamOut.writeUTF(messageToSend);
							streamOut.flush();

							audit.logPrint("What is the new board name?\n");
							messageToSend = console.nextLine();
							streamOut.writeUTF(messageToSend);
							streamOut.flush();

							// wait for valid board name check
							String status = streamIn.readUTF();
							if (!status.equals("<continue>")) {
								audit.logPrint("Board already exists.");
								break;
							}

							audit.logPrint("What is the college affiliation?\n(PO, HMC, CMC, PZ, and/or SC separated by spaces)\n");
							messageToSend = console.nextLine();
							streamOut.writeUTF(messageToSend);
							streamOut.flush();



						default:
//							System.out.println("Invalid action");
							audit.log("Invalid action");
							break;
					}

					

				} catch (IOException ioe) {
//					System.out.println("Sending error: " + ioe.getMessage());
					audit.logPrint("Sending error: " + ioe.getMessage());
				}
			}

			// close all the sockets and console
			console.close();
			streamOut.close();
			socket.close();

		} catch (IOException e) {
			// print error
//			System.out.println("Connection failed due to following reason");
			audit.logPrint("Connection failed due to following reason");
			audit.logPrint(e.getMessage());
//			System.out.println(e);

		}
	}

	private boolean boardSelectClient(DataInputStream streamIn, DataOutputStream streamOut) throws Exception {
		try {
			// send a request to see the board options
			streamOut.writeUTF(("<boards request>"));
			streamOut.flush();

			streamOut.writeUTF(localUser.getName());

			streamOut.flush();
			String boardMsgPrompt = (streamIn.readUTF());
			// System.out.println("Select a board:\n" + incomingMsg + "\n");
			System.out.println(boardMsgPrompt);
			// pick a board
			String selection = console.nextLine();
			streamOut.writeUTF(selection);
			streamOut.flush();

			String goodOrBadBoard = (streamIn.readUTF());


			if (goodOrBadBoard.equals("<good board>")) {
				return true;
			}

			System.out.println("This board belongs to: " + goodOrBadBoard + ", and you belong to: " + localUser.getSchoolAffiliation());
//			System.out.println("This board belongs to: " + boardAffiliation + ", and you belong to: " + localUser.getSchoolAffiliation());
			audit.logPrint("This board belongs to: " + goodOrBadBoard + ", and you belong to: " + localUser.getSchoolAffiliation());
			return false;

		}
		catch (IOException ioe) {
//			System.out.println("Could not get boards to select: " + ioe.getMessage());
			audit.logPrint("Could not get boards to select: " + ioe.getMessage());
			return false;
		}

	}

	/**
	 * args[0] ; port that Alice will connect to (Mallory's port)
	 * args[1] ; program configuration
	 */
	public static void main(String[] args) {

		// check for correct # of parameters
		if (args.length < 1) {
			System.out.println("Incorrect number of parameters");
		} else {
			// create Alice to start communication
			try {
				Client alice = (args.length > 2) ? new Client(args[0], args[2]) : new Client(args[0], null);



			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}
}

