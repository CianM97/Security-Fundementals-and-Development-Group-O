/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package emailserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmailServer {

    //server socket to listen to incoming connections.
    private static ServerSocket servSock;
    // the port number the server will listen in for any incoming connections.
    private static final int PORT = 12345;

    // main method
    public static void main(String[] args) {
        //@reference.Intro duction to bouncycastle with Java, baeldung.com. Available at:https://www.baeldung.com/java-bouncy-castle [Accessed 10/November/2023]
        // importing BouncyCastle security provider.
        Security.addProvider(new BouncyCastleProvider());
        try {
            //setting up the server socket, that listens in on port 12345.
            servSock = new ServerSocket(PORT);
            // prints a message to the console confirming that the server is up and running.
            System.out.println("Server online. Waiting for client to connect...");

            while (true) {
                // server excepting a connection from the client and handles each client in a thread.
                Socket emailClient = servSock.accept();
                // prints a message to the servers console with the clients IP.
                System.out.println("Client has connected: " + emailClient.getInetAddress());

                //creating a thread to handle the client by passing the emailClient object to it.
                Thread client = new Thread(new Client(emailClient));
                // starts the thread.
                client.start();
            }
        } catch (BindException e) {
            // Handles the exception for when the port is already in use.
            System.err.println("Port already in use or unable to bind: " + e.getMessage());
        } catch (IOException e) {
            // Handle other IO exceptions that might occur when setting up the server socket or when excepting incoming client connections.
            e.printStackTrace();
        } finally {
            try {
                if (servSock != null) {
                    servSock.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //class to handle each connected client.
    static class Client implements Runnable {

        // creating the socket object for each client.
        private final Socket socket;
        // creating the bufferedreader for each client.
        private BufferedReader reader;
        // creating the printwriter for each client.
        private PrintWriter writer;

        // constructor for the client class.
        public Client(Socket clientSocket) {
            this.socket = clientSocket;
        }

        @Override
        public void run() {
            try {
                //@reference.Java Cryptogragpy, KeyPairGenerator. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_keypairgenerator.htm [Accessed 10/November/2023]
                // initializing keypairgeneator object for an RSA algorithm.
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
                // setting the size of the key, 2048 bits for RSA key pair generation.
                keyPairGen.initialize(2048);
                // generates both public and private keys for the server(receiver)(RSA key pair).
                KeyPair serverKeyPair = keyPairGen.generateKeyPair();
                // retrieves the private key.
                //PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
                // retrieves the public key.
                PublicKey serverPublicKey = serverKeyPair.getPublic();

                // Set up input and output streams for communication with the client and the server, allows you to read the data the server sends to the client.
                reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                // allows you to send data from the client to the server.
                writer = new PrintWriter(socket.getOutputStream(), true);

                // send the severs pubic key to the client, by writing the object to the outputstream.
                ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
                // writes the server public key object to the objectoutputstream for the client.
                outputStream.writeObject(serverPublicKey);

                // retrieving the clients public key from the inputstream.
                ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
                // server reads the public key object from the client.
                PublicKey clientPublicKey = (PublicKey) inputStream.readObject();

                // receive an encyrpted email from the client, by using a bufferedreader.
                BufferedReader receiverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                // reads the string text from the sender, using a bufferedreader where receiverReader is an instance of bufferedreader, and stores it in the cipherText variable.
                String cipherText = receiverReader.readLine();

                // decrypt the received email using the secret key.
                //String decryptedPlainText = decryptMessage(cipherText, serverPrivateKey);
                // prints a message to the console along with the encrypted cipherText string.
                System.out.println("Encrypted email: " + cipherText);
                // prints a message to the console along with the decryptedPlainText string.
                //System.out.println("Received decrypted email: " + decryptedPlainText);

                // send a reply email from the receiver using a bufferdreader consoleReader to get input from the receivers console.
                BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
                // prompts a message for the receiver to reply to the last sent email.
                System.out.print("client receiver email reply: ");
                // reads the string text from the reveiver, using a bufferedreader where consoleReader is an instance of bufferedreader, and stores it in the replyEmail variable.
                String replyEmail = consoleReader.readLine();

                // Encrypts the email reply message with the encryptMessage method below.
                String cipherReply = encryptMessage(replyEmail, clientPublicKey);

                // Send encrypted email reply to client using a printwriter.
                PrintWriter senderwriter = new PrintWriter(socket.getOutputStream(), true);
                // writes the encrypted cipherReply to the outputstream.
                senderwriter.println(cipherReply);
                // prints a message to the receivers console to confirm the email has been sent.
                System.out.println("client receiver encrypted email reply: " + cipherReply);
                // IOException is caught when setting up input and output streams for communication with the client.
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException ex) {
                // handle specific exceptions.
                Logger.getLogger(EmailServer.class.getName()).log(Level.SEVERE, null, ex);
            } catch (Exception ex) {
                // handle general exceptions.
                Logger.getLogger(EmailServer.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                // closeing all the sockets.
                try {
                    reader.close();
                    writer.close();
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        //@reference.Java Cryptogragpy, encrypting data. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_encrypting_data.htm [Accessed 10/November/2023]
        // method to encrypt email content using RSA.
        private static String encryptMessage(String cipherReply, PublicKey publicKey) throws Exception {
            // creating a cipher object using the RSA algorithm.
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            // initializing the cipher object in encrypt mode with the provided public key.
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            // encrypts the cipherReply by converting it into bytes.
            byte[] encrypted = cipher.doFinal(cipherReply.getBytes());
            // encodes the encrypted bytes into a Base64 string.
            return Base64.getEncoder().encodeToString(encrypted);
        }
        //@reference.Java Cryptogragpy, decrypting data. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_decrypting_data.htm [Accessed 10/November/2023]
        // method to decrypt reply email content using RSA.
        private static String decryptMessage(String cipherText, PrivateKey privateKey) throws Exception {
            // creating a cipher object using the RSA algorithm.
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            // initializing the cipher object in decrypt mode with the provided private key.
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // decodes the Base64 encoded cipherText into bytes and decrypts the email.
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            // creating a new string to display the decrypted plaintext.
            return new String(decrypted);
        }
    }
}
