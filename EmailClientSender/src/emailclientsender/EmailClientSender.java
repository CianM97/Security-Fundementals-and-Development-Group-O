/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package emailclientsender;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmailClientSender {

    // creating and initializing server and port variables.
    private static final String SERVER = "localhost";
    // the port number the server will listen in for any incoming connections.
    private static final int PORT = 12345;

    // main method
    public static void main(String[] args) throws Exception {
        //@reference.Intro duction to bouncycastle with Java, baeldung.com. Available at:https://www.baeldung.com/java-bouncy-castle [Accessed 10/November/2023]
        // importing BouncyCastle security provider.
        Security.addProvider(new BouncyCastleProvider());
        // waitTime variable set in millieseconds, 5secs between each attempt to reconnect
        final int waitTime = 5000;
        // only 5 reconnection attempts can be made
        while (true) {
            // initializing socket as null at the start, to assign values to it later.
            Socket servSocket = null;
            try (
                    // createing the socket to establish a connection using the server and port variables.
                    Socket servsocket = new Socket(SERVER, PORT)) {
                //@reference.Java Cryptogragpy, KeyPairGenerator. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_keypairgenerator.htm [Accessed 10/November/2023]
                // initializing keypairgeneator object for an RSA algorithm.
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
                // setting the size of the key, 2048 bits for RSA key pair generation.
                keyPairGen.initialize(2048);
                // generates both public and private keys for the client(sender)(RSA key pair).
                KeyPair clientKeyPair = keyPairGen.generateKeyPair();
                // retrieves the client private key.
                PrivateKey clientPrivateKey = clientKeyPair.getPrivate();
                // retrieves the client public key.
                PublicKey clientPublicKey = clientKeyPair.getPublic();

                // Sends the client(Sender) public key to the server
                ObjectOutputStream outputStream = new ObjectOutputStream(servsocket.getOutputStream());
                // writes the client public key object to the outputstream.
                outputStream.writeObject(clientPublicKey);

                // creating objectinputstream to receive the Server(Receiver) public key from the server.
                ObjectInputStream inputStream = new ObjectInputStream(servsocket.getInputStream());
                // reading the serverPublictKey object from the objectinputstream
                PublicKey serverPublicKey = (PublicKey) inputStream.readObject();

                // setting up the reader and input streams to get user input from the console using a bufferedreader.
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                while (true) {
                    // Get the senders input with a prompt to the console.
                    System.out.print("Enter your email here: ");
                    // reads the string text from the user, using a bufferedreader where reader is an instance of bufferedreader, and stores it in the emailPlainText variable.
                    String emailPlaintext = reader.readLine();

                    // Encrypts senders email with the encryptMessage method created below.
                    String cipherText = encryptMessage(emailPlaintext, serverPublicKey);

                    // Send encrypted email to the server by creating an intance of printwriter.
                    PrintWriter writer = new PrintWriter(servsocket.getOutputStream(), true);
                    // writes the encrypted ciphertext to the outputstream
                    writer.println(cipherText);
                    // prints the message to the console to confirm the email has been sent.
                    System.out.println("Sent encrypted email: " + cipherText);

                    // Receive encrypted reply email from the server by creating a bufferedreader.
                    BufferedReader serverReader = new BufferedReader(new InputStreamReader(servsocket.getInputStream()));
                    // reads the string text from the receiver, using a bufferedreader where serverReader is an instance of bufferedreader, and stores it in the cipherReply variable.
                    String cipherReply = serverReader.readLine();

                    // Decrypts receivers reply email with the decryptMessage method created below.
                    String decryptedPlainText = decryptMessage(cipherReply, clientPrivateKey);
                    // prints receivers encrypted reply email to the senders console.
                    System.out.println("Encrypted email reply: " + cipherReply);
                    // prints receivers decrypted reply email to the senders console.
                    System.out.println("Received decrypted email reply: " + decryptedPlainText);
                }
                // IOException to catch when the host (local machine) dissconnects from the server and prints and error message to the console.
            } catch (IOException e) {
                System.err.println("Connection to the host has been unexpectedly disconnected: " + e.getMessage());
                e.printStackTrace();
                try {
                    // waiting time period before a reconnection attempt.
                    Thread.sleep(waitTime);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            } finally {
                try {
                    // closing the socket once finished.
                    if (servSocket != null) {
                        servSocket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    //@reference.Java Cryptogragpy, encrypting data. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_encrypting_data.htm [Accessed 10/November/2023]
    // method to encrypt email content using RSA.
    private static String encryptMessage(String emailPlaintext, PublicKey publicKey) throws Exception {
        // creating a cipher object using the RSA algorithm
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        // initializing the cipher object in encrypt mode with the provided public key.
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        // encrypts the emailPlainText by converting it into bytes
        byte[] encrypted = cipher.doFinal(emailPlaintext.getBytes());
        // encodes the encrypted bytes into a Base64 string.
        return Base64.getEncoder().encodeToString(encrypted);
    }
    //@reference.Java Cryptogragpy, decrypting data. Available at:https://www.tutorialspoint.com/java_cryptography/java_cryptography_decrypting_data.htm [Accessed 10/November/2023]
    // method to decrypt reply email content using RSA.
    private static String decryptMessage(String cipherReply, PrivateKey privateKey) throws Exception {
        // creating a cipher object using the RSA algorithm
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        // initializing the cipher object in decrypt mode with the provided private key.
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        // decodes the Base64 encoded cipherReply into bytes and decrypts the reply email.
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherReply));
        // creating a new string to display the decrypted plaintext.
        return new String(decrypted);
    }
}
