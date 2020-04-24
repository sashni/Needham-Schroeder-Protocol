package server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.ServerSocket;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;


public class Server {
    public static SecretKey keyAS;
    public static SecretKey keyBS;

    public Server() throws Exception {
    }

    public static void main(String[] args) throws Exception
    {

        // Reading data using readLine
        Server S = new Server();
        S.sendkeys();
        S.listen();
    }

    private void sendkeys() throws Exception {
        SecretKey[] keys = new SecretKey[2];
        keyAS = SecretKeyAS();
        keyBS = SecretKeyBS();

        // Send key to A
        Socket socket = new Socket("localhost", 800);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println(Base64.getEncoder().encodeToString(keyAS.getEncoded()));
        System.out.println("Sending key AS: " +keyAS);
        System.out.println(Base64.getEncoder().encodeToString(keyAS.getEncoded()));
        socket.close();

        //// Send key to B
        socket = new Socket("localhost", 801);
        out = new PrintWriter(socket.getOutputStream(), true);
        System.out.println("Sending key BS: "+keyBS);
        System.out.println(Base64.getEncoder().encodeToString(keyBS.getEncoded()));
        out.println(Base64.getEncoder().encodeToString(keyBS.getEncoded()));
        socket.close();
    }

    public static SecretKey SecretKeyAS() throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecretKey sk = kgen.generateKey();
        return sk;
    }

    public static SecretKey SecretKeyBS() throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecretKey sk = kgen.generateKey();
        return sk;
    }

    private void listen() throws Exception {
        ServerSocket socket1 = new ServerSocket(1025);
        Socket socketA = socket1.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socketA.getInputStream()));
        // [A, B, Na, Nb]
        String[] message = new String[4];
        for (int i = 0; i < 4; i++) {
            message[i] = in.readLine();
        }
        System.out.println("Message received (A->S): " + message[0] + message[1] + message[2] + message[3]);
        socketA.close();
        // Kab
        respond(message);
    }

    public void respond(String[] message) throws Exception{
        String keyAB = generate_keyAB();
        System.out.println("Nonces " + message[2]);
        System.out.println("Nonces " + message[3]);
        String[] ct = encrypt_sk(keyAB, message[2], message[3]);

        Socket socket = new Socket("localhost", 1027);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        System.out.println("Sending ciphertext (S->A): " + ct[0] + ct[1] + ct[2]);
        out.println(ct[0]);
        out.println(ct[1]);
        out.println(ct[2]);
        socket.close();
    }

    private String generate_keyAB() throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecretKey kAB = kgen.generateKey();
        String keyAB = Base64.getEncoder().encodeToString(kAB.getEncoded());
        return keyAB;
        //PrintWriter out = new PrintWriter(socketA.getOutputStream(), true);
        //out.println('B');
    }


    private String[] encrypt_sk(String keyAB, String Na, String Nb) throws Exception {
        String[] encoded = new String[3];
        byte[] iv = new byte[16];
        SecureRandom srandom = new SecureRandom();
        srandom.nextBytes(iv);
        encoded[0] = Base64.getEncoder().encodeToString(iv);
        System.out.println("IV: "+encoded[0]);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, keyAS, ivspec);
        String plaintext = keyAB+" B "+Na;
        byte[] input = plaintext.getBytes("UTF-8");
        byte[] ciphertext = c.doFinal(input);
        encoded[1] = Base64.getEncoder().encodeToString(ciphertext);

        c.init(Cipher.ENCRYPT_MODE, keyBS, ivspec);
        plaintext = keyAB+" A "+Nb;
        input = plaintext.getBytes("UTF-8");
        ciphertext = c.doFinal(input);
        encoded[2] = Base64.getEncoder().encodeToString(ciphertext);
        return encoded;
    }
}
