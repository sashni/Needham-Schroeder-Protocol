package client;

import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.Arrays;

import server.Server;

public class Client {
    private char clientname;
    public static SecretKey serverkey;
    public static SecretKey keyAB;
    public static String Na, Nb;
    public static boolean logs = true;

    public Client(char name) throws Exception {
        this.clientname = name;
    }

    public static void main(String[] args) throws Exception
    {
        java.io.Console cnsl = System.console();
        char name = cnsl.readLine("Enter clientname: (A/B) ").charAt(0);
        Client client = new Client(name);
        String log_choice = cnsl.readLine("Logs? (true/false) ");
        logs = (log_choice.equals("false")) ? false : true;
        client.getServerKey(client.clientname);
        if (client.clientname == 'A') {
            client.initiate();
        } else {
            client.listentoA();
        }
        System.out.println();
        System.out.println("Session key successfully established");
        System.out.println("Welcome to the Secure Communication Network");
        if (logs==true){System.out.println("Session Key: " + Base64.getEncoder().encodeToString(keyAB.getEncoded()));};

        int round = 1;
        byte[] iv = new byte[16];
        while (true) {
            String message;

            System.out.println();
            System.out.println("Round "+round);

            message = cnsl.readLine("Enter message to send securely: ");
            if(logs==true){System.out.println("Sending message: " + message);};

            byte b = (byte) (Array.getByte(iv, round%16) ^ 1);
            iv[round%16] = b;
            String siv = Base64.getEncoder().encodeToString(iv);
            if(logs==true){System.out.println("Round IV: "+siv);};
            String plaintext = client.secure_send(iv, message);
            System.out.println("Received message:  " +plaintext);
            round++;
        }
    }

    private void getServerKey(char client) throws Exception {
        ServerSocket socket1;
        if (client == 'A') {
        socket1 = new ServerSocket(800);
        } else {
            socket1 = new ServerSocket(801);
        }
        Socket socketS = socket1.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socketS.getInputStream()));
        String key = in.readLine();
        if(logs==true){System.out.println("serverkey: " + key+"\n");};
        socketS.close();

        byte[] keyb = Base64.getDecoder().decode(key);
        SecretKeySpec sk = new SecretKeySpec(keyb, "AES");
        serverkey = sk;
    }

    // Decrypt messages encrypted with server key
    private String decrypt_S(String siv, String message) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(message);
        System.out.println("Initialization Vector for Decryption: "+siv+"\n");
        byte[] iv = Base64.getDecoder().decode(siv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, serverkey, ivspec);
        String plaintext = new String(c.doFinal(encoded));
        return plaintext;
    }


    // Client A initiates communication
    private void initiate() throws Exception {
        String[] msg = new String[4];
        msg[0] = "A";
        msg[1] = "B";

        // Generate nonce Na
        Random rnd = new Random();
        Na = Integer.toString(rnd.nextInt());
        Nb = Integer.toString(rnd.nextInt());
        msg[2] = Na;
        msg[3] = Nb;

        System.out.println("Sending message (A->S): " + msg[0]+" " + msg[1]+" " + msg[2]+" " + msg[3]+"\n");
        Socket socket = new Socket("localhost",1025);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        for (int i = 0; i < msg.length; i++){
          out.println(msg[i]);
        }
        socket.close();
        listentoS();
    }

    private void listentoS() throws Exception {
        ServerSocket socket1 = new ServerSocket(1027);
        Socket socketS = socket1.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socketS.getInputStream()));
        String iv = in.readLine();
        String kAScipher = in.readLine();
        String kBScipher = in.readLine();
        socketS.close();
        socket1.close();

        System.out.println("Received ciphertext (S->A): " + iv+" " + kAScipher+" " + kBScipher+"\n");
        String[] plaintext = decrypt_S(iv, kAScipher).split(" ");
        assert (plaintext[1] == "B");
        assert (plaintext[2] == Na);

        byte[] keyb = Base64.getDecoder().decode(plaintext[0]);
        SecretKeySpec sk = new SecretKeySpec(keyb, "AES");
        keyAB = sk;
        if(logs==true){System.out.println("Decrypted ciphertext (serverkey): " +plaintext[0]+" " +plaintext[1]+" " +plaintext[2]+"\n");};
        forwardtoB(iv, kBScipher);
    }

    private void forwardtoB(String iv, String kBScipher) throws Exception {
        System.out.println("Forwarding to B (A->B): " + iv+" " + kBScipher+"\n");
        ServerSocket socket1 = new ServerSocket(1028);
        Socket socket = new Socket("localhost",1026);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println(iv);
        out.println(kBScipher);
        socket.close();

        // listen for response from B
        Socket socketB = socket1.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socketB.getInputStream()));
        String[] message = in.readLine().split(" ");
        assert (message[0]=="B");
        assert (message[1]==Nb);
        System.out.println("(B->A): Nonce received and accepted from B: "+message[0]+" "+message[1]+"\n");
        socketB.close();
        socket1.close();
    }


    private void listentoA() throws Exception {
        ServerSocket socket1 = new ServerSocket(1026);
        Socket socketS = socket1.accept();
        BufferedReader in = new BufferedReader(new InputStreamReader(socketS.getInputStream()));
        String iv = in.readLine();
        String kBScipher = in.readLine();
        socketS.close();
        socket1.close();

        System.out.println("Received ciphertext (A->B): " + iv+" " + kBScipher+"\n");
        String[] plaintext = decrypt_S(iv, kBScipher).split(" ");
        if(logs==true){System.out.println("Decrypted ciphertext: " + plaintext[0] + plaintext[1] + plaintext[2]+"\n");};
        assert(plaintext[1] == "A");
        byte[] keyb = Base64.getDecoder().decode(plaintext[0]);
        SecretKeySpec sk = new SecretKeySpec(keyb, "AES");
        keyAB = sk;
        Nb = plaintext[2];
        respondtoA(Nb);
    }

    private void respondtoA(String Nb) throws Exception {
        System.out.println("Responding (B->A): B " +Nb+"\n");
        Socket socket = new Socket("localhost",1028);
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        out.println("B "+Nb);
        socket.close();
    }

    private String secure_send(byte[] iv, String msg) throws Exception {
        String ciphertext2 = encrypt_msg(iv, msg);
        System.out.println("Sending ciphertext: " +ciphertext2+"\n");
        String plaintext2 = secure_send_BA(iv, ciphertext2);
        String plaintext1 = secure_send_AB(iv, ciphertext2);
        return (clientname == 'B') ? plaintext1 : plaintext2;
    }

    private String secure_send_AB(byte[] iv, String msg) throws Exception {
        String plaintext = "";
        if (clientname == 'B') {
            ServerSocket serverB = new ServerSocket(500);
            Socket socketB = serverB.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(socketB.getInputStream()));
            String ciphertext1 = in.readLine();
            plaintext = decrypt_msg(iv, ciphertext1);
            socketB.close();
            serverB.close();
        } else if (clientname == 'A') {
            Socket A = new Socket("localhost", 500);
            PrintWriter out = new PrintWriter(A.getOutputStream(), true);
            out.println(msg);
            A.close();
        }
        return plaintext;
    }

    private String secure_send_BA(byte[] iv, String msg) throws Exception {
        String plaintext = "";
        if (clientname == 'A') {
            ServerSocket serverA = new ServerSocket(502);
            Socket socketA = serverA.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(socketA.getInputStream()));
            String ciphertext1 = in.readLine();
            plaintext = decrypt_msg(iv, ciphertext1);
            socketA.close();
            serverA.close();
        } else if (clientname == 'B') {
            Socket B = new Socket("localhost", 502);
            PrintWriter out = new PrintWriter(B.getOutputStream(), true);
            out.println(msg);
            B.close();
        }
        return plaintext;
    }

    private String encrypt_msg(byte[] iv, String msg) throws Exception {
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, keyAB, ivspec);

        byte[] input = msg.getBytes("UTF-8");
        byte[] ciphertext = c.doFinal(input);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    private String decrypt_msg(byte[] iv, String ciphertext) throws Exception {
        byte[] ct = Base64.getDecoder().decode(ciphertext);
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, keyAB, ivspec);
        String plaintext = new String(c.doFinal(ct));
        return plaintext;
    }

}
