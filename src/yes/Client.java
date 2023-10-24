package yes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client  {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String username;
    private SecretKey key;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter IPv4, Or Write localhost");
        String ip = scanner.nextLine();
        //System.out.println("Enter key");
        //String almostkey = scanner.nextLine();
        String k = "asd";
        SecretKey key = generateKeyFromPassword(k);
        System.out.println("Enter Username");
        String username = scanner.nextLine();
        Socket socket = new Socket (ip, 2222);
        Client client = new Client(socket, username,key);
        client.listenForMessage();
        client.sendMessage();
    }

    public Client(Socket socket,String username,SecretKey key ){
        try{

            this.socket= socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.username = username;
            this.key = key;

        } catch(IOException e){
            closeEveryThing(socket,bufferedReader,bufferedWriter);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void sendMessage(){
        try{
            bufferedWriter.write(username);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()){
                String messageToSend = (username + ": " + scanner.nextLine());
                //System.out.println(messageToSend);
                String encryptedMsg = encrypt(messageToSend, key);
                bufferedWriter.write(encryptedMsg);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }

        }catch (IOException e ){
            closeEveryThing(socket,bufferedReader,bufferedWriter);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void listenForMessage(){
        new Thread(() -> {

            String msgFromGroupChat;

            while (socket.isConnected()){
                try{
                    msgFromGroupChat = bufferedReader.readLine();
                    //System.out.println("------------------"+msgFromGroupChat+"(kryptert)");
                    String decrypdedMsg = decrypt(msgFromGroupChat,key);
                    //System.out.println(decrypdedMsg + "(dekryptert)");
                    System.out.println(decrypdedMsg);

                }catch (IOException e){
                    closeEveryThing(socket,bufferedReader,bufferedWriter);
                } catch (javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException e) {
                    System.err.println("Error decrypting message: " + e.getMessage());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }

    public static SecretKey generateKeyFromPassword(String password) throws Exception {
        int iterations = 100;
        byte[] salt;
        salt = "123123".getBytes();

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 128); // 128-bit key
        SecretKey secretKey = factory.generateSecret(spec);

        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public static String encrypt(String input, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedString, SecretKey secretKey) throws Exception {
        if (encryptedString != null) {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedString);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        }
        return null;
    }

    public void closeEveryThing(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter){
        try {
            if (bufferedReader != null){
                bufferedReader.close();
            }
            if ( bufferedWriter!= null){
                bufferedWriter.close();
            }
            if (socket != null){
                socket.close();
            }
        }catch (IOException e){
            e.printStackTrace();
        }
    }
}
