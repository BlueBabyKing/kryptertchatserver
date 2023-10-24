package testarea;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class SuperSecret {
    public static void main(String[] args) {
        try {
            // Generate a secret key for encryption and decryption
            SecretKey secretKey = generateSecretKey();



            //test shit!!!

            System.out.println("salt er:" + generateSalt());

            Scanner scanner = new Scanner(System.in);
            System.out.println("skriv key");
            String keyproto = scanner.nextLine();
            SecretKey key= generateKeyFromPassword(keyproto);
            System.out.println(key);


            // String to be encrypted
            String originalString = "This is a secret message.";

            // Encrypt the string
            String encryptedString = encrypt(originalString, key);
            System.out.println("Encrypted String: " + encryptedString);

            // Decrypt the string
            String decryptedString = decrypt(encryptedString, key);
            System.out.println("Decrypted String: " + decryptedString);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SecretKey generateKeyFromPassword(String password) throws Exception {
        // Use a key derivation function (KDF) to derive a key from the password
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        salt = "[B@7d6f77cc".getBytes();

        int iterations = 10; // You can adjust the number of iterations for desired security

        // Use PBKDF2 (Password-Based Key Derivation Function 2) for key derivation
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 128); // 128-bit key
        SecretKey secretKey = factory.generateSecret(spec);

        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public static SecretKey generateSecretKey() throws Exception {
        // Use KeyGenerator to generate a random AES key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // 128-bit key size
        return keyGenerator.generateKey();
    }

    public static String encrypt(String input, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedString, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedString);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }


    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
}