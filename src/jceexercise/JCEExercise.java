package jceexercise;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import sun.misc.BASE64Encoder;

/**
 * @author dbeltran
 * @version 1.0
 */
public class JCEExercise {

    /**
     * Takes a String and cyphers it, then it decyphers the cyphered text.
     * <p>
     * Using Java Crypto Extensions
     * </p>
     * @param args the command line arguments
     * @see javax.crypto.*
     */
    public static void main(String[] args) {
        try {
            // Generates an AES key using KeyGenerator
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
            
            // Generates an initialization vector (iv)
            final int AES_KEYLENGTH = 128;
            byte[] iv = new byte[AES_KEYLENGTH / 8];
            SecureRandom prng = new SecureRandom();
            prng.nextBytes(iv);
            
            // Instance the AES algorithm
            Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            
            // Configure the AES algorithm
            aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            
            // Encrypt the data
            String strDataToEncrypt = "Hello World of Encryption using AES ";
            byte[] byteDataToEncrypt = strDataToEncrypt.getBytes();
            byte[] byteCipherText = aesCipherForEncryption.doFinal(byteDataToEncrypt);
            String strCipherText = new BASE64Encoder().encode(byteCipherText);
            System.out.println("Cipher Text generated using AES is: " + strCipherText);
            
            // Decipher the data
            Cipher aesCipherForDecryption = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] byteDecryptedText = aesCipherForDecryption.doFinal(byteCipherText);
            String strDecyptedText = new String(byteDecryptedText);
            System.out.println("Decrypted Text message is: " + strDecyptedText);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(JCEExercise.class.getName()).log(Level.SEVERE, "Invalid parameter -> ", ex);
        }   
    }
}
