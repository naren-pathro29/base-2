# base-2
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordEncryptionExample {

    private static final String SECRET_KEY = "YourSecretKey"; // Change this to your secret key

    public static void main(String[] args) {
        String originalPassword = "MyStrongPassword";
        System.out.println("Original Password: " + originalPassword);

        // Encrypt the password
        String encryptedPassword = encrypt(originalPassword);
        System.out.println("Encrypted Password: " + encryptedPassword);

        // Decrypt the password
        String decryptedPassword = decrypt(encryptedPassword);
        System.out.println("Decrypted Password: " + decryptedPassword);
    }

    private static String encrypt(String password) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec secretKeySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "
