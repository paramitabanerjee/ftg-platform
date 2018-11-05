package food.togo.platform;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class HashUtil {

    private static String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static int iterations = 10000  ;
    private static int keySize = 128;


    //PBKDF2 password hashing
    public static String hashPassword(String password, byte[] salt)  throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] hash = f.generateSecret(spec).getEncoded();
        Base64.Encoder enc = Base64.getEncoder();
        System.out.printf("salt: %s%n", enc.encodeToString(salt));
        System.out.printf("hash: %s%n", enc.encodeToString(hash));

        return enc.encodeToString(hash);

    }
}
