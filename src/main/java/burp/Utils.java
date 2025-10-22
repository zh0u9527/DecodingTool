package burp;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class Utils {
    /**
     * 动态生成 key 和 iv。
     * @return
     */
    public static String[] getKeyAndIV() {

        // 生成AES-128密钥
        KeyGenerator keyGen = null;
        try {
            keyGen = keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.init(128); // AES-128
        SecretKey secretKey = keyGen.generateKey();
        byte[] keyBytes = secretKey.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);

        // 生成随机IV
        byte[] ivBytes = new byte[16]; // 128-bit IV
        new java.security.SecureRandom().nextBytes(ivBytes);
        String base64IV = Base64.getEncoder().encodeToString(ivBytes);

        // 输出Base64编码的密钥和IV
        return new String[]{base64Key, base64IV};
    }

}
