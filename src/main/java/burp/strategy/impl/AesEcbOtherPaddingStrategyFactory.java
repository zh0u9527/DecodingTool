package burp.strategy.impl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesEcbOtherPaddingStrategyFactory implements burp.strategy.CipherStrategyFactory{
    @Override
    public String encrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    @Override
    public String decrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
}
