package burp.strategy.impl;
import burp.strategy.CipherStrategyFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesCbcOtherPaddingStrategyFactory implements CipherStrategyFactory{
    @Override
    public String encrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec tmpIv = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, tmpIv);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    @Override
    public String decrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec tmpIv = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, tmpIv);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
}
