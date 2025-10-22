package burp.strategy.impl;

import burp.strategy.CipherStrategyFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesCbcNoPaddingStrategyFactory implements CipherStrategyFactory {
    @Override
    public String encrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // 零填充：将明文长度补齐为16的倍数
        int blockSize = 16;
        int plaintextLength = message.length();
        int padding = blockSize - (plaintextLength % blockSize);
        for (int i = 0; i < padding; i++) {
            message += "\0";
        }

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    @Override
    public String decrypt(String message, String key, String iv, String mode) throws Exception {
        Cipher cipher = Cipher.getInstance(mode);
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));

        // 去除 ZeroPadding
        int lastNonZeroIndex = decryptedBytes.length - 1;
        while (lastNonZeroIndex >= 0 && decryptedBytes[lastNonZeroIndex] == 0) {
            lastNonZeroIndex--;
        }

        // 使用实际有效长度构建字符串
        return new String(decryptedBytes, 0, lastNonZeroIndex + 1);
    }
}
