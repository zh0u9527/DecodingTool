package burp.strategy.impl;

import burp.strategy.CipherStrategyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesOfbNoPaddingStrategyFactory implements CipherStrategyFactory {
    @Override
    public String encrypt(String message, String key, String iv, String model) throws Exception {
        //适配临时项目，因为key和iv直接通过将二进制转为base64进行表示的。而且加密的key只能通过服务器响应头的字段进行获取。
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] ivBytes = Base64.getDecoder().decode(iv);

        // 创建密钥和IV参数
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // 创建Cipher实例并初始化
        Cipher cipher = Cipher.getInstance(model);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        // 加密
        byte[] ciphertextBytes = cipher.doFinal(message.getBytes());

        // 返回Base64编码的密文
        return Base64.getEncoder().encodeToString(ciphertextBytes);
    }

    @Override
    public String decrypt(String message, String key, String iv, String model) throws Exception {
        //解密key通过服务器的请求头获取
        byte[] keyBytes = Base64.getDecoder().decode(key);
        byte[] ivBytes = Base64.getDecoder().decode(iv);

        // 创建密钥和IV参数
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // 创建Cipher实例并初始化
        Cipher cipher = Cipher.getInstance(model);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        // 解密
        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(message));

        // 返回明文
        return new String(plaintextBytes);
    }
}
