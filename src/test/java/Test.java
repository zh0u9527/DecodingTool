import burp.common.Constant;
import burp.strategy.impl.AesOfbNoPaddingStrategyFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Test {
    public static void main(String[] args) throws Exception {
        AesOfbNoPaddingStrategyFactory a = new AesOfbNoPaddingStrategyFactory();
        String[] keyAndIV = getKeyAndIV();
        String key = keyAndIV[0];
        String iv = keyAndIV[1];
        String s = a.encrypt("{\"requestID\":\"8ede6335-e62a-4ef6-ab09-124e9dabbc25\",\"param\":{\"loginName\":\"fdajfi\",\"password\":\"dffda\",\"salt\":1706935745302}}",
                key, iv, Constant.AES_OFB_NoPadding);
        System.out.println(s);
    }

    public  static String[] getKeyAndIV() throws NoSuchAlgorithmException {
        // 生成AES-128密钥
        KeyGenerator keyGen = keyGen = KeyGenerator.getInstance("AES");
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
