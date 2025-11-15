package burp.strategy;

import burp.common.Constant;
import burp.strategy.impl.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class InitCipherStrategy {
    private static final Map<String, CipherStrategyFactory> strategies = new HashMap<>();

    //如果需要添加其它的密码，直接在这里添加即可，然后在CipherStrategyFactory中添加对应的实现类即可
    static {
        strategies.put(Constant.AES_CBC_NoPadding, new AesCbcNoPaddingStrategyFactory());
        strategies.put(Constant.AES_CBC_PKCS5Padding, new AesCbcOtherPaddingStrategyFactory());
        strategies.put(Constant.AES_CBC_PKCS7Padding, new AesCbcOtherPaddingStrategyFactory());
        strategies.put(Constant.AES_ECB_NoPadding, new AesEcbNoPaddingStrategyFactory());
        strategies.put(Constant.AES_ECB_PKCS5Padding, new AesEcbOtherPaddingStrategyFactory());
        strategies.put(Constant.AES_ECB_PKCS7Padding, new AesEcbOtherPaddingStrategyFactory());
        strategies.put(Constant.AES_OFB_NoPadding, new AesOfbNoPaddingStrategyFactory());
        strategies.put(Constant.Base64_DEncode_Strategy, new Base64DEncodeStrategyFactory());
        strategies.put(Constant.URL_DEncode_Strategy, new URLDEncodeStrategyFactory());

        // 添加其他策略类的实例到 strategies
    }

    //为了方便将常量池添加到下拉选择框，这里提供一个对外开放的方法
    public static String[] getSelectMode(){
        Set<String> keySet = strategies.keySet();
        return keySet.toArray(new String[0]);

    }
    public static String selectMode(String message, String key, String iv, String mode, boolean flag) {
        CipherStrategyFactory strategy = strategies.get(mode);
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported mode: " + mode);
        }

        try {
            //true表示加密，false表示解密
            return flag ? strategy.encrypt(message, key, iv, mode) : strategy.decrypt(message, key, iv, mode);
        } catch (Exception e) {
//            throw new RuntimeException(e);
            // 如果解密失败则返回原密文
            return message;
        }
    }
}
