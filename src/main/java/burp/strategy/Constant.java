package burp.strategy;

public class Constant {
    public static final String AES_CBC_NoPadding = "AES/CBC/NoPadding";
    public static final String AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";
    public static final String AES_CBC_PKCS7Padding = "AES/CBC/PKCS7Padding";
    public static final String AES_ECB_NoPadding = "AES/ECB/NoPadding";
    public static final String AES_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding";
    public static final String AES_ECB_PKCS7Padding = "AES/ECB/PKCS7Padding";
    public static final String AES_OFB_NoPadding = "AES/OFB/NoPadding";


    //请求头 iv ,注意格式问题。
//    public static final String AES_IV_PARAM = "X-IV-Param: ";
    public static final String AES_IV_PARAM = "X-IV-Param: ";


    // AesEcbPKCS5PaddingStrategyFactory
    // AesEcbPKCS7PaddingStrategyFactory
    // AesEcbNoPaddingStrategyFactory
}
