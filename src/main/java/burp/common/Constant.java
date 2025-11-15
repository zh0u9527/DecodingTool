package burp.common;

public class Constant {
    public static final String AES_CBC_NoPadding = "AES/CBC/NoPadding";
    public static final String AES_CBC_PKCS5Padding = "AES/CBC/PKCS5Padding";
    public static final String AES_CBC_PKCS7Padding = "AES/CBC/PKCS7Padding";
    public static final String AES_ECB_NoPadding = "AES/ECB/NoPadding";
    public static final String AES_ECB_PKCS5Padding = "AES/ECB/PKCS5Padding";
    public static final String AES_ECB_PKCS7Padding = "AES/ECB/PKCS7Padding";
    public static final String AES_OFB_NoPadding = "AES/OFB/NoPadding";
    // 编码系列
    public static final String Base64_DEncode_Strategy = "BASE64_DEncode";
    public static final String URL_DEncode_Strategy = "URL_DEncode";


    /*
    未发现需要解密的请求参数
     */
    public static final String NO_FOUND_PARAM = "未发现参数";

    /*
    堆栈异常常量
     */
    public static final String STACK_INFO = "堆栈异常信息";

    /*
    http 请求头参数值前缀
     */
    public static final String HTTP_HEADER_PREFIX = ": ";

    /*
    插件在burp显示的名称
     */
    public static final String BURP_TABLE_NAME = "DecodingTool";

    /*
    工具标识头
     */
    public static final String TOOL_HEAD_PARAM = BURP_TABLE_NAME + ": 1";

    /*
    安装插件之后打印消息。
     */
    public static final String INSTALLED_MSG = "Welcome to use the " + BURP_TABLE_NAME;





    // AesEcbPKCS5PaddingStrategyFactory
    // AesEcbPKCS7PaddingStrategyFactory
    // AesEcbNoPaddingStrategyFactory
}
