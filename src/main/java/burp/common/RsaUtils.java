package burp.common;

import cn.hutool.core.io.FileUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;

/**
 * 在实战中，系统可能会将请求的数据包首先使用aes加密，这里aes加密的key和iv每次都是从前端随机生成，然后使用非对称加密对key和iv进行加密发送到服务器。
 * 这里的思路是：
 * 1、首先使用burp的替换功能将响应体中的公钥使用本地生成的密钥对公钥进行替换，然后在响应到前端浏览器，这样浏览器加密的数据我们就能解密了。
 * 2、在burp插件中对请求头中rsa加密的数据使用本地私钥进行解密，取出其中随机生成的aes key和iv，拿到之后对通信的数据包进行解密、以及加密操作。
 * 3、在使用原本的服务器公钥对请求头中rsa解密部分进行加密，这样服务器也能够正常获取前端传递的key和iv。
 */
public class RsaUtils {

    // 本地私钥key
    static RSA private_key = new RSA(readFileContent("private.pem"),null);
    //服务器端公钥key
    static RSA public_key = new RSA(null, readFileContent("public.pem"));

    /**
     * 用于对浏览器发送的数据进行解密，然后取出其中的aes加密的key和iv。
     * @param msg
     * @return
     */
    public static String localRsaDecrypt(String msg){
        return private_key.decryptStr(msg, KeyType.PrivateKey);
    }

    /**
     * 用于将数据加密之后发送到服务器。
     * @param msg
     * @return
     */
    public static String serverRsaEncrypt(String msg){
        return public_key.encryptBase64(msg, KeyType.PublicKey);
    }

    private static String readFileContent(String filePath){
        return FileUtil.readUtf8String(filePath)
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s", "");
    }
}
