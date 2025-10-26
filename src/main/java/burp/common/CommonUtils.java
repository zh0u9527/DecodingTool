package burp.common;

import java.net.URL;
import java.util.List;

import burp.BurpExtender;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.StrUtil;

/**
 * 综合工具集
 */
public class CommonUtils {

    /**
     * 从 http 请求头中获取指定参数的值
     * @param headers
     * @param headerName
     * @return
     */
    public static String getHeaderParamValue(List<String> headers, String headerName){
        headerName = handlerHeaderNamePrefix(headerName);
        for (String header : headers) {
            if (header.startsWith(headerName)) {
                return header.substring(headerName.length());
            }
        }
        return null;
    }

    /**
     * 从header中判断是否存在以headerName开始的请求头，如果存在，则使用新的value值进行替换
     * @param headers
     * @param headerName
     * @param value
     */
    public static void updateHeaderParamValue(List<String> headers, String headerName, String value){
        headerName = handlerHeaderNamePrefix(headerName);
        for (int i = 0; i < headers.size(); i++) {
            String header = headers.get(i);
            if (header.startsWith(headerName)) {
                // 替换旧的header值
                headers.set(i, headerName + value);
                break;
            }
        }
    }


    /**
     * 判断字符串是否为base64编码
     * @param str
     * @return
     */
    public static boolean isBase64(String str) {
        if (str == null || str.length() % 4 != 0) {
            return false;
        }
        if (!str.matches("^[A-Za-z0-9+/]+={0,2}$")) {
            return false;
        }
        try {
            Base64.decode(str);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 根据url获取主机名，返回空字符串或主机名
     * @param _url
     * @return
     */
    public static String getHost(String _url){
        if (StrUtil.isBlank(_url))
            return "";

        try{
            URL abc = new URL(_url);
            return abc.getHost();
        }catch (Exception ex){
            return _url;
        }
    }


    public static void printOut(BurpExtender burp, String prefix, String msg){
        if(! burp.isDebug){ return; }
        burp.stdout.println(prefix + " :: " + msg);
    }

    public static void printErr(BurpExtender burp, String prefix, String errMsg){
        if(! burp.isDebug){ return; }
        burp.stderr.println(prefix + " :: " + errMsg);
    }

    /**
     * 处理http请求头参数问题，为了更好的获取到请求头参数值，当写的请求头没有带: 时，自动拼接。
     * @param headerName
     * @return
     */
    private static String handlerHeaderNamePrefix(String headerName){
        if (!headerName.contains(Constant.HTTP_HEADER_PREFIX))
            headerName = Constant.HTTP_HEADER_PREFIX + headerName;
        return headerName;
    }
}
