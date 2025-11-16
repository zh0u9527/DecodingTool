package burp.common;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.Arrays;
import java.util.List;

public class HandleSign {
    /**
     * 从请求头中获取到签名
     * @param headers
     * @param signParamName
     * @return
     */
    public static String generatorSign(List<String> headers, String signParamName) {
        // 签名逻辑



        return null;
    }

    public static void updateSign(BurpExtender burp, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = burp.helpers.analyzeRequest(messageInfo);
        byte[] _request = messageInfo.getRequest();
        // 获取请求头头
        List<String> headers = requestInfo.getHeaders();
        // 请求体
        String requestBody = reqBody(requestInfo, _request);


        // 1、签名计算规则
        String signValue = generatorSign(headers, burp._signature);
        // 2、计算完成签名之后更新请求头
        CommonUtils.updateHeaderParamValue(headers, burp._signature, signValue);
    }

    /**
     * 从requestInfo中获取这个请求体
     * @param requestInfo
     * @return
     */
    public static String reqBody(IRequestInfo requestInfo, byte[] request) {
        // 请求头长度
        int bodyOffset = requestInfo.getBodyOffset();

        byte[] bodyBytes = Arrays.copyOfRange(request, bodyOffset, request.length);
        return new String(bodyBytes);
    }

    /**
     * 获取指定参数值，支持form-urlencoded、json类型，优先从请求体当中获取，如果找不到，再从get参数中获取。
     * 1、为form-urlencoded时，自动对获取的参数进行url解码之后返回；
     * 2、为json时，应支持多层嵌套，比如user.name这种；
     * 3、项目中已经嵌入了hutool依赖，可以优先使用该工具完成。
     * @param requestInfo
     * @param paramName
     * @return
     */
    public static String getSpecificParamValue(IRequestInfo requestInfo, byte[] request, String paramName) {
        return null;
    }
}
