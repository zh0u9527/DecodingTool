package burp.common;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import burp.BurpExtender;
import burp.IParameter;
import burp.IRequestInfo;
import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

/**
 * 综合工具集
 */
public class CommonUtils {

    /**
     * 加解密url编码格式的参数
     * @param burp
     * @param _request
     * @param headers
     * @param _params
     * @param _do_enc
     * @return
     */
    public static byte[] updateReqParams(BurpExtender burp, byte[] _request, List<String> headers, String[] _params, Boolean _do_enc){
        IRequestInfo reqInfo = burp.helpers.analyzeRequest(_request);
        String method = reqInfo.getMethod();
        List<IParameter> allParams = reqInfo.getParameters();

        // 不再构造 message，只补 header
        if (!headers.contains(burp._Header)) {
            headers.add(burp._Header);
        }

        IRequestInfo newInfo = burp.helpers.analyzeRequest(_request);
        byte[] body = Arrays.copyOfRange(_request, newInfo.getBodyOffset(), _request.length);
        _request = burp.helpers.buildHttpMessage(headers, body);

        for (String paramName : _params) {
            IParameter targetParam = burp.helpers.getRequestParameter(_request, paramName);
            if (targetParam == null || targetParam.getName().isEmpty()) {
                continue;
            }

            String newValue = _do_enc ? burp.do_encrypt(targetParam.getValue().trim()) : burp.do_decrypt(targetParam.getValue().trim());

            // 特殊处理请求体覆盖模式
            if (burp._is_ovrr_req_body || burp._is_ovrr_res_body) {
                if (!headers.contains(burp._Header)) {
                    headers.add(burp._Header);
                }
                return burp.helpers.buildHttpMessage(headers, newValue.getBytes());
            }

            IParameter newParam = null;
            boolean updated = false;

            if ("POST".equalsIgnoreCase(method)) {
                if (targetParam.getType() == IParameter.PARAM_BODY) {
                    newParam = burp.helpers.buildParameter(paramName, newValue, IParameter.PARAM_BODY);
                    updated = true;
                } else {
                    for (IParameter param : allParams) {
                        if (param.getType() == IParameter.PARAM_BODY && param.getName().equals(paramName)) {
                            _request = burp.helpers.removeParameter(_request, param);
                            newParam = burp.helpers.buildParameter(paramName, newValue, IParameter.PARAM_BODY);
                            updated = true;
                            break;
                        }
                    }
                    if (!updated && targetParam.getType() == IParameter.PARAM_URL) {
                        newParam = burp.helpers.buildParameter(paramName, newValue, IParameter.PARAM_URL);
                        updated = true;
                    }
                }
            } else if ("GET".equalsIgnoreCase(method)) {
                if (targetParam.getType() == IParameter.PARAM_URL) {
                    newParam = burp.helpers.buildParameter(paramName, newValue, IParameter.PARAM_URL);
                    updated = true;
                }
            }

            if (updated && newParam != null) {
                _request = burp.helpers.removeParameter(_request, targetParam);
                _request = burp.helpers.addParameter(_request, newParam);
            }

        }

        return _request;
    }

    /**
     * 加解密json格式的参数
     * @param burp
     * @param _request
     * @param headers
     * @param _params
     * @param _do_enc
     * @return
     */
    public static byte[] updateReqParamsJson(BurpExtender burp, byte[] _request, List<String> headers, String[] _params, Boolean _do_enc){
        try {
            IRequestInfo reqInfo = burp.helpers.analyzeRequest(_request);
            // 获取请求体
            String reqBody = new String(_request, StandardCharsets.UTF_8).substring(reqInfo.getBodyOffset()).trim();

            // 解析 JSON
            JSONObject jsonObject = JSONUtil.parseObj(reqBody);

            for (String param : _params) {
                // 使用 JSONUtil.getByPath() 支持嵌套参数，如 "user.address.city"
                Object value = jsonObject.getByPath(param);
                if (value == null || StrUtil.isEmpty(value.toString())) {
                    burp.print_output(Constant.NO_FOUND_PARAM, param);
                    continue;
                }

                // 加密或解密
                String newValue = _do_enc ? burp.do_encrypt(value.toString().trim()) : burp.do_decrypt(value.toString().trim());

                // 修改 JSON
                jsonObject.putByPath(param, newValue);
            }

            // 格式化 JSON 确保结构正确
            String updateBody = JSONUtil.toJsonPrettyStr(jsonObject);

            // 确保 headers 里有必要的 Header
            if (!headers.contains(burp._Header)) {
                headers.add(burp._Header);
            }

            // 重新构造 HTTP 请求
            return burp.helpers.buildHttpMessage(headers, updateBody.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            burp.print_output(Constant.STACK_INFO, e.getMessage());
            return _request; // 发生异常返回原请求
        }
    }

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
