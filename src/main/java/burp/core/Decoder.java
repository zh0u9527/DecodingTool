package burp.core;

import burp.BurpExtender;
import burp.IParameter;
import burp.IRequestInfo;
import burp.common.CommonUtils;
import burp.common.Constant;
import burp.strategy.InitCipherStrategy;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 专门用于处理加解密流程问题
 */
public class Decoder {
    private static String remove0bff(BurpExtender burp, String _paramString) {
        //增强部分
        return replace0(burp, _paramString);
    }

    private static String do0bff(BurpExtender burp, String _paramString) {
        //增强部分
        return replace1(burp, _paramString);
    }

    private static String replace0(BurpExtender burp, String str) {
        for (int i = 0; i < burp._obffusicatedChar.length; i++) {
            if (str.contains(burp._obffusicatedChar[i])) {
                str = str.replace(burp._obffusicatedChar[i], burp._replaceWithChar[Math.min(i, burp._replaceWithChar.length - 1)]);
            }
        }
        return str;
    }

    private static String replace1(BurpExtender burp, String str) {
        return burp._obffusicatedChar[0] + str + burp._obffusicatedChar[0];
    }

    public static String doDecrypt(BurpExtender burp,String _enc_str){
        return doDecrypt(burp, _enc_str, true);
    }

    /**
     * 通过重载原来的方法来适配文本框的加解密问题，即如果文本框加解密数据时不需要过滤指定字符，如果是burp当中http的请求则需要过滤给定的字符。
     * @param _enc_str
     * @param isReplace true表示过滤（burp http请求），false表示不过滤（用户输入的数据）
     * @return
     */
    public static String doDecrypt(BurpExtender burp, String _enc_str, boolean isReplace){
        try{
            if (isReplace)
                _enc_str = remove0bff(burp, _enc_str);

            //进入加密
            _enc_str = InitCipherStrategy.selectMode(_enc_str, burp._secret_key, burp._iv_param, burp._enc_type, false);
            return _enc_str;
        }catch(Exception ex){
            CommonUtils.printErr(burp,"do_decrypt", ex.getMessage());
            return _enc_str;
        }
    }


    public static String doEncrypt(BurpExtender burp, String _dec_str){
        return doEncrypt(burp, _dec_str, true);
    }

    /**
     * 该函数的作用是用来插件中明文输入区域的加密
     * @param burp
     * @param _dec_str
     * @param isReplace
     * @return
     */
    public static String doEncrypt(BurpExtender burp, String _dec_str, boolean isReplace){
        try{
            _dec_str = InitCipherStrategy.selectMode(_dec_str, burp._secret_key, burp._iv_param, burp._enc_type, true);

            if (isReplace)
                return do0bff(burp, _dec_str);
            return _dec_str;
        }catch(Exception ex){
            CommonUtils.printErr(burp,"do_decrypt", ex.getMessage());
            return _dec_str;
        }
    }

    /**
     * 加解密url编码格式的参数
     * @param burp
     * @param _request
     * @param headers
     * @param _params
     * @param _do_enc
     * @return
     */
    public static byte[] updateReqParams(BurpExtender burp, byte[] _request, List<String> headers, String[] _params, Boolean _do_enc) {
        IRequestInfo reqInfo = burp.helpers.analyzeRequest(_request);
        String method = reqInfo.getMethod();
        List<IParameter> allParams = reqInfo.getParameters();

        // 确保 header 只加一次
        if (!headers.contains(burp._Header)) {
            headers.add(burp._Header);
        }

        // POST body
        byte[] body = Arrays.copyOfRange(_request, reqInfo.getBodyOffset(), _request.length);
        _request = burp.helpers.buildHttpMessage(headers, body);

        Map<String, String> updatedParams = new HashMap<>();

        for (String paramName : _params) {
            IParameter targetParam = burp.helpers.getRequestParameter(_request, paramName);
            if (targetParam == null || targetParam.getName().isEmpty()) {
                continue;
            }

            String value = targetParam.getValue().trim();
            String newValue;

            try {
                if (_do_enc) { // true表示加密，false表示解密
                    // 解密前先 URLDecode
                    value = Decoder.doEncrypt(burp, value);
                    newValue = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
                } else {
                    // 加密后再 URLEncode
                    value = URLDecoder.decode(value, StandardCharsets.UTF_8.name());
                    newValue = Decoder.doDecrypt(burp, value);
                }
            } catch (UnsupportedEncodingException e) {
                CommonUtils.printErr(burp,"updateReqParams", e.getMessage());
                throw  new RuntimeException(e);
            }

            updatedParams.put(paramName, newValue);
        }

        // 更新请求参数
        for (Map.Entry<String, String> entry : updatedParams.entrySet()) {
            String paramName = entry.getKey();
            String newValue = entry.getValue();
            IParameter oldParam = burp.helpers.getRequestParameter(_request, paramName);
            if (oldParam != null) {
                IParameter newParam = burp.helpers.buildParameter(paramName, newValue, oldParam.getType());
                _request = burp.helpers.removeParameter(_request, oldParam);
                _request = burp.helpers.addParameter(_request, newParam);
            }
        }

        // 覆盖模式特殊处理
        if (burp._is_ovrr_req_body || burp._is_ovrr_res_body) {
            return burp.helpers.buildHttpMessage(headers, Arrays.toString(_request).getBytes(StandardCharsets.UTF_8));
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
                    CommonUtils.printOut(burp, Constant.NO_FOUND_PARAM, param);
                    continue;
                }

                // 加密或解密
                String newValue = _do_enc ? Decoder.doEncrypt(burp,value.toString().trim()) : Decoder.doDecrypt(burp,value.toString().trim());

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
            CommonUtils.printOut(burp,Constant.STACK_INFO, e.getMessage());
            return _request; // 发生异常返回原请求
        }
    }
}
