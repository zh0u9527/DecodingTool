package burp.core;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.common.CommonUtils;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;

import java.util.List;

/**
 * 处理IProxyListener接口processProxyMessage函数
 */
public class ProcessProxyMessage {

    public static void request(BurpExtender burp, IHttpRequestResponse messageInfo){

        IRequestInfo reqInfo = burp.helpers.analyzeRequest(messageInfo);
        List<String> headers = reqInfo.getHeaders();
        // 这里获取的是请求的URL，而不是插件的白名单
        String reqUrl = CommonUtils.getHost(reqInfo.getUrl().toString());

        // 处理签名问题，如果不需要修改参与签名计算的参数，这里可以忽略
        if (!StrUtil.isBlank(burp._signature) && !StrUtil.isBlank(CommonUtils.getHeaderParamValue(headers, burp._signature))) {

        }

        if(StrUtil.isBlank(burp._host) || burp._host.contains(reqUrl)) {
            if (burp._is_req_body) {
                // decrypting request body
                String tmpreq = new String(messageInfo.getRequest());
                String messageBody = tmpreq.substring(reqInfo.getBodyOffset()).trim();

                burp.reqEncryptParamHash = SecureUtil.md5(messageBody);

                String decValue = Decoder.doDecrypt(burp, messageBody);
                headers.add(burp._Header);
                byte[] updateMessage = burp.helpers.buildHttpMessage(headers, decValue.getBytes());
                messageInfo.setRequest(updateMessage);
                CommonUtils.printOut(burp, "PPM-req", "Final Decrypted Request\n" + new String(updateMessage));
            } else if (burp._is_req_param) {

                byte[] _request = messageInfo.getRequest();

                if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
                    _request = Decoder.updateReqParamsJson(burp, _request, headers, burp._req_param, false);
                } else {
                    _request = Decoder.updateReqParams(burp, _request, headers, burp._req_param, false);
                }
                CommonUtils.printOut(burp, "PPM-req", "Final Decrypted Request\n" + new String(_request));
                messageInfo.setRequest(_request);

            } else {
                return;
            }
        }

    }

    public static void response(BurpExtender burp, IHttpRequestResponse messageInfo){
        IRequestInfo reqInfo = burp.helpers.analyzeRequest(messageInfo);
        IResponseInfo resInfo = burp.helpers.analyzeResponse(messageInfo.getResponse());
        List<String> headers = resInfo.getHeaders();
        if(!headers.contains(burp._Header)){ return; }

        String reqUrl = CommonUtils.getHost(reqInfo.getUrl().toString());

        if(StrUtil.isBlank(burp._host) || burp._host.contains(reqUrl)) {
            if (burp._is_res_body) {
                // Complete Response Body encryption
                String tmpreq = new String(messageInfo.getResponse());
                String messageBody = tmpreq.substring(resInfo.getBodyOffset()).trim();

                // 判断是否解密成功，如果解密失败，则直接跳过；防止二次加密，即hash不相等表示解密失败，不需要再次加密
                if (!SecureUtil.md5(messageBody).equals(burp.resqEncryptParamHash))
                    messageBody = Decoder.doEncrypt(burp, messageBody);

                byte[] updateMessage = burp.helpers.buildHttpMessage(headers, messageBody.getBytes());
                messageInfo.setResponse(updateMessage);
                CommonUtils.printOut(burp, "PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
            } else if (burp._is_res_param) {
                // implement left --------------------------
                byte[] _response = messageInfo.getResponse();

                _response = Decoder.updateReqParamsJson(burp, _response, headers, burp._res_param, true);
                messageInfo.setResponse(_response);
                CommonUtils.printOut(burp, "PHTM-res", "Final Decrypted Response\n" + new String(_response));
            } else {
                return;
            }
        }
    }
}
