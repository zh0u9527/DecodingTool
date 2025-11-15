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
 * 处理IHttpListener接口processHttpMessage函数
 */
public class ProcessHttpMessage {
    public static void request(BurpExtender burp,IHttpRequestResponse messageInfo){
        IRequestInfo reqInfo = burp.helpers.analyzeRequest(messageInfo);
        List<String> headers = reqInfo.getHeaders();
        if(!headers.contains(burp._Header)){ return; }
        String reqUrl = CommonUtils.getHost(reqInfo.getUrl().toString());

        if(StrUtil.isBlank(burp._host) || burp._host.contains(reqUrl)) {
            //针对整个请求体
            if (burp._is_req_body) {
                String tmpreq = new String(messageInfo.getRequest());
                String messageBody = tmpreq.substring(reqInfo.getBodyOffset()).trim();

                // 判断是否解密成功，如果解密失败，则直接跳过；防止二次加密，即hash不相等表示解密失败，不需要再次加密
                if (!SecureUtil.md5(messageBody).equals(burp.reqEncryptParamHash))
                    messageBody = Decoder.doEncrypt(burp, messageBody);

                byte[] updateMessage = burp.helpers.buildHttpMessage(headers, messageBody.getBytes());
                messageInfo.setRequest(updateMessage);
                CommonUtils.printOut(burp,"PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
            }
            //请求请求参数
            else if (burp._is_req_param) {

                byte[] _request = messageInfo.getRequest();

                if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
                    _request = Decoder.updateReqParamsJson(burp, _request, headers, burp._req_param, true);
                } else {
                    _request = Decoder.updateReqParams(burp, _request, headers, burp._req_param, true);
                }
                CommonUtils.printOut(burp,"PHTM-req", "Final Encrypted Request\n" + new String(_request));
                messageInfo.setRequest(_request);
            } else {
                return;
            }
        }
    }

    public static void response(BurpExtender burp,IHttpRequestResponse messageInfo){
        IRequestInfo reqInfo = burp.helpers.analyzeRequest(messageInfo);
        IResponseInfo resInfo = burp.helpers.analyzeResponse(messageInfo.getResponse());
        List<String> headers = resInfo.getHeaders();

        String reqUrl = CommonUtils.getHost(reqInfo.getUrl().toString());

        if(StrUtil.isBlank(burp._host) || burp._host.contains(reqUrl)) {
            //响应体
            if(burp._is_res_body){
                // Complete Response Body decryption
                String tmpreq = new String(messageInfo.getResponse());
                String messageBody = tmpreq.substring(resInfo.getBodyOffset()).trim();

                if (CommonUtils.isBase64(messageBody)) {
                    burp.resqEncryptParamHash = SecureUtil.md5(messageBody); // 记录原密文hash
                    messageBody = Decoder.doDecrypt(burp, messageBody);
                }

                headers.add(burp._Header);
                byte[] updateMessage = burp.helpers.buildHttpMessage(headers, messageBody.getBytes());
                messageInfo.setResponse(updateMessage);
                CommonUtils.printOut(burp,"PHTM-res", "Final Decrypted Response\n" + new String(updateMessage));
            }
            //响应体参数
            else if(burp._is_res_param){
                // implement left --------------------------
                byte[] _response = messageInfo.getResponse();

                _response = Decoder.updateReqParamsJson(burp, _response, headers, burp._res_param, false);
                messageInfo.setResponse(_response);
                CommonUtils.printOut(burp,"PHTM-res", "Final Decrypted Response\n" + new String(_response));
            }
            else{
                return;
            }

        }
    }
}
