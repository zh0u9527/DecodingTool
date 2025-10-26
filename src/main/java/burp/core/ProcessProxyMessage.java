package burp.core;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
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
        String whiteHost = CommonUtils.getHost(reqInfo.getUrl().toString());

        if(StrUtil.isBlank(whiteHost) || burp._host.contains(whiteHost)) {
            if (burp._is_req_body) {
                // decrypting request body
                String tmpreq = new String(messageInfo.getRequest());
                String messageBody = tmpreq.substring(reqInfo.getBodyOffset()).trim();

                burp.reqEncryptParamHash = SecureUtil.md5(messageBody);

                String decValue = burp.do_decrypt(messageBody);
                headers.add(burp._Header);
                byte[] updateMessage = burp.helpers.buildHttpMessage(headers, decValue.getBytes());
                messageInfo.setRequest(updateMessage);
                burp.print_output("PPM-req", "Final Decrypted Request\n" + new String(updateMessage));
            } else if (burp._is_req_param) {

                byte[] _request = messageInfo.getRequest();

                if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
                    _request = CommonUtils.updateReqParamsJson(burp, _request, headers, burp._req_param, false);
                } else {
                    _request = CommonUtils.updateReqParams(burp, _request, headers, burp._req_param, false);
                }
                burp.print_output("PPM-req", "Final Decrypted Request\n" + new String(_request));
                messageInfo.setRequest(_request);

            } else {
                return;
            }
        }

    }

    public static void response(){

    }
}
