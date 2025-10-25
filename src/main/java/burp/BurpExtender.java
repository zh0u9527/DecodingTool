package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import burp.common.CommonUtils;
import burp.common.Constant;
import burp.strategy.InitCipherStrategy;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;


/**
 *
 * @author Magic
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener {
    
    public String ExtensionName =  Constant.BURP_TABLE_NAME;
    public String TabName =  Constant.BURP_TABLE_NAME;
    public String _Header = Constant.TOOL_HEAD_PARAM;
    AES_Killer _aes_killer;
    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Boolean isDebug = true;
    public Boolean isRunning = false;
    
    public String _host;
    public String _enc_type;
    public String _secret_key;
    public String _iv_param;
    public String[] _req_param;
    public String[] _res_param;
    
    public String[] _obffusicatedChar;
    public String[] _replaceWithChar;
    
    public Boolean _exclude_iv = false;
    public Boolean _ignore_response = false;
    public Boolean _do_off = false;
    public Boolean _url_enc_dec = false;
    public Boolean _is_req_body = false;
    public Boolean _is_res_body = false;
    public Boolean _is_req_param = false;
    public Boolean _is_res_param = false;
    public Boolean _is_ovrr_req_body = false;
    public Boolean _is_ovrr_res_body = false;
    public Boolean _is_ovrr_req_body_form = false;
    public Boolean _is_ovrr_res_body_form = false;
    public Boolean _is_ovrr_req_body_json = false;
    public Boolean _is_ovrr_res_body_json = false;

    public String reqEncryptParamHash;
    public String resqEncryptParamHash;

    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks.setExtensionName(this.ExtensionName);
        
        _aes_killer = new AES_Killer(this);
        this.callbacks.addSuiteTab(this);
        this.stdout.println(Constant.INSTALLED_MSG);
    }

    @Override
    public String getTabCaption() {
        return this.TabName;
    }

    @Override
    public Component getUiComponent() {
        return this._aes_killer;
    }
    
    public void start_aes_killer(){
        this.callbacks.registerHttpListener(this);
        this.callbacks.registerProxyListener(this);
        this.isRunning = true;
    }
    
    public void stop_aes_killer(){
        this.callbacks.removeHttpListener(this);
        this.callbacks.removeProxyListener(this);
        this.isRunning = false;
    }
    
    private void print_output(String _src, String str){
        if(! isDebug){ return; }
        this.stdout.println(_src + " :: " + str);
    }
    
    private void print_error(String _src, String str){
        if(! isDebug){ return; }
        this.stderr.println(_src + " :: " + str);
    }
    


    public String remove_0bff(String _paramString) {
        //增强部分
        return replace0(_paramString);
    }
    
    public String do_0bff(String _paramString) {
        //增强部分
        return replace1(_paramString);
    }
    
    public String replace0(String str) {
        for (int i = 0; i < this._obffusicatedChar.length; i++) {
            if (str.contains(this._obffusicatedChar[i])) {
                str = str.replace(this._obffusicatedChar[i], this._replaceWithChar[Math.min(i, this._replaceWithChar.length - 1)]);
            }
        }
        return str;
    }

    public String replace1(String str) {
        return this._obffusicatedChar[0] + str + this._obffusicatedChar[0];
    }
    
    public String do_decrypt(String _enc_str){
       return this.do_decrypt(_enc_str, true);
    }

    /**
     * 通过重载原来的方法来适配文本框的加解密问题，即如果文本框加解密数据时不需要过滤指定字符，如果是burp当中http的请求则需要过滤给定的字符。
     * @param _enc_str
     * @param f true表示过滤（burp http请求），false表示不过滤（用户输入的数据）
     * @return
     */
    public String do_decrypt(String _enc_str, boolean f){
        try{
            //适配文本框加解密
            //增强逻辑
            if (f){
                _enc_str = remove_0bff(_enc_str);
            }

            //进入加密

            _enc_str = InitCipherStrategy.selectMode(_enc_str, _secret_key, _iv_param, _enc_type, false);
            return _enc_str;
        }catch(Exception ex){
            print_error("do_decrypt", ex.getMessage());
            return _enc_str;
        }
    }

    public String do_encrypt(String _dec_str){
        return this.do_encrypt(_dec_str, true);
    }

    public String do_encrypt(String _dec_str, boolean f){
        try{
            //适配文本框加解密
            //增强解密

            //进入解密
            /*
            这里临时项目，在进入解密之前需要判断
             */

            _dec_str = InitCipherStrategy.selectMode(_dec_str, _secret_key, _iv_param, _enc_type, true);
            if (f){
                return do_0bff(_dec_str);
            }
            return _dec_str;
        }catch(Exception ex){
            print_error("do_decrypt", ex.getMessage());
            return _dec_str;
        }
    }


    public byte[] update_req_params(byte[] _request, List<String> headers, String[] _params, Boolean _do_enc) {
        IRequestInfo reqInfo = this.helpers.analyzeRequest(_request);
        String method = reqInfo.getMethod();
        List<IParameter> allParams = reqInfo.getParameters();

        // 不再构造 message，只补 header
        if (!headers.contains(this._Header)) {
            headers.add(this._Header);
        }

        IRequestInfo newInfo = this.helpers.analyzeRequest(_request);
        byte[] body = Arrays.copyOfRange(_request, newInfo.getBodyOffset(), _request.length);
        _request = this.helpers.buildHttpMessage(headers, body);

        for (String paramName : _params) {
            IParameter targetParam = this.helpers.getRequestParameter(_request, paramName);
            if (targetParam == null || targetParam.getName().isEmpty()) {
                continue;
            }

            String newValue = _do_enc ? this.do_encrypt(targetParam.getValue().trim()) : this.do_decrypt(targetParam.getValue().trim());

            // 特殊处理请求体覆盖模式
            if (this._is_ovrr_req_body || this._is_ovrr_res_body) {
                if (!headers.contains(this._Header)) {
                    headers.add(this._Header);
                }
                return this.helpers.buildHttpMessage(headers, newValue.getBytes());
            }

            IParameter newParam = null;
            boolean updated = false;

            if ("POST".equalsIgnoreCase(method)) {
                if (targetParam.getType() == IParameter.PARAM_BODY) {
                    newParam = this.helpers.buildParameter(paramName, newValue, IParameter.PARAM_BODY);
                    updated = true;
                } else {
                    for (IParameter param : allParams) {
                        if (param.getType() == IParameter.PARAM_BODY && param.getName().equals(paramName)) {
                            _request = this.helpers.removeParameter(_request, param);
                            newParam = this.helpers.buildParameter(paramName, newValue, IParameter.PARAM_BODY);
                            updated = true;
                            break;
                        }
                    }
                    if (!updated && targetParam.getType() == IParameter.PARAM_URL) {
                        newParam = this.helpers.buildParameter(paramName, newValue, IParameter.PARAM_URL);
                        updated = true;
                    }
                }
            } else if ("GET".equalsIgnoreCase(method)) {
                if (targetParam.getType() == IParameter.PARAM_URL) {
                    newParam = this.helpers.buildParameter(paramName, newValue, IParameter.PARAM_URL);
                    updated = true;
                }
            }

            if (updated && newParam != null) {
                _request = this.helpers.removeParameter(_request, targetParam);
                _request = this.helpers.addParameter(_request, newParam);
            }

        }

        return _request;
    }

    public byte[] update_req_params_json(byte[] _request, List<String> headers, String[] _params, Boolean _do_enc) {
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(_request);
            // 获取请求体
            String reqBody = new String(_request, StandardCharsets.UTF_8).substring(reqInfo.getBodyOffset()).trim();

            // 解析 JSON
            JSONObject jsonObject = JSONUtil.parseObj(reqBody);

            for (String param : _params) {
                // 使用 JSONUtil.getByPath() 支持嵌套参数，如 "user.address.city"
                Object value = jsonObject.getByPath(param);
                if (value == null || StrUtil.isEmpty(value.toString())) {
                    this.print_output(Constant.NO_FOUND_PARAM, param);
                    continue;
                }

                // 加密或解密
                String newValue = _do_enc ? this.do_encrypt(value.toString().trim()) : this.do_decrypt(value.toString().trim());

                // 修改 JSON
                jsonObject.putByPath(param, newValue);
            }

            // 格式化 JSON 确保结构正确
            String updateBody = JSONUtil.toJsonPrettyStr(jsonObject);

            // 确保 headers 里有必要的 Header
            if (!headers.contains(this._Header)) {
                headers.add(this._Header);
            }

            // 重新构造 HTTP 请求
            return this.helpers.buildHttpMessage(headers, updateBody.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            this.print_output(Constant.STACK_INFO, e.getMessage());
            return _request; // 发生异常返回原请求
        }
    }
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = reqInfo.getHeaders();
            String whiteHost = CommonUtils.getHost(reqInfo.getUrl().toString());

            if(StrUtil.isBlank(whiteHost) || this._host.contains(whiteHost)) {
                if (this._is_req_body) {
                    // decrypting request body
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = tmpreq.substring(reqInfo.getBodyOffset()).trim();

                    this.reqEncryptParamHash = SecureUtil.md5(messageBody);

                    String decValue = this.do_decrypt(messageBody);
                    headers.add(this._Header);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, decValue.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(updateMessage));
                } else if (this._is_req_param) {

                    byte[] _request = messageInfo.getRequest();

                    if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
                        _request = update_req_params_json(_request, headers, this._req_param, false);
                    } else {
                        _request = update_req_params(_request, headers, this._req_param, false);
                    }
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);

                } else {
                    return;
                }
            }
        } else { //服务器响应离开burp发送到浏览器，最后一步。
            if(this._ignore_response) { return; }
            // PPM Response

            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            List<String> headers = resInfo.getHeaders();
            if(!headers.contains(this._Header)){ return; }

            String whiteHost = CommonUtils.getHost((reqInfo.getUrl().toString()));

            if(StrUtil.isBlank(whiteHost) || this._host.contains(whiteHost)) {

                if (this._is_res_body) {
                    // Complete Response Body encryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = tmpreq.substring(resInfo.getBodyOffset()).trim();

                    // 判断是否解密成功，如果解密失败，则直接跳过；防止二次加密，即hash不相等表示解密失败，不需要再次加密
                    if (!SecureUtil.md5(messageBody).equals(this.resqEncryptParamHash))
                        messageBody = this.do_encrypt(messageBody);

                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
                } else if (this._is_res_param) {
                    // implement left --------------------------
                    byte[] _response = messageInfo.getResponse();

                    _response = this.update_req_params_json(_response, headers, this._res_param, true);
                    messageInfo.setResponse(_response);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(_response));

                } else {
                    return;
                }
            }
        }
    }

    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) { //请求离开burp到达服务器之前对数据包进行修改
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = reqInfo.getHeaders();
            if(!headers.contains(this._Header)){ return; }
            String whiteHost = CommonUtils.getHost((reqInfo.getUrl().toString()));

            if(StrUtil.isBlank(whiteHost) || this._host.contains(whiteHost)) {
                //针对整个请求体
                if (this._is_req_body) {
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = tmpreq.substring(reqInfo.getBodyOffset()).trim();

                    // 判断是否解密成功，如果解密失败，则直接跳过；防止二次加密，即hash不相等表示解密失败，不需要再次加密
                    if (!SecureUtil.md5(messageBody).equals(this.reqEncryptParamHash))
                        messageBody = this.do_encrypt(messageBody);

                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
                }
                //请求请求参数
                else if (this._is_req_param) {

                    byte[] _request = messageInfo.getRequest();

                    if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON) {
                        _request = update_req_params_json(_request, headers, this._req_param, true);
                    } else {
                        _request = update_req_params(_request, headers, this._req_param, true);
                    }
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);
                } else {
                    return;
                }
            }
            
        }
        else { //响应从服务器到达burp
            if(this._ignore_response) { return; }
            
            // PHTM Response
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            List<String> headers = resInfo.getHeaders();

            String whiteHost = CommonUtils.getHost((reqInfo.getUrl().toString()));

            if(StrUtil.isBlank(whiteHost) || this._host.contains(whiteHost)) {
                //响应体
                if(this._is_res_body){
                    // Complete Response Body decryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = tmpreq.substring(resInfo.getBodyOffset()).trim();

                    if (CommonUtils.isBase64(messageBody)) {
                        this.resqEncryptParamHash = SecureUtil.md5(messageBody); // 记录原密文hash
                        messageBody = do_decrypt(messageBody);
                    }

                    headers.add(this._Header);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(updateMessage));
                }
                //响应体参数
                else if(this._is_res_param){
                    // implement left --------------------------
                    byte[] _response = messageInfo.getResponse();
                    
                    _response = this.update_req_params_json(_response, headers, this._res_param, false);
                    messageInfo.setResponse(_response);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(_response));
                }
                else{
                    return;
                }
                
            }
            
            
        }
    }

}
