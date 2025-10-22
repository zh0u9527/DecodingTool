/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import burp.strategy.Constant;
import burp.strategy.InitCipherStrategy;

/**
 *
 * @author Magic
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener {
    
    public String ExtensionName =  "AES KillerPro";
    public String TabName =  "AES KillerPro";
    public String _Header = "AES: KillerPro";
    AES_Killer _aes_killer;
    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Boolean isDebug = true;
    public Boolean isRunning = false;
    
    public Cipher cipher;
    public SecretKeySpec sec_key;
    public IvParameterSpec iv_param;
   
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
    
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks.setExtensionName(this.ExtensionName);
        
        _aes_killer = new AES_Killer(this);
        this.callbacks.addSuiteTab(this);
        this.stdout.println("AES_Killer Installed !!!");
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
    
    public String get_host(String _url){
        try{
            URL abc = new URL(_url);
            return abc.getHost().toString();
        }catch (Exception ex){
            print_error("get_endpoint", _url);
            return _url;
        }
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
    
    
    public byte[] update_req_params (byte[] _request, List<String> headers, String[] _params, Boolean _do_enc){
        for(int i = 0 ; i < _params.length; i++){
            IParameter _p = this.helpers.getRequestParameter(_request, _params[i]);
            if (_p == null || _p.getName().toString().length() == 0){ continue; }
            
            String _str = "";
            if(_do_enc) {
                _str = this.do_encrypt(_p.getValue().toString().trim());
            }
            else {
                _str = this.do_decrypt(_p.getValue().toString().trim());
            }
            
            if(this._is_ovrr_req_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            if(this._is_ovrr_res_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }

            
            IParameter _newP = this.helpers.buildParameter(_params[i], _str, _p.getType());
            _request = this.helpers.removeParameter(_request, _p);
            _request = this.helpers.addParameter(_request, _newP);
            if (!headers.contains(this._Header)) { headers.add(this._Header); }
            IRequestInfo reqInfo2 = helpers.analyzeRequest(_request);
            String tmpreq = new String(_request);
            String messageBody = new String(tmpreq.substring(reqInfo2.getBodyOffset())).trim();
            _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
        }
        return _request;
    }
    
    public byte[] update_req_params_json(byte[] _request, List<String> headers, String[] _params, Boolean _do_enc){
        for(int i=0; i< _params.length; i++){
            IParameter _p = this.helpers.getRequestParameter(_request, _params[i]);
            if (_p == null || _p.getName().toString().length() == 0){ continue; }
            
            String _str = "";
            if(_do_enc) {
                _str = this.do_encrypt(_p.getValue().toString().trim());
            }
            else {
                _str = this.do_decrypt(_p.getValue().toString().trim());
            }
            
            
            if(this._is_ovrr_req_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            if(this._is_ovrr_res_body){
                if (!headers.contains(this._Header)) { headers.add(this._Header); }
                _request = this.helpers.buildHttpMessage(headers, _str.getBytes());
                return _request;
            }
            
            
            IRequestInfo reqInfo = helpers.analyzeRequest(_request);
            String tmpreq = new String(_request);
            String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();

            int _fi = messageBody.indexOf(_params[i]);
            if(_fi < 0) { continue; }

            _fi = _fi + _params[i].length() + 3;
            int _si = messageBody.indexOf("\"", _fi);
            print_output("update_req_params_json", _str);
            print_output("update_req_params_json", messageBody.substring(0, _fi));
            print_output("update_req_params_json", messageBody.substring(_si, messageBody.length()));
            if (!headers.contains(this._Header)) { headers.add(this._Header); }
            messageBody = messageBody.substring(0, _fi) + _str + messageBody.substring(_si, messageBody.length());
            _request = this.helpers.buildHttpMessage(headers, messageBody.getBytes());
            
        }
        return _request;
    }
    
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();

            //从请求头中获取参数
            //----
            this._iv_param = getParamFormReqOrResp(headers, Constant.AES_IV_PARAM);
            //----

            if(this._host.contains(get_host(URL))) {
                
                if(this._is_req_body) {
                    // decrypting request body
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();

                    String decValue = this.do_decrypt(messageBody);
                    headers.add(new String(this._Header));
                    byte[] updateMessage = helpers.buildHttpMessage(headers, decValue.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(updateMessage));
                } else if(this._is_req_param){
                    
                    byte[] _request = messageInfo.getRequest();
                    
                    if(reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                        _request = update_req_params_json(_request, headers, this._req_param ,false);
                    }
                    else{
                        _request = update_req_params(_request, headers, this._req_param, false);                        
                    }
                    print_output("PPM-req", "Final Decrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);
                    
                } else {
                    return;
                }
                
            }
        } else {
            if(this._ignore_response) { return; }
            // PPM Response
            
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            String URL = new String(reqInfo.getUrl().toString());
            List headers = resInfo.getHeaders();

            //从请求头中获取参数
            //----
            this._iv_param = getParamFormReqOrResp(headers, Constant.AES_IV_PARAM);
            //----

            if(this._host.contains(this.get_host(URL))){
                
                if(!headers.contains(this._Header)){ return; }
                
                if(this._is_res_body){
                    // Complete Response Body encryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_encrypt(messageBody);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
                }
                else if(this._is_ovrr_res_body){
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_encrypt(messageBody);
                    
                    if(this._is_ovrr_res_body_form){
                        messageBody = this._req_param[0] + "=" + messageBody;
                    }
                    else if(this._is_ovrr_res_body_json){
                        messageBody = "{\"" + this._req_param[0] + "\":\"" + messageBody + "\"}";
                    }
                    
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setResponse(updateMessage);
                    print_output("PPM-res", "Final Encrypted Response\n" + new String(updateMessage));
                }
                else if(this._is_res_param){
                    // implement left --------------------------
                    byte[] _response = messageInfo.getResponse();
                    
                    _response = this.update_req_params_json(_response, headers, this._res_param, true);
                    messageInfo.setResponse(_response);
                    print_output("PHTM-res", "Final Decrypted Response\n" + new String(_response));
                    
                }
                else{
                    return;
                }
            
            }
        }
    }


    /**
     * 用于从请求或响应中获取指定参数
     * @param headers
     * @param paramName
     * @return
     */
    private String getParamFormReqOrResp(List<String> headers, String paramName) {
        for (String header : headers) {
//            if (header.startsWith("X-IV-Param: ")) {
            if (header.startsWith(paramName)) {
                return header.substring(paramName.length());
            }
        }
        return null;
    }

    public void replaceReqOrRespHeadersParam(IHttpRequestResponse messageInfo, String newValue, String paramName) {
        // 获取请求信息
        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = new ArrayList<>(reqInfo.getHeaders());
        int bodyOffset = reqInfo.getBodyOffset();
        byte[] request = messageInfo.getRequest();
        String body = new String(request, bodyOffset, request.length - bodyOffset);

        // 遍历请求头，查找并替换 X-IV-Param 参数
        for (int i = 0; i < headers.size(); i++) {
            String header = headers.get(i);
            if (header.startsWith(paramName)) {
                headers.set(i, paramName + newValue);
                break;
            }
        }
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) { //请求
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
            List headers = reqInfo.getHeaders();
            
            if(!headers.contains(this._Header)){ return; }

            //临时特殊项目
            String tempIv = Utils.getKeyAndIV()[1];
            //对本次请求的加密的iv作出更改
            this._iv_param = tempIv;
            //更新请求头中的解密iv
            replaceReqOrRespHeadersParam(messageInfo, tempIv, Constant.AES_IV_PARAM);
            
            if(this._host.contains(get_host(URL))){
                //针对整个请求体
                if(this._is_req_body) {
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
                    messageBody = this.do_encrypt(messageBody);
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
                }
                //针对覆盖请求体
                else if(this._is_ovrr_req_body){
                    String tmpreq = new String(messageInfo.getRequest());
                    String messageBody = new String(tmpreq.substring(reqInfo.getBodyOffset())).trim();
                    messageBody = this.do_encrypt(messageBody);
                    
                    if(this._is_ovrr_req_body_form){
                        messageBody = this._req_param[0] + "=" + messageBody;
                    }
                    else if(this._is_ovrr_req_body_json){
                        messageBody = "{\"" + this._req_param[0] + "\":\"" + messageBody + "\"}";
                    }
                    
                    byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                    messageInfo.setRequest(updateMessage);
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(updateMessage));
                }
                //请求请求参数
                else if(this._is_req_param){
                    
                    byte[] _request = messageInfo.getRequest();
                    
                    if(reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON){
                        _request = update_req_params_json(_request, headers, this._req_param, true);
                    }
                    else{
                        _request = update_req_params(_request, headers, this._req_param, true);                        
                    }
                    print_output("PHTM-req", "Final Encrypted Request\n" + new String(_request));
                    messageInfo.setRequest(_request);
                }
                else {
                    return;
                }
            }
            
            
        }
        else { //响应
            if(this._ignore_response) { return; }
            
            // PHTM Response
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
            String URL = new String(reqInfo.getUrl().toString());
            List headers = resInfo.getHeaders();

            //从请求头中获取参数
            //----
            this._iv_param = getParamFormReqOrResp(headers, Constant.AES_IV_PARAM);
            //----
            
            if(this._host.contains(this.get_host(URL))){
                //响应体
                if(this._is_res_body){
                    // Complete Response Body decryption
                    String tmpreq = new String(messageInfo.getResponse());
                    String messageBody = new String(tmpreq.substring(resInfo.getBodyOffset())).trim();
                    messageBody = do_decrypt(messageBody);
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
