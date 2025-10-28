package burp;

import java.awt.Component;
import java.io.PrintWriter;
import burp.common.Constant;
import burp.core.ProcessHttpMessage;
import burp.core.ProcessProxyMessage;

/**
 *
 * @author Magic
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener {
    
    public String ExtensionName =  Constant.BURP_TABLE_NAME;
    public String TabName =  Constant.BURP_TABLE_NAME;
    public String _Header = Constant.TOOL_HEAD_PARAM;
    DecodingTool _decodingTool;
    
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Boolean isDebug = true;
    public Boolean isRunning = false;
    
    public String _host = "";
    public String _enc_type = "";
    public String _secret_key = "";
    public String _iv_param = "";
    public String[] _req_param = new String[]{};
    public String[] _res_param = new String[]{};
    
    public String[] _obffusicatedChar = new String[]{};
    public String[] _replaceWithChar = new String[]{};
    
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
        
        _decodingTool = new DecodingTool(this);
        this.callbacks.addSuiteTab(this);
        this.stdout.println(Constant.INSTALLED_MSG);
    }

    @Override
    public String getTabCaption() {
        return this.TabName;
    }

    @Override
    public Component getUiComponent() {
        return this._decodingTool;
    }
    
    public void startDecodingTool(){
        this.callbacks.registerHttpListener(this);
        this.callbacks.registerProxyListener(this);
        this.isRunning = true;
    }
    
    public void stopDecodingTool(){
        this.callbacks.removeHttpListener(this);
        this.callbacks.removeProxyListener(this);
        this.isRunning = false;
    }


    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            ProcessProxyMessage.request(this, messageInfo);

        } else { //服务器响应离开burp发送到浏览器，最后一步。
            if (this._ignore_response) {
                return;
            }
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            ProcessProxyMessage.response(this, messageInfo);
        }
    }

    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) { //请求离开burp到达服务器之前对数据包进行修改
            ProcessHttpMessage.request(this, messageInfo);
            
        }
        else { //响应从服务器到达burp
            if(this._ignore_response) {
                return;
            }
            ProcessHttpMessage.response(this, messageInfo);
        }
    }

}
