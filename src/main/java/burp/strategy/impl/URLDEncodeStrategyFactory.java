package burp.strategy.impl;

import burp.strategy.CipherStrategyFactory;

import java.net.URLDecoder;
import java.net.URLEncoder;

public class URLDEncodeStrategyFactory implements CipherStrategyFactory {
    @Override
    public String encrypt(String message, String key, String iv, String model) throws Exception {
        return URLEncoder.encode(message, "UTF-8");
    }

    @Override
    public String decrypt(String message, String key, String iv, String model) throws Exception {
        return URLDecoder.decode(message, "UTF-8");
    }
}
