package burp.strategy.impl;

import burp.strategy.CipherStrategyFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64DEncodeStrategyFactory implements CipherStrategyFactory {
    @Override
    public String encrypt(String message, String key, String iv, String model) throws Exception {
        return Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String decrypt(String message, String key, String iv, String model) throws Exception {
        return new String(Base64.getDecoder().decode(message.getBytes()));
    }
}
