package burp.strategy;

public interface CipherStrategyFactory {
    String encrypt(String message, String key, String iv, String model) throws Exception;
    String decrypt(String message, String key, String iv, String model) throws Exception;
}
