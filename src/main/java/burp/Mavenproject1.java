/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package burp;

import burp.common.RsaUtils;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;

/**
 *
 * @author zhous
 */
public class Mavenproject1 {

    public static void main(String[] args) {
        String msg = "hello world";

        String cipher = RsaUtils.serverRsaEncrypt(msg);
        System.out.println(RsaUtils.serverRsaEncrypt(cipher));

        String text = RsaUtils.localRsaDecrypt(cipher);
        System.out.println(text);
    }
}
