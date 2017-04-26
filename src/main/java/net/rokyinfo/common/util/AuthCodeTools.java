package net.rokyinfo.common.util;

import sun.misc.BASE64Encoder;

import java.util.Random;

/**
 * Created by yuanzhijian on 2017/4/26.
 */
public class AuthCodeTools {

    public static String getAuthCode(String authCode,String ueSn) {

        byte[] keyBytes = "www.rokyinfo.com12345678".getBytes(); //24字节的密钥

        if (authCode != null) {

            keyBytes = authCode.getBytes();
        }

        String szSrc = ueSn;

        Random random = new Random();
        while (szSrc.length() < 16) {

            szSrc += String.valueOf(random.nextInt(10));
        }

        byte[] encoded = new byte[0];
        try {
            encoded = Des3.des3EncodeECB(keyBytes, szSrc.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BASE64Encoder().encode(encoded);
    }
}
