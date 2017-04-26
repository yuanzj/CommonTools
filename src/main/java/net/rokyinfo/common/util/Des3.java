/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.rokyinfo.common.util;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

public class Des3 {

    public static void main(String[] args) throws Exception {
        byte[] key = new BASE64Decoder().decodeBuffer("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4");
        
        byte[] keyBytes = {0x21, 0x32, 0x5F, 0x68, (byte) 0x98, 0x20, 0x50, 0x48, 0x38, 0x35, (byte) 0x89, 0x51, (byte) 0xDB, (byte) 0xED,
            0x65, 0x76, (byte) 0x87, 0x49, (byte) 0x84, (byte) 0xA8, 0x40, 0x50, 0x46, (byte) 0xF2};
        
        byte[] keyiv = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] data = "RK300-A0Z00250SN".getBytes();
        
        keyBytes = "www.rokyinfo.com12345678".getBytes();
        
//        byte[] data2 = {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74};
//        byte[] data2 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        byte[] data2 = {0x44, 0x35, 0x33, 0x30, 0x33, 0x45, 0x32, 0x42, 0x41, 0x39, 0x30, 0x31, 0x38, 0x34, 0x31, 0x37};
        
        byte[] data3 = {(byte)0x08, (byte)0xFE, (byte)0x86, (byte)0x5A, (byte)0xC2, (byte)0xFA, (byte)0xFA, (byte)0xAA, (byte)0x72, (byte)0xB9, (byte)0x85, (byte)0x01, (byte)0x81, (byte)0xB6, (byte)0x31, (byte)0xBF};
        
        for (int i = 0; i < data.length; i++) {

            String hex = Integer.toHexString(data[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            System.out.println(hex.toUpperCase());
        }

        System.out.println("ECB加密解密");
        byte[] str3 = des3EncodeECB(keyBytes, data);
        byte[] str4 = ees3DecodeECB(keyBytes, data3);
        for (int i = 0; i < str3.length; i++) {

            String hex = Integer.toHexString(str3[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            System.out.println(hex.toUpperCase());
        }
        System.out.println("解密后");
        System.out.println(new String(str4, "UTF-8"));
        for (int i = 0; i < str4.length; i++) {

            String hex = Integer.toHexString(str4[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            System.out.println(hex.toUpperCase());
        }
        System.out.println();
        System.out.println("CBC加密解密");
        byte[] str5 = des3EncodeCBC(keyBytes, keyiv, data2);
        byte[] str6 = des3DecodeCBC(keyBytes, keyiv, str5);
        for (int i = 0; i < str5.length; i++) {

            String hex = Integer.toHexString(str5[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }

            System.out.println(hex.toUpperCase());
        }
        System.out.println(new String(str6, "UTF-8"));
    }

    /**
     * ECB加密,不要IV
     *
     * @param key 密钥
     * @param data 明文
     * @return Base64编码的密文
     * @throws Exception
     */
    public static byte[] des3EncodeECB(byte[] key, byte[] data)
            throws Exception {
        Key deskey = null;
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
        deskey = keyfactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, deskey);
        byte[] bOut = cipher.doFinal(data);
        return bOut;
    }

    /**
     * ECB解密,不要IV
     *
     * @param key 密钥
     * @param data Base64编码的密文
     * @return 明文
     * @throws Exception
     */
    public static byte[] ees3DecodeECB(byte[] key, byte[] data)
            throws Exception {
        Key deskey = null;
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
        deskey = keyfactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, deskey);
        byte[] bOut = cipher.doFinal(data);
        return bOut;
    }

    /**
     * CBC加密
     *
     * @param key 密钥
     * @param keyiv IV
     * @param data 明文
     * @return Base64编码的密文
     * @throws Exception
     */
    public static byte[] des3EncodeCBC(byte[] key, byte[] keyiv, byte[] data)
            throws Exception {
        Key deskey = null;
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
        deskey = keyfactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(keyiv);
        cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);
        byte[] bOut = cipher.doFinal(data);
        return bOut;
    }

    /**
     * CBC解密
     *
     * @param key 密钥
     * @param keyiv IV
     * @param data Base64编码的密文
     * @return 明文
     * @throws Exception
     */
    public static byte[] des3DecodeCBC(byte[] key, byte[] keyiv, byte[] data)
            throws Exception {
        Key deskey = null;
        DESedeKeySpec spec = new DESedeKeySpec(key);
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
        deskey = keyfactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("desede" + "/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(keyiv);
        cipher.init(Cipher.DECRYPT_MODE, deskey, ips);
        byte[] bOut = cipher.doFinal(data);
        return bOut;
    }
}
