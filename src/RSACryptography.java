import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSACryptography {

    public static String data="hello world";
    public static String publicKeyString=
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOxw5q2Gio+aMCVIJNkB/NvRzj" +
                    "Y13eD/mqnVUBcpizq1lq/3eNOgUBBo8Fy4hThU2XcAXV8B5O9fwkmP58ajkC/M6N" +
                    "3CAclHV9tO2wZMAco0bpOBMa74SPt+2lWSomf89sD7JgrM41yDZ21+mnmY92leij" +
                    "LsUElPSOcMy12uGDvQIDAQAB" ;
    public static String privateKeyString=
            "MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAI7HDmrYaKj5owJU" +
                    "gk2QH829HONjXd4P+aqdVQFymLOrWWr/d406BQEGjwXLiFOFTZdwBdXwHk71/CSY" +
                    "/nxqOQL8zo3cIByUdX207bBkwByjRuk4ExrvhI+37aVZKiZ/z2wPsmCszjXINnbX" +
                    "6aeZj3aV6KMuxQSU9I5wzLXa4YO9AgMBAAECgYAUL8y4CpTxnyoPAEfUE5aLjjtx" +
                    "YvE4nmWcW9ZS+BLjBE0GNcx/aT6f4H+EQDysImLQEISitOp0G49k1US9wBsjxhnH" +
                    "RAn7gMyeWauxqwJMaL02786Wjut309mTmZ9aGf6Niu2VTeS4A5mNN8Mc7k2PFp+T" +
                    "fiByifeGHmgbT8wVeQJFAKsHA5Uo9/VM6tEygv5/BinvrNsDt0OlEGp/xn/ZaCHt" +
                    "JrPcyYUejJVGcZU3bT6O6jx0daK85foKBKHEHp2tv5tFUU8nAj0A1bbxqgZbsrgO" +
                    "vhFpXZgQSdk6lez3ZzFxyf1KpqdphNP6nMgeseEcSWMJ2KR9C+KeJmzOPKiZjEFS" +
                    "OSR7AkQNLGUiQB2ZT2tm4bUlVTNsV4HA/PBIzZYOHfl0L5LNyi6I/CCpmEjL1rk4" +
                    "/SP1BZ0VOwM0ncg5Ejx5GVoiWxe/Jf+1UQI8MYcYMmMO1Tg6kmnOlVYsUDD7lss3" +
                    "+r5GtJzys/SQS6wkpDjshCS7PXaqTX6xTBPUuur0ULJyA0MQHxYJAkRjZAZoe3WV" +
                    "HmRzLf8ncJHhKOXFJES6itawmRF5Q0F5GsinghhINtpVUx5D+fd7zU6ZYszUGTbC" +
                    "0sdSovKlvYRsGnMi+g==" ;

    public static void main(String[] args) throws Exception {
        // TODO Auto-generated method stub


        //获取公钥
        PublicKey publicKey=getPublicKey(publicKeyString);

        //获取私钥
        PrivateKey privateKey=getPrivateKey(privateKeyString);

        //公钥加密
        byte[] encryptedBytes=encrypt(data.getBytes(), publicKey);
        System.out.println("加密后："+new String(encryptedBytes));

        //私钥解密
        byte[] decryptedBytes=decrypt(encryptedBytes, privateKey);
        System.out.println("解密后："+new String(decryptedBytes));
    }

    //将base64编码后的公钥字符串转成PublicKey实例
    public static PublicKey getPublicKey(String publicKey) throws Exception{
        byte[ ] keyBytes=Base64.getDecoder().decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec=new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    //将base64编码后的私钥字符串转成PrivateKey实例
    public static PrivateKey getPrivateKey(String privateKey) throws Exception{
        byte[ ] keyBytes=Base64.getDecoder().decode(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec=new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, PublicKey publicKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");//java默认"RSA"="RSA/ECB/PKCS1Padding"
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, PrivateKey privateKey) throws Exception{
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(content);
    }

}