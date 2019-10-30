package com.kelvin.dhtest;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class DHTest {

    public static void main(String[] args) {

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048);

            // 密钥对1
            KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
            DHPublicKey publicKey1 = (DHPublicKey) keyPair1.getPublic();
            DHPrivateKey privateKey1 = (DHPrivateKey) keyPair1.getPrivate();
            System.out.println(publicKey1);
            System.out.println(privateKey1);

            // 密钥对2
            KeyPair keyPair2 = keyPairGenerator.generateKeyPair();
            DHPublicKey publicKey2 = (DHPublicKey) keyPair2.getPublic();
            DHPrivateKey privateKey2 = (DHPrivateKey) keyPair2.getPrivate();
            System.out.println(publicKey2);
            System.out.println(privateKey2);

            // KeyAgreement1
            KeyAgreement keyAgreement1 = KeyAgreement.getInstance("DH");
            keyAgreement1.init(privateKey1);
            keyAgreement1.doPhase(publicKey2, true);
            byte[] genKey1 = new byte[256];
            int len = keyAgreement1.generateSecret(genKey1, 0);
            System.out.println(Hex.encodeHex(genKey1));
            System.out.println(len);

            // KeyAgreement2
            KeyAgreement keyAgreement2 = KeyAgreement.getInstance("DH");
            keyAgreement2.init(privateKey2);
            keyAgreement2.doPhase(publicKey1, true);
            byte[] genKey2 = keyAgreement2.generateSecret();
            System.out.println(Hex.encodeHex(genKey2));
            System.out.println(genKey2.length);

            // 再试试直接生成secretkey（只是截取前面部分字节）
            KeyAgreement keyAgreement3 = KeyAgreement.getInstance("DH");
            keyAgreement3.init(privateKey2);
            keyAgreement3.doPhase(publicKey1, true);
            SecretKey secretKey = keyAgreement3.generateSecret("AES");
            System.out.println(Hex.encodeHex(secretKey.getEncoded()));


        } catch (NoSuchAlgorithmException | InvalidKeyException | ShortBufferException e) {
            e.printStackTrace();
        }
    }
}
