package com.stan.jwtdemo;

import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class JwtDemo {

    private static final String RSA_KEY = "RSA";

    public static void main(String[] args) throws Exception {
        String secretKey = "123455666";

        Map<String, Object> map = new HashMap<String, Object>() {
            private static final long serialVersionUID = 1L;

            {
                put("uid", Integer.parseInt("123"));
                put("exp", System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 15);
            }
        };

        String id = "rs256";
//        JWTSigner signer = JWTSignerUtil.createSigner(id,
//                // 随机生成密钥对，此处用户可自行读取`KeyPair`、公钥或私钥生成`JWTSigner`
//                KeyUtil.generateKeyPair(AlgorithmUtil.getAlgorithm(id)));

        JWTSigner signer = JWTSignerUtil.createSigner(id, getPrivateKey());

        String token = JWTUtil.createToken(map, signer);

        System.out.println("createToken: " + token);

        JWTSigner pubSigner = JWTSignerUtil.createSigner(id, getPublicKey());
        try {
            System.out.println("verify结果：" + JWTUtil.verify(token, pubSigner));
        } catch (Exception e) {
            System.out.println(e);
        }

        JWT jwt = JWTUtil.parseToken(token);
        System.out.println(jwt.getPayloads());
    }

    public static PrivateKey getPrivateKey() throws Exception {
        // 这里的key 需要使用将 rsa_private.pem 转换
        /**
         * openssl pkcs8 -topk8 -inform PEM -in rsa_private.pem -outform pem -nocrypt -out pkcs8Private.key
         */
        String priKeyStr = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANtwm1IHRNSwWaHl\n" +
                "FV8m1qjWhwGnXTlurMKniALw4wq0OODBBY0Dj2Ub770sdzLKcE2RaWgPxNR62VXX\n" +
                "ln/ToA73WDdT4IW8ioZGhpYhj3GVL5yAXcFMFNboLP2k31vRyOcbopVHJ7uUSLu6\n" +
                "vQkMO44MYvj0ABn8dtxWX/to1NA7AgMBAAECgYEAvAyZ7gewopullCle0TXVSsbc\n" +
                "1zv3ldoUTpOG6Q5JYsji3ShMe3WLktgH8JOEapA1ASQVskmhIX1NdlTT8iMGy3Y/\n" +
                "C6U+QuQhlM3UGCIAmDh6OIJr6a36AOE1PaIBuRlFLXHmx9YMQA7b1W38bcLaC+c6\n" +
                "BOd+4boPq0hlETljuiECQQDw9WATE/C/sYdCR58lM2OUztwYygNfYctFA/+5g5+c\n" +
                "jgTn8j8HmPvTn/cch7MOzSsA15Y+uNeQAab4TXfbmTqJAkEA6SNaqCTf4LicMlNg\n" +
                "dDXwCjHCvp6QDQvPCy2828NSHWhKH/pa1tYOxOrJzly9DhsrDhHxvSWYiJ8VXkod\n" +
                "9vFzowJBAI/zByJel0Tt2dBO2VRwDt2ndvWYOcuRsM3aRbueVoxAi83FesIfMtKK\n" +
                "jiYNK3t8NmSaZrex1ZXCZu2P2jrmn4ECQAG4xR6gxxZ9xomInBm/nDo3C90khqPS\n" +
                "BoFqoQ5ubtjQwFtkGe+kPQ+vPDZN8Qd9o9/CuipPcMTxh9LecUI1nkkCQQCuk/SV\n" +
                "w9kEDzuVDm1D1FPEEcLKMxGSTjaz/DsolecMxTSw6K+5emhObuudhOowOie2LaOd\n" +
                "kCiWuhji0RzxNllR";
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyStr));
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_KEY);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    public static PublicKey getPublicKey() throws Exception {
        String publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbcJtSB0TUsFmh5RVfJtao1ocB\n" +
                "p105bqzCp4gC8OMKtDjgwQWNA49lG++9LHcyynBNkWloD8TUetlV15Z/06AO91g3\n" +
                "U+CFvIqGRoaWIY9xlS+cgF3BTBTW6Cz9pN9b0cjnG6KVRye7lEi7ur0JDDuODGL4\n" +
                "9AAZ/HbcVl/7aNTQOwIDAQAB";

        byte[] keyBytes = Base64.decodeBase64(publicKeyStr);
        PublicKey publicKey = KeyFactory.getInstance(RSA_KEY).generatePublic(new X509EncodedKeySpec(keyBytes));
        return publicKey;
    }
}
