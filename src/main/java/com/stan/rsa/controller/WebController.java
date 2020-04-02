package com.stan.rsa.controller;

import com.stan.rsa.utils.RSAUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author：stanzeng
 * @Description：登陆解密密码
 * @Date ：Created in 2020/4/1 3:56 下午
 * @Modified By：
 */
@RestController
public class WebController {

    @Value("${rsa.publicKey}")
    private String rsaPublicKey;

    @Value("${rsa.privateKey}")
    private String rsaPrivateKey;

    /**
     * 登陆接口， 解密password
     *
     * @param username
     * @param password
     * @return
     */
    @RequestMapping("/api/login")
    public Object login(@RequestParam(required = false) String username,
                        @RequestParam(required = false) String password
    ) {
        System.out.println("rsaPublicKey: " + rsaPublicKey);

        try {
            // 解密得到原始明文密码
            String originPwd = RSAUtil.decrypt(password, rsaPrivateKey);

            Map<String, Object> res = new HashMap<>();
            res.put("code", 200);
            res.put("msg", "解密ok");
            res.put("username", username);
            res.put("password", originPwd);
            return res;
        } catch (Exception e) {
            e.printStackTrace();
        }

        Map<String, Object> res = new HashMap<>();
        res.put("code", -1);
        res.put("msg", "解密失败");
        return res;
    }

    @RequestMapping("/api/test")
    public Object test() {
        Map<String, Object> res = new HashMap<>();
        res.put("code", 200);
        res.put("msg", "test");
        return res;
    }
}
