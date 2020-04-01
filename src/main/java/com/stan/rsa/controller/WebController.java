package com.stan.rsa.controller;

import com.stan.rsa.utils.RSAUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author：stanzeng
 * @Description：登陆解密密码
 * @Date ：Created in 2020/4/1 3:56 下午
 * @Modified By：
 */
@Controller
public class WebController {

    @Value("${rsa.publicKey}")
    private String rsaPublicKey;

    @Value("${rsa.privateKey}")
    private String rsaPrivateKey;

    @RequestMapping("/")
    public String home() {
        System.out.println("rsaPublicKey: " + rsaPublicKey);
        return "index";
    }

    @RequestMapping("/test")
    public String test() {
        System.out.println("rsaPublicKey: " + rsaPublicKey);
        return "test";
    }

    /**
     * 登陆接口， 解密password
     * @param username
     * @param password
     * @return
     */
    @RequestMapping("/api/login")
    @ResponseBody
    public Object login(@RequestParam String username,
                        @RequestParam String password
    ) {
        try {
            // 解密得到原始明文密码
            String originPwd = RSAUtil.decrypt(password, rsaPrivateKey);

            Map<String, Object> res = new HashMap<>();
            res.put("code", 200);
            res.put("msg", "解密ok") ;
            res.put("username", username);
            res.put("password", originPwd);
            return res;
        } catch (Exception e) {
            e.printStackTrace();
        }

        Map<String, Object> res = new HashMap<>();
        res.put("code", -1);
        res.put("msg", "解密失败") ;
        return res;
    }
}
