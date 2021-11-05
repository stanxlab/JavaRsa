
# RSA 加密解密， 前后端密码交互

- 启动 ApplicationMain
- 访问 <http://localhost:8080/login.html>
- 登陆测试

## 前端
> demo 位于 resources/static 目录下

获取jsencrypt.js
- cdn
```html
<script src="https://cdn.bootcss.com/jsencrypt/2.3.1/jsencrypt.min.js"></script>
```
- 或者下载
<http://travistidwell.com/jsencrypt/>

- js代码
```js
    const publicKy =`MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDN8TOImaRCdDPKCuPUgX1d+U8R4LryYUKP9OqrwNF4fcLv6Y8DBXzGNXWLyFCPPCaN+bj5kYVBOsDPZP5BEj/8NJqpXs5EaNO5hsTUqM+cJMK2OqF1W+S950X2y40wXojJ3u7I7yP7jESpW719dBXcKVT6fepHhfcJFKzJQUSIKwIDAQAB`;
    const privateKey = `MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAM3xM4iZpEJ0M8oK49SBfV35TxHguvJhQo/06qvA0Xh9wu/pjwMFfMY1dYvIUI88Jo35uPmRhUE6wM9k/kESP/w0mqlezkRo07mGxNSoz5wkwrY6oXVb5L3nRfbLjTBeiMne7sjvI/uMRKlbvX10FdwpVPp96keF9wkUrMlBRIgrAgMBAAECgYEAuns+/uKhKsuuWbWiuDrJGt82CipFHlWTwGc2WHAxPbojWrtTFJlTcufVmM26pPkCsG0AYnyy/W4GScZZtPKhnE7eIgR7t6aJqMCsiFrOkkydy4rd3LanuPiwKRAfSyO6ae3eE1BJd7aVQQ0v6hBXaliHzVbcxI6+ntYABm8iQQECQQDp7ZD2VXp55bJtBlro/wLblbG5unjwiSSqF2Mi8SO9KUpykhKmZxbWPC/ttfiOWnWUiUWLQwUFUN5B0gX9whvpAkEA4V+mTfo4bTuuBL0gDxcmqYd4JVbn5oqsN9Pxu8Ltw8pr/hnBnFYnuwQGJ1ju2A83KfEFo7fp5gcVaDi3U5968wJBALAzNUGW2Q4AKgldBBUEIE7tzlSrVHU5l9hWjWHAaL8O3vi1dj7I37a21xMiQfpXwMEFNNDUxm9enkrNu52MHCECQQDZNNAY8wES9aOfWY7ePFe8p505j2psnFWicJfXd+SjACHYgYZBYB9mdFhh76oxfWiS+YGP6h543XbaPV8iLt/VAkBCdX4dRJRbGBOas41i/Y2ozIFES/KfzKMUh+FcLUpXc/OzaeixQmujJV57hgLQqbZMIP90nZGJ3JqvFXiXKFtd`;

    const btn = document.getElementById("testme");

    btn.onclick = function(){
        const input = document.getElementById("input");
        const text = input.textContent;
        console.log(text);

        // Encrypt with the public key...
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKy);
        const encrypted = encrypt.encrypt(text);
        console.log(encrypted);

        // Decrypt with the private key...
        const decrypt = new JSEncrypt();
        decrypt.setPrivateKey(privateKey);
        const uncrypted = decrypt.decrypt(encrypted);

        // Now a simple check to see if the round-trip worked.
        if (uncrypted == text) {
            console.info('It works!!!');
        }else {
            console.error('Something went wrong....');
        }
    }
```

## 本地生成公钥密钥
```shell script
openssl genrsa -out rsa_1024_priv.pem 1024

openssl rsa -pubout -in rsa_1024_priv.pem -out rsa_1024_pub.pem

# 查看私钥
cat rsa_1024_priv.pem
# 查看公钥
cat rsa_1024_pub.pem
```


# JWT RSA 非对称加密的使用
参考： <https://www.codeleading.com/article/9278493495/>

@see com.stan.jwtdemo.JwtDemo.java

这里的key 需要使用将 rsa_private.pem 转换
```sh
openssl pkcs8 -topk8 -inform PEM -in rsa_private.pem -outform pem -nocrypt -out pkcs8Private.key
```


