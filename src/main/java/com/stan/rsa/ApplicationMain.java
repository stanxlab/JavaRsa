package com.stan.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * war包
 */
@SpringBootApplication
public class ApplicationMain extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ApplicationMain.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(ApplicationMain.class, args);
    }

}

// jar 包
//@SpringBootApplication
//public class ApplicationMain {
//    public static void main(String[] args) {
//        SpringApplication.run(ApplicationMain.class, args);
//    }
//
//}