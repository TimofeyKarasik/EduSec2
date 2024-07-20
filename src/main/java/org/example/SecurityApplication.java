package org.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
/*
логины admin и  user
пароль 123
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
drop table if exists user_roles_java CASCADE;
 */
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

}