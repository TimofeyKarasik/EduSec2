package org.example.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @Autowired
    JdbcUserDetailsManager userManager;

    @Autowired
    PasswordEncoder passwordEncoder;
    @PreAuthorize("hasAuthority('PERMISSION_ROUTE2')")
    @GetMapping("/")
    public String index() {
        return "home";
    }

    @PreAuthorize("hasAuthority('PERMISSION_ROUTE2')")
    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @PreAuthorize("hasAuthority('PERMISSION_ROUTE2')")
    @GetMapping("/badRef")
    public String badRef() {
        return "badRef";
    }

    @PreAuthorize("hasAuthority('PERMISSION_ROUTE2')")
    @GetMapping("/errorReferer")
    public String errorReferer() {
        return "errorReferer";
    }

    @PreAuthorize("hasAuthority('PERMISSION_ROUTE1')")
    @GetMapping("/create_user")
    public String create_user()
    {
        if (!userManager.userExists("joe")){
            UserDetails userDetailsUser = User.builder()
                    .username("joe")
                    .password(passwordEncoder.encode("123"))
                    .roles("ADMIN")
                    .authorities("PERMISSION_ROUTE1")
                    .build();
            userManager.createUser(userDetailsUser);
        }
        return "create_user";
    }


}