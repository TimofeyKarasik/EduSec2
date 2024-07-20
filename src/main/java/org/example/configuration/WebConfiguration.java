package org.example.configuration;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import javax.sql.DataSource;
import java.util.ArrayList;

@Configuration
@ComponentScan("org.example.controller")

public class WebConfiguration {

    final ArrayList<String> whiteList = doWhiteList();

    @Autowired
    public DataSource dataSource;


    private ArrayList<String> doWhiteList(){
        ArrayList<String> list = new ArrayList<String>();
        list.add("http://localhost:8080/");
        list.add("http://localhost:8080/errorReferer");
        list.add("http://localhost:8080/login");
        list.add("http://localhost:8080/home");
        list.add("http://localhost:8080/loguot");
        return list;
    };

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    public JdbcUserDetailsManager userDetailsManager(){
        var m = new JdbcUserDetailsManager(dataSource);
        m.setEnableGroups(true);
        return m;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http
    ) throws Exception {

        http.authorizeHttpRequests(authz -> authz
                .requestMatchers("/**").authenticated()
                );

        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable);
        http.formLogin(c-> c.defaultSuccessUrl("/",true))
                .rememberMe(c -> {
                    var repository = new JdbcTokenRepositoryImpl();
                    repository.setDataSource(dataSource);
                    c.tokenRepository(repository);
                    c.key("0xCAFEBABE0xDEADBABE0xBA0BAB");
                })
        ;


        /*Ниже задается что у пользователя не может быть больше одной сессии*/
        http.sessionManagement(sessionManagement -> {sessionManagement.maximumSessions(1);})
                .authenticationProvider(
                        new AuthenticationProvider() {
                            @Override
                            public Authentication authenticate(Authentication authentication)
                                    throws AuthenticationException {
                                String userName = authentication.getName();
                                String password = authentication.getCredentials().toString();
                                UserDetails principal = userDetailsManager().loadUserByUsername(userName);
                                if (!principal.getUsername().equals(userName)){
                                    throw new UsernameNotFoundException("User not found");
                                }
                                if (!principal.getPassword().equals(password)) {
                                    throw new BadCredentialsException("Bad password");
                                }

                                return new UsernamePasswordAuthenticationToken(
                                        principal, password, principal.getAuthorities());
                            }

                            @Override
                            public boolean supports(Class<?> authentication) {
                                return authentication.equals(UsernamePasswordAuthenticationToken.class);
                            }
                        }

                )
        ;
        return http.build();
    }


    @Bean
    WebSecurityCustomizer globalSecurity(){
        return web -> web.requestRejectedHandler((request, response, requestRejectedException) -> {

                    response.sendRedirect(response.encodeRedirectURL("http://localhost:8080/errorReferer"));
                })
                .httpFirewall(
                        new StrictHttpFirewall() {
                            @Override
                            public FirewalledRequest getFirewalledRequest(
                                    HttpServletRequest request
                            ) throws RequestRejectedException{
                                return super.getFirewalledRequest(request);
                            }
                        }
                );
    }

    @Bean
    RoleHierarchy roleHierarchy(){
        var hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
                ROLE_ADMIN > PERMISSION_INDEX
                ROLE_ADMIN > PERMISSION_ROUTE1
                ROLE_ADMIN > PERMISSION_ROUTE2
                ROLE_ADMIN > PERMISSION_INDEX
                ROLE_ADMIN > PERMISSION_ROUTE2
                """);
        return hierarchy;
    }

    @Bean
    MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy){
        var expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy);
        return expressionHandler;
    }


}
