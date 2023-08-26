package com.shamal.loginapp.security;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
@Configuration
@EnableWebSecurity
    public class SecurityConfiguration{
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http, UserDetailsService userDetailsService, HttpSession session) throws Exception {
            http
                    .authorizeHttpRequests(authorizeRequests ->
                            authorizeRequests
                                    .requestMatchers("/login").permitAll()
                                    .anyRequest().authenticated()
                    )
                    .formLogin(formLogin ->
                            formLogin
                                    .loginPage("/login")
                                    .successHandler((request, response, authentication) -> {
                                        response.sendRedirect("/dashboard");
                                    })
                                    .permitAll()
                    )
                    .logout(logout ->
                                logout
                                    .logoutUrl("/logout")
                                    .logoutSuccessUrl("/login?logout")
                                    .invalidateHttpSession(true)
                                    .deleteCookies("JSESSIONID")
                    )
                    .rememberMe(rememberMe ->
                            rememberMe
                                    .rememberMeServices(rememberMeServices(userDetailsService))
                                    .key("dashboardToken")
                    );
            return http.build();
        }
    @Bean
    public RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
        TokenBasedRememberMeServices rememberMeServices =
                new TokenBasedRememberMeServices("dashboardToken", userDetailsService);
        rememberMeServices.setAlwaysRemember(true);
        return rememberMeServices;
    }
        @Bean
        public WebSecurityCustomizer ignoringCustomizer() {
            return (web) -> web.ignoring().requestMatchers("/css/**", "/img/**");
        }

        @Bean
        public UserDetailsService userDetailsService() {
            PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

            UserDetails user = User.builder()
                    .username("shamal")
                    .password(passwordEncoder.encode("Password7"))
                    .roles("USER")
                    .build();

            UserDetails user2 = User.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("password"))
                    .roles("USER", "ADMIN")
                    .build();

            return new InMemoryUserDetailsManager(user,user2);
        }

    }
