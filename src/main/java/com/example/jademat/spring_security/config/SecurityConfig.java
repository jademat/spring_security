package com.example.jademat.spring_security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // SecurityFilterChain : 스프링 시큐리티에서 적용된 보얀규칙들을 필터로 구현해 둔 것
    @Bean
    public SecurityFilterChain FilterChain(HttpSecurity http, HttpServlet httpServlet, HttpServletResponse httpServletResponse) throws Exception {
        http
                .csrf().disable()                                                   // CSRF 필터 끔
            .authorizeHttpRequests()                                            // URL 기반 인가 설정
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/logout").authenticated()                          // 인증 받은 사용자만 접근 가능
                .antMatchers("/**").permitAll()                                 // 인증/인가 여부와 상관 없이 접근 가능
                    .and()
            .formLogin()                                                    // form login 인증 사용
                    .and()
            .logout()                                                       // 로그아웃 설정
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")                                            // 로그아웃 성공 후 리다이렉트 될 URL
                .invalidateHttpSession(true)                                      // 세션 무효화
                .deleteCookies("JSESSIONID")                                      // JESSIONID 쿠키 삭제
                .permitAll();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {  // 비밀번호 암호화에 사용할 인코더
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
                // .roles("ADMIN","USER")
                .roles("ADMIN") // ADMIN 권한 가짐
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }

}
