package com.example.jademat.spring_security.config;

import com.example.jademat.spring_security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // SecurityFilterChain : 스프링 시큐리티에서 적용된 보얀규칙들을 필터로 구현해 둔 것
    @Bean
    public SecurityFilterChain FilterChain(HttpSecurity http, HttpServlet httpServlet, HttpServletResponse httpServletResponse) throws Exception {
        http
                .csrf().disable()                                                   // CSRF 필터 끔
                //.userDetailsService(userDetailsService)                             // userDetailsService 설정
            .authorizeHttpRequests()                                                // URL 기반 인가 설정
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/logout").authenticated()                           // 인증 받은 사용자만 접근 가능
                .antMatchers("/**","/member/**").permitAll()                   // 인증/인가 여부와 상관 없이 접근 가능
                .and()
                .sessionManagement()                                                // JWT 인증을 위해 STATELESS 설정
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // JWT 필터 설정
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);





//            .formLogin()                                                            // form login 인증 사용
//                .loginPage("/member/login")                                         // 커스텀 로그인 페이지 경로
//                .usernameParameter("userid")                                        // 아이디 매개변수 지정
//                .passwordParameter("passwd")                                        // 비밀번호 매개변수 지정
//                .defaultSuccessUrl("/")                                             // 로그인 성공시 리다이렉트 URL
//                .failureUrl("/login?error=true")                                    // 로그인 실패시 리다이렉트 URL
//                .permitAll()
//                .and()
//            .logout()                                                               // 로그아웃 설정
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//                .logoutSuccessUrl("/")                                              // 로그아웃 성공 후 리다이렉트 될 URL
//                .invalidateHttpSession(true)                                        // 세션 무효화
//                .deleteCookies("JSESSIONID")                                        // JESSIONID 쿠키 삭제
//                .permitAll();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {                                      // 비밀번호 암호화에 사용할 인코더
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
