package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * WebSecurityConfigurerAdapter: 스프링 시큐리티의 웹 보안 기능 초기화 및 설정
 * HttpSecurity: 세부적인 보안 기능을 설정 할 수있는 API 제공
 **/
@Configuration
@EnableWebSecurity
//@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    UserDetailsService userDetailsService;
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
//        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // http 방식으로 요청 시, 보안검사를 실시한다.
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                // 어떠한 요청에도 인증을 받도록 api 설정
                .anyRequest().permitAll();

        // 인가 API 예제) shop이라는 자원에 접근할 때 http 보안 검사를 한다.
        // 주의 사항 - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야한다. 위에서 아래로 검증을 해나가기 때문
//        http
//                .authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated()
//        ;


        http
                // 인증방식은 formLogin과 httpBasic방식을 사용하겠다.
                .formLogin()
//                .loginPage("/login")            // 사용자 정의 로그인 페이지
//                .defaultSuccessUrl("/")         // 로그인 성공후 이동 페이지
//                .failureUrl("/login")           // 로그인 실패 후 이동 페이지
//                .usernameParameter("userId")    // 아이디 파라미터명 설정
//                .passwordParameter("password")  // 패스워드 파라미터명 설정
//                .loginProcessingUrl("/login")   // 로그인 Form Action Url
//                // 로그인 성공 후 핸들러
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        SavedRequest savedRequest = requestCache.getRequest(request, response);
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        response.sendRedirect(redirectUrl);
//                    }
//                })
//                // 로그인 실패 후 핸들러
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception: " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll(
        ;

        // 원칙적으로 http.logout은 POST 방식, GET 으로 처리하는 방식은 뒤에 설명.
//        http
//                .logout()                                   // 로그아웃 처리
//                .logoutUrl("/logout")                       // 로그아웃 처리 URL
//                .logoutSuccessUrl("/login")                 // 로그아웃 성공 후 이동페이지
//                // 로그아웃 핸들러
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                // 로그아웃 성공 후 핸들러
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me") // 로그아웃 후 쿠키 삭제
//        ;
//
////        http
////                .rememberMe()
////                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
////                .tokenValiditySeconds(3600)      // Default는 14일
////                .alwaysRemember(true)            // 리멤버 미 기능이 활성화 되지 않아도 항상 실행
////                .userDetailsService(userDetailsService) // 리멤버 미 기능 사용 시 꼭 필요, 시스템에 있는 사용자 계정 조회 과정에 필요한 설정
////        ;
//
//        // 동시 세션 제어 - 동일 계정으로 접속이 허용되는 최대 세션 수 제한
//        http
//                .sessionManagement()  // 인증 시 사용자의 세션 정보를 등록, 조회, 삭제 등의 세션 이력을 관리
//                .maximumSessions(1)   // 최대 허용 가능 세션 수, -1: 무한
//                .maxSessionsPreventsLogin(true) // 동시 로그인 차단, false: 기존 세션 만료(default)
//                .expiredUrl("/expired")    // 세션이 만료된 경우 이동 할 페이지
//        ;
//
//        // 세션 고정 보호 - 바뀌지 않는 세션 값을 이용한 해킹 방지
//        http
//                .sessionManagement()
//                .sessionFixation()
//                .changeSessionId() // default
//        ;
//
//        // 인가, 인증 예외 처리
//        http
//                .exceptionHandling()
////                .authenticationEntryPoint(new AuthenticationEntryPoint() {
////                    @Override
////                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
////                        response.sendRedirect("/login");
////                    }
////                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        response.sendRedirect("/denied");
//                    }
//                })
//
//        ;

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }
}

//@Configuration
//@EnableWebSecurity
//@Order(1)
//class SecurityConfig2 extends WebSecurityConfigurerAdapter {
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().permitAll()
//                .and()
//                .formLogin()
//        ;
//    }
//}
