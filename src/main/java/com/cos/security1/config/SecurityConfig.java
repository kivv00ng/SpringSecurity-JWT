package com.cos.security1.config;

import com.cos.security1.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

//1.코드 받기(인증) 2. 엑세스토큰(권한) 3.사용자프로필 정보를 가져옴
//      4-1. 정보를 토대로 회원가입 자동으로 진행
//      4-2. (이메일, 전화번호, 이름, 아이디) 쇼핑몰 -> (집주소),백화점몰 -> 추가정보 기입하고 회원가입


@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록 (스프링 필터 사용해봣쥬?)

//securedEnabled: @Secured 어노테이션 활성화 => controller에서 특정 url처리 메서드에 적용시 필터적용
//prePostEnabled: @PreAuthorize 어노테이션 활성 => controller 에서 url처리 메서드가 호출되기 전에 실행
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig{
    private final PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean()
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해준다=> 컨트롤러에서 /login을 따로 만들어 주지않아도 됨
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);//구글 로그인이 완료된 후의 처리가 필요함. Tip.코드X, (엑세스토큰 _ 사용자프로필정보 O)

        return http.build();
    }

    /*
    기존: WebSecurityConfigurerAdapter를 상속하고 configure매소드를 오버라이딩하여 설정하는 방법
    => 현재: SecurityFilterChain을 리턴하는 메소드를 빈에 등록하는 방식(컴포넌트 방식으로 컨테이너가 관리)
    //https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter

    @Override
    protected void configure(HttpSecurity http) throws  Exception{
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin").access("\"hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }

     */
}
