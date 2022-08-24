package com.cos.security1.config.jwt;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import java.util.Date;
// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// login 요청해서 usernmae, password전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.


@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final String secretKey;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,String secretKey) {
        this.authenticationManager = authenticationManager;
        this.secretKey = secretKey;
    }


    //attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication함수가 실행된다.
    //JWT토큰을 만들어서 request요청한 사용자에 JWT토큰을 응답해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("successfulAuthentication() 실행됨: 인증이 완료되었다는 뜻");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //토큰 생성
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretKey);
        //SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
        Key key = Keys.hmacShaKeyFor(apiKeySecretBytes);
        //Key key = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        String jwtToken =
                Jwts.builder()
                        .setSubject("cos토큰")
                        .setExpiration(new Date(System.currentTimeMillis()+(60000*10)))
                        .claim("id", principalDetails.getUser().getId())
                        .claim("username", principalDetails.getUser().getUsername())
                        .signWith(key, SignatureAlgorithm.HS512).compact();


        //client에 토큰 전달
        response.addHeader("Authorization", "Bearer "+jwtToken);
        //super.successfulAuthentication(request, response, chain, authResult);
    }

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter: 로그인 시도중");

        // 1. username, password 받는다.

        try {
            /*
         BufferedReader br = request.getReader();
         String input = null;
         while((input = br.readLine()) !=null){
             log.info("#####"+input);
         }

             */
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
            //DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session영역에 저장됨.=>로그인 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            //authentication 객체를 session영역에 저장하도록 return해주면됨.
            //jwtx토큰을 사용하면서 굳이 세션에 저장하는 이유는 권한관리를 security가 대신 해주기 때문에 세션에 저장해줌.
            //jwt토큰 만듬
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }


       return null;
    }
}
