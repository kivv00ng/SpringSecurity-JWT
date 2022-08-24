package com.cos.security1.config.jwt;


import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;

//시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있음.
//권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게되어 있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이필터를 안탄다.
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final String secretKey;

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, @Value("${jwt.secretKey}") String secretKey) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.secretKey = secretKey;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        log.info("인증이나 권한이 필요한 주소에 요청 됨");

        //header가 있는지 확인
        String jwtHeader = request.getHeader("Authorization");
        log.info("********* jwtHeader : "+jwtHeader);

        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            return;
        }
        //JWT 토큰 검증을 통해서 정상적인 사용자인지 확인
        //String jwtToken = request.getHeader("Authorization").replace("Bearer ","");
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretKey);
        Jws<Claims> parsedToken = Jwts.parserBuilder()
                .setSigningKey(apiKeySecretBytes)
                .build().parseClaimsJws(jwtHeader.replace("Bearer ", ""));
        Claims claims = parsedToken.getBody();
        String userName = (String)claims.get("username");

        log.info("============================");
        log.info("#######userName: "+userName);
        log.info("============================");

        if(userName != null){
            User userEntity = userRepository.findByUsername(userName);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            //Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null, principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

}
