package com.cos.security1.oauth;

import com.cos.security1.config.auth.CustomBCryptPasswordEncoder;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final CustomBCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    //구글로부터 받은 userRequest데이터에 대한 후처리를 하는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException{
        log.info("##userRequest: "+userRequest.toString());
        log.info("##userRequest.getClientRegistration(): "+userRequest.getClientRegistration());
        log.info("##userRequest.getAccessToken(): "+userRequest.getAccessToken());
        log.info("##userRequest.getAccessToken().getValue() : "+userRequest.getAccessToken().getTokenValue());
        log.info("##userRequest.getClientRegistration(): "+userRequest.getClientRegistration());

        OAuth2User oauth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 ->구글 로그인창->로그인완료->code를 리턴(OAuth-client라이브러리)->AccessToken 요청
        //->userRequest 정보 받음 ->loadUser함수 호출->구글로부터 회원프로필 받음.
        log.info("##super.loadUser(userRequest): "+oauth2User.getAttributes());


        String provider = userRequest.getClientRegistration().getClientId(); //google
        String providerId = oauth2User.getAttribute("sub");
        String username = provider+"_"+providerId; // google_*********
        String password = bCryptPasswordEncoder.encode("겟인데어");
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

         User userEntity = userRepository.findByUsername(username);
         if(userEntity == null){
             userEntity = User.CreateUser(
                     username,
                     password,
                     email,
                     role,
                     provider,
                     providerId);
            userRepository.save(userEntity);
         }

       return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
