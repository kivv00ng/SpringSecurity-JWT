package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller //view 리턴
@Slf4j
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(
            Authentication authentication,
            @AuthenticationPrincipal PrincipalDetails userDetails){//DI(의존성 주입)
        log.info("/test/login ========== ");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication: "+principalDetails.getUser().toString());
        log.info("userDetails: "+userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOAuthLogin(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth){//DI(의존성 주입)
        log.info("/test/oauth/login ========== ");
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication: "+oauth2User.getAttributes());
        log.info("oauth2User: "+oauth.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping("/")
    public String index(){
        return "index";
    }


    //OAUTH 로그인을 해도, 일반 로그인을 해도 똑같이 principalDetails로 받음.
    //@AuthenticationPrcinipal을 사용하면 따로 다운그레이 안해도 됨.
   @GetMapping("/user")
    @ResponseBody
    public String userV1(@AuthenticationPrincipal PrincipalDetails principalDetails){
        log.info("principalDetails: "+principalDetails.getUser());
        return "user";
    }


    @GetMapping("/loginForm")
    public String loginFrom(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    //form형식으로 사용시
    //@PostMapping("/join")
    public String joinV1(@ModelAttribute JoinForm joinForm){
        String rawPassword = joinForm.getPassword();

        //비밀번호 암호화
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        User user = User.CreateUser(
                joinForm.getUsername(),
                encPassword,
                joinForm.getEmail(),
                "ROLE_USER",
                null,
                null);

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    //json형태(postman 사용시)
    @PostMapping("/join")
    public String joinV2(@RequestBody JoinForm joinForm){
        String rawPassword = joinForm.getPassword();

        //비밀번호 암호화
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        User user = User.CreateUser(
                joinForm.getUsername(),
                encPassword,
                joinForm.getEmail(),
                "ROLE_USER",
                null,
                null);

        userRepository.save(user);

        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String inf(){
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER')")
    @GetMapping("/data")
    @ResponseBody
    public String data(){
        return "데이터정보";
    }

    //user, manager, admin 권한만 접근가능
    @GetMapping("/api/v1/user")
    @ResponseBody
    public String userV2(){

        return "user";
    }

    //manager, admin 권한만 접근가능
    @GetMapping("/api/v1/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    //admin 권한만 접근가능
    @GetMapping("/api/v1/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

}
