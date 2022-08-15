package com.cos.security1.controller;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //view 리턴
@Slf4j
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(){
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager(){
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginFrom(){
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(@ModelAttribute JoinForm joinForm){
        String rawPassword = joinForm.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);

        User user = User.CreateUser(
                joinForm.getName(),
                encPassword,
                joinForm.getEmail(),
                "ROLE_USER");

        userRepository.save(user);

        return "redirect:/loginForm";
    }

}
