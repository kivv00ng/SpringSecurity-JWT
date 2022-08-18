package com.cos.security1.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;


@Component
public class CustomBCryptPasswordEncoder extends BCryptPasswordEncoder {
}
