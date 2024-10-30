package com.example.api_user.controller;

import com.example.api_user.dto.LoginDTO;
import com.example.api_user.security.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider service;

    public AuthController(AuthenticationManager authenticationManager, JwtTokenProvider service) {
        this.authenticationManager = authenticationManager;
        this.service = service;
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginDTO loginDTO){
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
            );
            UserDetails user = (UserDetails) authentication.getPrincipal();
            return service.generateToken(user);
        }catch(AuthenticationException e){
            throw new RuntimeException("Invalid Credentials");
        }
    }
}
