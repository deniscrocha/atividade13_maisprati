package com.example.api_user.service;

import com.example.api_user.model.User;
import com.example.api_user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword()).build();
    }
    public UserDetails loadUserById(String id) throws UsernameNotFoundException{
        int castedId = Integer.valueOf(id);
        Optional<User> optionalUser = userRepository.findById(castedId);
        if(!optionalUser.isPresent()){
            throw new UsernameNotFoundException("Usuario com ID não encontrado: " + castedId + " | " + id);
        }
        User user = optionalUser.get();
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword()).build();
    }
}
