package com.tech.security.jwt.service;

import com.tech.security.jwt.entity.UserInfo;
import com.tech.security.jwt.model.UserInfoDetails;
import com.tech.security.jwt.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserInfoService implements UserDetailsService {
    @Autowired
    private UserInfoRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserInfo> userInfo = repository.findByName(username);
        return userInfo.map(UserInfoDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found" + username));
    }

    public String addUser(UserInfo userInfo) {
        userInfo.setPassword(passwordEncoder.encode(userInfo.getPassword()));
        repository.save(userInfo);
        return "User added successfully";
    }
}
