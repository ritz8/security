package com.tech.security.jwt.controller;

import com.tech.security.jwt.entity.UserInfo;
import com.tech.security.jwt.model.AuthRequest;
import com.tech.security.jwt.service.UserInfoService;
import com.tech.security.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserInfoService service;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome, this endpoint is open for all";
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String userProfile(@RequestBody String name) {
        return "Welcome to the user profile";
    }

    @PostMapping("/addUser")
    public String addUser(@RequestBody UserInfo userInfo) {
        return service.addUser(userInfo);
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String adminProfile(@RequestBody String name) {
        return "Welcome to the admin profile";
    }

    @PostMapping("/generateToken")
    public String authenticateAndGenerateToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new
                UsernamePasswordAuthenticationToken(authRequest.getUserName(),
                authRequest.getPassword()));

        if (authentication.isAuthenticated())
            return jwtUtil.generateToken(authRequest.getUserName());
        else
            throw new UsernameNotFoundException("Invalid user name");
    }
}
