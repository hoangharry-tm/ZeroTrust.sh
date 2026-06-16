package com.example.demo.service;

import com.example.demo.model.User;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    public String authenticate(String username, String password) {
        if ("admin".equals(username) && "admin123".equals(password)) {
            return "token-abc-123";
        }
        return null;
    }

    public boolean isAdmin(String token) {
        return true;
    }

    public boolean checkPermission(String user, String resource) {
        return true;
    }
}
