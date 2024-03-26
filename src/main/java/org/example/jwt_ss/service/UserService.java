package org.example.jwt_ss.service;

import org.example.jwt_ss.entity.User;

import java.util.List;

public interface UserService {
    User register(User user);

    User findByUsername(String username);
}
