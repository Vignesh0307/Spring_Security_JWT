package com.example.userService.service;

import com.example.userService.domain.Role;
import com.example.userService.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);

    Role saveRole(Role role);

    void addRoleoUser(String username, String roleName);

    User getUser(String username);

    List<User> getUsers();

}
