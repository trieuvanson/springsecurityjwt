package com.security.springsecurityjwt.service;

import com.security.springsecurityjwt.model.Role;
import com.security.springsecurityjwt.model.User;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    User getUser(String userName);
    List<User> getUsers();
}
