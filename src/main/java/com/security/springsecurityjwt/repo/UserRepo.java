package com.security.springsecurityjwt.repo;

import com.security.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
