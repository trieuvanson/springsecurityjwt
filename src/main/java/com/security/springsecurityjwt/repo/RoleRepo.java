package com.security.springsecurityjwt.repo;

import com.security.springsecurityjwt.model.Role;
import com.security.springsecurityjwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
