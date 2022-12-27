package com.example.userService.repo;

import com.example.userService.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role,Long> {

    Role findByName(String username);
}
