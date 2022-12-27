package com.example.userService.service;

import com.example.userService.domain.Role;
import com.example.userService.domain.User;
import com.example.userService.repo.RoleRepo;
import com.example.userService.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
     // get the user from the database
       User user = userRepo.findByUsername(username);
       if(user == null){
           log.error("User not found in the database ");
           throw new UsernameNotFoundException("User not found in the database");
       }else{
           log.error("User found in the database : {}", username);
       }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
       user.getRoles().forEach(role -> {
           authorities.add(new SimpleGrantedAuthority(role.getName()));
       });

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);

    }

    @Override
    public User saveUser(User user) {
        log.info("saving new user to the database");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role to the database");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleoUser(String username, String roleName) {
        log.info("saving new addRoleoUser to the database");
        User user = userRepo.findByUsername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("getting User to the database");
        return userRepo.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("getting all User to the database");
        return userRepo.findAll();
    }


}
