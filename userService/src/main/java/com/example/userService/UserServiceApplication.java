package com.example.userService;

import com.example.userService.domain.Role;
import com.example.userService.domain.User;
import com.example.userService.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
		   userService.saveRole((new Role(null,"ROLE_USER")));
			userService.saveRole((new Role(null,"ROLE_MANAGER")));
			userService.saveRole((new Role(null,"ROLE_ADMIN")));
			userService.saveRole((new Role(null,"ROLE_SUPER_ADMIN")));

			userService.saveUser(new User(null,"John Travolta", "john","1234", new ArrayList<>()));
			userService.saveUser(new User(null,"Will Smith", "will","1234", new ArrayList<>()));
			userService.saveUser(new User(null,"Jim Carry", "jim","1234", new ArrayList<>()));
			userService.saveUser(new User(null,"Arnold", "arnold","1234", new ArrayList<>()));

			userService.addRoleoUser("john","ROLE_USER");
			userService.addRoleoUser("will","ROLE_MANAGER");
			userService.addRoleoUser("jim","ROLE_ADMIN");
			userService.addRoleoUser("arnold","ROLE_SUPER_ADMIN");
			userService.addRoleoUser("arnold","ROLE_ADMIN");
			userService.addRoleoUser("arnold","ROLE_USER");


		};
	}
}
