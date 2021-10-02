package com.security.springsecurityjwt;

import com.security.springsecurityjwt.model.Role;
import com.security.springsecurityjwt.model.User;
import com.security.springsecurityjwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringsecurityjwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringsecurityjwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder()	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
//			userService.saveRole(new Role(null, "1"));
//			userService.saveRole(new Role(null, "2"));
//			userService.saveRole(new Role(null, "3"));
//
//			userService.saveUser(new User(null, "A", "AA", "1234", new ArrayList<>()));
//			userService.saveUser(new User(null, "B", "BB", "1234", new ArrayList<>()));
//			userService.saveUser(new User(null, "C", "CC", "1234", new ArrayList<>()));
//
//			userService.addRoleToUser("AA", "1");
//			userService.addRoleToUser("AA", "2");
//			userService.addRoleToUser("AA", "3");
//			userService.addRoleToUser("BB", "1");
//			userService.addRoleToUser("BB", "2");
//			userService.addRoleToUser("BB", "3");
//			userService.addRoleToUser("CC", "1");
//			userService.addRoleToUser("CC", "2");
//			userService.addRoleToUser("CC", "3");
		};
	}
}
