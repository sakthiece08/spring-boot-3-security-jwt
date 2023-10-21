package com.teqmonic.springsecurityjwt;

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.teqmonic.springsecurityjwt.entity.RoleEntity;
import com.teqmonic.springsecurityjwt.entity.UserEntity;
import com.teqmonic.springsecurityjwt.repository.RoleRepository;
import com.teqmonic.springsecurityjwt.repository.UserRepository;

import lombok.extern.java.Log;

@Log
@SpringBootApplication
public class SpringSecurityJwtApplication {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner() {
		log.info("Saving data into database...");
		return args -> {
			// save available Roles
			List<String> roles = List.of("ADMIN", "USER", "PUBLIC");
			roles.forEach(role -> {
				roleRepository.save(RoleEntity.builder().authority(role).build());
			});
			log.info("Roles are created..");
            // create Admin user if "ADMIN" authority exists
			roleRepository.findByAuthority("ADMIN").ifPresent(roleEntity -> {
				userRepository.save(UserEntity.builder().userName("admin").password(passwordEncoder.encode("password"))
						.roles(Set.of(roleEntity)).build());
				log.info("Admin user has been created..");
			});
		};

	}

}
