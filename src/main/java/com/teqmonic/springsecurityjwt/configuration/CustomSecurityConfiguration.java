package com.teqmonic.springsecurityjwt.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.teqmonic.springsecurityjwt.service.UserDetailsServiceImpl;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class CustomSecurityConfiguration {
	
	private final UserDetailsServiceImpl userDetailsService; 

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return 
		 http // in Production don't disable CRSF with Stateless session
		.csrf(csrf -> csrf.disable())
		.authorizeHttpRequests(
				auth -> auth.requestMatchers(AntPathRequestMatcher.antMatcher("/auth/**")).permitAll())
		.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
		.userDetailsService(userDetailsService)
		.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.httpBasic(Customizer.withDefaults())
		.build();
	}
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
