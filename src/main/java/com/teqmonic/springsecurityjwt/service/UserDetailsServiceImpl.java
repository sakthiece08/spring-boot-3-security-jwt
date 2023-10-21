package com.teqmonic.springsecurityjwt.service;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.teqmonic.springsecurityjwt.model.ApplicationUser;
import com.teqmonic.springsecurityjwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
	
	Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.info("In loadUserByUsername for user {}", username);
		
		return Optional.ofNullable(username)
				.flatMap(userRepository::findByUserName)
				.map(ApplicationUser::new)
				.orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

	}

}
