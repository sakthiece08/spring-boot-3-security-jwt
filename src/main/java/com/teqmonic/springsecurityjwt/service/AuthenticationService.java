package com.teqmonic.springsecurityjwt.service;

import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.teqmonic.springsecurityjwt.entity.UserEntity;
import com.teqmonic.springsecurityjwt.model.RegistrationDTO;
import com.teqmonic.springsecurityjwt.model.exception.UserCreationException;
import com.teqmonic.springsecurityjwt.repository.RoleRepository;
import com.teqmonic.springsecurityjwt.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional
public class AuthenticationService {

	private final UserRepository userRepository;

	private final RoleRepository roleRepository;

	private final PasswordEncoder encoder;

	private final String USER_AUTHORITY = "USER";

	public boolean registerUser(RegistrationDTO registrationDTO) throws UserCreationException {
		log.info("Start creation of new user {}", registrationDTO.userName());

		roleRepository.findByAuthority(USER_AUTHORITY).ifPresentOrElse(
		 roleEntity -> 
		 {
		  try {		
		 	userRepository.save(UserEntity.builder()
					.userName(registrationDTO.userName())
					.password(encoder.encode(registrationDTO.password()))
					.roles(Set.of(roleEntity))
					.build());
		
		     }
		  catch (Exception e) { // handle data integrity exceptions
		     handleException(registrationDTO.userName());
		    }
	    }, 
		  () -> handleException(registrationDTO.userName()));

		log.info("User {} with authority {} has been created. ", registrationDTO.userName(), USER_AUTHORITY);
		return Boolean.TRUE;
	}

	/**
	 * @param registrationDTO
	 */
	private void handleException(String userName) {
		log.error("User creation failed for the user ", userName);
		throw new UserCreationException("User creation failed for the user " + userName);
	}

}
