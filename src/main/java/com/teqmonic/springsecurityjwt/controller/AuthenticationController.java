package com.teqmonic.springsecurityjwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.teqmonic.springsecurityjwt.model.LoginResponse;
import com.teqmonic.springsecurityjwt.model.RegistrationDTO;
import com.teqmonic.springsecurityjwt.model.exception.UserCreationException;
import com.teqmonic.springsecurityjwt.service.AuthenticationService;
import com.teqmonic.springsecurityjwt.service.TokenService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

	private final AuthenticationService authenticationService;
	
	private final TokenService tokenService;
	
	
	@Qualifier(value = "userRegistrationAuthManager")
	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/register")
	public HttpEntity<String> register(@RequestBody RegistrationDTO registration) {
		try {
			authenticationService.registerUser(registration);
		} catch (UserCreationException ex) {
			return new ResponseEntity<String>("error", HttpStatus.INTERNAL_SERVER_ERROR);
		}
		return new ResponseEntity<String>("success", HttpStatus.CREATED);
	}
	
	@PostMapping("/token")
	public HttpEntity<LoginResponse> getToken(@RequestBody RegistrationDTO registration) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(registration.userName(), registration.password()));
		String token = tokenService.generateToken(authentication);
		return new ResponseEntity<LoginResponse>(new LoginResponse(registration.userName(), token), HttpStatus.OK);
	}
}
