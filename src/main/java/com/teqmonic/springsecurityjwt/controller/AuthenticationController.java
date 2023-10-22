package com.teqmonic.springsecurityjwt.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.teqmonic.springsecurityjwt.model.RegistrationDTO;
import com.teqmonic.springsecurityjwt.model.exception.UserCreationException;
import com.teqmonic.springsecurityjwt.service.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

	private final AuthenticationService authenticationService;

	@PostMapping("/register")
	public HttpEntity<String> register(@RequestBody RegistrationDTO registration) {
		try {
			authenticationService.registerUser(registration);
		} catch (UserCreationException ex) {
			return new ResponseEntity<String>("error", HttpStatus.INTERNAL_SERVER_ERROR);
		}
		return new ResponseEntity<String>("success", HttpStatus.CREATED);
	}
}
