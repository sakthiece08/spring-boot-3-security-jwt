package com.teqmonic.springsecurityjwt.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {
	
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/")
	public String home(Principal principal) {
		return "Hello, admin " + principal.getName();
	}

}
