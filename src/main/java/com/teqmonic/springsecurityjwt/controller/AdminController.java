package com.teqmonic.springsecurityjwt.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.teqmonic.springsecurityjwt.entity.RoleEntity;
import com.teqmonic.springsecurityjwt.repository.RoleRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/admin")
public class AdminController {
	
	private final RoleRepository roleRepository;
	
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	@GetMapping("/")
	public String home(Principal principal) {
		return "Welcome to Admin page, " + principal.getName();
	}
	
	/**
	 * 
	 * @return
	 */
	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/roles/")
	public Iterable<RoleEntity> getRoles() {
		return roleRepository.findAll();
	}

}
