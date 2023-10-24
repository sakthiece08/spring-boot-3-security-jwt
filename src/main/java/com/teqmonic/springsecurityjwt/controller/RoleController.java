package com.teqmonic.springsecurityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/admin")
public class RoleController {

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@GetMapping("/roles")
	public String getRoles() {
		return "Sample_role";
	}

}
