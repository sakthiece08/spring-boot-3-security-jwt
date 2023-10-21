package com.teqmonic.springsecurityjwt.model;

import org.springframework.security.core.GrantedAuthority;

import com.teqmonic.springsecurityjwt.entity.RoleEntity;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ApplicationRole implements GrantedAuthority{

	private static final long serialVersionUID = 848963786367675338L;
	
	private final RoleEntity role;

	@Override
	public String getAuthority() {
		return role.getAuthority();
	}

}
