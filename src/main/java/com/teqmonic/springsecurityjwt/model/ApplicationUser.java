package com.teqmonic.springsecurityjwt.model;

import java.util.Collection;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.teqmonic.springsecurityjwt.entity.RoleEntity;
import com.teqmonic.springsecurityjwt.entity.UserEntity;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ApplicationUser implements UserDetails{

	private static final long serialVersionUID = 1L;
	
	private final UserEntity user;
	
	@Override
	public String getUsername() {
		return user.getUserName();
	}
	
	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		
		return Optional.ofNullable(user.getRoles()).get()
				.stream()
				.map(RoleEntity::getAuthority)
				.map(SimpleGrantedAuthority::new)
				.toList();
		
		//return user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getAuthority())).toList();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

}
