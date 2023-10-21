package com.teqmonic.springsecurityjwt.model.exception;

import org.springframework.security.core.AuthenticationException;

public class UserCreationException extends AuthenticationException{

	public UserCreationException(String msg) {
		super(msg);
		// TODO Auto-generated constructor stub
	}

	private static final long serialVersionUID = 1L;

}
