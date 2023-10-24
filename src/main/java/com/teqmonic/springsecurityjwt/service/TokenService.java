package com.teqmonic.springsecurityjwt.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

	@Autowired
	private JwtEncoder jwtEncoder;

	public String generateToken(Authentication authentication) {
		String authorities = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("self")
				.issuedAt(Instant.now())
				.subject(authentication.getName())
				.claim("roles", authorities)
				//.expiresAt(Instant.now().plus(1, ChronoUnit.HOURS))
				.build();

		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

	}

}
