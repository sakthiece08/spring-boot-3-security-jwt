package com.teqmonic.springsecurityjwt.configuration;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.teqmonic.springsecurityjwt.service.UserDetailsServiceImpl;
import com.teqmonic.springsecurityjwt.utils.RSAKeyProperties;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class CustomSecurityConfiguration {

	private final UserDetailsServiceImpl userDetailsService;

	private final RSAKeyProperties keyProperties;

	/**
	 * This is used to convert Authorities mapped to the user with Prefix - "ROLE_"
	 * so, in the controller the authorities can be safely checked against the spel "hasAuthority('ROLE_ADMIN')"
	 * 
	 * Without the below AuthoritiesMapper, still we can leverage spel "hasRole('ADMIN')" to use
	 * without using the prefix - "ROLE_"
	 * 
	 * @param http
	 * @return
	 * @throws Exception
	 */
	@Bean("adminFunctionAuthManager")
	AuthenticationManager adminFunctionAuthManager(HttpSecurity http) throws Exception {
		
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		daoAuthenticationProvider.setAuthoritiesMapper((auth) -> {
			List<GrantedAuthority> authList = new ArrayList<>();
			auth.forEach((au) -> {
				authList.add(new SimpleGrantedAuthority("ROLE_" + au.getAuthority()));
			});
			return authList;
		});
		
		return new ProviderManager(daoAuthenticationProvider);
		
		
		// using Custom Authentication provider
		/**AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.authenticationProvider(authProvider);
		//authenticationManagerBuilder.userDetailsService(userDetailsService);
		return authenticationManagerBuilder.build();
		**/
	}
	
	@Bean("userRegistrationAuthManager")
	AuthenticationManager authManagerUserRegistration(HttpSecurity http) throws Exception {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService);
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());		
		return new ProviderManager(daoAuthenticationProvider);
	}
	
	/**
	 * Leveraging multiple SecurityFilterChain beans each targeted for specific paths
	 * 
	 * @param http
	 * @return
	 * @throws Exception
	 */
	
	@Bean
	@Order(1)
	SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
		return http				
				.securityMatcher(AntPathRequestMatcher.antMatcher("/api/admin/**"))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.authenticationManager(adminFunctionAuthManager(http))
				.httpBasic(Customizer.withDefaults())
				.build();
	}
	

	@Bean
	@Order(2)
	SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
		// in Production don't disable CRSF with Stateless session
		return http
		        .securityMatcher(AntPathRequestMatcher.antMatcher("/api/**"))
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.oauth2ResourceServer(
						server -> server.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
		        .build();
	}
	
	@Bean
	@Order(3)
	SecurityFilterChain userRegistrationSecurityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(csrf -> csrf.disable())
				.securityMatcher(AntPathRequestMatcher.antMatcher("/auth/**"))
				.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.build();
	}
	
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(keyProperties.getPublicKey()).privateKey(keyProperties.getPrivateKey()).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
	
	@Bean
	JwtDecoder decoder() {
		return NimbusJwtDecoder.withPublicKey(keyProperties.getPublicKey()).build();
	}
	
	/**
	* Below JwtAuthenticationConverter is required in the following cases:
	* Set up Authorities in the back end as "ADMIN", and in the code with check "hasRole('ROLE_ADMIN')"
	* 
	* Claims in the token is mapped with Prefix - "ROLE_"
	*
	**/
	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("roles"); // claims in the jwt token
		jwtGrantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
		//jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
		JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
		jwtConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
		return jwtConverter;
	}
	
	/*
	 * Overriding DefaultMethodSecurityExpressionHandler bean to add DefaultRolePrefix, so in the method level
	 * authorization check, no need to add the prefix, instead just define the actual role hasRole('READ') for
	 * hasRole('ROLE_READ') 
	 * 
	 * This DefaultMethodSecurityExpressionHandler bean and the above jwtAuthenticationConverter bean goes hand in hand.
	 * The former is applied while parsing claims in the token and this bean is used while checking method level access.
	 * 
	 * 
	 */
	@Bean
	DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler() {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		handler.setDefaultRolePrefix("ROLE_");
		return handler;
	}

}
