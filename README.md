# spring-security-jwt (Using Asymmetric Keys Encryption) 

Asymmetric key pair - One key to sign the token and another key to verify the signature. Private key to encode the token and Public key to decode the same.

This service has a Java application code for a Spring Boot 3+, Spring Data JPA, Spring Security, Spring Web, and OAuth2Resource server application which allows users to login or register using HTTP POST requests, then view endpoints based on their roles.

Database: PostgreSQL

Users are authenticated against a database using a custom UserDetailsService and AuthenticationManager along with Spring Data JPA repositories.

When a successful login occurs, a JWT is generated and sent back to the user, the user can use this JWT in the header as a bearer token to access authenticated routes according to their roles

## JWT components
```
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
```
