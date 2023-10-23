package com.teqmonic.springsecurityjwt.utils;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Component
public class RSAKeyProperties {

	private RSAPublicKey publicKey;
	private RSAPrivateKey privateKey;

	@PostConstruct
	public void setRSAKeys() {
		KeyPair keyPair = KeyGeneratorUtil.generateRSAKey();
		this.publicKey = (RSAPublicKey) keyPair.getPublic();
		this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
	}

}
