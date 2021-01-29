package springsecuritytraining.demo.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import javax.crypto.SecretKey;

import io.jsonwebtoken.security.Keys;

@Configuration
public class JwtSecretKey {
	
	private final JwtConfig jwtConfig;
	
	@Autowired
	public JwtSecretKey(JwtConfig jwtConfig) {
		this.jwtConfig = jwtConfig;
	}
	
	@Bean
	public SecretKey getSecretKeyForSigning() {
		return Keys.hmacShaKeyFor(this.jwtConfig.getSecretKey().getBytes());
	}
	
}
