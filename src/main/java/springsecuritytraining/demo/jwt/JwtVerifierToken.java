package springsecuritytraining.demo.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtVerifierToken extends OncePerRequestFilter {
	
	private final SecretKey secretKey;
	private final JwtConfig jwtConfig;
	
	@Autowired
	public JwtVerifierToken(SecretKey secretKey, JwtConfig jwtConfig) {
		super();
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, 
			HttpServletResponse response, 
			FilterChain filterChain) throws ServletException, IOException {
		
		String authorizationHeader = request.getHeader(this.jwtConfig.getAuthorizationHeader());
		
		if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(this.jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}
		
		String token = authorizationHeader.replace(this.jwtConfig.getTokenPrefix(), "");
		try {
			
			Jws<Claims> claimsJws = Jwts.parser()
										.setSigningKey(this.secretKey)
										.parseClaimsJws(token);
			
			Claims claimsBody = claimsJws.getBody();
			
			String username = claimsBody.getSubject();
			var authorities = (List<Map<String, String>>)claimsBody.get("authorities");
			
			Set<SimpleGrantedAuthority> simpleGrantedAuthority = authorities.stream().map(m -> 
										new SimpleGrantedAuthority(m.get("authority"))).collect(Collectors.toSet());
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					username, 
					null, 
					simpleGrantedAuthority
					);
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (JwtException e) {
			throw new IllegalStateException(String.format("Token %s canot be true", token));
		}
		
		filterChain.doFilter(request, response);
		
	}
	
	

}
