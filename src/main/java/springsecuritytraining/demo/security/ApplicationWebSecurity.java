package springsecuritytraining.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import springsecuritytraining.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static springsecuritytraining.demo.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import static springsecuritytraining.demo.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationWebSecurity extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;

	@Autowired
	public ApplicationWebSecurity(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(this.authenticationManager()))
			.authorizeRequests()
				.antMatchers("/", "index", "/css/**", "/js/**")
				.permitAll()
				// antMatchers'order does matter
				/*
				 * .antMatchers("/api/**").hasRole(STUDENT.name())
				 * .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(
				 * COURSE_WRITE.getPermission())
				 * .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.
				 * getPermission())
				 * .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.
				 * getPermission()) .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(),
				 * ADMINTRAINEE.name())
				 */
			.anyRequest()
				.authenticated();
//			.and()
				/* .httpBasic(); */
			/*.formLogin()
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses")
				.passwordParameter("password")
				.usernameParameter("username")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
				// key use to md5 hash (hash username + expiration time)
				.key("somethingverysecure")
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login");*/
			
				
	}

	@Override
	@Bean
	// how to retrive user from DB
	protected UserDetailsService userDetailsService() {
		System.out.println(ADMIN.name());
		UserDetails user = User.builder()
			.username("student").password(this.passwordEncoder.encode("123123"))
//			.roles(STUDENT.name())
			.authorities(STUDENT.getGrantedAuthorities())
			.build();
		
		UserDetails admin = User.builder()
				.username("admin").password(this.passwordEncoder.encode("123123"))
//				.roles(ADMIN.name())
				.authorities(ADMIN.getGrantedAuthorities())
				.build();
		
		UserDetails admintrainee = User.builder()
				.username("admintrainee").password(this.passwordEncoder.encode("123123"))
//				.roles(ADMINTRAINEE.name())
				.authorities(ADMINTRAINEE.getGrantedAuthorities())
				.build();
		
		return new InMemoryUserDetailsManager(user, admin, admintrainee);
	}

}
