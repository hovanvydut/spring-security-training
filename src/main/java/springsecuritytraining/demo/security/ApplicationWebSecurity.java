package springsecuritytraining.demo.security;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import springsecuritytraining.demo.auth.ApplicationUserService;
import springsecuritytraining.demo.jwt.JwtConfig;
import springsecuritytraining.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import springsecuritytraining.demo.jwt.JwtVerifierToken;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationWebSecurity extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;

	@Autowired
	public ApplicationWebSecurity(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
			JwtConfig jwtConfig, SecretKey secretKey) {
		super();
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.sessionManagement()
            	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
            .addFilterAfter(new JwtVerifierToken(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests()
				.antMatchers("/", "index", "/css/**", "/js/**")
				.permitAll()
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
			/*.and()
				 .httpBasic(); 
			.formLogin()
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

	/*
	 * @Override
	 * 
	 * @Bean // how to retrive user from DB protected UserDetailsService
	 * userDetailsService() { System.out.println(ADMIN.name()); UserDetails user =
	 * User.builder()
	 * .username("student").password(this.passwordEncoder.encode("123123")) //
	 * .roles(STUDENT.name()) .authorities(STUDENT.getGrantedAuthorities())
	 * .build();
	 * 
	 * UserDetails admin = User.builder()
	 * .username("admin").password(this.passwordEncoder.encode("123123")) //
	 * .roles(ADMIN.name()) .authorities(ADMIN.getGrantedAuthorities()) .build();
	 * 
	 * UserDetails admintrainee = User.builder()
	 * .username("admintrainee").password(this.passwordEncoder.encode("123123")) //
	 * .roles(ADMINTRAINEE.name())
	 * .authorities(ADMINTRAINEE.getGrantedAuthorities()) .build();
	 * 
	 * 
	 * return new InMemoryUserDetailsManager(user, admin, admintrainee); }
	 */

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

}
