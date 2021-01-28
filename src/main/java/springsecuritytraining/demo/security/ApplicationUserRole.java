package springsecuritytraining.demo.security;

import static springsecuritytraining.demo.security.ApplicationUserPermission.COURSE_READ;
import static springsecuritytraining.demo.security.ApplicationUserPermission.COURSE_WRITE;
import static springsecuritytraining.demo.security.ApplicationUserPermission.STUDENT_READ;
import static springsecuritytraining.demo.security.ApplicationUserPermission.STUDENT_WRITE;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;

public enum ApplicationUserRole {
	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ));
	
	private final Set<ApplicationUserPermission> permissions;
	
	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}
	
	public Set<ApplicationUserPermission> getPermissions() {
		return this.permissions;
	}
	
	public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
		Set<SimpleGrantedAuthority> permissions = this.getPermissions().stream()
			.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
			.collect(Collectors.toSet());
		
		permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
		return permissions;
	}
}
