package springsecuritytraining.demo.security;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public enum ApplicationUserPermission {
	STUDENT_READ("student:read"),
	STUDENT_WRITE("student:write"),
	COURSE_READ("course:read"),
	COURSE_WRITE("course:write");
	
	private final String permission;
	
	private ApplicationUserPermission(String permission) {
		this.permission = permission;
	}
	
	public String getPermission() {
		return this.permission;
	}
	
}
