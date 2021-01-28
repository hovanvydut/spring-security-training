package springsecuritytraining.demo.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
	
	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "Vy"),
			new Student(2, "Tung"),
			new Student(3, "Toang"));
	
	@GetMapping
	// hasRole("ROLE_") hasAnyRole("ROLE_") hasAuthority("permission") hasAnyAuthority("permission")
	@PreAuthorize("hasAnyRole('ADMIN', 'ADMINTRAINEE')")
	public List<Student> getAllStudents() {
		return STUDENTS;
	}
	
	@PostMapping
	@PreAuthorize("hasAuthority('course:write')")
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println("registerNewStudent");
		System.out.println(student);
	}
	
	@DeleteMapping("/{studentId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void deleteStudent(@PathVariable Integer studentId) {
		System.out.println("deleteStudent");
		System.out.println(studentId);
	}
	
	@PutMapping("/{studentId}")
	@PreAuthorize("hasAuthority('course:write')")
	public void updateStudent(@PathVariable Integer studentId, 
			@RequestBody Student student) {
		System.out.println("updateStudent");
		System.out.println(String.format("%s %s", studentId, student));
	}
	
}
