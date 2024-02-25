package telran.java51.security.model;

import java.security.Principal;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class User implements Principal {
	private String name;
	private Set<String> roles;

}
