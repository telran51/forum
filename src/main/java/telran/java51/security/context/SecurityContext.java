package telran.java51.security.context;

import telran.java51.security.model.User;

public interface SecurityContext {
	User addUserSession(String sessionId, User user);
	
	User removeUserSession(String sessionId);
	
	User getUserBySessionId(String sessionId);
}
