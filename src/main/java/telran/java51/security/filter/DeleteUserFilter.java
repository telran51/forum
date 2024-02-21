package telran.java51.security.filter;

import java.io.IOException;
import java.security.Principal;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import telran.java51.accounting.dao.UserAccountRepository;
import telran.java51.accounting.model.UserAccount;

@Component
@Order(40)
@RequiredArgsConstructor
public class DeleteUserFilter implements Filter {
	
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			Principal principal =  request.getUserPrincipal();
			String[] arr = request.getServletPath().split("/");
			String userName = arr[arr.length - 1];
			UserAccount userAccount = userAccountRepository
					.findById(principal.getName()).get();
			if (!(userAccount.getRoles().contains("ADMINISTRATOR") 
					|| principal.getName().equalsIgnoreCase(userName))) {
				response.sendError(403);
				return;
			}

		}
		chain.doFilter(request, response);

	}

	private boolean checkEndPoint(String method, String path) {
		return HttpMethod.DELETE.matches(method) && path.matches("/account/user/\\w+");
	}

}
