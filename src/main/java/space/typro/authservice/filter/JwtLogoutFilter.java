package space.typro.authservice.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import space.typro.authservice.domain.TokenUser;
import space.typro.authservice.model.DeactivatedToken;
import space.typro.authservice.repository.DeactivatedTokenRepository;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

import static space.typro.authservice.constant.SecurityConst.JWT_LOGOUT;


public class JwtLogoutFilter extends OncePerRequestFilter {
    @Setter
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/jwt/logout", HttpMethod.PATCH.name());

    @Setter
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private final DeactivatedTokenRepository deactivatedTokenRepository;

    public JwtLogoutFilter(DeactivatedTokenRepository deactivatedTokenRepository) {
        this.deactivatedTokenRepository = deactivatedTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
         if (this.requestMatcher.matches(request)) {
             if (this.securityContextRepository.containsContext(request)) {
                 var context = this.securityContextRepository.loadDeferredContext(request).get();
                 if (
                         context != null &&
                         context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken &&
                         context.getAuthentication().getPrincipal() instanceof TokenUser user &&
                         context.getAuthentication().getAuthorities()
                                 .contains(new SimpleGrantedAuthority(JWT_LOGOUT))
                 ) {
                    var deactivatedToken = DeactivatedToken.builder()
                            .id(user.getToken().id())
                            .keepUntil(user.getToken().expiresAt())
                    .build();
                    try {
                        deactivatedTokenRepository.save(deactivatedToken);
                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                        return;
                    } catch (DataIntegrityViolationException ex) {
                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                        return;
                    } catch (IllegalArgumentException ex) {
                        throw new AccessDeniedException("Invalid token expiration time");
                    }
                 }
             }
             throw new AccessDeniedException("User must be authentication with JWT");
         }
         filterChain.doFilter(request, response);
    }
}
