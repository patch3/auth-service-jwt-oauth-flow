package space.typro.authservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import space.typro.authservice.domain.Token;
import space.typro.authservice.domain.TokenUser;
import space.typro.authservice.domain.Tokens;
import space.typro.authservice.factory.DefaultAccessTokenFactory;

import java.io.IOException;
import java.util.Optional;
import java.util.function.Function;

import static space.typro.authservice.constant.SecurityConst.JWT_REFRESH;

public class RefreshTokenFilter extends OncePerRequestFilter {
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/jwt/refresh", HttpMethod.PATCH.name());

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private Function<Token, Token> accessTokenFaction = new DefaultAccessTokenFactory();

    private Function<Token, Optional<String>> accessTokenStringSerializer;

    private ObjectMapper objectMapper = new ObjectMapper();


    public RefreshTokenFilter() {
        this.accessTokenStringSerializer = token -> Optional.of(token.toString());
    }

    public RefreshTokenFilter(Function<Token, Optional<String>> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            if (this.securityContextRepository.containsContext(request)) {
                var context = this.securityContextRepository.loadDeferredContext(request).get();
                if (
                        context != null && context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken &&
                        context.getAuthentication().getPrincipal() instanceof TokenUser user &&
                                context.getAuthentication().getAuthorities()
                                        .contains(new SimpleGrantedAuthority(JWT_REFRESH))
                ) {
                    var accessToken = this.accessTokenFaction.apply(user.getToken());
                    var accessTokenString = this.accessTokenStringSerializer.apply(accessToken)
                                    .orElseThrow(() -> new IllegalStateException("Access token serialization failed"));

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                    this.objectMapper.writeValue(
                            response.getWriter(),
                            Tokens.builder()
                                    .accessToken(accessTokenString)
                                    .accessTokenExpiry(accessToken.expiresAt().toString())
                                    .refreshToken(null)
                                    .refreshTokenExpiry(null)
                            .build()
                    );
                    throw new AccessDeniedException("User must be authenticated with JWT");
                }
                filterChain.doFilter(request, response);
            }
        }
    }
}
