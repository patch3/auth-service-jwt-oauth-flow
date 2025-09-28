package space.typro.authservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import space.typro.authservice.domain.Token;
import space.typro.authservice.domain.Tokens;
import space.typro.authservice.factory.DefaultAccessTokenFactory;
import space.typro.authservice.factory.DefaultRefreshTokenFactory;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.Optional;
import java.util.function.Function;

@Setter
public class RequestJwtTokenFilter extends OncePerRequestFilter {
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/api/jwt/tokens", HttpMethod.POST.name());

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private Function<Authentication, Token> refreshTokenFactory = new DefaultRefreshTokenFactory();
    private Function<Token, Token> accessTokenFactory           = new DefaultAccessTokenFactory();

    private Function<Token, Optional<String>> refreshTokenStringSerializer;
    private Function<Token, Optional<String>> accessTokenStringSerializer;

    private ObjectMapper objectMapper = new ObjectMapper();

    public RequestJwtTokenFilter() {
        this.refreshTokenStringSerializer = token -> Optional.of(token.toString());
        this.accessTokenStringSerializer  = token -> Optional.of(token.toString());
    }

    public RequestJwtTokenFilter(Function<Token, Optional<String>> refreshTokenStringSerializer,
                                  Function<Token, Optional<String>> accessTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        this.accessTokenStringSerializer  = accessTokenStringSerializer;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            var context = this.securityContextRepository.loadDeferredContext(request).get();
            if (context != null &&
                    !(context.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                var contex = this.securityContextRepository.loadDeferredContext(request).get();
                if (contex != null &&
                        !(contex.getAuthentication() instanceof PreAuthenticatedAuthenticationToken)) {
                    var refreshToken = this.refreshTokenFactory.apply(contex.getAuthentication());
                    var accessToken = this.accessTokenFactory.apply(refreshToken);

                    var refreshTokenString = this.refreshTokenStringSerializer.apply(refreshToken)
                            .orElseThrow(() -> new IllegalStateException("Refresh token serialization failed"));
                    var accessTokenString  = this.accessTokenStringSerializer.apply(accessToken)
                            .orElseThrow(() -> new IllegalStateException("Access token serialization failed"));

                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);

                    this.objectMapper.writeValue(
                            response.getWriter(),
                            Tokens.builder()
                                    .refreshToken(refreshTokenString)
                                    .refreshTokenExpiry(refreshToken.expiresAt().toString())
                                    .accessToken(accessTokenString)
                                    .accessTokenExpiry(accessToken.expiresAt().toString())
                            .build()
                    );
                    return;
                }
            }
            throw new AccessDeniedException("User must be authenticated");
        }
        filterChain.doFilter(request, response);
    }
}
