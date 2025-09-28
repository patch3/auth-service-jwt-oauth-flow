package space.typro.authservice.security;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Setter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import space.typro.authservice.converter.JwtAuthenticationConverter;
import space.typro.authservice.domain.Token;
import space.typro.authservice.filter.JwtLogoutFilter;
import space.typro.authservice.filter.RefreshTokenFilter;
import space.typro.authservice.filter.RequestJwtTokenFilter;
import space.typro.authservice.repository.DeactivatedTokenRepository;
import space.typro.authservice.service.TokenAuthenticationUserDetailsService;

import java.util.Optional;
import java.util.function.Function;

@Setter
@AllArgsConstructor
public class JwtAuthenticationConfigurer extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {
    private Function<Token, Optional<String>> refreshTokenStringSerializer;
    private Function<String, Optional<Token>> refreshTokenStringDeserializer;

    private Function<Token, Optional<String>> accessTokenStringSerializer;
    private Function<String, Optional<Token>> accessTokenStringDeserializer;

    private DeactivatedTokenRepository deactivatedTokenRepository;


    @Override
    public void init(HttpSecurity builder) {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/tokens", "POST"));
        }
    }


    @Override
    public void configure(HttpSecurity builder) {
        var requestJwtTokenFilter = new RequestJwtTokenFilter(
                this.refreshTokenStringSerializer,
                this.accessTokenStringSerializer
        );

        var jwtAuthenticationFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new JwtAuthenticationConverter(this.accessTokenStringDeserializer, this.refreshTokenStringDeserializer)
        );
        jwtAuthenticationFilter
                .setSuccessHandler(
                        (request, _, _) ->
                                CsrfFilter.skipRequest(request)
                );
        jwtAuthenticationFilter
                .setFailureHandler((_, response, _) ->
                        response.sendError(HttpServletResponse.SC_FORBIDDEN)
                );

        var authenticationProvider = new PreAuthenticatedAuthenticationProvider();
        authenticationProvider.setPreAuthenticatedUserDetailsService(
                new TokenAuthenticationUserDetailsService(this.deactivatedTokenRepository)
        );

        var refreshTokenFilter = new RefreshTokenFilter(this.accessTokenStringSerializer);

        var jwtLogoutFilter = new JwtLogoutFilter(this.deactivatedTokenRepository);

        builder.addFilterAfter(requestJwtTokenFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, CsrfFilter.class)
                .addFilterAfter(refreshTokenFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(jwtLogoutFilter, ExceptionTranslationFilter.class)
                .authenticationProvider(authenticationProvider);
    }
}
