package space.typro.authservice.converter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import space.typro.authservice.domain.Token;

import java.util.Optional;
import java.util.function.Function;

import static space.typro.authservice.constant.SecurityConst.BEARER_;
import static space.typro.authservice.constant.SecurityConst.BEARER_PREFIX_LENGTH;

@AllArgsConstructor
public class JwtAuthenticationConverter implements AuthenticationConverter {
    private final Function<String, Optional<Token>> accessTokenStringDeserializer;
    private final Function<String, Optional<Token>> refreshTokenStringDeserializer;

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith(BEARER_)) {
            var token = authorization.substring(BEARER_PREFIX_LENGTH);
            var accessTokenOp = this.accessTokenStringDeserializer.apply(token);
            if (accessTokenOp.isPresent()) {
                return new PreAuthenticatedAuthenticationToken(accessTokenOp.get(), token);
            }
            var refreshTokenOp = this.refreshTokenStringDeserializer.apply(token);
            if (refreshTokenOp.isPresent()) {
                return new PreAuthenticatedAuthenticationToken(refreshTokenOp.get(), token);
            }
        }
        return null;
    }
}
