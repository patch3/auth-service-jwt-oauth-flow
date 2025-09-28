package space.typro.authservice.factory;

import lombok.AllArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import space.typro.authservice.domain.Token;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.UUID;
import java.util.function.Function;

import static space.typro.authservice.constant.RoleConst.GRANT_;
import static space.typro.authservice.constant.SecurityConst.JWT_LOGOUT;
import static space.typro.authservice.constant.SecurityConst.JWT_REFRESH;

@Setter
@AllArgsConstructor
public class DefaultRefreshTokenFactory implements Function<Authentication, Token> {
    private Duration tokenTtl;

    public DefaultRefreshTokenFactory() {
        this.tokenTtl = Duration.ofDays(15);
    }

    @Override
    public Token apply(Authentication authenticator) {
        var authorities = new LinkedList<String>();
        authorities.add(JWT_REFRESH);
        authorities.add(JWT_LOGOUT);
        authenticator.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> GRANT_ + authority)
                .forEach(authorities::add);
        var now = Instant.now();
        return new Token(
                UUID.randomUUID(),
                authenticator.getName(),
                authorities,
                now,
                now.plus((this.tokenTtl))
        );
    }
}
