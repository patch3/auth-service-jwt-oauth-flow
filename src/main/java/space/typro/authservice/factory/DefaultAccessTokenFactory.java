package space.typro.authservice.factory;

import lombok.AllArgsConstructor;
import lombok.Setter;
import space.typro.authservice.domain.Token;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;

import static space.typro.authservice.constant.RoleConst.GRANT_;
import static space.typro.authservice.constant.RoleConst.GRANT_PREFIX_LENGTH;

@Setter
@AllArgsConstructor
public class DefaultAccessTokenFactory implements Function<Token, Token> {
    private Duration tokenTls;

    public DefaultAccessTokenFactory() {
        this.tokenTls = Duration.ofHours(1);
    }

    @Override
    public Token apply(Token token) {
        var now = Instant.now();
        return Token.builder()
                .id(token.id())
                .subject(token.subject())
                .authorities(
                        token.authorities().stream()
                            .filter(authority -> authority.startsWith(GRANT_))
                            .map(authority -> authority.substring(GRANT_PREFIX_LENGTH))
                        .toList()
                )
                .createdAt(now)
                .expiresAt(now.plus(this.tokenTls))
        .build();
    }
}
