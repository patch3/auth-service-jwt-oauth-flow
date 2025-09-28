package space.typro.authservice.serializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import space.typro.authservice.domain.Token;

import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

import static space.typro.authservice.constant.SecurityConst.CLAIM_AUTHORITIES;

@Slf4j
@AllArgsConstructor
public class AccessTokenJwsStringSerializer implements Function<Token, Optional<String>> {
    private final JWSSigner jwsSigner;

    @Setter
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    @Override
    public Optional<String> apply(Token token) {
        var jwsHeader = new JWSHeader.Builder(this.jwsAlgorithm)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim(CLAIM_AUTHORITIES, token.authorities())
        .build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet);
        try {
            signedJWT.sign(this.jwsSigner);
            return Optional.of(signedJWT.serialize());
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }
        return Optional.empty();
    }
}

