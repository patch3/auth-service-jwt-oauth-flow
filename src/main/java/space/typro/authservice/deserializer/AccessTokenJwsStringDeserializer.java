package space.typro.authservice.deserializer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import space.typro.authservice.domain.Token;

import java.text.ParseException;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static space.typro.authservice.constant.SecurityConst.CLAIM_AUTHORITIES;

@Slf4j
@AllArgsConstructor
public class AccessTokenJwsStringDeserializer implements Function<String, Optional<Token>> {
    private final JWSVerifier jwsVerifier;

    @Override
    public Optional<Token> apply(String string) {
        try {
            var signedJWT = SignedJWT.parse(string);
            if (signedJWT.verify(this.jwsVerifier)) {
                var claimsSet = signedJWT.getJWTClaimsSet();
                return Optional.of(
                        Token.builder()
                                .id(UUID.fromString(claimsSet.getJWTID()))
                                .subject(claimsSet.getSubject())
                                .authorities(claimsSet.getStringListClaim(CLAIM_AUTHORITIES))
                                .createdAt(claimsSet.getIssueTime().toInstant())
                                .expiresAt(claimsSet.getExpirationTime().toInstant())
                        .build()
                );
            }
        } catch (ParseException | JOSEException ex) {
            log.error(ex.getMessage(), ex);
        }
        return Optional.empty();
    }
}
