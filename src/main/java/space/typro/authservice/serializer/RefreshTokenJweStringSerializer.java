package space.typro.authservice.serializer;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
public class RefreshTokenJweStringSerializer implements Function<Token, Optional<String>> {
    private final JWEEncrypter jweEncrypter;

    @Setter
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    @Setter
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    public RefreshTokenJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }


    @Override
    public Optional<String> apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim(CLAIM_AUTHORITIES, token.authorities())
        .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, claimsSet);
        try {
            encryptedJWT.encrypt(this.jweEncrypter);
            return Optional.of(encryptedJWT.serialize());
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }
        return Optional.empty();
    }
}