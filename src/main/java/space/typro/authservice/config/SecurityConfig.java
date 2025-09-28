package space.typro.authservice.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import space.typro.authservice.deserializer.AccessTokenJwsStringDeserializer;
import space.typro.authservice.deserializer.RefreshTokenJweStringDeserializer;
import space.typro.authservice.repository.DeactivatedTokenRepository;
import space.typro.authservice.security.JwtAuthenticationConfigurer;
import space.typro.authservice.serializer.AccessTokenJwsStringSerializer;
import space.typro.authservice.serializer.RefreshTokenJweStringSerializer;

import java.text.ParseException;

import static space.typro.authservice.constant.Authority.ROLE_ADMIN;

@Configuration
public class SecurityConfig {
    @Bean
    public JwtAuthenticationConfigurer jwtAuthenticationConfigurer(
            @Value("${app.security.token.access.key}") String accessTokenKey,
            @Value("${app.security.token.refresh.key}") String refreshToken,
            DeactivatedTokenRepository deactivatedTokenRepository
    ) throws ParseException, JOSEException {
        return new JwtAuthenticationConfigurer(
                new RefreshTokenJweStringSerializer(new DirectEncrypter(OctetSequenceKey.parse(accessTokenKey))),
                new RefreshTokenJweStringDeserializer(new DirectDecrypter(OctetSequenceKey.parse(refreshToken))),
                new AccessTokenJwsStringSerializer(new MACSigner(OctetSequenceKey.parse(accessTokenKey))),
                new AccessTokenJwsStringDeserializer(new MACVerifier(OctetSequenceKey.parse(accessTokenKey))),
                deactivatedTokenRepository
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationConfigurer jwtAuthenticationConfigurer
    ) throws Exception {
        http.apply(jwtAuthenticationConfigurer);

        return http
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .requestMatchers("/admin.html").hasRole(ROLE_ADMIN.withoutPrefix())
                                .requestMatchers("/error").permitAll()
                                .anyRequest().authenticated())
                .build();
    }
}
