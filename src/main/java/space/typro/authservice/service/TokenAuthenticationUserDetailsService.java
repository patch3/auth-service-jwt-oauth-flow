package space.typro.authservice.service;

import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import space.typro.authservice.domain.Token;
import space.typro.authservice.domain.TokenUser;
import space.typro.authservice.repository.DeactivatedTokenRepository;

import java.time.Instant;
import java.time.LocalDateTime;

import static space.typro.authservice.constant.SecurityConst.CLAIM_NOPASSWORD;

@AllArgsConstructor
public class TokenAuthenticationUserDetailsService
        implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {
    private final DeactivatedTokenRepository deactivatedTokenRepository;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticatedToken)
            throws UsernameNotFoundException {
        if (authenticatedToken.getDetails() instanceof Token token) {
            var isTokenActive = !deactivatedTokenRepository.existsActiveByIdAndNow(
                    token.id(),
                    LocalDateTime.now()
            ) && token.expiresAt().isAfter(Instant.now());
            return new TokenUser(
                    token.subject(),
                    CLAIM_NOPASSWORD,
                    isTokenActive,
                    token.authorities().stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList(),
                    token
            );
        }
        throw new UsernameNotFoundException("Principal must be of type Token");
    }
}
