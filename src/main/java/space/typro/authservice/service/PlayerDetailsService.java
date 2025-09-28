package space.typro.authservice.service;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import space.typro.authservice.repository.PlayerRepository;

import java.util.stream.Collectors;


@Service
@RequiredArgsConstructor
public class PlayerDetailsService implements UserDetailsService {
    private final PlayerRepository playerRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String nickname) throws UsernameNotFoundException {
        var player = playerRepository.findByNickname(nickname)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + nickname));
        
        return User.builder()
                .username(player.getNickname())
                .password(player.getPassword())
                .authorities(player.getAuthorities().stream()
                        .map(authority -> new SimpleGrantedAuthority(authority.getAuthority().name()))
                        .collect(Collectors.toList())
                )
        .build();
    }
}
