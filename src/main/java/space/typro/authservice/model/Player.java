package space.typro.authservice.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


@Entity
@Table(name = "t_player")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Player {
    @Id
    @Column(name = "id", columnDefinition = "uuid", nullable = false)
    private UUID id;

    @Column(name = "c_nickname", nullable = false, unique = true, length = 16)
    private String nickname;

    @Column(name = "c_password", nullable = false, length = 32)
    private String password;

    @OneToMany(mappedBy = "player", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @ToString.Exclude
    private Set<PlayerAuthority> authorities = new HashSet<>();

    public void addAuthority(PlayerAuthority authority) {
        authorities.add(authority);
        authority.setPlayer(this);
    }

    public void removeAuthority(PlayerAuthority authority) {
        authorities.remove(authority);
        authority.setPlayer(null);
    }
}
