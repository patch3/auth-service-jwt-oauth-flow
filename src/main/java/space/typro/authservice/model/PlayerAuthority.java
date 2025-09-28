package space.typro.authservice.model;

import jakarta.persistence.*;
import lombok.*;
import space.typro.authservice.constant.Authority;


@Entity
@Table(name = "t_player_authority")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PlayerAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_player", nullable = false)
    private Player player;

    @Column(name = "c_authority", unique = true, nullable = false, length = 64)
    private Authority authority;
}
