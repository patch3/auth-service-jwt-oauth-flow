package space.typro.authservice.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "t_deactivated_token")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeactivatedToken {
    @Id
    @Column(name = "id", columnDefinition = "uuid")
    private UUID id;

    @Column(name = "c_keep_until", nullable = false)
    private Instant keepUntil;

    @PrePersist
    @PreUpdate
    protected void validateKeepUntil() {
        if (keepUntil != null && !keepUntil.isAfter(Instant.now())) {
            throw new IllegalArgumentException("c_keep_until must be in the future");
        }
    }
}
