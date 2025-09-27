package space.typro.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import space.typro.authservice.model.PlayerAuthority;

@Repository
public interface PlayerAuthorityRepository extends JpaRepository<PlayerAuthority, Long> {

}
