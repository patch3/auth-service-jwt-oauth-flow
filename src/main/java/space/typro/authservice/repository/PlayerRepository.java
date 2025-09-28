package space.typro.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import space.typro.authservice.model.Player;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PlayerRepository extends JpaRepository<Player, UUID> {

    @Query("SELECT p FROM Player p LEFT JOIN FETCH p.authorities WHERE p.nickname = :nickname")
    Optional<Player> findByNicknameWithAuthorities(@Param("nickname") String nickname);

    Optional<Player> findByNickname(String nickName);
}
