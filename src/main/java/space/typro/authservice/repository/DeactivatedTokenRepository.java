package space.typro.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import space.typro.authservice.model.DeactivatedToken;

import java.time.LocalDateTime;
import java.util.UUID;

@Repository
public interface DeactivatedTokenRepository extends JpaRepository<DeactivatedToken, UUID> {
    /*
     * Удаление просроченных токенов
     */
    @Modifying
    @Query("DELETE FROM DeactivatedToken dt WHERE dt.keepUntil <= :now")
    void deleteExpired(@Param("now")LocalDateTime now);

    /*
     * Проверка, активен ли токен (Не деактивирован и не истек)
     */
    @Query("SELECT COUNT(dt) > 0 FROM DeactivatedToken dt WHERE dt.id = :tokenId AND dt.keepUntil > :now")
    boolean existsActiveByIdAndNow(@Param("tokenId") UUID tokenId, @Param("now") LocalDateTime now);
}
