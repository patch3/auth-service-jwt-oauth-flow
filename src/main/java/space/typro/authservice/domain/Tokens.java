package space.typro.authservice.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record Tokens(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("access_token_expiry") String accessTokenExpiry,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("refresh_token_expiry") String refreshTokenExpiry
) {}
