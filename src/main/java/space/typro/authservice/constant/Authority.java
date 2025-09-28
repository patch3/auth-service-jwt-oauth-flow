package space.typro.authservice.constant;

import io.micrometer.common.lang.NonNull;
import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static space.typro.authservice.constant.NumberConst.ZERO;
import static space.typro.authservice.constant.RoleConst.*;


public enum Authority {
    ROLE_NON    (NON_CODE),
    ROLE_PLAYER (PLAYER_CODE),
    ROLE_ADMIN  (ADMIN_CODE);

    @Getter
    private final short code;

    private static final Map<Short, Authority> BY_CODE = Arrays.stream(values())
            .collect(Collectors.toMap(Authority::getCode, Function.identity()));


    Authority(short code) {
        this.code = code;
    }
    
    Authority(int code) {
        if (code < ZERO || code > Short.MAX_VALUE) {
            throw new IllegalArgumentException("Code must be between 0 and 32767");
        }
        this.code = (short) code;
    }

    public String withoutPrefix() {
        return name().startsWith(ROLE_) ? name().substring(ROLE_PREFIX_LENGTH) : name();
    }

    public static Optional<Authority> fromString(@NonNull String value) {
        try {
            return Optional.of(Authority.valueOf(value));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public static Optional<Authority> fromShortString(@NonNull String value) {
        return fromString(ROLE_ + value);
    }

    public static Authority fromCode(short code) {
         return BY_CODE.get(code);
    }
}
