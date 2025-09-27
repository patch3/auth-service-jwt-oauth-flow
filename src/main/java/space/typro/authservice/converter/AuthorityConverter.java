package space.typro.authservice.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import space.typro.authservice.constant.Authority;

import static space.typro.authservice.constant.RoleConst.NON_CODE;


@Converter(autoApply = true)
public class AuthorityConverter implements AttributeConverter<Authority, Short> {
    @Override
    public Short convertToDatabaseColumn(Authority attribute) {
        return attribute == null ? NON_CODE : attribute.getCode();
    }


    @Override
    public Authority convertToEntityAttribute(Short dbDate) {
        return dbDate == null ? Authority.ROLE_NON : Authority.fromCode(dbDate);
    }
}
