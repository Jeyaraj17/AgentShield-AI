package com.agentshield.identity.validation;

import java.nio.charset.StandardCharsets;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class BcryptPasswordValidator implements ConstraintValidator<ValidBcryptPassword, CharSequence> {

    private static final int MINIMUM_CODE_POINTS = 12;
    private static final int MAXIMUM_UTF8_BYTES = 72;

    @Override
    public boolean isValid(CharSequence password, ConstraintValidatorContext context) {
        if (password == null) {
            return true;
        }

        String value = password.toString();
        int codePointCount = value.codePointCount(0, value.length());
        int utf8ByteCount = value.getBytes(StandardCharsets.UTF_8).length;
        return codePointCount >= MINIMUM_CODE_POINTS && utf8ByteCount <= MAXIMUM_UTF8_BYTES;
    }
}
