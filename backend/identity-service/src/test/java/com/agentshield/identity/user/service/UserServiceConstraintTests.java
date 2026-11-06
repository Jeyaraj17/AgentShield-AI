package com.agentshield.identity.user.service;

import java.sql.SQLException;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.agentshield.identity.user.api.CreateUserRequest;
import com.agentshield.identity.user.persistence.UserRepository;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceConstraintTests {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void translatesNamedEmailConstraintViolation() {
        String email = "person@example.com";
        when(userRepository.existsByEmailNormalized(email)).thenReturn(false);
        when(passwordEncoder.encode("StrongPassword1!")).thenReturn("bcrypt-hash");
        DataIntegrityViolationException databaseException = violationOf("uk_users_email_normalized");
        when(userRepository.saveAndFlush(any())).thenThrow(databaseException);

        assertThrows(DuplicateUserEmailException.class,
                () -> userService.createUser(new CreateUserRequest(
                        email, "First", "Last", "StrongPassword1!")));
    }

    @Test
    void preservesUnrelatedDatabaseIntegrityViolation() {
        String email = "other@example.com";
        when(userRepository.existsByEmailNormalized(email)).thenReturn(false);
        when(passwordEncoder.encode("StrongPassword1!")).thenReturn("bcrypt-hash");
        DataIntegrityViolationException databaseException = violationOf("ck_users_name_policy");
        when(userRepository.saveAndFlush(any())).thenThrow(databaseException);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> userService.createUser(new CreateUserRequest(
                        email, "First", "Last", "StrongPassword1!")));

        assertSame(databaseException, thrown);
    }

    private DataIntegrityViolationException violationOf(String constraintName) {
        ConstraintViolationException hibernateException = new ConstraintViolationException(
                "constraint violation", new SQLException("constraint violation"), "insert into users",
                constraintName);
        return new DataIntegrityViolationException("Database integrity violation", hibernateException);
    }
}
