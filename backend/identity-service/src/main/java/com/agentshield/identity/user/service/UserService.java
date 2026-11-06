package com.agentshield.identity.user.service;

import java.util.Locale;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.identity.user.api.CreateUserRequest;
import com.agentshield.identity.user.api.UserResponse;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        String email = request.email().strip().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmailNormalized(email)) {
            throw new DuplicateUserEmailException(email);
        }

        String passwordHash = passwordEncoder.encode(request.password());
        User user = new User(email, request.firstName(), request.lastName(), passwordHash);
        try {
            return UserResponse.from(userRepository.saveAndFlush(user));
        } catch (DataIntegrityViolationException exception) {
            if (violatesEmailConstraint(exception)) {
                throw new DuplicateUserEmailException(email);
            }
            throw exception;
        }
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));
        return UserResponse.from(user);
    }

    private boolean violatesEmailConstraint(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && "uk_users_email_normalized".equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }
        }
        return false;
    }
}
