package com.agentshield.identity.auth;

import java.util.Locale;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.agentshield.identity.user.persistence.UserRepository;

@Service
public class IdentityUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public IdentityUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        String normalizedEmail = email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
        com.agentshield.identity.user.domain.User identity = userRepository.findByEmailNormalized(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));

        return User.withUsername(identity.getEmailNormalized())
                .password(identity.getPasswordHash())
                .authorities("ROLE_USER")
                .disabled(identity.getStatus() != com.agentshield.identity.user.domain.UserStatus.ACTIVE)
                .build();
    }
}
