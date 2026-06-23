// JV-007 SAFE: auth-named methods with real logic — no unconditional return true/null
package com.acmecorp.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class RealUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public RealUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Safe: real database lookup — throws if not found
        return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}

@Service
class RealAccessControlService {

    private final PermissionRepository permRepo;
    private final RoleRepository roleRepo;

    RealAccessControlService(PermissionRepository permRepo, RoleRepository roleRepo) {
        this.permRepo = permRepo;
        this.roleRepo = roleRepo;
    }

    public boolean isAuthorized(String userId, String resource) {
        // Safe: real lookup — result depends on actual permissions
        return permRepo.hasPermission(userId, resource);
    }

    public boolean authenticate(String username, String hashedPassword) {
        // Safe: real comparison
        Optional<User> user = userRepository.findByUsername(username);
        return user.isPresent() && passwordEncoder.matches(hashedPassword, user.get().getPasswordHash());
    }
}
