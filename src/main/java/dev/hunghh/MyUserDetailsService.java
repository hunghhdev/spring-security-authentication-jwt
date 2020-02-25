package dev.hunghh;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service("myUserDetailsService")
public class MyUserDetailsService implements UserDetailsService {

    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        Set<String> authorities = new HashSet<>();
        authorities.add("ROLE_ADMIN");
        User user = new User();
        user.setUsername("hunghh");
        user.setPassword("$2a$10$uTjmpvNiz1llVAUfeSH2n.ivGtaVxV2ZgqEijrLNm6E3RZE8s2qoK");
        user.setAuthorities(authorities);
        return user;
    }
}
