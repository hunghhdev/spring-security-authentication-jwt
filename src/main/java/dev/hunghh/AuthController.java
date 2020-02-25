package dev.hunghh;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class AuthController {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginModel loginModel) {
        User user = myUserDetailsService.loadUserByUsername(loginModel.getUsername());
        if (passwordEncoder.matches(loginModel.getPassword(), user.password()))
            return new ResponseEntity<>(jwtUtil.generateTokenLogin(user), HttpStatus.OK);
        return new ResponseEntity<>(null, HttpStatus.OK);
    }

    @GetMapping("/getUser")
    public ResponseEntity<User> getUser(Authentication authentication) {
        return new ResponseEntity<>((User) authentication.getPrincipal(), HttpStatus.OK);
    }
}
