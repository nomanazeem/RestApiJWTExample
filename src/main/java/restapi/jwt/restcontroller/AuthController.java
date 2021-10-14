package restapi.jwt.restcontroller;

import org.springframework.security.core.userdetails.UserDetails;
import restapi.jwt.model.Role;
import restapi.jwt.model.User;
import restapi.jwt.payload.request.LoginRequest;
import restapi.jwt.payload.request.SignupRequest;
import restapi.jwt.payload.response.JwtResponse;
import restapi.jwt.payload.response.MessageResponse;
import restapi.jwt.repository.IRoleRepository;
import restapi.jwt.repository.IUserRepository;
import restapi.jwt.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    IUserRepository userRepository;


    @Autowired
    IRoleRepository roleRepository;


    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

       @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
          /* System.out.println("username:"+username);
           System.out.println("password:"+password);*/

           Authentication authentication = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (AccountStatusException | BadCredentialsException ase) {

            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(false,"Error: Invalid Username or password!", null));

        } // If the username/password are wrong the spec says we should send 400/invalid grant

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(false,"Error: Could not authenticate user: "+loginRequest.getUsername(), null));
        }


        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

       UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(
                true
                , jwt,
                0L,
                userDetails.getUsername(),
                "",
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(false,"Error: Username is already taken!", null));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(false,"Error: Email is already in use!", null));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword()));


        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(signUpRequest.getRole()));

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse(true,"User registered successfully!", null));
    }
}
