package com.mk.springsecurityjw.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mk.springsecurityjw.auth.JwtProvider;
import com.mk.springsecurityjw.models.User;
import com.mk.springsecurityjw.pojo.JwtResponse;
import com.mk.springsecurityjw.repositories.RoleRepository;
import com.mk.springsecurityjw.repositories.UserRepository;
 

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
public class AuthRestAPIs {
 
    @Autowired
    AuthenticationManager authenticationManager;
 
    @Autowired
    UserRepository userRepository;
 
    @Autowired
    RoleRepository roleRepository;
 
    @Autowired
    PasswordEncoder encoder;
 
    @Autowired
    JwtProvider jwtProvider;
 
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(User user) {
 
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername(),
                        user.getPassword()
                )
        );
 
        SecurityContextHolder.getContext().setAuthentication(authentication);
 
        String jwt = jwtProvider.generateJwtToken(authentication);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }
 
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(User user) {
        if(userRepository.existsByUsername(user.getUsername())) {
            return new ResponseEntity<String>("Fail -> Username is already taken!",
                    HttpStatus.BAD_REQUEST);
        }
 
        if(userRepository.existsByEmail(user.getEmail())) {
            return new ResponseEntity<String>("Fail -> Email is already in use!",
                    HttpStatus.BAD_REQUEST);
        }
 
        // Creating user's account
        User userCreated = new User(user.getName(), user.getUsername(),
        		user.getEmail(), encoder.encode(user.getPassword()));
 
//        Set<String> strRoles = null;
//        Set<Role> roles = new HashSet<>();
 
//        strRoles.forEach(role -> {
//        	switch(role) {
//	    		case "admin":
//	    			Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	    			roles.add(adminRole);
//	    			
//	    			break;
//	    		case "pm":
//	            	Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	            	roles.add(pmRole);
//	            	
//	    			break;
//	    		default:
//	        		Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
//	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
//	        		roles.add(userRole);        			
//        	}
//        });
        
//        user.setRoles(roles);
        userRepository.save(userCreated);
        return ResponseEntity.ok().body("User registered successfully!");
    }
    
	@GetMapping("/user")
	@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
	public String userAccess() {
		return ">>> User Contents!";
	}
	
	@GetMapping("/pm")
	@PreAuthorize("hasRole('PM') or hasRole('ADMIN')")
	public String projectManagementAccess() {
		return ">>> Board Management Project";
	}
	
	@GetMapping("/admin")
	@PreAuthorize("hasRole('ADMIN')")
	public String adminAccess() {
		return ">>> Admin Contents";
	}
    
	@GetMapping("/foo")
	public String foo() {
		return ">>> Foo Contents";
	}
}