package com.practice.jwt.springsecurityjwt.resources;

import com.practice.jwt.springsecurityjwt.domain.AuthenticationRequest;
import com.practice.jwt.springsecurityjwt.domain.AuthenticationResponse;
import com.practice.jwt.springsecurityjwt.services.MyUserDetailsService;
import com.practice.jwt.springsecurityjwt.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @GetMapping("/hello")
    public String getHello(){
        return "Hello World!!";
    }

    @PostMapping("/authenticate")
    private ResponseEntity<?> generateToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword())
            );
        }
        catch (BadCredentialsException be){
            throw new Exception("Incorrect UserName/Password", be);
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(
                authenticationRequest.getUserName()
        );

        final String jwt = jwtUtil.generateToken(userDetails);

        return  ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}
