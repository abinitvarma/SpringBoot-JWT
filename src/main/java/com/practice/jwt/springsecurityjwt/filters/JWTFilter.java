package com.practice.jwt.springsecurityjwt.filters;

import com.practice.jwt.springsecurityjwt.services.MyUserDetailsService;
import com.practice.jwt.springsecurityjwt.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        final String authorizationHeader = httpServletRequest.getHeader("Authorization"); //Get Token from header

        String userName = null;
        String jwtToken = null;

        if(authorizationHeader!=null && authorizationHeader.startsWith("TOKEN ")){
            jwtToken = authorizationHeader.substring(6);
            userName = jwtUtil.getUsernameFromToken(jwtToken);
        }

        if(userName!= null && SecurityContextHolder.getContext().getAuthentication() == null){
            final UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

            if(jwtUtil.validateToken(jwtToken,userDetails)){ // validate token
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,null,userDetails.getAuthorities()
                        ); // Create your own UsernamePasswordAuthenticationToken instead of letting Spring do it
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(httpServletRequest)
                ); // Set the details as the HttpRequest

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken); // Set it in the Security Context (No Spring interference!!)
            }
        }

        filterChain.doFilter(httpServletRequest,httpServletResponse); // continue the filter chain
    }
}
