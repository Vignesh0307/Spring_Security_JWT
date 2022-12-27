package com.example.userService.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // depedency injection for authentication manger to authenticate the user
    //attempts to authenticate the passed authentication object, returning a
    // fully populated authentication object(including granted authorities if it is sucessful).

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    // attempt authentication performs the actual authentication .
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
       String username = request.getParameter("username");
       String password = request.getParameter("password");
       log.info("user Name is : {}", username);
       log.info("Password is {} ", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    // default behaviour for success authentication
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authentication)
            throws IOException, ServletException {
       // whenever the authentication is succesful this will send the access token
        // and the refreh token to the user

        // This User is the spring security user .
        User user = (User)authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        // This is the access token
        String access_token = JWT.create().withSubject(user.getUsername())
                // when does it expires
                .withExpiresAt(new Date(System.currentTimeMillis() +10*60*100))
                // Issuer is like the author of the token
                .withIssuer(request.getRequestURL().toString())
                //to the roles and his authority
                .withClaim("roles",
                        user.getAuthorities().stream().map(GrantedAuthority :: getAuthority).collect(Collectors.toList()))
                // we are sigining with algorithm
                .sign(algorithm);

        // This is the refresh_token after the access_token expires refresh token will come into the picture
        String refresh_token = JWT.create().withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() +30*60*100))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
       /*
        // setting the access_token to the response header
        response.setHeader("access_token",access_token);
        response.setHeader("refresh_token",refresh_token);
        */

        // Instead of adding access_token to the response header we are adding it in
        //response body
        Map<String,String> tokens = new HashMap<>();
        tokens.put("access_token",access_token);
        tokens.put("refresh_token",refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(),tokens);
    }

}
