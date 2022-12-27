package com.example.userService.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAutherizationFilter extends OncePerRequestFilter {

    // This OncePerRequest filter class is going to intercept every request that is coming .
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       // if it is the login path then I don't need to do anything everyone is allowed here
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
            // now the request will go through
            filterChain.doFilter(request,response);
        }else{
            // Iam accesing the authorization header  by giving the authorization key to get the authorization Header
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            // whenever we are sending the request then we are going to put the Bearer and space before the token
            // Bearer is can be anything that we giving along with the token
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                try {
                    // getting the token
                    String token = authorizationHeader.substring("Bearer ".length());
                    // we are using secret in this algorithm because while authenticating
                    // in CustomAuthenticationFiler we gave secret to the algorithm
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    // validates claims and signature
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    // verifying that token is valid
                    DecodedJWT decodeJWT = verifier.verify(token);
                    // after verifiying the token we are getting the username and roles
                    String username = decodeJWT.getSubject();
                    String[] roles = decodeJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    // after getting the roles we are converting to the authority
                    stream(roles).forEach(role ->{
                        authorities.add((new SimpleGrantedAuthority(role)));
                    });
                    // It is designed for simple presentation of a username and password
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    // now we are putting that user in the securityContextHolder
                    // now spring will look at their username , roles and decide what are the request they can access
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    filterChain.doFilter(request, response);
                }catch (Exception ex){
                    // If there is an error we are setting this in their response header
                       log.error("Error logging in : {}", ex.getMessage());
                       response.setHeader("error",ex.getMessage());
                       response.setStatus(FORBIDDEN.value());
                    //   response.sendError(FORBIDDEN.value());
                    // If there is an error we are setting that in the response body
                    Map<String,String> error = new HashMap<>();
                    error.put("error_msg",ex.getMessage());

                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }
            }else{
                filterChain.doFilter(request, response);
            }
        }
    }
}
