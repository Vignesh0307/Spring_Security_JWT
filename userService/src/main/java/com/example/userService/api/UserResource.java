package com.example.userService.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.userService.domain.Role;
import com.example.userService.domain.User;
import com.example.userService.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>>getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User>saveUser(@RequestBody User user){
        URI uri =URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role){
        URI uri =URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtoUser")
    public ResponseEntity<?>addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleoUser(form.getUserName(),form.getRoleName() );
      //  return ResponseEntity.ok().body(userService.addRoleoUser(form.getUserName(),form.getRoleName() ));
        return ResponseEntity.ok().build();
    }

    @GetMapping ("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            try {
                // getting the refresh_token
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                // we are using secret in this algorithm because while authenticating
                // in CustomAuthenticationFiler we gave secret to the algorithm
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                // validates claims and signature
                JWTVerifier verifier = JWT.require(algorithm).build();
                // verifying that refresh_token is valid
                DecodedJWT decodeJWT = verifier.verify(refresh_token);
                // after verifiying the refresh_token we are getting the username and roles
                String username = decodeJWT.getSubject();
                User user = userService.getUser(username);
              // This is the access refresh_token
                String access_token = JWT.create().withSubject(user.getUsername())
                        // when does it expires
                        .withExpiresAt(new Date(System.currentTimeMillis() +10*60*100))
                        // Issuer is like the author of the refresh_token
                        .withIssuer(request.getRequestURL().toString())
                        //to the roles and his authority
                        .withClaim("roles",
                                user.getRoles().stream().map(Role ::getName).collect(Collectors.toList()))
                        // we are sigining with algorithm
                        .sign(algorithm);

                Map<String,String> tokens = new HashMap<>();
                tokens.put("access_token",access_token);
                tokens.put("refresh_token",refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),tokens);

            }catch (Exception ex){
                //   response.sendError(FORBIDDEN.value());
                // If there is an error we are setting that in the response body
                Map<String,String> error = new HashMap<>();
                error.put("error_msg",ex.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),error);
            }
        }else{
            throw new RuntimeException("Refresh token is missing");
        }
    }

}

@Data
class RoleToUserForm{
    private String userName;
    private String roleName;
}
