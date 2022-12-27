package com.example.userService.security;

import com.example.userService.filter.CustomAuthenticationFilter;
import com.example.userService.filter.CustomAutherizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   // private UserDetailsService userDetailsService;

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // Authentication manager builder used to create an authentication manager
    // It also useful in adding userdetails service
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);

    }

     */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       // super.configure(auth);
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter
                                                                        (authenticationManagerBean());
        // to tell that url starts with here .
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");
      //  super.configure(http);
        http.csrf().disable();
        // make the session as a stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
       // now permiting the request based on the role .
        http.authorizeRequests().antMatchers("/api/login/**","/api/token/refresh/**").permitAll();
        http.authorizeRequests().antMatchers(HttpMethod.GET,"/api/user/**")
                        .hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(HttpMethod.POST,"/api/user/save/**")
                .hasAnyAuthority("ROLE_ADMIN");
        // Authenticating every request .
        http.authorizeRequests().anyRequest().authenticated();
        // it is the authentication filter
        http.addFilter(customAuthenticationFilter);
        // adding this filter to work  before everything
        http.addFilterBefore(new CustomAutherizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


}
