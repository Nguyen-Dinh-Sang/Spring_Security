package com.anhitmayman.springsecurity.config;

import com.anhitmayman.springsecurity.model.UserRepository;
import lombok.AllArgsConstructor;
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

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/*
* 1: OncePerRequestFilter, filter one is a once request, all request comes to backend would be intercepted by this filter first
* 2: What we need to do first is we need to tell spring that, this is a component or a Bean, add @Component
*/
@Component
@AllArgsConstructor
public class JwtAthFilter extends OncePerRequestFilter {

    private UserRepository userRepository;
    private JwtService jwtService;

    /*
    * 3: Get the authorization from the header of request
    * 4: Check have the authorization header
    * 5: extract the user email.
    * HttpServletResponse response: we can intercept every request and make and extract data,
    * example if want to add a header to response we can do using this once per request filter
    * FilterChain filterChain: is the chain of responsibility design pattern so it will it contains the list of the
    * other filters
    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader(AUTHORIZATION);
        final String userEmail;
        final String jwtToken;

        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwtToken = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwtToken);

        /*
        * check that the user is not authenticated yet because if user is authenticated -> don't need to
        * perform again all check and setting or and updating SecurityContextHolder
        */
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userRepository.findUserByEmail(userEmail);
            if (jwtService.isTokenValid(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
