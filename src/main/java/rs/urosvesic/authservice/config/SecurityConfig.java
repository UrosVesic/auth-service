package rs.urosvesic.authservice.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import rs.urosvesic.authservice.converter.JwtConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {
    private static final String URL_SIGN_UP = "/api/cognito/sign-up";
    private static final String URL_SIGN_IN = "/api/cognito/sign-in";
    private static final String URLS_SWAGGER_UI = "/swagger-ui/**";

    private static final String URL_SWAGGER_UI = "/swagger-ui.html";
    private static final String URL_API_DOCS = "/v3/api-docs/**";
    private static final String URL_ACTUATOR = "/actuator/**";
    private static final String URL_REFRESH_TOKEN = "/api/cognito/refresh-token";
    private static final String URL_FORGOT_PASSWORD = "/api/cognito/forgot-password";
    private static final String URL_RESET_PASSWORD = "/api/cognito/reset-password";
    private static final String URL_ENABLE_USER = "/api/cognito/enable/**";
    private static final String URL_DISABLE_USER = "/api/cognito/disable/**";



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        String[] permitAllEndpointList = {URL_SIGN_UP, URL_SIGN_IN, URLS_SWAGGER_UI,
                URL_SWAGGER_UI, URL_API_DOCS, URL_ACTUATOR,URL_REFRESH_TOKEN, URL_FORGOT_PASSWORD,
                URL_RESET_PASSWORD};

        String[] hasAuthorityAdminEndpoints = {URL_ENABLE_USER,URL_DISABLE_USER};

        http.cors().and().csrf().disable()
                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry
                        .antMatchers(permitAllEndpointList)
                        .permitAll()
                        .antMatchers(hasAuthorityAdminEndpoints)
                        .hasAuthority("admin")
                        .antMatchers(HttpMethod.OPTIONS,"/**")
                        .permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtConverter());

        return http.build();
    }

    private Converter<Jwt, JwtAuthenticationToken> jwtConverter() {
        JwtConverter converter = new JwtConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<String> claims = jwt.getClaimAsStringList("cognito:groups");
            if(claims==null){
                return Collections.emptyList();
            }
            List<GrantedAuthority> authorities  = new ArrayList<>();
            claims.forEach(c->authorities.add(new SimpleGrantedAuthority(c)));
            return authorities;
        });
        return converter;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return null;
    }

}
