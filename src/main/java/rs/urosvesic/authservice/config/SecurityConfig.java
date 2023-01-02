package rs.urosvesic.authservice.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

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



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        String[] permitAllEndpointList = {URL_SIGN_UP, URL_SIGN_IN, URLS_SWAGGER_UI, URL_SWAGGER_UI, URL_API_DOCS, URL_ACTUATOR};

        http.cors().and().csrf().disable()
                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry
                        .antMatchers(permitAllEndpointList)
                        .permitAll()
                        .antMatchers(HttpMethod.OPTIONS,"/**")
                        .permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling()
                .and()
                .oauth2ResourceServer().jwt();

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return null;
    }

}
