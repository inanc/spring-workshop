package spring.security.base;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/").permitAll();
                    authorize.requestMatchers("/css/**").permitAll();
                    authorize.requestMatchers("/error").permitAll();
                    authorize.requestMatchers("/favicon.svg").permitAll();
                    authorize.anyRequest().authenticated();
                })
                .formLogin(form -> {
                    form.defaultSuccessUrl("/private");
                })
                .oauth2Login(oidc -> {
                    oidc.defaultSuccessUrl("/private");
                })
                .addFilterBefore(new ForbiddenFilter(), AuthorizationFilter.class)
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var userFactory = User.withDefaultPasswordEncoder();
        var inanc = userFactory.username("inanc")
                .password("password")
                .build();
        var yagiz = userFactory.username("yagiz")
                .password("password")
                .build();
        return new InMemoryUserDetailsManager(inanc, yagiz);
    }
}
